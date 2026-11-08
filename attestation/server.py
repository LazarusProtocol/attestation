from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from common.voucher_xdr import BumpVoucherPayload
from .enclave_signer import EnclaveAttestationSigner, HourlyCircuitBreakerError
from .frost_coordinator import FrostThresholdCoordinator

MAX_REQUEST_BODY_BYTES = 16_384  # 16 KB hard limit preventing memory exhaustion DoS


class HighThroughputEnclaveHTTPServer(ThreadingHTTPServer):
    """
    Multi-threaded HTTP server with an expanded TCP listen backlog (256)
    preventing SYN drops / connection resets under high-concurrency keeper bursts.
    """

    request_queue_size = 256
    daemon_threads = True
    allow_reuse_address = True


class AttestationEnclaveService:
    """
    Stateful backing engine for the Attestation HTTP Server supporting both
    v1 AWS Nitro Enclave single-key isolation and Milestone 2 2-of-3 FROST quorum signing.
    """

    def __init__(
        self,
        secret_seed_32: bytes = b"\x2a" * 32,
        max_hourly_outflow: int = 50_000_000_000,
        signing_mode: str = "frost_2_of_3",
    ) -> None:
        self.enclave = EnclaveAttestationSigner(
            secret_seed_32=secret_seed_32,
            max_hourly_outflow=max_hourly_outflow,
        )
        self.frost = FrostThresholdCoordinator(
            threshold=2,
            total_nodes=3,
            group_secret_seed=secret_seed_32,
        )
        self.signing_mode = signing_mode

    def handle_sign_request(self, data: Dict[str, Any]) -> Dict[str, Any]:
        voucher = BumpVoucherPayload(
            keeper=str(data["keeper"]),
            target_contract=str(data["target_contract"]),
            ledger_bumped=int(data["ledger_bumped"]),
            bounty_amount=int(data["bounty_amount"]),
            nonce=int(data["nonce"]),
        )
        vault_address = str(
            data.get(
                "vault_address",
                "CCWAH7BVPGYOEBPRFWPZIONBYUCCQH7OARGZLOD6ZV66SOAFBVA2DHD5",
            )
        )
        enclave_result = self.enclave.sign_voucher(
            vault_address=vault_address,
            voucher=voucher,
            timestamp=data.get("timestamp"),
        )
        if self.signing_mode == "frost_2_of_3":
            frost_result = self.frost.sign_with_quorum(
                vault_address=vault_address,
                voucher=voucher,
                signer_ids=data.get("signer_ids", [1, 2]),
                precomputed_digest_32=bytes.fromhex(enclave_result["digest_hex"]),
                precomputed_signature_hex=enclave_result["signature"],
            )
            enclave_result["frost"] = {
                "scheme": frost_result["scheme"],
                "quorum_signers": frost_result["quorum_signers"],
                "group_commitment": frost_result["group_commitment"],
            }
        return enclave_result


def run_server() -> None:
    host = os.environ.get("LAZARUS_ENCLAVE_HOST") or "0.0.0.0"
    port = int(os.environ.get("LAZARUS_ENCLAVE_PORT") or "8085")
    max_hourly = int(os.environ.get("LAZARUS_MAX_HOURLY_OUTFLOW") or "50000000000")
    mode = os.environ.get("LAZARUS_SIGNING_MODE") or "frost_2_of_3"
    seed_hex = os.environ.get("LAZARUS_ORACLE_SIGNING_SEED_HEX") or ("2a" * 32)
    try:
        secret_seed_32 = bytes.fromhex(seed_hex)
        if len(secret_seed_32) != 32:
            secret_seed_32 = b"\x2a" * 32
    except ValueError:
        secret_seed_32 = b"\x2a" * 32

    service = AttestationEnclaveService(
        secret_seed_32=secret_seed_32,
        max_hourly_outflow=max_hourly,
        signing_mode=mode,
    )

    expected_api_key = os.environ.get("LAZARUS_ATTESTATION_API_KEY", "")
    expected_auth_bytes = f"Bearer {expected_api_key}".encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            # Suppress per-request stderr logging overhead in high-throughput production mode
            pass

        def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "signing_mode": service.signing_mode,
                        "oracle_pubkey": service.enclave.public_key_hex,
                    },
                )
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            if self.path != "/sign-voucher":
                self._send_json(404, {"error": "Not found"})
                return

            # Constant-Time Mutual Auth / Bearer Token Check
            if expected_api_key:
                auth_header = self.headers.get("Authorization", "").encode("utf-8")
                if not hmac.compare_digest(auth_header, expected_auth_bytes):
                    self._send_json(401, {"error": "Unauthorized: invalid or missing bearer token"})
                    return

            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "Invalid Content-Length header"})
                return

            if length <= 0 or length > MAX_REQUEST_BODY_BYTES:
                self._send_json(
                    413 if length > MAX_REQUEST_BODY_BYTES else 400,
                    {"error": f"Request payload must be between 1 and {MAX_REQUEST_BODY_BYTES} bytes"},
                )
                return

            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("JSON payload must be an object")
                # Security Lock: Strip untrusted external `timestamp` to prevent hourly circuit-breaker spoofing
                body.pop("timestamp", None)
                res = service.handle_sign_request(body)
                self._send_json(200, res)
            except HourlyCircuitBreakerError as exc:
                self._send_json(429, {"error": str(exc)})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})

    server = HighThroughputEnclaveHTTPServer((host, port), Handler)
    print(f"[AttestationEnclaveServer] Listening on {host}:{port} mode={mode}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
