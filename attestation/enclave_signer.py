from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from common.voucher_xdr import (
    BumpVoucherPayload,
    hash_voucher_payload,
    sign_digest_ed25519,
)

PROTOCOL_FEE_BPS = 500
BPS_DENOMINATOR = 10_000
MAX_TRACKED_KEEPERS = 100_000


class HourlyCircuitBreakerError(RuntimeError):
    """Raised when the enclave hourly outflow circuit breaker is tripped."""


class EnclaveAttestationSigner:
    """
    v1 AWS Nitro Enclave isolated Ed25519 attestation signer (`mvp.md` Section 3).
    Enforces:
      - Strict positive bounty & ledger_bumped validation
      - Thread-safe monotonic per-keeper sequence nonces (with bounded memory map)
      - Off-chain hourly outflow circuit breaker mirroring `lazarus_vault`'s `MaxHourlyOutflow`
      - Pre-signature state validation (preventing CPU exhaustion DoS on invalid nonces / tripped circuit breaker)
      - Canonical `LAZARUS_VOUCHER_V1` domain-separated Ed25519 signing
    """

    def __init__(
        self,
        secret_seed_32: bytes = b"\x2a" * 32,
        max_hourly_outflow: int = 50_000_000_000,
    ) -> None:
        if len(secret_seed_32) != 32:
            raise ValueError("secret_seed_32 must be exactly 32 bytes")
        self._secret_seed = secret_seed_32
        _, self.public_key_bytes = sign_digest_ed25519(b"\x00" * 32, self._secret_seed)
        self._public_key_hex = self.public_key_bytes.hex()
        self.max_hourly_outflow = max_hourly_outflow
        self.tracked_hour: int = 0
        self.hourly_outflow_accumulator: int = 0
        self.keeper_nonces: Dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    def sign_voucher(
        self,
        vault_address: str,
        voucher: BumpVoucherPayload,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        if voucher.bounty_amount <= 0:
            raise ValueError("BountyOutOfBounds: bounty_amount must be > 0")
        if voucher.ledger_bumped <= 0:
            raise ValueError("BountyOutOfBounds: ledger_bumped must be > 0")
        if voucher.nonce <= 0:
            raise ValueError("InvalidNonce: nonce must be > 0")

        protocol_fee = (voucher.bounty_amount * PROTOCOL_FEE_BPS) // BPS_DENOMINATOR
        total_deduction = voucher.bounty_amount + protocol_fee
        now_ts = int(timestamp if timestamp is not None else time.time())
        current_hour = now_ts // 3600

        # Validate payload serialization bounds before locking/signing
        digest_32 = hash_voucher_payload(vault_address, voucher)

        # Atomic state validation and reservation BEFORE expensive Ed25519 signing
        with self._lock:
            expected_nonce = self.keeper_nonces.get(voucher.keeper, 0) + 1
            if voucher.nonce != expected_nonce:
                raise ValueError(
                    f"InvalidNonce: expected {expected_nonce}, got {voucher.nonce}"
                )

            is_new_hour = current_hour > self.tracked_hour
            prospective = (
                total_deduction
                if is_new_hour
                else self.hourly_outflow_accumulator + total_deduction
            )
            if prospective > self.max_hourly_outflow:
                raise HourlyCircuitBreakerError(
                    f"HourlyOutflowExceeded: {prospective} > {self.max_hourly_outflow}"
                )

            if is_new_hour:
                self.tracked_hour = current_hour
            self.hourly_outflow_accumulator = prospective
            if (
                voucher.keeper not in self.keeper_nonces
                and len(self.keeper_nonces) >= MAX_TRACKED_KEEPERS
            ):
                oldest_keeper = next(iter(self.keeper_nonces))
                del self.keeper_nonces[oldest_keeper]
            self.keeper_nonces[voucher.keeper] = voucher.nonce

        signature_64, _ = sign_digest_ed25519(digest_32, self._secret_seed)

        return {
            "vault_address": vault_address,
            "voucher": voucher.to_dict(),
            "digest_hex": digest_32.hex(),
            "signature": signature_64.hex(),
            "oracle_pubkey": self._public_key_hex,
        }
