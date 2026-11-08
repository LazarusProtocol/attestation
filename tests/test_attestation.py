from __future__ import annotations

import unittest
from typing import Any, Dict

from attestation.enclave_signer import (
    EnclaveAttestationSigner,
    HourlyCircuitBreakerError,
)
from attestation.frost_coordinator import FrostThresholdCoordinator
from attestation.server import AttestationEnclaveService
from common.voucher_xdr import (
    BumpVoucherPayload,
    hash_voucher_payload,
    serialize_voucher_payload,
    sign_digest_ed25519,
    verify_digest_ed25519,
)


class LazarusAttestationTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.vault_id = "CCLAZARUSVAULTCONTRACTADDRESS0000000000000000000000000000"
        self.contract_id = "CCBLENDPOOLCONTRACT0000000000000000000000000000000000001"
        self.keeper_addr = "GKEEPERNODEADDRESS00000000000000000000000000000000000001"

    def test_canonical_xdr_serialization_and_ed25519_verification(self) -> None:
        voucher = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=550_000,
            bounty_amount=1_000_000,
            nonce=1,
        )
        raw_payload = serialize_voucher_payload(self.vault_id, voucher)
        self.assertTrue(raw_payload.startswith(b"LAZARUS_VOUCHER_V1"))

        digest = hash_voucher_payload(self.vault_id, voucher)
        self.assertEqual(len(digest), 32)

        seed = b"\x2a" * 32
        sig, pub = sign_digest_ed25519(digest, seed)
        self.assertEqual(len(sig), 64)
        self.assertEqual(len(pub), 32)
        self.assertTrue(verify_digest_ed25519(digest, sig, pub, secret_seed_32=seed))

    def test_enclave_signer_monotonic_nonces_and_hourly_circuit_breaker(self) -> None:
        signer = EnclaveAttestationSigner(
            secret_seed_32=b"\x42" * 32,
            max_hourly_outflow=5_000_000,  # 0.50 USDC
        )

        v1 = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=500_000,
            bounty_amount=2_000_000,
            nonce=1,
        )
        res1 = signer.sign_voucher(
            vault_address=self.vault_id, voucher=v1, timestamp=3600 * 10
        )
        self.assertEqual(res1["voucher"]["nonce"], 1)
        self.assertEqual(len(res1["signature"]), 128)

        # Replaying nonce 1 or skipping to 3 fails monotonic assertion
        with self.assertRaises(ValueError):
            signer.sign_voucher(
                vault_address=self.vault_id, voucher=v1, timestamp=3600 * 10
            )

        v3_skip = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=500_000,
            bounty_amount=2_000_000,
            nonce=3,
        )
        with self.assertRaises(ValueError):
            signer.sign_voucher(
                vault_address=self.vault_id, voucher=v3_skip, timestamp=3600 * 10
            )

        # Voucher 2 within outflow limit succeeds
        v2 = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=500_000,
            bounty_amount=2_000_000,
            nonce=2,
        )
        res2 = signer.sign_voucher(
            vault_address=self.vault_id, voucher=v2, timestamp=3600 * 10
        )
        self.assertEqual(res2["voucher"]["nonce"], 2)

        # Voucher 3 in same hour trips max_hourly_outflow circuit breaker
        v3 = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=500_000,
            bounty_amount=2_000_000,
            nonce=3,
        )
        with self.assertRaises(HourlyCircuitBreakerError):
            signer.sign_voucher(
                vault_address=self.vault_id, voucher=v3, timestamp=3600 * 10
            )

        # Advancing timestamp by 1 hour rolls over accumulator and allows signing
        res3_next_hour = signer.sign_voucher(
            vault_address=self.vault_id, voucher=v3, timestamp=3600 * 11
        )
        self.assertEqual(res3_next_hour["voucher"]["nonce"], 3)

    def test_frost_mpc_threshold_signing(self) -> None:
        frost = FrostThresholdCoordinator(
            threshold=2,
            total_nodes=3,
            group_secret_seed=b"\x99" * 32,
        )

        voucher = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=500_000,
            bounty_amount=1_000_000,
            nonce=1,
        )

        # 2-of-3 threshold quorum with signers [1, 2]
        res = frost.sign_with_quorum(
            vault_address=self.vault_id,
            voucher=voucher,
            signer_ids=[1, 2],
        )
        self.assertEqual(res["scheme"], "FROST-Ed25519-2-of-3")
        self.assertEqual(res["quorum_signers"], [1, 2])
        self.assertEqual(len(res["signature"]), 128)
        self.assertEqual(len(res["partial_shares"]), 2)

        # Insufficient threshold (< 2) raises ValueError
        with self.assertRaises(ValueError):
            frost.sign_with_quorum(
                vault_address=self.vault_id,
                voucher=voucher,
                signer_ids=[1],
            )

    def test_attestation_service_handler(self) -> None:
        service = AttestationEnclaveService(
            secret_seed_32=b"\x2a" * 32,
            max_hourly_outflow=50_000_000_000,
            signing_mode="frost_2_of_3",
        )

        req_payload = {
            "vault_address": self.vault_id,
            "keeper": self.keeper_addr,
            "target_contract": self.contract_id,
            "ledger_bumped": 500_000,
            "bounty_amount": 1_000_000,
            "nonce": 1,
            "signer_ids": [2, 3],
        }

        res = service.handle_sign_request(req_payload)
        self.assertEqual(res["voucher"]["nonce"], 1)
        self.assertIn("frost", res)
        self.assertEqual(res["frost"]["quorum_signers"], [2, 3])
        self.assertEqual(len(res["signature"]), 128)

    def test_security_zero_ledger_and_bounty_guards(self) -> None:
        signer = EnclaveAttestationSigner(secret_seed_32=b"\x2a" * 32)
        bad_ledger_voucher = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=0,
            bounty_amount=1_000_000,
            nonce=1,
        )
        with self.assertRaises(ValueError):
            signer.sign_voucher(self.vault_id, bad_ledger_voucher)

        bad_bounty_voucher = BumpVoucherPayload(
            keeper=self.keeper_addr,
            target_contract=self.contract_id,
            ledger_bumped=500_000,
            bounty_amount=0,
            nonce=1,
        )
        with self.assertRaises(ValueError):
            signer.sign_voucher(self.vault_id, bad_bounty_voucher)


if __name__ == "__main__":
    unittest.main()

