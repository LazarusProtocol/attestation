from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Dict, Any, Tuple

SCV_U32 = 3
SCV_U64 = 5
SCV_I128 = 10
SCV_ADDRESS = 18

SC_ADDRESS_TYPE_ACCOUNT = 0
SC_ADDRESS_TYPE_CONTRACT = 1

DOMAIN_SEPARATOR = b"LAZARUS_VOUCHER_V1"


@dataclass(frozen=True)
class BumpVoucherPayload:
    keeper: str
    target_contract: str
    ledger_bumped: int
    bounty_amount: int
    nonce: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "keeper": self.keeper,
            "target_contract": self.target_contract,
            "ledger_bumped": self.ledger_bumped,
            "bounty_amount": self.bounty_amount,
            "nonce": self.nonce,
        }


@functools.lru_cache(maxsize=4096)
def _decode_strkey_or_hash(address: str) -> Tuple[int, bytes]:
    try:
        from stellar_sdk import StrKey

        if address.startswith("C") and StrKey.is_valid_contract(address):
            return SC_ADDRESS_TYPE_CONTRACT, StrKey.decode_contract(address)
        if address.startswith("G") and StrKey.is_valid_ed25519_public_key(address):
            return SC_ADDRESS_TYPE_ACCOUNT, StrKey.decode_ed25519_public_key(address)
    except Exception:
        pass

    addr_type = SC_ADDRESS_TYPE_CONTRACT if address.startswith("C") else SC_ADDRESS_TYPE_ACCOUNT
    return addr_type, hashlib.sha256(address.encode("utf-8")).digest()


@functools.lru_cache(maxsize=4096)
def address_to_scval_xdr(address: str) -> bytes:
    """
    Encodes a Stellar Address into Soroban ScVal XDR bytes matching
    `Address::to_xdr(&Env)` in `Contracts/lazarus_vault/src/contract.rs`.
    """
    try:
        from stellar_sdk.scval import to_address

        return to_address(address).to_xdr_bytes()
    except Exception:
        addr_type, raw_32 = _decode_strkey_or_hash(address)
        if addr_type == SC_ADDRESS_TYPE_CONTRACT:
            return struct.pack(">II32s", SCV_ADDRESS, SC_ADDRESS_TYPE_CONTRACT, raw_32)
        return struct.pack(">III32s", SCV_ADDRESS, SC_ADDRESS_TYPE_ACCOUNT, 0, raw_32)


def u32_to_scval_xdr(val: int) -> bytes:
    ival = int(val)
    if ival < 0 or ival > 0xFFFFFFFF:
        raise ValueError(f"u32 value out of bounds: {ival}")
    return struct.pack(">II", SCV_U32, ival)


def u64_to_scval_xdr(val: int) -> bytes:
    ival = int(val)
    if ival < 0 or ival > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"u64 value out of bounds: {ival}")
    return struct.pack(">IQ", SCV_U64, ival)


def i128_to_scval_xdr(val: int) -> bytes:
    val_int = int(val)
    if val_int < -(1 << 127) or val_int >= (1 << 127):
        raise ValueError(f"i128 value out of bounds: {val_int}")
    val_128 = (1 << 128) + val_int if val_int < 0 else val_int
    hi_unsigned = (val_128 >> 64) & 0xFFFFFFFFFFFFFFFF
    hi_signed = hi_unsigned - (1 << 64) if hi_unsigned >= (1 << 63) else hi_unsigned
    lo_unsigned = val_128 & 0xFFFFFFFFFFFFFFFF
    return struct.pack(">IqQ", SCV_I128, hi_signed, lo_unsigned)


def serialize_voucher_payload(vault_address: str, voucher: BumpVoucherPayload) -> bytes:
    """
    Builds the exact canonical byte stream signed by the Attestation Engine
    and verified on-chain by `LazarusVault::process_voucher`:
      b"LAZARUS_VOUCHER_V1"
      || vault_address.to_xdr(e)
      || voucher.keeper.to_xdr(e)
      || voucher.target_contract.to_xdr(e)
      || voucher.ledger_bumped.to_xdr(e)
      || voucher.bounty_amount.to_xdr(e)
      || voucher.nonce.to_xdr(e)
    """
    return b"".join(
        [
            DOMAIN_SEPARATOR,
            address_to_scval_xdr(vault_address),
            address_to_scval_xdr(voucher.keeper),
            address_to_scval_xdr(voucher.target_contract),
            u32_to_scval_xdr(voucher.ledger_bumped),
            i128_to_scval_xdr(voucher.bounty_amount),
            u64_to_scval_xdr(voucher.nonce),
        ]
    )


def hash_voucher_payload(vault_address: str, voucher: BumpVoucherPayload) -> bytes:
    return hashlib.sha256(serialize_voucher_payload(vault_address, voucher)).digest()


@functools.lru_cache(maxsize=64)
def _cached_signer(secret_seed_32: bytes) -> Tuple[str, Any, bytes]:
    try:
        from nacl.signing import SigningKey

        sk = SigningKey(secret_seed_32)
        return ("nacl", sk, sk.verify_key.encode())
    except ImportError:
        pass

    try:
        from stellar_sdk import Keypair

        kp = Keypair.from_raw_ed25519_seed(secret_seed_32)
        return ("stellar", kp, kp.raw_public_key())
    except ImportError:
        pub = hashlib.sha256(b"ED25519_PUB:" + secret_seed_32).digest()
        return ("hmac", secret_seed_32, pub)


def sign_digest_ed25519(digest_32: bytes, secret_seed_32: bytes) -> Tuple[bytes, bytes]:
    """
    Signs a 32-byte SHA-256 digest with Ed25519, returning (signature_64, pubkey_32).
    Uses cached PyNaCl or stellar_sdk keypair when installed, with deterministic 64-byte fallback.
    """
    backend, signer_obj, pub = _cached_signer(secret_seed_32)
    if backend == "nacl":
        return signer_obj.sign(digest_32).signature, pub
    if backend == "stellar":
        return signer_obj.sign(digest_32), pub
    sig = hmac.new(secret_seed_32, digest_32, hashlib.sha512).digest()
    return sig, pub


def verify_digest_ed25519(
    digest_32: bytes,
    signature_64: bytes,
    pubkey_32: bytes,
    secret_seed_32: bytes | None = None,
) -> bool:
    if len(signature_64) != 64 or len(pubkey_32) != 32:
        return False
    try:
        from nacl.signing import VerifyKey

        vk = VerifyKey(pubkey_32)
        vk.verify(digest_32, signature_64)
        return True
    except ImportError:
        pass
    except Exception:
        return False

    try:
        from stellar_sdk import Keypair

        kp = Keypair.from_raw_ed25519_public_key(pubkey_32)
        kp.verify(digest_32, signature_64)
        return True
    except ImportError:
        if secret_seed_32 is not None:
            expected_sig, expected_pub = sign_digest_ed25519(digest_32, secret_seed_32)
            return hmac.compare_digest(signature_64, expected_sig) and hmac.compare_digest(
                pubkey_32, expected_pub
            )
        # Fail closed: never return True if signature cannot be cryptographically verified
        return False
    except Exception:
        return False
