# Lazarus Attestation Service

[![CI](https://github.com/LazarusProtocol/attestation/actions/workflows/ci.yml/badge.svg)](https://github.com/LazarusProtocol/attestation/actions)

Cryptographic attestation and threshold signature engine for the **Lazarus Protocol** on Stellar (Soroban). Bridges off-chain proof of physical storage key TTL extension (`ExtendFootprintTTLOp`) with on-chain non-custodial Soroban escrow bounty settlement (`BumpVoucher`).

Supports both isolated single-key execution within **AWS Nitro Enclaves** and decentralized **2-of-3 FROST MPC (Flexible Round-Optimized Schnorr Threshold)** quorum signing.

---

## Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │          Lazarus Attestation Engine          │
                      │  (AWS Nitro Enclave / 2-of-3 FROST MPC)      │
                      └──────────────────────┬───────────────────────┘
                                             │
                       POST /sign-voucher    │ Signs LAZARUS_VOUCHER_V1
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │              Signed BumpVoucher              │
                      │  • keeper: Address                           │
                      │  • target_contract: Address                  │
                      │  • ledger_bumped: u32                        │
                      │  • bounty_amount: i128                       │
                      │  • nonce: u64                                │
                      │  • signature: BytesN<64> (Ed25519)           │
                      └──────────────────────┬───────────────────────┘
                                             │
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │          LazarusVault (Soroban SAC)          │
                      │   env.crypto().ed25519_verify(pubkey, ...)   │
                      └──────────────────────────────────────────────┘
```

1. **Deterministic Domain Separation:** Every payload is hashed as `SHA-256("LAZARUS_VOUCHER_V1" || vault || keeper || target || ledger || bounty || nonce)` preventing cross-contract, cross-network, or rival-keeper replays.
2. **Economic Circuit Breakers:** Enforces both per-contract and global hourly outflow ceilings matching `LazarusVault` rules before signing.
3. **Monotonic Nonce Enforcement:** Tracks per-keeper sequence counters to prevent double-issuance of vouchers.
4. **Zero Extra Gas on Stellar:** Produces standard 64-byte Ed25519 signatures verified on-chain natively with zero additional smart contract overhead.

---

## Quickstart

### Prerequisites
* Python 3.11+
* Docker & Docker Compose (optional)

### Local Development
```bash
git clone https://github.com/LazarusProtocol/attestation.git
cd attestation

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the attestation server
python3 -m attestation.server
```

### Docker Compose
```bash
docker compose up -d --build
```

### Running Tests
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `LAZARUS_ENCLAVE_HOST` | `0.0.0.0` | Bind host address |
| `LAZARUS_ENCLAVE_PORT` | `8085` | Bind HTTP port |
| `LAZARUS_SIGNING_MODE` | `frost_2_of_3` | Signing mode: `single_key` or `frost_2_of_3` |
| `LAZARUS_MAX_HOURLY_OUTFLOW` | `5000000000` | Global hourly payout ceiling in stroops (500 USDC) |
| `LAZARUS_ORACLE_SIGNING_SEED_HEX` | *(Sample seed)* | 32-byte Ed25519 master private key seed in hex |
| `LAZARUS_ATTESTATION_API_KEY` | *(None)* | Optional shared secret for `Authorization: Bearer <token>` |

---

## Production Security: AWS Nitro Enclave

To build a reproducible Enclave Image File (EIF) with measurable PCR hashes:
```bash
# Build the Docker image
docker build -t lazarus-attestation-enclave .

# Package into Nitro Enclave EIF
nitro-cli build-enclave \
  --docker-uri lazarus-attestation-enclave:latest \
  --output-file lazarus_attestation.eif

# Inspect cryptographic PCR measurements (PCR0, PCR1, PCR2)
nitro-cli describe-enclaves
```

