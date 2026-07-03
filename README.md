# Tillitis Ethereum Wallet

A hardware-backed Ethereum wallet using the [Tillitis TKey](https://tillitis.se/) security token.

The TKey derives a stable secp256k1 key from its internal CDI (Compound Device Identity) — a device-bound secret that never leaves the hardware. The wallet app runs on the TKey, signs digests inside it, and exposes no private key export command.

## What this repo contains

| Path | What it is |
|------|------------|
| `cmd/tkey-eth/` | Host CLI — build, run, and verify |
| `device/ethsign/` | TKey device app (C, RISC-V) |
| `scripts/two_key_ceremony.py` | Operator script for the two-key ceremony |

## What is implemented

**Device app** (`device/ethsign/`):

- derives a secp256k1 private key from TKey CDI using BLAKE2s and a fixed domain string
- returns the uncompressed Ethereum public key
- signs 32-byte digests on-device; private key never leaves the TKey
- reports its own BLAKE2s app digest for measurement

**Host CLI** (`cmd/tkey-eth/`):

| Command | What it does |
|---------|--------------|
| `address` | Print the Ethereum address for the connected TKey |
| `sign-digest` | Sign a raw 32-byte digest |
| `sign-tx` | Sign an unsigned Ethereum transaction (JSON) |
| `sign-personal` | Sign a `personal_sign` message |
| `sign-typed-data` | Sign EIP-712 typed data |
| `verify-live` | Run a live verifier session and write a verifier transcript |
| `bind-two-key-init` | Phase 1 of the two-key ceremony: capture Tillitis identity |
| `bind-two-key-wallet` | Phase 2: capture wallet key and Ethereum signature |
| `bind-two-key-finalize` | Phase 3: get Tillitis identity signature over the binding |
| `verify-two-key` | Offline verification of a completed two-key bundle |
| `attest` | Issue a self-asserted certificate over the wallet pubkey |
| `prove` | Sign a challenge against an existing certificate |
| `verify` | Verify a certificate and optional proof offline |

## Build

### Host CLI (requires Go 1.23+)

```bash
go build -o .bin/tkey-eth ./cmd/tkey-eth/
```

Run from the repo root if you want the default `device/ethsign/app.bin` path to resolve automatically, or pass `--app` explicitly.

### Device app (requires the Tillitis SDK)

```bash
make -C device/ethsign
```

The pre-built binary `device/ethsign/app.bin` is included in this repo.

## Usage

### Get the Ethereum address

```bash
.bin/tkey-eth address --port /dev/ttyACM0
```

Output:

```
pubkey=0x04...
address=0x...
```

### Sign a transaction

Prepare an unsigned transaction JSON file:

```json
{
  "type": "0x2",
  "chainId": "0x1",
  "nonce": 0,
  "maxPriorityFeePerGas": "0x3b9aca00",
  "maxFeePerGas": "0x77359400",
  "gas": 21000,
  "to": "0x000000000000000000000000000000000000dEaD",
  "value": "0xde0b6b3a7640000"
}
```

```bash
.bin/tkey-eth sign-tx --port /dev/ttyACM0 --tx tx.json
```

Output is JSON with `address`, `digest`, `signature`, `raw_transaction`, and `tx_hash`.

### Sign a personal message

```bash
.bin/tkey-eth sign-personal --port /dev/ttyACM0 --message 'hello'
# or from a file:
.bin/tkey-eth sign-personal --port /dev/ttyACM0 --message-file msg.bin
```

### Sign EIP-712 typed data

```bash
.bin/tkey-eth sign-typed-data --port /dev/ttyACM0 --typed-data typed-data.json
```

### User secret (USS)

To bind the wallet key to a user passphrase in addition to the device identity:

```bash
echo -n "my-passphrase" > uss.bin
.bin/tkey-eth address --port /dev/ttyACM0 --uss-file uss.bin
```

The TKey must be replugged to change the USS.

## Verification flows

The wallet ships two verification flows. Neither requires trust in operator testimony beyond what is explicit.

### Live verifier (`verify-live`)

A verifier starts from firmware mode, observes the full loading sequence, and produces a signed transcript.

```bash
.bin/tkey-eth verify-live --port /dev/ttyACM0 --out artifacts/live-verify.json
```

The verifier witnesses:

1. the device UDI (from firmware mode)
2. the wallet app load
3. the on-device BLAKE2s app digest matching the loaded binary
4. the Tillitis vendor verification for that UDI (fetched from `tkey.tillitis.se`)
5. a fresh wallet-key signature over a random challenge

**What this proves:** a live verifier observed a genuine Tillitis device, running the measured wallet app, controlling the stated Ethereum address.

**What this does not prove:** that the private key is non-exportable, or that the Tillitis vendor signed the Ethereum pubkey directly.

### Two-key ceremony (`bind-two-key-*`)

Produces an offline-verifiable bundle where both the Tillitis identity key and the Ethereum wallet key sign the same binding statement.

Run the guided ceremony:

```bash
python3 scripts/two_key_ceremony.py --port /dev/ttyACM0
```

The script drives three phases (each requires a replug to return to firmware mode):

1. **Phase 1** — reads UDI, fetches and verifies the Tillitis vendor evidence, loads the Tillitis signer app, records the identity public key and firmware hash
2. **Phase 2** — loads the Ethereum wallet app, records wallet app digests, records the Ethereum pubkey and address, signs the binding hash with the wallet key
3. **Phase 3** — reloads the Tillitis signer app and signs the same binding hash with the Tillitis identity key

Output: `artifacts/two-key-bind.json`

Offline verification (no device or network needed):

```bash
.bin/tkey-eth verify-two-key --bundle artifacts/two-key-bind.json
```

The verifier checks:

- the embedded Tillitis verification JSON matches the stated UDI
- the Tillitis vendor signature is valid over `UDI || firmware_sha512 || identity_pubkey`
- the Tillitis identity key signed the binding hash
- the Ethereum wallet key signed the same binding hash
- the wallet pubkey matches the wallet address

**What this proves:** both keys jointly signed the same statement; offline verifiers can check without the device.

**What this does not prove:** that the Ethereum private key was generated inside the TKey rather than imported by the wallet app.

### Self-asserted certificate and proof (`attest` / `prove` / `verify`)

A weaker but self-contained flow that issues a certificate over the wallet pubkey signed by a locally generated attestation key, then produces a challenge-response proof.

```bash
.bin/tkey-eth attest --port /dev/ttyACM0 --out artifacts/cert.json
.bin/tkey-eth prove --cert artifacts/cert.json --out artifacts/proof.json
.bin/tkey-eth verify --cert artifacts/cert.json --proof artifacts/proof.json
```

The attestation key is self-generated; this flow does not involve Tillitis vendor signatures.

## Key derivation

The device app derives the private key deterministically:

```
for counter = 0, 1, 2, ...:
    candidate = BLAKE2s(CDI || "tkey-eth-sign-v1" || counter)
    if candidate is a valid secp256k1 scalar:
        privkey = candidate
        break
```

The CDI is device-bound and never exported. The same TKey with the same USS always derives the same key.

## Testing

```bash
go test ./cmd/tkey-eth/
```

Tests cover all pure functions (hex decoding, address derivation, signature finalization, low-S normalization, transaction parsing, certificate encoding and verification, proof verification, two-key payload encoding, and UDI round-trips). No device is required.

## Security properties and limitations

| Property | Status |
|----------|--------|
| Private key never leaves the TKey | Yes — the device app has no export command |
| Key is deterministic from CDI | Yes — same TKey + USS = same key |
| Key derivation is auditable | Yes — source in `device/ethsign/main.c` |
| Vendor-attested Ethereum pubkey | No — not available without a separate attestation app |
| Proof that key was generated on-device (not imported) | No — current flows cannot prove this |
| Low-s signature normalization (EIP-2) | Yes — done in the host CLI |

The two stronger evidence directions (on-device attestation and zero-knowledge key-generation proof) are documented in the parent repo but not yet implemented.

## Requirements

- **Host CLI:** Go 1.23 or later
- **Device app build:** [Tillitis SDK](https://github.com/tillitis/tillitis-key1)
- **Two-key ceremony:** Python 3.10 or later, `tkey-verification` signer app binaries (see `research/upstream/tkey-verification/`)
- **Hardware:** Tillitis TKey connected via USB serial (`/dev/ttyACM0` on Linux, `/dev/cu.usbmodem*` on macOS)
