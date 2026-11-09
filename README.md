# Tillitis Ethereum Wallet

A hardware-backed Ethereum wallet using the [Tillitis TKey](https://tillitis.se/) security token.

The TKey derives a stable secp256k1 key from its internal CDI (Compound Device Identity) — a device-bound secret that never leaves the hardware. The wallet app runs on the TKey, signs digests inside it, and exposes no private key export command.

The command line follows [hw-wallet-cli-spec](https://github.com/mab-xyz/hw-wallet-cli-spec), shared with `yketh` (YubiKey): same commands, flags and JSON. `--device` is the serial port of the TKey (detected when omitted), and `scripts/check_spec.sh` checks the CLI against the spec.

## What this repo contains

| Path | What it is |
|------|------------|
| `cmd/tkey-eth/` | Host CLI — build, run, and verify |
| `device/ethsign/` | TKey device app, single key (C, RISC-V) |
| `device/ethsign-hd/` | TKey device app, BIP-32 HD keys (C, RISC-V) |
| `tests/bip32/` | Native test of the device BIP-32 code against the BIP-32 spec vectors |
| `scripts/hw_check_hd.sh` | Hardware check of BIP-32 mode on a plugged TKey |
| `scripts/check_spec.sh` | Check the CLI against [hw-wallet-cli-spec](https://github.com/mab-xyz/hw-wallet-cli-spec): `--help` flags and golden JSON |
| `scripts/two_key_ceremony.py` | Operator script for the two-key ceremony |

## What is implemented

**Device app** (`device/ethsign/`):

- derives exactly one key per (device, app binary, USS): no BIP-32/BIP-44 HD derivation, no derivation path, no account index
- derives a secp256k1 private key from TKey CDI using BLAKE2s and a fixed domain string
- returns the uncompressed Ethereum public key (64 bytes X||Y, no `0x04` prefix)
- signs 32-byte digests on-device; private key never leaves the TKey
- reports its own BLAKE2s app digest for measurement

**HD device app** (`device/ethsign-hd/`, name `eth `/`hd32`):

- BIP-32 private derivation (hardened and normal) from a seed `BLAKE2s(CDI || "tkey-eth-bip32-v1\0")`
- `GET_PUBKEY` and `SIGN_DIGEST` take a path (up to 10 levels); `GET_PUBKEY` also returns the chain code
- caches the last derived key and public key in RAM until unplug (see [Signing speed](#signing-speed))
- different binary from `device/ethsign/`, hence a different CDI: its keys are unrelated to the single-key address

**Host CLI** (`cmd/tkey-eth/`):

| Command | What it does |
|---------|--------------|
| `address` | Print the Ethereum address for the connected TKey |
| `sign-digest` | Sign a raw 32-byte digest |
| `sign-tx` | Sign an unsigned Ethereum transaction (JSON) |
| `sign-personal` | Sign a `personal_sign` message |
| `sign-typed-data` | Sign EIP-712 typed data |
| `verify-hd` | Check the HD app's child keys against a host CKDpub and its signatures (silent on success) |
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

```bash
make -C device/ethsign-hd
```

The pre-built binary `device/ethsign-hd/app.bin` is included as well. Both binaries rebuild byte-identically with the pinned toolchain; any change to a binary changes the keys it derives.

## Usage

### Get the Ethereum address

```bash
.bin/tkey-eth address --device /dev/ttyACM0
```

Output:

```
pubkey=0x...   # 64 bytes, X||Y, no 0x04 prefix
address=0x...
```

`--json` prints the same two fields as a JSON object.

### Sign a raw digest

```bash
.bin/tkey-eth sign-digest --device /dev/ttyACM0 --digest 0x<32 bytes>
```

Output is JSON with `address`, `digest` and `signature`.

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
.bin/tkey-eth sign-tx --device /dev/ttyACM0 --tx tx.json
```

Output is JSON with `address`, `digest`, `signature`, `raw_transaction`, and `tx_hash`. Every `signature` is `0x` + r‖s‖v (65 bytes, low s) with **v = 27 or 28**, what `ecrecover` and OpenZeppelin take; the transaction inside `raw_transaction` carries its own v.

### Sign a personal message

```bash
.bin/tkey-eth sign-personal --device /dev/ttyACM0 --message 'hello'
# or from a file:
.bin/tkey-eth sign-personal --device /dev/ttyACM0 --message-file msg.bin
```

### Sign EIP-712 typed data

```bash
.bin/tkey-eth sign-typed-data --device /dev/ttyACM0 --typed-data typed-data.json
```

### User secret (USS)

To bind the wallet key to a user passphrase in addition to the device identity:

```bash
echo -n "my-passphrase" > uss.bin
.bin/tkey-eth address --device /dev/ttyACM0 --uss-file uss.bin
```

The TKey must be replugged to change the USS.

### HD addresses (BIP-32 `--path`)

`address`, `sign-digest`, `sign-tx`, `sign-personal` and `sign-typed-data` accept `--path`. With it, the CLI loads `device/ethsign-hd/app.bin` (unless `--app` is given) and uses the key at that path; without it, nothing changes and the single-key app is used.

```bash
.bin/tkey-eth address --device /dev/ttyACM0 --path "m/44'/60'/0'/0/0"
.bin/tkey-eth sign-personal --device /dev/ttyACM0 --path "m/44'/60'/0'/0/1" --message "hello"
```

Hardened indices take `'`, `h` or `H`. Only one app runs per power cycle: switching between `--path` and no `--path` requires replugging the TKey (the CLI says so). The seed is never exported, so these addresses cannot be restored in another wallet from a mnemonic.

## Verification flows

The wallet ships two verification flows. Neither requires trust in operator testimony beyond what is explicit.

### Live verifier (`verify-live`)

A verifier starts from firmware mode, observes the full loading sequence, and produces a signed transcript.

```bash
.bin/tkey-eth verify-live --device /dev/ttyACM0 --out artifacts/live-verify.json
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
python3 scripts/two_key_ceremony.py --device /dev/ttyACM0
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
.bin/tkey-eth attest --device /dev/ttyACM0 --out artifacts/cert.json
.bin/tkey-eth prove --cert artifacts/cert.json --out artifacts/proof.json
.bin/tkey-eth verify --cert artifacts/cert.json --proof artifacts/proof.json
```

The attestation key is self-generated; this flow does not involve Tillitis vendor signatures.

`attest` writes the certificate to `--out` and prints `{"kind": "tkey-self", "address": …, "cert": …}`; `verify` prints `{"kind": "tkey-self", "address": …, "certificate": "ok"}` (plus `"proof": "ok"` with `--proof`). `kind` tells a verifier how strong the proof is: `tkey-self` is self-asserted, unlike `yubico-opgp` from `yketh`, which chains to a Yubico root.

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

The HD app (`device/ethsign-hd/bip32.c`) derives per BIP-32:

```
seed   = BLAKE2s(CDI || "tkey-eth-bip32-v1\0")              # 32 bytes
master = HMAC-SHA512("Bitcoin seed", seed)                # key || chain code
child  = CKDpriv(parent, index) for each index of --path
```

The CDI depends on the app binary, so the two apps derive unrelated keys on the same TKey.

## Signing speed

Measured on a TKey (2026-11-09, end to end including the CLI, spread ≤ 0.05 s). "First" is the first request for a path since the TKey was plugged in or since another path was used (5 runs); "repeat" is the same path again (10 runs):

- `sign-tx --path m/44'/60'/0'/0/0` (standard): first 9.6 s, repeat 2.7 s
- `sign-tx --path m`: first 5.0 s, repeat 2.7 s
- `sign-tx --path` with 10 levels, 7 of them non-hardened: first 20.9 s, repeat 2.7 s
- `address --path m/44'/60'/0'/0/0`: first 7.0 s, repeat 0.1 s

The HD app keeps the last derived key and its public key in RAM until the TKey is unplugged, so signing again with the same address costs a single ECDSA signature. Using another path replaces the cached key.

Almost all of the time goes to secp256k1 arithmetic on the TKey CPU: about 2.3 s per public-key computation (one per non-hardened path level, plus one for the final public key) and about 2.6 s per signature. Hardened levels, HMAC, BLAKE2s and USB I/O are negligible. The single-key app (no `--path`) has no cache and computes the public key and the signature on every `sign-tx`; expect about 5 s, like the first `--path m` request.

## Testing

```bash
go test ./cmd/tkey-eth/
make -C tests/bip32 test      # device BIP-32 code vs BIP-32 spec vectors 1-4, natively; silent on success
scripts/hw_check_hd.sh        # needs a TKey with the HD app loadable (fresh plug); silent on success
```

`tests/bip32/vectors.txt` is extracted from `bip-0032.mediawiki` by `tests/bip32/gen_vectors.py`. The Go tests also check the host CKDpub against the non-hardened steps of the same vectors.

Tests cover all pure functions (hex decoding, address derivation, signature finalization, low-S normalization, transaction parsing, certificate encoding and verification, proof verification, two-key payload encoding, and UDI round-trips). No device is required.

## Security properties and limitations

| Property | Status |
|----------|--------|
| Private key never leaves the TKey | Yes — the device app has no export command |
| Key is deterministic from CDI | Yes — same TKey + USS = same key |
| Key derivation is auditable | Yes — source in `device/ethsign/main.c` and `device/ethsign-hd/bip32.c` |
| Vendor-attested Ethereum pubkey | No — not available without a separate attestation app |
| Proof that key was generated on-device (not imported) | No — current flows cannot prove this |
| Low-s signature normalization (EIP-2) | Yes — done in the host CLI |

The two stronger evidence directions (on-device attestation and zero-knowledge key-generation proof) are documented in the parent repo but not yet implemented.

## Requirements

- **Host CLI:** Go 1.23 or later
- **Device app build:** [Tillitis SDK](https://github.com/tillitis/tillitis-key1)
- **Two-key ceremony:** Python 3.10 or later, `tkey-verification` signer app binaries (see `research/upstream/tkey-verification/`)
- **Hardware:** Tillitis TKey connected via USB serial (`/dev/ttyACM0` on Linux, `/dev/cu.usbmodem*` on macOS)
