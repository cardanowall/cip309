# TypeScript Examples

Self-contained TypeScript reference implementations of the CIP-309 **wire
primitives**. Each module is the smallest faithful illustration of one piece of
the standard — content hashing, canonical CBOR, record-level `COSE_Sign1`
signatures, key derivation, sealed-PoE encryption, the structural validator, and
the standalone verifier — plus end-to-end demos that wire them together into a
publish → verify flow.

These examples exist to show that CIP-309 is **implementable from public
cryptographic libraries alone**, independent of any SDK. They depend only on
audited, widely-used primitives (`@noble/*`, `cbor2`, `hash-wasm`, `zod`) and
import **none** of the `@cardanowall/*` packages. The pinned wire bytes in
`src/smoke-parity.ts` are the cross-language conformance vectors; any conformant
implementation (TypeScript, Python, Rust, …) MUST reproduce them byte-for-byte.

## Self-contained note

There is no dependency on any published CIP-309 SDK. Every module here is
standalone and copy-pasteable; the cross-file imports are only between the
example modules in `src/`. If you want the installable, batteries-included
library instead, use the published packages — but these examples are
deliberately reduced to the wire standard so they can be audited line by line.

## What each example shows

Primitive modules (`src/`):

| File | Demonstrates |
| --- | --- |
| `hash-dual.ts` | SHA-256 + BLAKE2b-256 dual content hashing. |
| `cbor-canonical.ts` | Deterministic (canonical) CBOR encode/decode, with float rejection. |
| `cbor-walker.ts` | Byte-slicing the label-309 value out of a serialised Cardano tx (no re-encode). |
| `cose-sign1.ts` | `COSE_Sign1` encode/decode + `Sig_structure` builder. |
| `ed25519.ts` | Ed25519 keygen / sign / strict verify. |
| `x25519.ts` | X25519 keygen / ECDH. |
| `mlkem768x25519.ts` | X-Wing hybrid KEM (ML-KEM-768 + X25519) wrapper. |
| `hkdf.ts` | HKDF-SHA-256. |
| `seed-derive.ts` | Deriving Ed25519 / X25519 / X-Wing keypairs from a 32-byte seed. |
| `merkle-sha2-256.ts` | RFC 6962 / RFC 9162 Merkle tree, roots + inclusion proofs (self-test). |
| `merkle-leaves-list.ts` | Canonical-CBOR codec for the off-chain Merkle leaves-list. |
| `cid-validator.ts` | Full IPFS CID (v0/v1) structural parsing (self-test). |
| `cip-309-encoder.ts` | Encoding a PoE record to canonical CBOR + the record-signature payload. |
| `cip-309-validator.ts` | Pure-function structural validator over record bytes. |
| `ecies-sealed-poe.ts` | Multi-recipient sealed-PoE wrap/unwrap (X25519 and X-Wing KEMs). |
| `passphrase-kdf-unwrap.ts` | Sealed-PoE passphrase path (Argon2id → XChaCha20-Poly1305). |
| `off-host-sign.ts` | Off-host (HSM/KMS/air-gap) signing helper + CIP-8 hashed mode. |
| `standalone-verifier.ts` | The full service-independent verifier (`verifyTx`). |

Runnable demos and tests (`src/`):

| File | Shows |
| --- | --- |
| `end-to-end.ts` | Publish + verify a signed hash-only PoE, then a sealed-PoE wrap → unwrap roundtrip. |
| `standalone-verify-example.ts` | Driving `verifyTx` against a synthetic tx via an injected (offline) gateway. |
| `smoke-parity.ts` | Canonical-CBOR byte-parity against the pinned conformance vectors. |
| `smoke-validator.ts` | Structural-validator accept/reject behaviour across many record shapes. |
| `smoke-tx-extract.ts` | Positional byte-slice extraction of the label-309 value (and non-laundering proof). |

## How to run

Requires Node.js 22.18+ (which runs TypeScript ESM directly — no transpiler,
no build step) and [pnpm](https://pnpm.io). Install once:

```sh
pnpm install --ignore-workspace
```

Run a single example directly:

```sh
node src/end-to-end.ts               # publish/verify + sealed-PoE roundtrip
node src/standalone-verify-example.ts # standalone verifier over a synthetic tx
node src/smoke-parity.ts             # canonical-CBOR byte-parity vectors
node src/smoke-validator.ts          # structural-validator behaviour
node src/smoke-tx-extract.ts         # label-309 byte-slice extraction
node src/merkle-sha2-256.ts          # Merkle root + inclusion-proof self-test
node src/cid-validator.ts            # IPFS CID self-test
```

Or use the package scripts:

```sh
pnpm demo            # src/end-to-end.ts
pnpm verify          # src/standalone-verify-example.ts
pnpm smoke           # run every demo + smoke test + self-test in sequence
pnpm typecheck       # tsc --noEmit over the whole project
```

The only runtime dependencies are the audited cryptographic libraries; the lone
dev dependencies are `typescript` (for `pnpm typecheck`) and `@types/node`.
Every example exits non-zero on a failed assertion, so the scripts double as a
regression suite.

## Out of scope

These examples cover the CIP-309 **wire standard only**. The identity
key-envelope — building or unlocking the envelope, diceware passphrases, the
passphrase/PIN vault, and envelope discovery/recovery — is **out of scope** and
does not appear here. Key derivation is demonstrated only down to the seed; how
a seed is stored and protected is an implementation concern outside this
standard. The sealed-PoE **passphrase path** (Argon2id-derived content key) is
in scope, since it is part of the record wire format; Argon2id used for envelope
discovery is not.

## License

Apache-2.0 (see [`../../LICENSE`](../../LICENSE)).
