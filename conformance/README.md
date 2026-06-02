# CIP-309 conformance vectors

This directory is the **single shared source of truth** for CIP-309
conformance. Every conforming implementation — TypeScript, Python, Rust, Go,
native mobile, or any future port — **MUST** validate against these vectors. No
implementation ships its own copy: an implementation is conformant if and only
if it reproduces the byte-pinned outputs and the structural verdicts defined
here.

The vectors are the contract. If an implementation disagrees with a vector, the
implementation is wrong.

## What these vectors cover

The corpus spans the full CIP-309 wire surface and its cryptographic
primitives:

- **Canonical CBOR** — RFC 8949 deterministic encoding, round-trip identity,
  and decode-rejection (duplicate keys, malformed input).
- **Hashing** — SHA-256, BLAKE2b-256, dual-hash equivalence.
- **Key derivation** — HKDF-SHA-256 (RFC 5869) and Argon2id v1.3 (RFC 9106).
- **AEAD** — XChaCha20-Poly1305 and ChaCha20-Poly1305 (RFC 8439).
- **KEM** — X25519 (RFC 7748) and ML-KEM-768 + X25519 (X-Wing hybrid).
- **Signatures** — Ed25519 (RFC 8032) including the strict-mode /
  torsion-rejection differentiating fixtures.
- **COSE** — `COSE_Sign1`, `Sig_structure`, `COSE_Key`, and the production-form
  record-level signature, plus CIP-30 per-wallet signed records.
- **Merkle** — `rfc9162-sha256` leaves-list validation.
- **Seed → key derivation** — seed to Ed25519 / X25519 / X-Wing keys and the
  bech32 recipient encodings.
- **Sealed-PoE** — multi-recipient wrap/unwrap for both the classical and the
  post-quantum hybrid KEM, plus tamper-detection negatives.
- **Records** — a maximal positive record and the structural-validator negative
  corpus.
- **Cross-implementation interop** — records published by one implementation and
  decrypted by another.

## Vector JSON conventions

- One JSON file per scenario. Files are grouped by area into one subdirectory
  per primitive family (see [Layout](#layout)).
- **All binary values are lowercase hex strings.** A field carrying a CBOR byte
  string (`bstr`), a key, a nonce, a digest, a ciphertext, or a signature is
  encoded as hex (e.g. `"cbor_hex"`, `"seed_hex"`, `"expected_..._hex"`). A
  zero-length byte string is the empty string `""`.
- Each file pins its inputs and the expected outputs. Known-answer files pin the
  exact output bytes; negative files pin the expected typed error code(s) drawn
  from [`../registries`](../registries).
- Fields are descriptive metadata only where named `version`, `primitive`,
  `source`, `name`, or `note`; the load-bearing data lives in the input and
  `expected_*` fields.

## Positive / negative split

- **Positive (known-answer) vectors** assert that a given input produces an
  exact output. They are byte-pinned: every conforming implementation MUST emit
  the same bytes.
- **Negative vectors** assert that a malformed or adversarial input is rejected.
  They pin the expected error code (for structural rejection) or the rejection
  verdict (for tamper detection). Negative files are named `*-negative.json` or
  carry an explicit `expected_error_code(s)` / rejection field.

## Byte-identical vs structural parity

Not every vector is byte-pinned. [`parity-matrix.json`](parity-matrix.json) is a
machine-readable manifest splitting the corpus into two classes:

- **`byte_identical`** — implementations MUST produce identical output bytes.
  This covers canonical CBOR, `COSE_Sign1` bytes, `slots_mac`, seed-derived
  keys, and every fixed-input KAT.
- **`structural_parity_only`** — implementations MUST agree on the semantic
  result (round-trip success, accept/reject verdict, emitted error code) but the
  exact bytes are not pinned, because the inputs are non-deterministic (random
  keypairs / nonces) or the wire form admits writer-dependent variation.

A second implementation that passes every `byte_identical` entry and matches
every `structural_parity_only` verdict is conformant for record encoding,
multi-recipient sealed-PoE, strict-mode COSE_Sign1 Ed25519 signing, seed-to-key
derivation, and structural-validator code emission.

## Layout

| Area | Contents |
|---|---|
| `cbor/` | Canonical CBOR encode/decode (RFC 8949) + decode-rejection |
| `hash/` | SHA-256, BLAKE2b-256, dual-hash equivalence |
| `kdf/` | HKDF-SHA-256, Argon2id v1.3, Argon2id parameter constants |
| `aead/` | ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305 |
| `kem/` | X25519 (RFC 7748), ML-KEM-768 + X25519 (X-Wing) |
| `sig/` | Ed25519 (KAT, round-trip, strict/torsion) |
| `cose/` | `COSE_Sign1`, `Sig_structure`, build/verify, strict-Ed25519 |
| `wallet-cose/` | CIP-30 per-wallet signed records (valid + rejection) |
| `merkle/` | `rfc9162-sha256` leaves-list validation |
| `seed-derive/` | seed → Ed25519 / X25519 / X-Wing keys + recipient encodings |
| `sealed-poe/` | multi-recipient wrap/unwrap (classical + hybrid) + negatives |
| `poe-record/` | maximal positive record (full wire surface) |
| `validator/` | structural-validator negative corpus (per error code) |
| `cross-service/` | cross-implementation interop sealed records |

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
