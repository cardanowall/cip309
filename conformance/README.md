# Label 309 conformance vectors

This directory is the **single shared source of truth** for Label 309
conformance. Every conforming implementation — TypeScript, Python, Rust, Go,
native mobile, or any future port — **MUST** validate against these vectors. No
implementation ships its own copy: an implementation is conformant if and only
if it reproduces the byte-pinned outputs and the structural verdicts defined
here.

The vectors are the contract. If an implementation disagrees with a vector, the
implementation is wrong.

## What these vectors cover

The corpus spans the full Label 309 wire surface and its cryptographic
primitives:

- **Canonical CBOR** — RFC 8949 deterministic encoding, round-trip identity,
  and decode-rejection (duplicate keys, malformed input).
- **Hashing** — SHA-256, BLAKE2b-256, dual-hash equivalence.
- **Key derivation** — HKDF-SHA-256 (RFC 5869) and Argon2id v1.3 (RFC 9106).
- **AEAD** — ChaCha20-Poly1305 (RFC 8439), the primitive behind both the
  per-slot key wrap and the `chacha20-poly1305-stream64k` content format, plus
  XChaCha20-Poly1305 primitive KATs.
- **KEM** — X25519 (RFC 7748) and ML-KEM-768 + X25519 (X-Wing hybrid).
- **Signatures** — Ed25519 (RFC 8032) including the strict-mode /
  torsion-rejection differentiating fixtures.
- **COSE** — `COSE_Sign1`, `Sig_structure`, `COSE_Key`, the production-form
  record-level signature, the protected-header byte-preservation (`to_sign`
  verbatim) rule, the CIP-30 attached→detached payload transform, and the
  per-wallet CIP-30 shape-vectors.
- **Merkle** — `rfc9162-sha256` root/inclusion-proof construction and the
  canonical-CBOR leaves-list document.
- **Seed → key derivation** — seed to Ed25519 / X25519 / X-Wing keys, the
  bech32 recipient encodings, and the checksummed `l309-seed` identity-seed
  string encoding.
- **Sealed-PoE** — multi-recipient wrap/unwrap for both the classical and the
  post-quantum hybrid KEM, the segmented-STREAM content layer, the passphrase
  path with its in-ciphertext key commitment, and tamper-detection negatives.
- **Carriage** — the whole-body chunk-array transport under metadata label 309
  and the three Conway auxiliary-data envelope forms.
- **Cardano binding** — the transaction-hash / `auxiliary_data_hash` integrity
  binding and the confirmation-depth arithmetic.
- **Records** — maximal and mixed-signature positive records and the
  structural-validator corpora (negative, positive/boundary, role-dependent,
  resource bounds).
- **Cross-implementation interop** — records published by one implementation and
  decrypted by another.

Record-body fields are plain CBOR values: a URI is a single text string, a
`COSE_Sign1` or `COSE_Key` is a single byte string, an X-Wing `kem_ct` is a
single 1120-byte byte string. The only chunking anywhere in the corpus is the
ledger-forced whole-body transport split exercised under `carriage/`.

## Vector JSON conventions

- One JSON file per scenario. Files are grouped by area into one subdirectory
  per primitive family (see [Layout](#layout)).
- **All binary values are lowercase hex strings.** A field carrying a CBOR byte
  string (`bstr`), a key, a nonce, a digest, a ciphertext, or a signature is
  encoded as hex (e.g. `"cbor_hex"`, `"seed_hex"`, `"expected_..._hex"`). A
  zero-length byte string is the empty string `""`.
- Each file pins its inputs and the expected outputs. Known-answer files pin the
  exact output bytes. Negative files pin the expected typed error code(s):
  record-, validator-, and verifier-level codes are drawn from
  [`../registries`](../registries); the construction-API negatives (the
  `seed-derive/` negatives and the sealed-PoE `wrap`/`unwrap` raise vectors)
  additionally pin caller-input codes naming invalid arguments to the producing
  or decrypting API itself (see
  [Construction-API error namespace](#construction-api-error-namespace)).
- `expected_error_codes` pins the exact error-severity code set (sorted) the
  validator MUST emit; an empty array marks a contrast case that MUST validate.
  `expected_info_codes` pins info-severity tags that MUST be surfaced without
  failing the record.
- `expected_by_role` carries two dispositions for the same bytes where the
  registry defines dual severity: `public` (the default public-verifier
  reading) and `recipient_or_strict` (the recipient verifier and strict
  sealed-crypto mode).
- `validator_options`, where present, names the validator configuration the
  expectation assumes — `supportedCriticalExtensions`, and the
  deployment-pinned resource bounds (`maxSlots`, `maxEncEnvelopeBytes`,
  `passphraseParamsCeiling`). A vector without it assumes a default-configured
  validator.
- Fields are descriptive metadata only where named `version`, `primitive`,
  `source`, `name`, `kind`, or `note`; the load-bearing data lives in the input
  and `expected_*` fields.

## Construction-API error namespace

The wire error-code registry describes records and verification outcomes; a
construction API (a sealing, signing, or key-derivation function rejecting its
caller's arguments) raises typed errors of its own. The vectors pin one
namespace rule for those:

- **Where the concept is identical to a wire code, the construction API reuses
  the registry string verbatim** — e.g. an unsupported `enc.scheme` argument is
  `UNSUPPORTED_ENVELOPE_SCHEME`, an undersized salt is
  `ENC_PASSPHRASE_SALT_TOO_SHORT`, a malformed wire length is
  `KEM_CT_LENGTH_MISMATCH` — so a consumer correlating construction failures
  with validator/verifier reports sees one vocabulary.
- **Conditions that exist only at the construction boundary keep
  construction-only names with no wire counterpart** — raw caller-input lengths
  and key material (`INVALID_CEK_LENGTH`, `INVALID_EPHEMERAL_SECRET_LENGTH`,
  `EPHEMERAL_SECRETS_COUNT_MISMATCH`, `INVALID_RECIPIENT_KEY`,
  `INVALID_PASSPHRASE_PARAMS`, `INVALID_SEED_LENGTH`), the raw
  pre-normalization passphrase cap (`PASSPHRASE_INPUT_TOO_LONG`), and similar
  caller-argument rejections. These codes are defined by the vectors, not by
  the wire registry, and conforming implementations MUST emit them byte-exact
  all the same.
- **A standalone verifier never surfaces construction-only names in its
  report.** When the recipient-verifier decryption step hits a construction
  rejection, it maps the failure into the wire vocabulary at the boundary: the
  passphrase input codes `ENC_PASSPHRASE_UNNORMALIZABLE`,
  `ENC_PASSPHRASE_EMPTY`, and `KDF_DERIVATION_FAILED` pass through verbatim
  (they are wire codes already); every other construction rejection is reported
  as `KDF_DERIVATION_FAILED` — the credential/derivation input was rejected
  before key derivation could run.

## Positive / negative split

- **Positive (known-answer) vectors** assert that a given input produces an
  exact output. They are byte-pinned: every conforming implementation MUST emit
  the same bytes.
- **Negative vectors** assert that a malformed or adversarial input is rejected.
  They pin the expected error code (for structural rejection) or the rejection
  verdict (for tamper detection). Negative files are named `*-negative.json` or
  carry an explicit `expected_error_code(s)` / rejection field.

**Acceptance criterion:** every Part A code and the carriage code in
[`../registries/error-codes.json`](../registries/error-codes.json) has a byte
fixture; every Part B code has a fixture or a specified harness behaviour — the
network-dependent codes (provider availability, fetch outcomes, leaves-list
availability, service independence) and the runtime-dependent dispositions (the
verifier-capability and profile tags `MERKLE_UNSUPPORTED` /
`OUT_OF_PROFILE_SKIPPED`, and the caller-passphrase input codes) are asserted by
the verifier test harness rather than by byte vectors.

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

## Regeneration pipeline

The sealed-PoE vectors (and the cross-service interop records built on them)
are produced by the reference implementation's vector generator, not authored
by hand: every normally-random value — CEK, `enc.nonce`, per-slot X25519
ephemerals, X-Wing encapsulation randomness, passphrase salt, shuffle
permutation — is pinned to recorded test seeds, and all transcript bytes derive
from one shared reference `canonicalEncode`, so the set regenerates
deterministically and byte-identically. Primitive KATs copied from external
reference sources (RFC test vectors, the X-Wing draft appendix, the CCTV
Ed25519 corpus) are never recomputed; they are transcribed verbatim and stay
byte-identical across regenerations.

## Layout

| Area             | Contents                                                                                       |
| ---------------- | ---------------------------------------------------------------------------------------------- |
| `cbor/`          | Canonical CBOR encode/decode (RFC 8949) + decode-rejection                                     |
| `carriage/`      | Label-309 chunk-array transport + Conway auxiliary-data envelope forms                         |
| `cardano/`       | Transaction-hash / `auxiliary_data_hash` binding, confirmation depth                           |
| `hash/`          | SHA-256, BLAKE2b-256, dual-hash equivalence                                                    |
| `kdf/`           | HKDF-SHA-256, Argon2id v1.3, Argon2id parameter constants, passphrase-normalization → CEK pins |
| `unicode/`       | Pinned Unicode 16.0.0 NFKC normalization oracle (UCD NormalizationTest derived)                |
| `aead/`          | ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305                                               |
| `kem/`           | X25519 (RFC 7748), ML-KEM-768 + X25519 (X-Wing)                                                |
| `sig/`           | Ed25519 (KAT, round-trip, strict/torsion)                                                      |
| `cose/`          | `COSE_Sign1` build/verify, `Sig_structure`, `to_sign` verbatim, attached→detached transform    |
| `wallet-cose/`   | CIP-30 per-wallet shape-vectors (valid + rejection)                                            |
| `merkle/`        | `rfc9162-sha256` root/proof KATs + leaves-list document                                        |
| `seed-derive/`   | seed → Ed25519 / X25519 / X-Wing keys + recipient + identity-seed encodings                    |
| `sealed-poe/`    | multi-recipient wrap/unwrap (classical + hybrid) + negatives                                   |
| `poe-record/`    | maximal + mixed-signature positive records (full wire surface)                                 |
| `validator/`     | structural-validator corpora: negative, positive/boundary, role-dependent, bounds              |
| `cross-service/` | cross-implementation interop sealed records                                                    |

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
