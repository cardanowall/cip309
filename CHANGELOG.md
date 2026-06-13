# Changelog

All notable changes to the Label 309 standard repository are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** Label 309 is a working draft. All releases are pre-1.0, and
> the wire format, registries, and conformance vectors may change in
> backward-incompatible ways until a 1.0 release. Pre-1.0 versions do not carry
> the stability guarantees of [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-06-13

### Added

- Negative-case conformance vectors for the CIDv1 URI profile: a multibase body whose case disagrees with the prefix it advertises is non-canonical and is rejected. No change to the specification text, registries, or wire format.

## [0.5.0] - 2026-06-12

### Changed

- Version alignment with the coordinated 0.5.0 release; no changes to the specification, registries, or conformance vectors.

## [0.4.0] - 2026-06-11

### Changed

- **BREAKING (wire format):** The sealed-PoE construction is finalized: nonce-salted key derivation, a content-hash-bound slot transcript, segmented STREAM content encryption (`chacha20-poly1305-stream64k`), an in-ciphertext passphrase commitment, and passphrase normalization pinned to Unicode 16.0 NFKC. Records sealed under earlier releases do not decrypt or verify under 0.4.0, and vice versa.
- **BREAKING (wire format):** Record fields are de-chunked: `kem_ct` is a single byte string, URIs are plain text strings, and COSE fields are single byte strings. The only remaining chunking is the ledger-imposed ≤64-byte segmentation of the whole record body for transport.
- **BREAKING (verifier):** Verification concludes in a four-state verdict — `valid`, `pending`, `unverifiable`, or `failed` — with paired exit codes (0/3/2/1) and a defined report schema (camelCase fields, positional `items`/`merkle` results, severity-tagged issues). Verifiers enforce transaction-hash and auxiliary-data binding, never fabricate confirmation depth, never follow redirects, and treat a deny-host violation as terminal on the resolve path and per-attempt on the content path. Bytes that fail a URI's own content address are attributed to the provider as `URI_PROVIDER_INTEGRITY_MISMATCH`, distinct from a content-hash failure.
- Conformance vectors regenerated under the finalized wire format; every transaction vector is fully bound (transaction hash and auxiliary-data hash).

### Added

- Identity-seed string encoding: a checksummed bech32 form rendered uppercase as `L309-SEED-1…` (HRP `l309-seed-`), accepted alongside raw hex, with a byte-pinned conformance vector.
- The error-code registry now holds 76 codes.
- New conformance families: carriage, Cardano, KDF, Unicode normalization, seed encoding, and recipient-scan negatives.

## [0.3.0] - 2026-06-06

### Changed

- **BREAKING (wire format):** Finalized the sealed-PoE scheme-1 construction. `slots_mac` now authenticates a header-bound slots transcript hash (`slots_hash`); content is encrypted under an HKDF-derived `payload_key` (never the CEK directly) with structured AAD on both the recipient-slots and passphrase paths (`AD_CONTENT_SLOTS`, `AD_CONTENT_PASSPHRASE`); the X-Wing per-slot KEK salt binds the reassembled `kem_ct` and the recipient public key. Envelopes sealed under 0.2.0 do not decrypt under 0.3.0.
- Hardened recipient trial-decrypt: explicit all-zero X25519 shared-secret rejection folded into a constant-time `kem_ok` bit, CEK-conflict detection across matching slots, duplicate-encapsulation-material rejection, and slot-count / envelope-size bounds checked before any cryptographic work.
- Pinned the passphrase normalization profile `cardano-poe-pw-norm-v1` (NFKC, `White_Space` collapse, trim; Unicode 16.0) with a 4096-byte pre-KDF input bound.

### Added

- New normative sections: `canonicalEncode` (deterministic encoding of protocol context objects), sealed-PoE internal labels, the passphrase normalization profile, and forbidden producer patterns.
- Error codes `ENC_SLOTS_DUPLICATE_KEM_MATERIAL`, `ENC_SLOTS_TOO_MANY`, and `ENC_ENVELOPE_TOO_LARGE` in the error-code registry.
- Conformance vectors for the finalized construction: transcript bytes, hybrid KEK salt, the first passphrase-path positives, construction negatives, duplicate-KEM-material cases, an X-Wing draft-10 deterministic-encapsulation KAT, an HKDF empty-salt KAT, and recipient-string round-trips.

## [0.2.0] - 2026-06-04

### Changed

- Renamed the standard to **Label 309** (from the earlier working name), anchored to the reserved Cardano transaction-metadata label 309. The wire format, registries, and conformance vectors are unchanged.

## [0.1.0] - 2026-06-02

### Added

- Initial public release of the Label 309 standard: specification, conformance vectors, and reference examples.
