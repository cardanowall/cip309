# Changelog

All notable changes to the Label 309 standard repository are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

> **Pre-1.0 notice.** Label 309 is a working draft. All releases are pre-1.0, and
> the wire format, registries, and conformance vectors may change in
> backward-incompatible ways until a 1.0 release. Pre-1.0 versions do not carry
> the stability guarantees of [Semantic Versioning](https://semver.org/).

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
