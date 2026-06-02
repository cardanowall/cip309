# Registries

This directory holds the extensible **named-identifier registries** that make
CIP-309 algorithm-agile. Rather than hard-coding a fixed set of algorithms, the
record format references stable named identifiers, and these registries define
what each identifier means and the exact wire-level values a structural
validator pins to it. Post-quantum and future algorithms are introduced here
additively, without breaking existing records.

## Files

Each registry is a single JSON file:

| File | What it registers |
| --- | --- |
| [`hash-algorithms.json`](hash-algorithms.json) | Content-hash algorithms (item `hashes` digests and Merkle leaf digests). |
| [`merkle-commitment-algorithms.json`](merkle-commitment-algorithms.json) | Merkle list-commitment tree constructions for `merkle[]` roots. |
| [`aead-algorithms.json`](aead-algorithms.json) | Wire-selectable authenticated-encryption ciphers for sealed-PoE content. |
| [`kem-algorithms.json`](kem-algorithms.json) | Key-encapsulation mechanisms that wrap a content-encryption key to a recipient slot. |
| [`kdf-algorithms.json`](kdf-algorithms.json) | Wire-selectable passphrase key-derivation functions for the passphrase key-path. |
| [`signature-algorithms.json`](signature-algorithms.json) | Optional record-signature algorithms, keyed by COSE algorithm label. |
| [`error-codes.json`](error-codes.json) | The complete stable catalogue of validator and verifier error codes. |

## Entry shape

Every registry file is a top-level object:

```json
{
  "registry": "<name>",
  "description": "...",
  "entries": [ ... ]
}
```

Each entry is a **named identifier** paired with a **stable public reference**
(an RFC, a CIP at a permanent address, a FIPS publication, or another durable
specification) and the wire-level values pinned to it. Common per-entry fields:

- `identifier` — what appears in a record (for `error-codes.json`, the field is
  `code`; for `signature-algorithms.json`, entries are additionally keyed by
  `cose_alg_label`).
- `description` — a self-contained explanation of the entry.
- `reference` — the stable public reference an implementer follows to
  interoperate.
- the relevant **pinned value(s)** — e.g. `digest_length_bytes`,
  `root_length_bytes`, `nonce_length_bytes`, the recipient-slot field lengths
  and `wrap_length_bytes`, KDF `params` floors, or, for error codes, the `part`
  (`"A"` structural validator / `"B"` public/recipient verifier) and `severity`
  (`error` / `warning` / `info`).

The two error codes that carry dual severity (`MERKLE_UNSUPPORTED`,
`OUT_OF_PROFILE_SKIPPED`) are flagged with `"dual_severity": true`: their default
reading is `info`, and a strict / merkle-only verifier promotes them to `error`.

## Additive-only policy

Additions are **additive-only**: identifiers and error codes are never
repurposed or removed, and their pinned values never change. Error codes are
SCREAMING_SNAKE_CASE and stable — implementations emit them byte-exact and MUST
NOT introduce lowercase synonyms. This is what lets a record published years ago
keep verifying, and what lets new algorithms be introduced without a wire-format
break.

Every new entry MUST ship with:

1. a **stable public reference** at a permanent address, and
2. **conformance vectors** (see [`../conformance`](../conformance)) demonstrating
   that all independent implementations agree on it.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
