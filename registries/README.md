# Registries

This directory holds the extensible **named-identifier registries** that make
Label 309 algorithm-agile. Rather than hard-coding a fixed set of algorithms, the
record format references stable named identifiers, and these registries define
what each identifier means and the exact wire-level values a structural
validator pins to it. Post-quantum and future algorithms are introduced here
additively, without breaking existing records.

## Files

Each registry is a single JSON file:

| File                                                                     | What it registers                                                                         |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| [`hash-algorithms.json`](hash-algorithms.json)                           | Content-hash algorithms (item `hashes` digests and Merkle leaf digests).                  |
| [`merkle-commitment-algorithms.json`](merkle-commitment-algorithms.json) | Merkle list-commitment tree constructions for `merkle[]` roots.                           |
| [`aead-algorithms.json`](aead-algorithms.json)                           | Wire-selectable content formats (AEAD constructions) for sealed-PoE ciphertext.           |
| [`kem-algorithms.json`](kem-algorithms.json)                             | Key-encapsulation mechanisms that wrap a content-encryption key to a recipient slot.      |
| [`kdf-algorithms.json`](kdf-algorithms.json)                             | Wire-selectable passphrase key-derivation functions for the passphrase key-path.          |
| [`signature-algorithms.json`](signature-algorithms.json)                 | Optional record-signature algorithms, keyed by COSE algorithm label.                      |
| [`error-codes.json`](error-codes.json)                                   | The complete stable catalogue of validator and verifier error codes.                      |
| [`companion-cips.json`](companion-cips.json)                             | Advisory namespace-prefix registrations for companion CIPs (extension keys `^[a-z]+-.+`). |

## Entry shape

Every registry file is a top-level object:

```json
{
  "registry": "<name>",
  "description": "...",
  "entries": [ ... ]
}
```

Each algorithm entry is a **named identifier** paired with a **stable public
reference** (an RFC, a CIP at a permanent address, a FIPS publication, an IANA
codepoint, or another durable specification) and the wire-level values pinned to
it. Error-code entries carry no `reference` — the codes are defined by this
standard itself, and each entry's trigger semantics live in its `description`
and the specification prose. Common per-entry fields:

- `identifier` — what appears in a record (for `error-codes.json`, the field is
  `code`; for `signature-algorithms.json`, entries are additionally keyed by
  `cose_alg_label`; for `companion-cips.json`, the field is `prefix`).
- `description` — a self-contained explanation of the entry.
- `reference` — the stable public reference an implementer follows to
  interoperate (algorithm registries and companion-CIP registrations).
- the relevant **pinned value(s)** — e.g. `digest_length_bytes`,
  `root_length_bytes`, the content-format chunk/nonce/tag constants, the
  recipient-slot field lengths and `wrap_length_bytes`, KDF `params` floors, or,
  for error codes, the `part` and `severity`.

For error codes, `part` names the layer that emits the code: `"A"` — the
structural validator (a pure function over the reassembled CBOR record body);
`"B"` — the public / recipient verifier; `"carriage"` — the pre-validator
transport step that reassembles the label-309 chunk array.

Four error codes are **dual-severity** and carry `"dual_severity": true`:
`severity` holds the default reading, and the entry's description names the
context that promotes it to `error` — the recipient role / strict sealed-crypto
mode for `ENC_UNSUPPORTED`, the merkle-only escalation for `MERKLE_UNSUPPORTED`,
strict end-to-end mode for `OUT_OF_PROFILE_SKIPPED`, and the
no-verified-content-commitment floor for `MERKLE_LEAVES_UNAVAILABLE`. The
default reading is `info` for the first three and `warning` for the last.

## Additive-only policy

Additions are **additive-only**: identifiers and error codes are never
repurposed or removed, their pinned values never change, and the trigger
semantics of an existing error code are immutable — a new failure mode gets a
new code. Error codes are SCREAMING_SNAKE_CASE and stable — implementations
emit them byte-exact and MUST NOT introduce lowercase synonyms. This is what
lets a record published years ago keep verifying, and what lets new algorithms
be introduced without a wire-format break.

Every new entry MUST ship with:

1. a **stable public reference** at a permanent address, and
2. **conformance vectors** (see [`../conformance`](../conformance)) demonstrating
   that all independent implementations agree on it.

The one exception on vectors is `companion-cips.json`, whose registrations are
advisory namespace-prefix reservations with no wire enforcement.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
