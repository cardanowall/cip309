# JSON Schemas

This directory holds the **JSON Schema** (draft 2020-12) definitions of the
Label 309 PoE record, its sub-structures, and the two normative companion
documents — the off-chain Merkle leaves-list and the verifier report — for
tooling and validators that prefer a JSON contract to the
[CDDL grammar](../cddl/label-309.cddl). They are a machine-readable view of the
model defined normatively in [`../spec`](../spec), and are kept in **lockstep**
with both the specification prose and `../cddl/label-309.cddl`: the three
describe the same structure, and a record that satisfies one is expected to
satisfy the others.

The record schemas model the **reassembled record body** — the canonical-CBOR
bytes obtained after byte-concatenating the ≤ 64-byte chunk array stored under
metadata label 309. The chunk-array transport wrapper is reassembled before
structural validation and is not modelled here; the body's fields carry no
64-byte string cap of their own.

## Files

The set is twelve files. The record root references every sub-structure; shared
primitives live in `defs.schema.json` and are `$ref`'d by filename.

| File                              | Covers                                                                                                                                                                                                                                             |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `poe-record.schema.json`          | Root v1 record: `{ v: 1, ? items[], ? merkle[], ? supersedes, ? sigs[], ? crit[] }` (every array non-empty when present) plus the open extension-key namespace. `$ref`s every sub-structure.                                                       |
| `item-entry.schema.json`          | A content item: `{ hashes (required), ? uris[] (plain URI strings), ? enc }`.                                                                                                                                                                      |
| `hash-map.schema.json`            | Non-empty map of content-hash-alg → 32-byte digest.                                                                                                                                                                                                |
| `merkle-commit.schema.json`       | A Merkle list commitment: `{ alg, root (32B), leaf_count (1 .. 2^32 − 1), ? uris[] }`.                                                                                                                                                             |
| `encryption-envelope.schema.json` | Sealed-PoE `enc` as the choice `enc-scheme-1 / enc-opaque`: the closed scheme-1 map `{ scheme: 1, aead, nonce (24B), ? kem, ? slots[], ? slots_mac (32B), ? passphrase }`, or `{ scheme: uint, … }`.                                               |
| `encryption-slot.schema.json`     | A recipient slot as the choice of two closed KEM shapes: classical `{ epk (32B), wrap (48B) }` (kem = `x25519`) / hybrid `{ kem_ct (1120B), wrap (48B) }` (kem = `mlkem768x25519`).                                                                |
| `passphrase-block.schema.json`    | Passphrase derivation: `{ alg (kdf), salt (16..64B), params: { m, t, p } (closed uint32 map) }`.                                                                                                                                                   |
| `sig-entry.schema.json`           | An authorship signature: `{ cose_sign1 (bstr, required), ? cose_key (bstr) }` — each a single byte string.                                                                                                                                         |
| `supersedes.schema.json`          | A 32-byte prior-record transaction hash.                                                                                                                                                                                                           |
| `merkle-leaves.schema.json`       | The normative off-chain leaves-list document: `{ format: "cardano-poe-merkle-leaves-v1", tree_alg, root (32B), leaves[] (32B each), leaf_count, ? leaf_alg }`.                                                                                     |
| `verify-report.schema.json`       | The verifier report's minimum contract: verdict + exit-code mapping, chain facts (`confirmationDepth`/`confirmationThreshold`, `block_time`, `block_slot`), issue list, per-claim content-check status, per-item decryption outcomes, audit trail. |
| `defs.schema.json`                | Shared `$defs`: `bytes`, `bytes32`, `bytes48`, `bytes1120`, `uint32`, `uri`, and the open algorithm-identifier string types (`content-hash-alg`, `merkle-commit-alg`, `aead-alg`, `kem-alg`, `kdf-alg`).                                           |

## Root and `$ref` structure

`poe-record.schema.json` is the entry point for the record model. Its keys
reference, in turn, `item-entry`, `merkle-commit`, `sig-entry`, and
`supersedes`. `item-entry` references `hash-map` and `encryption-envelope`; the
envelope references `encryption-slot` and `passphrase-block`. Every byte-string
type, the pinned integer range, the URI type, and every open
algorithm-identifier string resolve into `defs.schema.json`.
`merkle-leaves.schema.json` (which also resolves into `defs.schema.json`) and
`verify-report.schema.json` (self-contained) are stand-alone entry points for
their respective documents.

All `$id`s use the `https://label309.org/schemas/<name>.schema.json` form. **This
is a stable identifier convention, not a resolvable URL** — do not assume any
`$id` dereferences over the network. Cross-references are by **relative
filename** (e.g. `defs.schema.json#/$defs/bytes32`), so the set resolves
correctly from this directory regardless of where it is hosted.

## Byte strings are modelled as hex

CBOR has a native byte-string (`bstr`) type; JSON does not. Every byte string is
therefore modelled here as a **lowercase-hex JSON string** whose character count
is twice the documented byte length:

- `bytes32` (digest / Merkle root / leaf / supersedes / `epk` / `slots_mac`) = `^[0-9a-f]{64}$`
- `bytes48` (slot `wrap` = 32-byte CEK + 16-byte tag) = `^[0-9a-f]{96}$`
- `bytes1120` (hybrid-slot `kem_ct`, the X-Wing encapsulation) = `^[0-9a-f]{2240}$`
- `bytes` (unbounded: `cose_sign1` / `cose_key`) = `^([0-9a-f]{2})*$`

URIs are CBOR `tstr` and are modelled as plain JSON strings with no length cap —
the whole-body transport satisfies the ledger's string cap, so a long URI is a
single text string.

## Choices are `anyOf`

Two grammar rules are choices, and both are expressed with `anyOf`:

- `enc = enc-scheme-1 / enc-opaque`. The opaque alternative (`scheme` is any
  unsigned integer; everything else unconstrained) exists so an envelope sealed
  under an identifier the implementation does not support still parses at the
  schema layer instead of being rejected before the typed pass can apply the
  degrade-to-opaque rule. The choice is deliberately **not** a discriminator: a
  `scheme: 1` map that fails the scheme-1 shape still matches the opaque
  reading, and it is the typed pass — never the schema — that holds a fully
  supported envelope to the scheme-1 shape and key-path rules.
- `slot = classical-slot / hybrid-slot`. Both closed shapes are admitted
  structurally; binding the chosen shape to `enc.kem` and the no-mixing rule
  are typed-pass checks.

## Permissive structural superset (important caveat)

These schemas — exactly like the CDDL grammar — model only the **permissive
structural superset** of a valid record. JSON Schema can express per-field
types, fixed lengths, closed vs open maps, non-emptiness, integer ranges, and
literals, but it **cannot** express the cross-field invariants that make a
record actually valid. The following are therefore **not** asserted here; they
are the typed error-code pass performed by the reference validator's domain
checks and proven by the [conformance vectors](../conformance):

- at least one of `items[]` / `merkle[]` must be present (`SCHEMA_EMPTY_RECORD`);
- `enc.slots` XOR `enc.passphrase` (`ENC_NO_KEY_PATH` / `ENC_EXCLUSIVITY_VIOLATION`);
- `enc.slots` requires both `enc.kem` and `enc.slots_mac`
  (`ENC_KEM_REQUIRED` / `ENC_SLOTS_MAC_REQUIRED`), and `slots_mac` without
  `slots` is rejected (`ENC_SLOTS_REQUIRED`);
- which slot shape the declared `enc.kem` selects, and the no-mixing rule
  (`ENC_SLOT_INVALID_SHAPE`);
- the argon2id parameter floors (`m >= 65536`, `t >= 3`, `p >= 1`) and
  deployment ceilings;
- registry membership of every algorithm identifier (hash, merkle, aead, kem,
  kdf, signature) — every identifier type is an **open** string by design;
- per-algorithm digest lengths and the per-format nonce length;
- URI absoluteness, fragment-freeness, allowed-scheme and per-scheme body shape;
- COSE_Sign1 structural decode, the signature key-path exclusivity, and the
  private-key-leak guard;
- the leaves-list bindings: `leaf_count` = length of `leaves` = on-chain
  `merkle[i].leaf_count`, `tree_alg` = on-chain `merkle[i].alg`, and the root
  recompute.

A record that passes these schemas is **structurally well-formed but not yet
proven valid** — full validation requires the typed pass, and a conformant
verifier emits the precise registry codes, never a generic schema-mismatch
error.

## Lockstep

These schemas stay in lockstep with [`../cddl/label-309.cddl`](../cddl/label-309.cddl)
and the normative prose in [`../spec`](../spec). Any change to the model must be
reflected in all three, and the conformance vectors are the shared arbiter.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
