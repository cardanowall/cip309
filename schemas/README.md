# JSON Schemas

This directory holds the **JSON Schema** (draft 2020-12) definitions of the
CIP-309 PoE record and its sub-structures, for tooling and validators that
prefer a JSON contract to the [CDDL grammar](../cddl/cip-309.cddl). They are a
machine-readable view of the record model defined normatively in
[`../spec`](../spec), and are kept in **lockstep** with both the specification
prose and `../cddl/cip-309.cddl`: the three describe the same structure, and a
record that satisfies one is expected to satisfy the others.

## Files

The set is twelve files. The root references every sub-structure; shared
primitives live in `defs.schema.json` and are `$ref`'d by filename.

| File                              | Covers                                                                                                                                                                           |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `poe-record.schema.json`          | Root v1 record: `{ v: 1, ? items[], ? merkle[], ? supersedes, ? sigs[], ? crit[] }` plus the open extension-key namespace (`^x-.+` / `^[a-z]+-.+`). `$ref`s every sub-structure. |
| `item-entry.schema.json`          | A content item: `{ hashes (required), ? uris[][], ? enc }`.                                                                                                                      |
| `hash-map.schema.json`            | Non-empty map of content-hash-alg → 32-byte digest.                                                                                                                              |
| `merkle-commit.schema.json`       | A Merkle list commitment: `{ alg, root (32B), leaf_count (uint >= 1), ? uris[][] }`.                                                                                             |
| `encryption-envelope.schema.json` | Sealed-PoE `enc`: `{ scheme: 1, aead, nonce, ? kem, ? slots[], ? slots_mac (32B), ? passphrase }`.                                                                               |
| `encryption-slot.schema.json`     | A KEM-driven recipient slot: classical `{ epk (32B), wrap (48B) }` (kem = `x25519`) vs hybrid `{ kem_ct ([bstr 1..64]), wrap (48B) }` (kem = `mlkem768x25519`).                  |
| `passphrase-block.schema.json`    | Passphrase derivation: `{ alg (kdf), salt (16..64B), params }`; the closed argon2id `{ m, t, p }` shape is documented as a `$def`.                                               |
| `sig-entry.schema.json`           | An authorship signature: `{ cose_sign1 (chunked-bytes-array, required), ? cose_key (chunked-bytes-array) }`.                                                                     |
| `chunked-bytes-array.schema.json` | `[1* bstr .size (1..64)]` — non-empty array of 1..64-byte chunks.                                                                                                                |
| `uri-chunk-array.schema.json`     | `[1* tstr .size (1..64)]` — non-empty array of 1..64-byte text chunks.                                                                                                           |
| `supersedes.schema.json`          | A 32-byte prior-record transaction hash.                                                                                                                                         |
| `defs.schema.json`                | Shared `$defs`: `bytes32`, `bytes48`, and the open algorithm-identifier string types (`content-hash-alg`, `merkle-commit-alg`, `aead-alg`, `kem-alg`, `kdf-alg`).                |

## Root and `$ref` structure

`poe-record.schema.json` is the entry point. Its keys reference, in turn,
`item-entry`, `merkle-commit`, `sig-entry`, and `supersedes`. `item-entry`
references `hash-map`, `uri-chunk-array`, and (by intent) `encryption-envelope`;
the envelope references `encryption-slot` and `passphrase-block`; slots and
signatures reference `chunked-bytes-array`. Every fixed-length byte string and
every open algorithm-identifier string resolves into `defs.schema.json`.

All `$id`s use the `https://cip309.org/schemas/<name>.schema.json` form. **This
is a stable identifier convention, not a resolvable URL** — do not assume any
`$id` dereferences over the network. Cross-references are by **relative
filename** (e.g. `defs.schema.json#/$defs/bytes32`), so the set resolves
correctly from this directory regardless of where it is hosted.

## Byte strings are modelled as hex

CBOR has a native byte-string (`bstr`) type; JSON does not. Every byte string is
therefore modelled here as a **lowercase-hex JSON string** whose character count
is twice the documented byte length:

- `bytes32` (32-byte digest / Merkle root / supersedes / slots_mac) = `^[0-9a-f]{64}$`
- `bytes48` (48-byte slot `wrap` = 32-byte CEK + 16-byte tag) = `^[0-9a-f]{96}$`
- a chunk of a `chunked-bytes-array` = `^([0-9a-f]{2}){1,64}$` (1..64 bytes)

`uri-chunk-array` chunks are CBOR `tstr` and are modelled as plain JSON strings;
their `.size (1..64)` is a **byte-count** bound on the UTF-8 encoding, so the
structural `maxLength: 64` (a Unicode-character bound) is a permissive
over-approximation that the validator tightens to the exact byte count.

## Permissive structural superset (important caveat)

These schemas — exactly like the CDDL grammar — model only the **permissive
structural superset** of a valid record. JSON Schema can express per-field
types, fixed lengths, closed vs open maps, and the `v == 1` literal, but it
**cannot** express the cross-field invariants that make a record actually valid.
The following are therefore **not** asserted here; they are the typed
error-code pass performed by the reference validator's domain checks and proven
by the [conformance vectors](../conformance):

- `items[]`-or-`merkle[]` must be non-empty (a record needs at least one claim);
- `enc.slots` XOR `enc.passphrase` (mutually exclusive);
- `enc.slots` requires both `enc.kem` and `enc.slots_mac`, and must be non-empty;
- the KEM-driven slot shape (which of `epk` / `kem_ct` must/must not be present
  for the declared `kem`, and the exact field lengths — e.g. `kem_ct`
  reassembling to 1120 bytes for `mlkem768x25519`);
- the argon2id parameter floors (`m >= 65536`, `t >= 3`, `p >= 1`);
- registry membership of every algorithm identifier (hash, merkle, aead, kem,
  kdf, signature);
- per-algorithm digest / nonce lengths;
- `enc.scheme == 1`;
- URI absoluteness, fragment-freeness, allowed-scheme and per-scheme body shape;
- COSE_Sign1 structural decode and the private-key-leak guard.

A record that passes these schemas is **structurally well-formed but not yet
proven valid** — full validation requires the domain pass.

## Lockstep

These schemas stay in lockstep with [`../cddl/cip-309.cddl`](../cddl/cip-309.cddl)
and the normative prose in [`../spec`](../spec). Any change to the record model
must be reflected in all three, and the conformance vectors are the shared
arbiter.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
