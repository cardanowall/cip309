# CDDL Grammar

This directory holds the canonical **CDDL** (Concise Data Definition Language,
[RFC 8610](https://www.rfc-editor.org/rfc/rfc8610)) grammar for the Label 309 PoE
record.

The grammar is the machine-checkable companion to the normative prose in
[`../spec`](../spec): it defines the record's structure precisely enough that a
CDDL tool can validate candidate CBOR records against it. Where the prose
describes the record model in words, the CDDL pins the same structure as a
grammar that tooling can enforce.

## Files

- [`label-309.cddl`](./label-309.cddl) — the canonical grammar for the PoE record
  and its sub-structures (`poe-record`, `poe-common`, `item-entry`, `hash-map`,
  `merkle-commit`, `enc`, `slot`, `sig-entry`, the chunk-array transport types,
  and the algorithm-identifier rules).

## What it covers

`label-309.cddl` models the **reassembled record body** — the canonical-CBOR
bytes obtained after byte-concatenating the array of ≤ 64-byte chunks stored on
chain under Cardano transaction-metadata label `309`. It is a deliberately
**permissive structural superset**: it captures the closed map shapes and core
byte lengths, but cross-field invariants (e.g. `enc` key-path exclusivity, the
items-or-merkle presence rule, algorithm registry membership, Merkle
leaf-count binding) and the precise typed error codes a conformant verifier
emits are specified in the prose in [`../spec`](../spec), the algorithm
[registries](../registries), and the [conformance](../conformance) vectors —
**not** in the grammar.

## Relationship to the JSON Schemas

This file pairs 1:1 with the JSON Schemas in [`../schemas`](../schemas): the
CDDL grammar and the JSON Schemas describe the same record structure from two
machine-readable angles, and a record that satisfies one is expected to satisfy
the other. Both are kept in lockstep with the specification prose.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
