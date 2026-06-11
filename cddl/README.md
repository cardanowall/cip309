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

- [`label-309.cddl`](./label-309.cddl) — the canonical grammar, in two parts:
  - **The PoE record body** — `poe-record`, `poe-common`, `item-entry`,
    `hash-map`, `merkle-commit`, the `enc = enc-scheme-1 / enc-opaque`
    envelope union, `slot` (classical and hybrid shapes), `passphrase-block`,
    `sig-entry`, the extension-key/extension-value rules, and the
    algorithm-identifier rules.
  - **The off-chain leaves-list document** — `leaves-list`, the normative
    canonical-CBOR container (format id `cardano-poe-merkle-leaves-v1`) that
    carries the ordered leaf list behind a `merkle[i]` commitment, published
    at the content-addressed URIs in `merkle[i].uris`.

## What it covers

The record-body grammar models the **reassembled record body** — the
canonical-CBOR bytes obtained after byte-concatenating the array of ≤ 64-byte
chunks stored on chain under Cardano transaction-metadata label `309`. The
chunk-array transport wrapper is reassembled before structural validation and
is not modelled here; the reassembled body is plain deterministic CBOR whose
fields are not subject to the ledger's 64-byte string cap, which the transport
wrapper alone satisfies.

Both grammars are a deliberately **permissive structural superset**: they
capture the closed map shapes and core byte lengths, but cross-field
invariants (e.g. `enc` key-path exclusivity, the items-or-merkle presence
rule, algorithm registry membership, Merkle leaf-count binding) and the
precise typed error codes a conformant verifier emits are specified in the
prose in [`../spec`](../spec), the algorithm [registries](../registries), and
the [conformance](../conformance) vectors — **not** in the grammar. A generic
CDDL tool confirms only that a candidate matches the permissive superset; full
conformance requires the typed-error pass described in the specification.

## Relationship to the JSON Schemas

The record-body grammar pairs 1:1 with the JSON Schemas in
[`../schemas`](../schemas): the CDDL grammar and the JSON Schemas describe the
same record structure from two machine-readable angles, and a record that
satisfies one is expected to satisfy the other. Both are kept in lockstep with
the specification prose.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
