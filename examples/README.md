# Examples

This directory holds runnable **reference implementations** that demonstrate the
CIP-309 **wire** primitives in practice: each cryptographic primitive in
isolation, and an end-to-end publish/verify flow.

The examples will cover:

- content hashing,
- canonical CBOR encoding of a record,
- record-level `COSE_Sign1` signatures,
- seed and key derivation (stopping at the seed — see scope below),
- sealed-PoE wrap and unwrap (multi-recipient encryption, with the ciphertext
  referenced by a content-addressed `ar://` / `ipfs://` URI),
- the standalone verifier and structural validator.

The examples are provided in two languages:

- [`typescript/`](./typescript) — TypeScript reference examples.
- [`python/`](./python) — Python reference examples.

The examples are kept consistent with the canonical conformance vectors in
[`../conformance`](../conformance). They are intended as the smallest faithful
illustration of how to build and verify a PoE record, not as production tooling.

For full, installable reference SDKs and tooling, see the sibling ecosystem
repositories: [cip309-ts](https://github.com/cardanowall/cip309-ts) (TypeScript),
[cip309-py](https://github.com/cardanowall/cip309-py) (Python),
[cip309-rs](https://github.com/cardanowall/cip309-rs) (Rust), and
[cip309-cli](https://github.com/cardanowall/cip309-cli) (command-line verifier).

## Out of scope

These examples cover the CIP-309 **wire standard only**. The identity
key-envelope — building or unlocking the envelope, diceware passphrases, the
passphrase/PIN vault, and envelope discovery — is **out of scope** and will
**not** appear here. Key derivation is demonstrated only down to the seed; how a
seed is stored and protected is an implementation concern outside this standard.

## Status

**Working draft — to be authored.**

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
