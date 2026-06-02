# CIP-309 — Proof of Existence on Cardano

CIP-309 is an open standard for **Proof of Existence (PoE)** anchored on the
Cardano blockchain. A publisher hashes content and records the digest — together
with optional metadata — on-chain under transaction **metadata label 309**.
Anyone holding the resulting transaction reference can later prove that *this
content existed on or before the block time* — without trusting the publisher,
their domain, or any server.

This repository is the reference home of the standard: the normative
specification, the canonical grammar and schemas, the extensible identifier
registries, and the cross-implementation conformance vectors.

## Status

**Working draft — pre-1.0.** CIP-309 has **not** yet been submitted to the
formal Cardano CIP process. This repository serves as the reference home for the
standard while it is finalized for submission. The wire format and registries
are stabilizing; expect refinement before a 1.0 release. See
[CHANGELOG.md](CHANGELOG.md) for what has changed.

## What CIP-309 is

A PoE record is a small, canonically encoded structure carried in a Cardano
transaction's metadata under label 309. Its primary claim is a **content hash**:
the digest of some piece of content the publisher wishes to timestamp. Because
the record lives in a settled blockchain transaction, its existence is bounded
above by the block time — a fact any observer can confirm independently. A
verifier needs only the transaction metadata, optionally the original content
bytes, and a public blockchain explorer; no issuer server is ever required.

## The five invariants

1. **Content-first** — the content hash is the primary claim; everything else is metadata about it.
2. **Issuer-agnostic** — any wallet can publish; verifiers never trust the publisher.
3. **Storage-agnostic** — content URIs are an optional plural list (`ar://`, `ipfs://`); hash-only records are valid.
4. **Standalone-verifiable** — a verifier needs only the transaction metadata, optionally the content bytes, and a public blockchain explorer. No issuer server is required at any step.
5. **Algorithm-agile** — hashes, AEADs, KEMs, KDFs, and signatures all reference named identifiers from extensible registries; post-quantum migration is additive.

## Verifying a proof

Standalone verifiability is the core promise: anyone can confirm a CIP-309 proof
from public inputs alone. The standard defines three verifier roles, each a
superset of the previous:

- **Structural validator** — a pure function over the record's CBOR bytes. No I/O, no signature checks, no decryption. It answers a single question: is this a well-formed CIP-309 record?
- **Public verifier** — fetches the transaction metadata, runs structural validation, and verifies any record-level signatures. It does not decrypt.
- **Recipient verifier** — a public verifier that additionally holds an X25519 private key, decrypts a sealed PoE, and recomputes the plaintext hashes.

## Repository layout

| Directory      | Purpose                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------- |
| `spec/`        | The normative standard prose — the authoritative definition of CIP-309.                  |
| `cddl/`        | The canonical CDDL grammar for the on-chain record (`cip-309.cddl`).                      |
| `schemas/`     | JSON Schemas for the record and its sub-structures.                                       |
| `registries/` | The extensible named-identifier registries: error codes and hash / KDF / signature / KEM / AEAD algorithms. |
| `conformance/` | Canonical cross-implementation test vectors — the byte-parity source of truth.           |
| `examples/`    | Runnable reference implementations (`examples/typescript/`, `examples/python/`).          |

Wire-format specifics — exact byte layouts, CBOR tags, field encodings — live in
`spec/`, `cddl/`, and `schemas/`, not in this README.

## Reference implementations

Reference tooling lives in sibling repositories within the same GitHub
organization. All three language SDKs are validated against the **same** canonical
conformance vectors in this repository, and produce **byte-identical** output for
the same inputs. That cross-implementation byte-parity is a core guarantee of the
standard.

| Repository    | Distribution                                                                                                                                                  | Summary                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`cip309-ts`](https://github.com/cardanowall/cip309-ts)   | npm: `@cardanowall/crypto-core` (primitives), `@cardanowall/poe-standard` (wire format), `@cardanowall/sdk-ts` (SDK + standalone verifier)                     | The TypeScript reference implementation for browser and Node.                  |
| [`cip309-py`](https://github.com/cardanowall/cip309-py)   | PyPI: `cardanowall-sdk` (import name `cardanowall`)                                                                                                            | The Python SDK — a byte-identical parity twin of the TypeScript SDK.           |
| [`cip309-rs`](https://github.com/cardanowall/cip309-rs)   | crates.io: `cardanowall`                                                                                                                                       | The Rust SDK — the byte-parity twin in Rust.                                   |
| [`cip309-cli`](https://github.com/cardanowall/cip309-cli)  | crates.io: `cardanowall-cli` (binary `cardanowall`)                                                                                                            | A command-line standalone verifier and toolkit built on the Rust SDK.         |

## License

This repository uses a split license:

- **Code, examples, data schemas, CDDL grammar, and conformance vectors** are licensed under **Apache-2.0** — see [LICENSE](LICENSE).
- **Specification prose** is licensed under **CC-BY-4.0** — see [LICENSE-docs](LICENSE-docs).

Inbound contributions are accepted under the **Developer Certificate of Origin
(DCO)** via a `Signed-off-by` line. There is **no CLA**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose changes and the DCO
sign-off requirement. To report a security issue, see [SECURITY.md](SECURITY.md).
