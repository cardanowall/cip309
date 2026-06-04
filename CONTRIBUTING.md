# Contributing to Label 309

Thank you for your interest in improving Label 309 — an open standard for
**Proof of Existence (PoE)** anchored on the Cardano blockchain.

Label 309 is a **working draft**, pre-1.0, and is being finalized for submission
to the formal Cardano CIP process. Contributions at this stage are especially
valuable: they shape a standard before it is frozen. This document explains
what lives in this repository, how to propose changes to the standard and its
machine-readable artifacts, and the discipline that keeps every reference
implementation byte-identical.

All contributions are made under the licensing and sign-off terms described in
[Licensing](#licensing) and [Developer Certificate of Origin](#developer-certificate-of-origin-dco).

---

## What belongs in this repository

This is the **home of the standard itself** and its normative,
machine-readable artifacts. Contributions here concern the wire format and the
materials that define and test it:

| Path           | Contents                                                                                                  |
| -------------- | --------------------------------------------------------------------------------------------------------- |
| `spec/`        | The normative standard prose.                                                                             |
| `cddl/`        | The canonical CDDL grammar for the on-chain record.                                                       |
| `schemas/`     | JSON Schemas for the record and its sub-structures.                                                       |
| `registries/`  | The extensible named-identifier registries (error codes; hash, KDF, signature, KEM, and AEAD algorithms). |
| `conformance/` | Canonical cross-implementation test vectors — the parity source of truth.                                 |
| `examples/`    | Small, runnable reference implementations in TypeScript and Python.                                       |

If your change touches the meaning of the wire format, the grammar, a schema, a
registry, or the conformance corpus, you are in the right place.

### What does NOT belong here

The **reference implementations** are maintained in sibling repositories. Bug
fixes, performance work, new SDK surface, packaging, and language-specific
issues belong with the implementation, not the standard:

- **`label-309-ts`** — TypeScript packages on npm: `@cardanowall/crypto-core`
  (primitives), `@cardanowall/poe-standard` (wire format), `@cardanowall/sdk-ts`
  (SDK + standalone verifier).
- **`label-309-py`** — Python SDK on PyPI (distribution `cardanowall-sdk`, import
  `cardanowall`); a byte-identical parity twin of the TypeScript SDK.
- **`label-309-rs`** — Rust SDK on crates.io (crate `cardanowall`); the Rust
  byte-parity twin.
- **`label-309-cli`** — the command-line tool on crates.io (crate
  `cardanowall-cli`, binary `cardanowall`); a standalone verifier and toolkit
  built on the Rust SDK.

If you are unsure which repository a change belongs to, open an issue here and
ask. A spec ambiguity that an implementation merely exposes is a spec issue; a
divergence between an implementation and the conformance vectors is an
implementation issue (the vectors are authoritative).

---

## Before you start

- **Read the spec.** Familiarize yourself with the five invariants the standard
  is built around — content-first, issuer-agnostic, storage-agnostic,
  standalone-verifiable, and algorithm-agile. A change that weakens any of them
  is very unlikely to be accepted; propose it as a discussion first so the
  trade-off can be examined in the open.
- **Search existing issues and discussions.** Your concern may already be under
  review.
- **Open an issue or discussion before a large or normative change.** See below.

---

## Proposing a change to the standard

Normative changes — anything that alters what a conforming record looks like,
what a verifier must accept or reject, or what an identifier means — follow a
discussion-first process:

1. **Open an issue or discussion** describing the problem and the proposed
   change. State which invariant(s) the change interacts with and why the
   change preserves them. For wire-format changes, describe the impact on
   existing records: the standard favors additive, backward-compatible
   evolution.
2. **Reach rough consensus** in the issue before opening a pull request for
   normative prose. This avoids large rewrites that have to be unwound.
3. **Open a pull request** that updates, together and in one coherent set:
   - the relevant `spec/` prose,
   - the `cddl/` grammar, if the record shape changes,
   - the affected `schemas/`,
   - the relevant `registries/` entries, and
   - **new or updated `conformance/` vectors** that pin the change at the byte
     level (see [Conformance-vector discipline](#conformance-vector-discipline)).

A normative pull request that changes the wire format but ships no vectors is
incomplete and will be asked to add them.

### Editorial and non-normative changes

Typo fixes, clarifications that do not change meaning, broken links, and
example improvements can go straight to a pull request without a prior issue.
If a reviewer judges that an "editorial" change actually shifts meaning, it
will be reclassified as normative and routed through the discussion process.

---

## Proposing a registry addition

The registries make the standard **algorithm-agile**: hashes, KDFs,
signatures, KEMs, and AEADs are referenced by stable named identifiers rather
than hard-coded, so post-quantum and future migrations are **additive**. The
error-code registry works the same way.

To propose a new identifier:

1. **Open an issue** titled for the registry and the identifier (for example,
   "Registry: add hash `…`").
2. **Provide a stable public reference.** The algorithm must be a named, vetted
   primitive with a permanent, citable specification — an RFC, a NIST FIPS or
   SP publication, a CFRG document, or an equivalent standards-track source.
   Bespoke, unpublished, or proprietary algorithms are not accepted.
3. **Justify the addition.** Explain the gap the identifier fills and why an
   existing registered identifier does not serve. New entries are added because
   they are needed, not pre-emptively.
4. **Specify it completely.** Give the exact identifier string, parameter sizes
   (digest length, key/nonce/tag sizes, security level, and so on), and any
   encoding rules a conforming implementation needs.
5. **Additive only.** Registered identifiers are not redefined or removed once
   published; an identifier may be marked deprecated, but its meaning is
   permanent so that old records remain verifiable forever. Deprecation is a
   spec change, not a deletion.

A registry pull request updates the registry file, the spec prose that
references it where applicable, and conformance vectors exercising the new
identifier so every implementation can prove byte-parity support for it.

---

## Conformance-vector discipline

Cross-implementation **byte-parity** is a core guarantee of Label 309: the
TypeScript, Python, and Rust SDKs produce and accept byte-identical output for
the same inputs, validated against the **same canonical conformance vectors**
in `conformance/`. The vectors — not any one implementation — are the source of
truth for behavior.

This imposes one rule on every wire-affecting change:

> **Any change to the wire format ships with byte-pinned conformance vectors in
> the same pull request.**

Concretely:

- A vector pins exact inputs to exact canonical-CBOR output bytes (and, for
  validation cases, to an exact accept/reject outcome and error code).
- New behavior adds new vectors; changed behavior updates the affected vectors
  and explains the change in the pull request description.
- Vectors are data under the code license (see [Licensing](#licensing)) so that
  every implementation can vendor and run them.
- A change that alters canonical bytes without updating vectors will desynchronize
  the implementations and will not be merged.

When in doubt, add a vector. The cost of an extra vector is negligible; the
cost of an implementation drifting from the standard is not.

---

## Building and testing the examples

The `examples/` directory holds small, runnable reference implementations that
demonstrate publishing and verification against the canonical vectors. They are
intentionally minimal and dependency-light.

- **TypeScript** (`examples/typescript/`): a recent LTS Node.js and a package
  manager. Install dependencies and run the example's test or start script as
  described in that directory's README.
- **Python** (`examples/python/`): a currently supported CPython. Create a
  virtual environment, install the example's dependencies, and run its tests as
  described in that directory's README.

Both examples are expected to validate against the vectors in `conformance/`.
If you change a vector, run both examples to confirm they still pass; if they
do not, either the vector or the example is wrong, and the pull request must
resolve which.

---

## Pull request checklist

Before opening a pull request, confirm:

- [ ] The change is in the right repository (standard vs. an SDK repo).
- [ ] Normative changes were discussed in an issue first and reached rough
      consensus.
- [ ] Spec prose, CDDL, schemas, and registries are updated together and agree
      with each other.
- [ ] Wire-affecting changes include new or updated byte-pinned conformance
      vectors.
- [ ] The TypeScript and Python examples still pass against the vectors.
- [ ] Every commit is signed off (see DCO below).
- [ ] The change preserves the five invariants, or the pull request explains
      and justifies the deviation.

---

## Style and house rules

- Write for an audience implementing the standard independently. Prose must be
  precise and self-contained; a reader should never need a private document to
  understand a requirement.
- Keep the standards-track materials **vendor-neutral**. The standard does not
  depend on, and must not be written around, any particular hosted service,
  company, or product.
- Cite only stable, public references — RFCs, CIPs at a permanent address,
  NIST/FIPS publications, BIPs, and the like.

---

## Developer Certificate of Origin (DCO)

This project uses the **Developer Certificate of Origin**. There is **no CLA**.

The DCO is a lightweight attestation that you have the right to submit your
contribution under the project's licenses. You make it by adding a
`Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Add it automatically with:

```
git commit -s
```

The name and email must be real and must match the commit author. By signing
off, you certify the statements in the Developer Certificate of Origin,
version 1.1 (reproduced below). Pull requests whose commits are not signed off
will be asked to amend before merge.

> **Developer Certificate of Origin, Version 1.1**
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my
> knowledge, is covered under an appropriate open source license and I have the
> right under that license to submit that work with modifications, whether
> created in whole or in part by me, under the same open source license (unless
> I am permitted to submit under a different license), as indicated in the file;
> or
>
> (c) The contribution was provided directly to me by some other person who
> certified (a), (b) or (c) and I have not modified it.
>
> (d) I understand and agree that this project and the contribution are public
> and that a record of the contribution (including all personal information I
> submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s)
> involved.

---

## Licensing

By contributing, you agree that your contributions are licensed under the
project's licenses according to their type:

- **Code, examples, schemas-as-data, CDDL, and conformance vectors** —
  Apache License 2.0 (see [`LICENSE`](LICENSE)).
- **Specification prose** — Creative Commons Attribution 4.0 International
  (see [`LICENSE-docs`](LICENSE-docs)).

---

## Code of Conduct

All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
Please read it before contributing.

## Security

Do not report security-impacting issues through public issues or pull requests.
Follow the private process in our [Security Policy](SECURITY.md).
