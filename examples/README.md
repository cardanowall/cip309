# Examples

This directory holds **runnable, self-checking examples** that demonstrate the
[Label 309 standard](../spec/label-309.md) end to end: producing a
Proof-of-Existence record, carrying it across the metadata-label-309
transport, validating it structurally, verifying it standalone (with the
four-state verdict and its exit codes), sealing content to recipients, and
anchoring batches under a `merkle[]` commitment.

The examples drive the published **reference SDKs** — the same packages any
integrator installs — rather than re-implementing the cryptography inline:

- [`typescript/`](./typescript) — examples over
  [`@cardanowall/poe-standard`](https://www.npmjs.com/package/@cardanowall/poe-standard) and
  [`@cardanowall/sdk-ts`](https://www.npmjs.com/package/@cardanowall/sdk-ts).
- [`python/`](./python) — the behavioural twin, over
  [`cardanowall-sdk`](https://pypi.org/project/cardanowall-sdk/).

Every example runs offline (verification uses an injected explorer stub — no
operator, no issuer server, per the standalone-verifiability invariant) and
exits non-zero on a failed check, so each set doubles as a regression suite.

The normative byte-level oracle for **independent** implementations is not
the example code but the conformance corpus in
[`../conformance`](../conformance) — pinned wire bytes and expected error
codes that any conformant implementation (TypeScript, Python, Rust, …) must
reproduce. Both example sets replay the validator corpus directly, and the
reference SDKs in
[label-309-ts](https://github.com/cardanowall/label-309-ts),
[label-309-py](https://github.com/cardanowall/label-309-py), and
[label-309-rs](https://github.com/cardanowall/label-309-rs) are pinned to it
byte-for-byte ([label-309-cli](https://github.com/cardanowall/label-309-cli)
is the command-line verifier built on the Rust SDK).

## Out of scope

These examples cover the Label 309 **wire standard and its verifier roles**.
Operator-specific machinery — accounts, billing, key custody and recovery,
identity envelopes — is out of scope and does not appear here. Key derivation
is demonstrated only down to the seed; how a seed is stored and protected is
an implementation concern outside this standard.

## License

Apache-2.0 (see [`../LICENSE`](../LICENSE)).
