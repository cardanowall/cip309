---
name: Registry addition
about: Propose a new entry in an extensible registry (algorithm or error code)
title: 'registry: add <named-identifier>'
labels: ['registry', 'needs-triage']
---

<!--
The standard is algorithm-agile: hashes, KDFs, signatures, KEMs, and AEADs all
reference named identifiers from extensible registries, and error codes are
likewise registered. New entries are ADDITIVE — they never change the meaning of
an existing identifier. Use this template to propose one.
-->

## Registry

Which registry does this entry belong to? (hash / kdf / signature / kem / aead /
error-code)

## Proposed named identifier

The exact, stable string identifier to register (for example, an algorithm name
or an error code):

## Stable public reference

Link to the permanent, public specification that defines this primitive — an RFC,
a CIP at its permanent address, a BIP, or a peer-reviewed published paper.
Self-published or unstable references are not sufficient.

## Security rationale

Why is this primitive appropriate for the role? Summarize its security level and
the current state of cryptanalysis. For post-quantum primitives, state the
assumed hardness and parameter set.

## Why this is additive

Confirm that adding this identifier does not alter the behaviour of any existing
entry, and does not require a change to the wire format, the CDDL grammar, or the
structural validator beyond recognizing the new identifier.

## Conformance vectors

A registry addition is not complete without canonical cross-implementation test
vectors. Describe the vectors you will contribute (or have contributed) under
`conformance/` so that the TypeScript, Python, and Rust implementations can be
checked for byte-identical behaviour.
