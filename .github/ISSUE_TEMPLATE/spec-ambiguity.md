---
name: Specification ambiguity or error
about: Report wording in the normative specification that is ambiguous, contradictory, or incorrect
title: "spec: <short description of the ambiguity>"
labels: ["spec", "needs-triage"]
---

<!--
Use this template when the normative text could be read in more than one way, or
where it contradicts itself, the CDDL grammar, the JSON Schemas, or the
conformance vectors. For SDK bugs, open an issue on the relevant reference
implementation repository instead (see the contact links on the new-issue page).
-->

## Location in the specification

Chapter / file and section heading or anchor (for example, "spec/03-record-format §4.6.1"):

## The ambiguity or error

Quote the exact passage, then describe how it can be read more than one way, or
how it conflicts with another normative artifact (CDDL, JSON Schema, registry,
or a conformance vector).

## Suggested resolution

Propose specific replacement wording, or describe the single interpretation that
should be made normative.

## Impact on implementations

Could two conforming implementations diverge because of this? Does it affect the
canonical CBOR byte output, structural validation, signature verification, or
sealed-PoE decryption? Note any conformance vector that would need to be added
or corrected.
