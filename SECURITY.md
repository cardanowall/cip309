# Security Policy

CIP-309 is a standard for cryptographic Proof of Existence. Its security
properties matter to everyone who relies on a proof, so we take reports
seriously and ask that they be handled responsibly.

## Scope

This repository holds the **standard** and its reference materials: the
specification prose, the CDDL grammar, JSON Schemas, the algorithm/error
registries, the conformance vectors, and the reference examples.

In scope for a report here:

- A flaw or ambiguity in the **specification** with security impact — anything
  that lets a conformant implementation be misled into accepting an invalid
  proof, decrypting something it should not, or leaking information it should
  not.
- A defect in the **conformance vectors** or **reference examples** that would
  cause correct implementations to diverge or to enshrine an insecure behaviour.

Out of scope here (report it in the relevant implementation repository instead):

- Bugs in a specific SDK or the CLI — `cip309-ts`, `cip309-py`, `cip309-rs`,
  `cip309-cli`. Use that repository's security policy.

## Core security goals

A report is **high priority** if it undermines any of the standard's core
guarantees:

- **Standalone verifiability** — a proof verifies from the transaction metadata,
  the optional content bytes, and a public blockchain explorer alone.
- **Zero issuer trust** — verifying a proof never requires trusting the
  publisher, their domain, or any server.
- **Confidentiality of sealed PoE** — only an intended recipient can decrypt a
  sealed payload, and trial-decryption does not leak which recipient matched.
- **Algorithm agility done safely** — registry additions cannot weaken existing
  records or enable downgrade.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security report.**

Preferred channel: GitHub's **private vulnerability reporting** for this
repository (the _Security_ tab → _Report a vulnerability_).

Alternative contact: `hello@cardanowall.com`.

Please include, as far as you can:

- A clear description of the issue and the security property it breaks.
- The exact location — the spec section, vector file, or example — and a
  minimal reproduction (a record, a vector, or steps).
- The impact and, if you have one, a suggested remediation.

## What to expect

- We aim to acknowledge a report promptly and to keep you informed as we
  investigate.
- We practise **coordinated disclosure**: we will agree a disclosure timeline
  with you, fix the issue (which for a standard may mean a normative change plus
  updated conformance vectors), and credit you unless you prefer otherwise.
- Because this standard is a **pre-1.0 working draft**, there are no
  long-term-supported released versions yet; fixes land on the current draft.

Thank you for helping keep CIP-309 trustworthy.
