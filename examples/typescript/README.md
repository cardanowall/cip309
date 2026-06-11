# TypeScript Examples

Runnable TypeScript examples for the Label 309 Proof-of-Existence standard.
Each script is a self-checking walk-through of one part of the standard,
driven through the published reference packages:

- [`@cardanowall/poe-standard`](https://www.npmjs.com/package/@cardanowall/poe-standard) —
  the wire format: record schema, canonical-CBOR encoder, the metadata-label-309
  chunk-array transport, and the pure structural validator.
- [`@cardanowall/sdk-ts`](https://www.npmjs.com/package/@cardanowall/sdk-ts) —
  the standalone verifier (`verifyTx` / `verifyResolved`), record signing
  helpers, sealed-PoE encryption, seed-derived keys, and Merkle tooling.

The examples never contact a Label 309 operator: verification runs against a
caller-configured public explorer (here, an injected offline stub), exactly as
the standard's service-independence invariant requires. The byte-level oracle
for any independent implementation is the conformance corpus in
[`../../conformance`](../../conformance) — `src/validate-record.ts` replays it
directly.

## What each example shows

| Script                   | Demonstrates                                                                                                                                                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/end-to-end.ts`      | The full produce → carry → verify loop: dual-hash content, sign the record (COSE_Sign1), canonical CBOR + the whole-body ≤ 64-byte chunk-array transport, structural validation, standalone verification with the four-state verdict, and a sealed-PoE round trip. |
| `src/verify-offline.ts`  | The verifier surface in depth: all four verdicts (`valid` / `pending` / `unverifiable` / `failed`) with their exit codes, the `fetchContent` switch, the audit trail, and the attribution split on fetched content.                                                |
| `src/sealed-poe.ts`      | The sealed-PoE construction: both KEMs (`x25519` and the X-Wing hybrid `mlkem768x25519`), the single-byte-string `kem_ct`, the segmented STREAM content format, the hash-claim binding, trial-decrypt, and the typed decryption outcomes.                          |
| `src/merkle-batch.ts`    | Batch anchoring with a top-level `merkle[]` commitment: the RFC 9162 root, the normative CBOR leaves-list document, inclusion proofs, and verifying the commitment through the report's per-commitment entries.                                                    |
| `src/validate-record.ts` | The structural validator's discriminated result and typed issues, then a replay of the validator conformance corpus (`../../conformance/validator/`) — code-for-code agreement with the cross-language oracle.                                                     |

## How to run

Requires Node.js 22.18+ (which runs TypeScript directly — no transpiler, no
build step) and [pnpm](https://pnpm.io) or npm. Install once, then run any
script:

```sh
pnpm install --ignore-workspace

node src/end-to-end.ts       # produce → carry → verify walk-through
node src/verify-offline.ts   # the four verdicts + attribution split
node src/sealed-poe.ts       # sealed-PoE construction tour
node src/merkle-batch.ts     # merkle[] batch anchoring
node src/validate-record.ts  # validator + conformance replay
```

Or use the package scripts:

```sh
pnpm demo            # src/end-to-end.ts
pnpm verify          # src/verify-offline.ts
pnpm smoke           # run every example in sequence
pnpm typecheck       # tsc --noEmit over the whole project
```

Every example is offline and deterministic in outcome, and exits non-zero on
a failed check, so `pnpm smoke` doubles as a regression suite. Expected tail
of a run:

```
PASS  attributable mismatch: verdict failed, exit 1
PASS  attributable mismatch: URI_INTEGRITY_MISMATCH raised
PASS  attributable mismatch: claim reported mismatched

ALL verifier-tour checks PASSED
```

The dependency ranges track the current published `0.x` line of the reference
packages; the examples in this repository are written against the same
revision of the standard as the specification beside them, so install the
latest published packages. To run the examples against a local checkout of
the SDK source instead, link the built packages into `node_modules/@cardanowall/`.

## Reading the verdict

`verifyTx` / `verifyResolved` emit a report whose minimum contract is pinned
by [`../../schemas/verify-report.schema.json`](../../schemas/verify-report.schema.json):
the four-state `verdict` with its `exitCode` mapping (`valid` → 0, `failed` → 1,
`unverifiable` → 2, `pending` → 3), the sorted `issues` list, one per-claim
`contentCheck` entry per record item and per `merkle[]` commitment
(`checked` / `mismatched` / `not_checked` — an unchecked claim can never
masquerade as a verified one), and the `auditTrail` of every outbound call.

`failed` is reserved for record-attributable outcomes. On fetched content
that means the attribution split: bytes that provably belong to the published
URI and fail a committed digest condemn the record
(`URI_INTEGRITY_MISMATCH` → `failed`), while bytes a gateway merely served
indict the provider (`URI_PROVIDER_INTEGRITY_MISMATCH`, warning) and leave
the record `unverifiable`.

## Out of scope

These examples cover the Label 309 wire standard and its verifier roles.
Operator-specific concerns — accounts, billing, key custody, how a seed is
stored and protected — are implementation concerns outside the standard and
do not appear here.

## License

Apache-2.0 (see [`../../LICENSE`](../../LICENSE)).
