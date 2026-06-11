# Python Examples

Runnable Python examples for the Label 309 Proof-of-Existence standard. Each
script is a self-checking walk-through of one part of the standard, driven
through the published reference SDK
[`cardanowall-sdk`](https://pypi.org/project/cardanowall-sdk/) (import name
`cardanowall`): the wire format (`cardanowall.poe_standard`), the standalone
verifier (`cardanowall.verifier`), sealed-PoE encryption, seed-derived keys,
and Merkle tooling.

These scripts are the **behavioural twin** of the
[TypeScript examples](../typescript): fed the same inputs, the two SDKs
produce byte-identical wire bytes and the same verdicts, issue codes, and
report entries. The byte-level oracle for any independent implementation is
the conformance corpus in [`../../conformance`](../../conformance) —
`validate_record.py` replays it directly.

The examples never contact a Label 309 operator: verification runs against a
caller-configured public explorer (here, an injected offline stub), exactly
as the standard's service-independence invariant requires.

## What each example shows

| Script               | Demonstrates                                                                                                                                                                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `end_to_end.py`      | The full produce → carry → verify loop: dual-hash content, sign the record (COSE_Sign1), canonical CBOR + the whole-body ≤ 64-byte chunk-array transport, structural validation, standalone verification with the four-state verdict, and a sealed-PoE round trip. |
| `verify_offline.py`  | The verifier surface in depth: all four verdicts (`valid` / `pending` / `unverifiable` / `failed`) with their exit codes, the `fetch_content` switch, the audit trail, and the attribution split on fetched content.                                               |
| `sealed_poe.py`      | The sealed-PoE construction: both KEMs (`x25519` and the X-Wing hybrid `mlkem768x25519`), the single-byte-string `kem_ct`, the segmented STREAM content format, the hash-claim binding, trial-decrypt, and the typed decryption outcomes.                          |
| `merkle_batch.py`    | Batch anchoring with a top-level `merkle[]` commitment: the RFC 9162 root, the normative CBOR leaves-list document, inclusion proofs, and verifying the commitment through the report's per-commitment entries.                                                    |
| `validate_record.py` | The structural validator's discriminated result and typed issues, then a replay of the validator conformance corpus (`../../conformance/validator/`) — code-for-code agreement with the cross-language oracle.                                                     |

## How to run

With [uv](https://docs.astral.sh/uv/) (Python 3.11+):

```bash
uv sync                            # create the venv and install the SDK

uv run python end_to_end.py        # produce → carry → verify walk-through
uv run python verify_offline.py    # the four verdicts + attribution split
uv run python sealed_poe.py        # sealed-PoE construction tour
uv run python merkle_batch.py      # merkle[] batch anchoring
uv run python validate_record.py   # validator + conformance replay
```

Every example is offline and deterministic in outcome, and exits non-zero on
a failed check, so the set doubles as a regression suite. Expected tail of a
run:

```
PASS  attributable mismatch: verdict failed, exit 1
PASS  attributable mismatch: URI_INTEGRITY_MISMATCH raised
PASS  attributable mismatch: claim reported mismatched

ALL verifier-tour checks PASSED
```

Quality gates (linter, formatter, type checker):

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run mypy end_to_end.py verify_offline.py sealed_poe.py merkle_batch.py validate_record.py
```

The dependency range tracks the current published `0.x` line of the SDK; the
examples in this repository are written against the same revision of the
standard as the specification beside them, so install the latest published
package. To run the examples against a local checkout of the SDK source
instead, install it editable into the venv
(`uv pip install -e <path-to-sdk>`).

## Reading the verdict

`verify_tx` / `verify_record_bytes` emit a report whose minimum contract is
pinned by [`../../schemas/verify-report.schema.json`](../../schemas/verify-report.schema.json):
the four-state `verdict` with its exit-code mapping (`valid` → 0, `failed` → 1,
`unverifiable` → 2, `pending` → 3), the sorted issue list, one per-claim
`content_check` entry per record item and per `merkle[]` commitment
(`checked` / `mismatched` / `not_checked` — an unchecked claim can never
masquerade as a verified one), and the audit trail of every outbound call.

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
