"""Label 309 structural validator — surface demo + conformance replay.

The structural validator is a pure function over record-body bytes: no I/O,
no signature crypto, no decryption. It returns a discriminated result —
``ValidateOk`` with the decoded record (plus any warning- and info-severity
issues), or ``ValidateFail`` with the typed error-severity issue list. Every
issue carries a path from the record root, a SCREAMING_SNAKE code from the
error-code registry, a severity, and a human-readable message.

After a short tour of that surface, the example replays the conformance
corpus shipped next to the specification (``../conformance/validator/``):
byte-pinned record bodies, each with the exact set of error-severity codes a
conformant validator emits. The corpus is the cross-language oracle — any
implementation must agree with it code-for-code.

Run: ``uv run python validate_record.py`` (exits non-zero on any disagreement).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from cardanowall import validate_poe_record

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    suffix = "" if ok or not detail else f" — {detail}"
    print(f"{'PASS' if ok else 'FAIL'}  {label}{suffix}")
    if not ok:
        failures += 1


# -- Surface tour ----------------------------------------------------------------


def surface_tour() -> None:
    # The smallest conformant record: v plus one item with one registered
    # content hash. (a2 = map(2); "v" → 1; "items" → [ { "hashes":
    # { "sha2-256": h'11…11' } } ].)
    minimal = bytes.fromhex(
        "a2617601656974656d7381a166686173686573a168736861322d3235365820" + "11" * 32
    )
    ok = validate_poe_record(minimal)
    check("minimal hash-only record validates", ok.ok)

    # An unknown field inside a closed map is a structural rejection with a
    # precise path. (Same record with "bogus": 1 inside the item map.)
    unknown_field = bytes.fromhex(
        "a2617601656974656d7381a265626f6775730166686173686573a168736861322d3235365820" + "11" * 32
    )
    bad = validate_poe_record(unknown_field)
    check("unknown field is rejected", not bad.ok)
    if not bad.ok:
        issue = bad.issues[0]
        print(
            f"issue               : code={issue.code} severity={issue.severity} "
            f"path={list(issue.path)}"
        )
        print(f"                      {issue.message}")
        check(
            "issue is SCHEMA_UNKNOWN_FIELD at items[0]",
            issue.code == "SCHEMA_UNKNOWN_FIELD"
            and issue.path[0] == "items"
            and issue.path[1] == 0,
        )


# -- Conformance replay -------------------------------------------------------------

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "conformance" / "validator"


def to_options(vector: dict[str, Any]) -> dict[str, Any]:
    """Map the corpus's validator_options keys onto ``validate`` kwargs."""
    fixture = vector.get("validator_options")
    if fixture is None:
        return {}
    options: dict[str, Any] = {}
    if "supportedCriticalExtensions" in fixture:
        options["supported_critical_extensions"] = set(fixture["supportedCriticalExtensions"])
    if "maxSlots" in fixture:
        options["max_slots"] = fixture["maxSlots"]
    if "maxEncEnvelopeBytes" in fixture:
        options["max_enc_envelope_bytes"] = fixture["maxEncEnvelopeBytes"]
    if "passphraseParamsCeiling" in fixture:
        options["passphrase_params_ceiling"] = fixture["passphraseParamsCeiling"]
    return options


def replay(file: str) -> None:
    corpus = json.loads((CORPUS_DIR / file).read_text())
    vectors: list[dict[str, Any]] = corpus["vectors"]
    passed = 0
    for vector in vectors:
        result = validate_poe_record(bytes.fromhex(vector["cbor_hex"]), **to_options(vector))
        expected = sorted(vector["expected_error_codes"])
        actual = (
            [] if result.ok else sorted({i.code for i in result.issues if i.severity == "error"})
        )
        codes_agree = actual == expected
        # Positive vectors may additionally pin info-severity tags that MUST
        # be surfaced without failing the record.
        info_agrees = True
        if "expected_info_codes" in vector:
            expected_info = sorted(vector["expected_info_codes"])
            actual_info = sorted({i.code for i in result.info}) if result.ok else []
            info_agrees = actual_info == expected_info
        if codes_agree and info_agrees:
            passed += 1
        else:
            check(
                f"{file} :: {vector['name']}",
                False,
                f"expected {expected} got {actual}",
            )
    check(f"{file}: {passed}/{len(vectors)} vectors agree", passed == len(vectors))


def main() -> None:
    surface_tour()
    print("\n--- conformance replay ---")
    replay("validator-positive.json")
    replay("validator-negative.json")
    replay("validator-bounds-negative.json")

    if failures:
        print(f"\n{failures} check(s) FAILED")
        sys.exit(1)
    print("\nALL validator checks PASSED")


if __name__ == "__main__":
    main()
