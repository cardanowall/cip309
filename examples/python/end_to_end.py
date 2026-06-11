"""Label 309 end-to-end walk-through: produce a signed Proof-of-Existence
record, carry it across the metadata-label-309 transport, and verify it
standalone — all offline.

1. Hash the content (SHA-256 + BLAKE2b-256, the dual-hash recommendation).
2. Build the record body and attach a record-level COSE_Sign1 signature.
3. Encode the body to canonical CBOR and split it into the whole-body
   <= 64-byte chunk array — the only chunking the format performs. Fields
   inside the body (URIs, signatures, KEM ciphertexts) are ordinary CBOR
   values with no per-field chunk wrappers.
4. Reassemble + structurally validate, exactly as a verifier would.
5. Run the standalone verifier (``verify_record_bytes``) over the record body
   plus an explorer-asserted block-info tuple and read the four-state verdict
   and its process exit code.
6. Round-trip a sealed PoE: wrap the content to a recipient, unwrap it with
   the recipient's seed-derived key, and recheck the plaintext hashes.

Run: ``uv run python end_to_end.py`` (exits non-zero on any failed check).
"""

from __future__ import annotations

import asyncio
import sys
from typing import cast

from cardanowall import (
    PoeRecord,
    decrypt_sealed_from_seed,
    ecies_sealed_poe_wrap,
    encode_poe_record,
    signer_from_seed,
    validate_poe_record,
)
from cardanowall.client import assemble_cose_sign1, prepare_sig_structure
from cardanowall.hash import blake2b_256, sha2_256
from cardanowall.seed_derive import derive_x25519_keypair_from_seed
from cardanowall.verifier import (
    BlockInfo,
    Label309ReassemblyOk,
    VerifyRecordInput,
    chunk_record_body,
    encode_label_309_value,
    exit_code_for_verdict,
    reassemble_label_309_value,
    verify_record_bytes,
)
from cardanowall.verifier.signatures import verify_record_signatures

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    suffix = "" if ok or not detail else f" — {detail}"
    print(f"{'PASS' if ok else 'FAIL'}  {label}{suffix}")
    if not ok:
        failures += 1


async def main() -> None:
    # -- 1. Hash the content --------------------------------------------------
    # The content hash is the primary claim; everything else is metadata about
    # it. Two independent digests (SHA-2 and BLAKE2b families) guard the claim
    # against a future break in either.
    content = b"end-to-end example content"
    hashes = {"sha2-256": sha2_256(content), "blake2b-256": blake2b_256(content)}
    print(f"content sha2-256    : {hashes['sha2-256'].hex()}")

    # -- 2. Build the record and sign it --------------------------------------
    # Authorship is an opt-in claim: the record validates with or without
    # `sigs`. The signature covers the canonical CBOR of the body minus
    # `sigs`, domain-separated by the 25-byte prefix
    # "cardano-poe-record-sig-v1" (handled inside the helpers). The signing
    # flow is off-host-friendly: prepare the Sig_structure, sign it anywhere
    # (HSM, air-gap, wallet), then assemble the COSE_Sign1.
    unsigned: PoeRecord = cast(PoeRecord, {"v": 1, "items": [{"hashes": hashes}]})
    signer = signer_from_seed(bytes([7]) * 32)
    sig_structure, _protected = prepare_sig_structure(
        record=unsigned, signer_pubkey=signer.signer_pubkey
    )
    signature = signer.sign(sig_structure)
    _cose, sig_entry = assemble_cose_sign1(
        record=unsigned, signer_pubkey=signer.signer_pubkey, signature=signature
    )
    record: PoeRecord = cast(PoeRecord, {**unsigned, "sigs": [sig_entry]})
    # The COSE_Sign1 is one byte string inside the body — no per-field chunking.
    check("sigs[0].cose_sign1 is a single byte string", isinstance(sig_entry["cose_sign1"], bytes))

    # -- 3. Canonical CBOR + the chunk-array transport ------------------------
    # The body is serialised once to canonical CBOR (RFC 8949 section 4.2.1)
    # and crosses the ledger as an opaque whole-body chunk array of <= 64-byte
    # byte strings — the ledger's per-metadatum string cap is the only reason
    # the split exists, and chunk boundaries carry no semantics.
    body = encode_poe_record(record)
    chunks = chunk_record_body(body)
    label_309_value = encode_label_309_value(body)
    print(
        f"record body         : {len(body)} bytes → {len(chunks)} transport chunk(s), "
        f"label-309 value {len(label_309_value)} bytes"
    )

    # -- 4. Reassemble + structural validation --------------------------------
    # A verifier byte-concatenates the chunk array back into the body, then
    # runs the pure structural validator: no I/O, no signature crypto, no
    # decryption.
    reassembled = reassemble_label_309_value(label_309_value)
    check(
        "transport round-trips byte-identically",
        isinstance(reassembled, Label309ReassemblyOk) and reassembled.body == body,
    )
    validation = validate_poe_record(body)
    check("structural validation accepts the record", validation.ok)

    # The record-level signature verifies against the reassembled bytes alone.
    if validation.ok:
        sigs = verify_record_signatures(validation.record, network="cardano:mainnet")
        check(
            "record signature verifies (path 1, in-signature kid)",
            len(sigs) == 1
            and sigs[0].verdict == "valid"
            and sigs[0].signer_pub == signer.signer_pubkey.hex(),
        )

    # -- 5. Standalone verification -------------------------------------------
    # ``verify_record_bytes`` runs the verifier pipeline from the
    # structural-validator step onward over caller-supplied record-body bytes
    # plus the explorer-asserted block-info tuple (``verify_tx`` is the
    # sibling entry point that resolves a live transaction first — see
    # verify_offline.py). The verdict is four-state and maps to a process exit
    # code so scripts can branch without parsing the report:
    #   valid → 0   failed → 1   unverifiable → 2   pending → 3
    report = await verify_record_bytes(
        body,
        BlockInfo(confirmation_depth=20, block_time=1_700_000_000),
        # Hash-only record: nothing to fetch anyway.
        VerifyRecordInput(fetch_content=False),
        tx_hash="11" * 32,
    )
    print(
        f"verdict             : {report.verdict} (exit code {report.exit_code}), "
        f"block_time {report.block_time}"
    )
    check("verdict is valid with exit code 0", report.verdict == "valid" and report.exit_code == 0)
    check(
        "exit code follows the verdict mapping",
        exit_code_for_verdict(report.verdict) == report.exit_code,
    )
    check("report carries one per-item entry", len(report.items) == 1)
    check(
        'hash-only claim is reported not_checked, never silently "ok"',
        report.items[0].content_check == "not_checked",
    )
    check("offline run has an empty audit trail", len(report.audit_trail) == 0)

    # -- 6. Sealed PoE round-trip ----------------------------------------------
    # A sealed PoE keeps the plaintext readable only by intended recipients
    # while the on-chain record still commits to the plaintext hash. The
    # envelope is bound to this item's `hashes` map, so an envelope spliced
    # onto a different hash claim fails before any content work
    # (sealed_poe.py tours the construction in depth).
    recipient_seed = bytes([9]) * 32
    recipient_pub = derive_x25519_keypair_from_seed(recipient_seed)["public_key"]
    sealed = ecies_sealed_poe_wrap(
        plaintext=content, hashes=hashes, recipient_public_keys=[recipient_pub], kem="x25519"
    )
    opened = decrypt_sealed_from_seed(
        seed=recipient_seed,
        envelope=sealed.envelope,
        ciphertext=sealed.ciphertext,
        hashes=hashes,
    )
    check("sealed PoE unwraps for the recipient", opened.matched)
    if opened.matched and opened.plaintext is not None:
        check("decrypted plaintext matches the original bytes", opened.plaintext == content)
        # The post-decryption recheck: recompute every digest in `hashes` over
        # the recovered plaintext. A mismatch is a record-attributable
        # `failed` outcome (URI_INTEGRITY_MISMATCH) — the recipient must
        # refuse to act.
        check(
            "plaintext-hash recheck passes",
            sha2_256(opened.plaintext) == hashes["sha2-256"]
            and blake2b_256(opened.plaintext) == hashes["blake2b-256"],
        )

    if failures:
        print(f"\n{failures} check(s) FAILED")
        sys.exit(1)
    print("\nALL end-to-end checks PASSED")


if __name__ == "__main__":
    asyncio.run(main())
