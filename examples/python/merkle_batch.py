"""Label 309 batch anchoring — the top-level ``merkle[]`` list commitment.

One transaction can anchor an ordered list of leaf digests by committing
only the RFC 9162 Merkle root and the leaf count on chain; the full leaves
list lives off-chain in the normative CBOR leaves-list document. Anyone
holding the document can recompute the root; anyone holding a single leaf
plus an inclusion proof can verify membership without the other leaves.

The example:

1. hashes a batch of documents into leaf digests (SHA-256),
2. builds the on-chain commitment ``{ alg, root, leaf_count }`` and validates
   the record structurally,
3. encodes / decodes the off-chain CBOR leaves-list document and recomputes
   the root from it,
4. produces and verifies an RFC 9162 inclusion proof for one leaf,
5. hands the leaves-list to the standalone verifier OUT OF BAND
   (``merkle_leaves``) and reads the per-commitment content_check from the
   report — caller-supplied bytes are attributable by definition and need no
   fetch.

Run: ``uv run python merkle_batch.py`` (exits non-zero on any failed check).
"""

from __future__ import annotations

import asyncio
import sys
from typing import cast

from cardanowall import PoeRecord, encode_poe_record, validate_poe_record
from cardanowall.hash import sha2_256
from cardanowall.merkle import (
    MERKLE_ALG_ID,
    decode_leaves_list,
    encode_leaves_list,
    merkle_sha2_256_inclusion_proof,
    merkle_sha2_256_root,
    merkle_sha2_256_verify_inclusion,
)
from cardanowall.verifier import BlockInfo, VerifyRecordInput, verify_record_bytes

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    suffix = "" if ok or not detail else f" — {detail}"
    print(f"{'PASS' if ok else 'FAIL'}  {label}{suffix}")
    if not ok:
        failures += 1


async def main() -> None:
    # -- 1. The batch -----------------------------------------------------------
    documents = [f"batch document #{i}".encode() for i in range(5)]
    leaves = [sha2_256(d) for d in documents]

    # -- 2. The on-chain commitment ----------------------------------------------
    root = merkle_sha2_256_root(leaves)
    record: PoeRecord = cast(
        PoeRecord,
        {
            "v": 1,
            "merkle": [
                {
                    "alg": MERKLE_ALG_ID,  # 'rfc9162-sha256'
                    "root": root,
                    "leaf_count": len(leaves),  # REQUIRED alongside the root
                }
            ],
        },
    )
    print(f"merkle root         : {root.hex()} over {len(leaves)} leaves")
    check(
        "record with a merkle[] commitment validates",
        validate_poe_record(encode_poe_record(record)).ok,
    )

    # -- 3. The off-chain leaves-list document (normative CBOR) ------------------
    # The wire form every implementation must read; a JSON projection of it is
    # a display convenience only.
    leaves_list_bytes = encode_leaves_list(leaves=leaves, root=root)
    decoded = decode_leaves_list(leaves_list_bytes)
    print(
        f"leaves-list document: {len(leaves_list_bytes)} bytes, "
        f"format {decoded['format']}, tree {decoded['tree_alg']}"
    )
    check("document round-trips the leaf set", decoded["leaf_count"] == len(leaves))
    check(
        "root recomputes from the decoded leaves",
        merkle_sha2_256_root(decoded["leaves"]) == root,
    )

    # -- 4. Inclusion proof for one leaf ------------------------------------------
    # log2(N) sibling hashes prove membership of leaf 3 without revealing the
    # other documents.
    index = 3
    proof = merkle_sha2_256_inclusion_proof(leaves, index)
    check(
        "inclusion proof verifies",
        merkle_sha2_256_verify_inclusion(leaves[index], index, len(leaves), proof, root),
    )
    check(
        "proof rejects a different leaf",
        not merkle_sha2_256_verify_inclusion(
            sha2_256(b"not in the batch"), index, len(leaves), proof, root
        ),
    )

    # -- 5. The verifier checks the commitment -----------------------------------
    # ``merkle_leaves`` supplies the document out of band, keyed by
    # ``merkle[i]`` index: no fetch is issued, the bytes are attributable by
    # definition, and the report's per-commitment entry shows the claim was
    # actually checked (document validated + root recomputed). Had the
    # commitment carried ``uris[]``, the verifier would fetch the document
    # from there instead.
    report = await verify_record_bytes(
        encode_poe_record(record),
        BlockInfo(confirmation_depth=20, block_time=1_700_000_000),
        VerifyRecordInput(merkle_leaves={0: leaves_list_bytes}),
        tx_hash="22" * 32,
    )
    check("verdict valid", report.verdict == "valid" and report.exit_code == 0)
    check("one per-commitment report entry", len(report.merkle) == 1)
    check("commitment content_check is checked", report.merkle[0].content_check == "checked")

    # A leaves-list that does not match the on-chain root is record-attributable.
    reversed_leaves = list(reversed(leaves))
    wrong_list = encode_leaves_list(
        leaves=reversed_leaves, root=merkle_sha2_256_root(reversed_leaves)
    )
    mismatch = await verify_record_bytes(
        encode_poe_record(record),
        BlockInfo(confirmation_depth=20, block_time=1_700_000_000),
        VerifyRecordInput(merkle_leaves={0: wrong_list}),
        tx_hash="22" * 32,
    )
    check(
        "root mismatch → verdict failed with MERKLE_ROOT_MISMATCH",
        mismatch.verdict == "failed"
        and any(i.code == "MERKLE_ROOT_MISMATCH" for i in mismatch.issues)
        and mismatch.merkle[0].content_check == "mismatched",
        ",".join(sorted({i.code for i in mismatch.issues})),
    )

    if failures:
        print(f"\n{failures} check(s) FAILED")
        sys.exit(1)
    print("\nALL merkle-batch checks PASSED")


if __name__ == "__main__":
    asyncio.run(main())
