"""Label 309 standalone-verifier tour — every verdict, offline.

Drives the full ``verify_tx`` pipeline with an injected ``fetch_outbound``
that serves a synthetic Cardano transaction and its content, so the example
is reproducible without any network. In production the same call resolves a
real transaction through whatever Koios-compatible explorer chain the caller
configures; nothing else changes.

The synthetic transaction genuinely satisfies the verifier's integrity
bindings: the requested hash is the blake2b-256 of the transaction body, and
the body commits to the auxiliary data (which carries the label-309 chunk
array) via ``auxiliary_data_hash``.

The tour exercises the four-state verdict and its exit-code mapping —

    valid → 0    failed → 1    unverifiable → 2    pending → 3

— plus the ``fetch_content`` switch and the attribution split on fetched
content: bytes that provably belong to the URI (e.g. an ipfs:// raw CID
whose multihash recomputes) and fail a committed digest condemn the record
(URI_INTEGRITY_MISMATCH → failed), while bytes a gateway merely served
(e.g. ar://, no offline binding check) that mismatch indict only the
provider (URI_PROVIDER_INTEGRITY_MISMATCH, warning) — the claim ends
unchecked and the verdict is `unverifiable`, never `failed`.

Run: ``uv run python verify_offline.py`` (exits non-zero on any failed check).
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import cast

from cardanowall import PoeRecord, encode_poe_record, signer_from_seed
from cardanowall.client import assemble_cose_sign1, prepare_sig_structure
from cardanowall.hash import blake2b_256, sha2_256
from cardanowall.verifier import (
    FetchOutbound,
    FetchOutboundOptions,
    FetchOutboundResult,
    VerifyReport,
    VerifyTxInput,
    encode_label_309_value,
    verify_report_to_dict,
    verify_tx,
)

# Explicit gateway chains keep the demo's routing visible; any
# Koios-compatible explorer and any Arweave/IPFS gateways work the same way.
CARDANO_GATEWAY = "https://koios.example/api/v1"
ARWEAVE_GATEWAY = "https://arweave-gateway.example"
IPFS_GATEWAY = "https://ipfs-gateway.example"
ARWEAVE_TXID = "A" * 43

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    suffix = "" if ok or not detail else f" — {detail}"
    print(f"{'PASS' if ok else 'FAIL'}  {label}{suffix}")
    if not ok:
        failures += 1


# -- Synthetic bound transaction ----------------------------------------------
# Minimal definite-length CBOR writers for the OUTER transaction wrapper. The
# wrapper is the ledger's shape, not this standard's — the record body inside
# it is produced by the SDK encoders above.


def cbor_head(major_type: int, n: int) -> bytes:
    """CBOR header for ``major_type`` with argument ``n`` (n < 2^16 suffices here)."""
    if n < 24:
        return bytes([(major_type << 5) | n])
    if n < 0x100:
        return bytes([(major_type << 5) | 24, n])
    return bytes([(major_type << 5) | 25, (n >> 8) & 0xFF, n & 0xFF])


def build_bound_tx(record_body: bytes) -> tuple[str, bytes]:
    """Build ``(tx_hash_hex, tx_cbor)`` for a transaction whose auxiliary data
    carries the record body as the label-309 chunk array, with both integrity
    bindings the verifier checks satisfied: blake2b-256(body) is the
    transaction hash, and the body's ``auxiliary_data_hash`` (key 7) is
    blake2b-256(aux data)."""
    # auxiliary data: the plain metadata-map form, { 309: <chunk array> }
    aux = cbor_head(5, 1) + cbor_head(0, 309) + encode_label_309_value(record_body)
    # transaction body: { 7: blake2b-256(aux) }
    body = cbor_head(5, 1) + cbor_head(0, 7) + cbor_head(2, 32) + blake2b_256(aux)
    # transaction: [ body, witness_set, is_valid, auxiliary_data ]
    tx_cbor = cbor_head(4, 4) + body + b"\xa0\xf5" + aux
    return blake2b_256(body).hex(), tx_cbor


# -- Injected fetch_outbound ---------------------------------------------------


def make_gateway_stub(
    tx_hash: str,
    tx_cbor: bytes,
    confirmations: int,
    content: dict[str, bytes] | None = None,
) -> FetchOutbound:
    def json_response(value: object) -> FetchOutboundResult:
        return FetchOutboundResult(status=200, bytes=json.dumps(value).encode(), duration_ms=1)

    async def stub(url: str, opts: FetchOutboundOptions) -> FetchOutboundResult:
        if url == f"{CARDANO_GATEWAY}/tx_cbor":
            return json_response([{"tx_hash": tx_hash, "cbor": tx_cbor.hex()}])
        if url == f"{CARDANO_GATEWAY}/tx_info":
            return json_response(
                [
                    {
                        "tx_hash": tx_hash,
                        "num_confirmations": confirmations,
                        "tx_timestamp": 1_700_000_000,
                        "absolute_slot": 99,
                    }
                ]
            )
        if content is not None and url in content:
            return FetchOutboundResult(status=200, bytes=content[url], duration_ms=1)
        return FetchOutboundResult(status=404, bytes=b"", duration_ms=1)

    return stub


# -- Record builders -------------------------------------------------------------


def build_signed_record(item: dict[str, object]) -> PoeRecord:
    unsigned: PoeRecord = cast(PoeRecord, {"v": 1, "items": [item]})
    signer = signer_from_seed(bytes([3]) * 32)
    sig_structure, _protected = prepare_sig_structure(
        record=unsigned, signer_pubkey=signer.signer_pubkey
    )
    _cose, sig_entry = assemble_cose_sign1(
        record=unsigned, signer_pubkey=signer.signer_pubkey, signature=signer.sign(sig_structure)
    )
    return cast(PoeRecord, {**unsigned, "sigs": [sig_entry]})


def raw_sha256_cid_v1(content: bytes) -> str:
    """A raw-codec CIDv1 string whose multihash binding the verifier can
    recompute offline: 0x01 CIDv1 | 0x55 raw | 0x12 sha2-256 | 0x20 32 bytes."""
    cid_bytes = bytes([0x01, 0x55, 0x12, 0x20]) + sha2_256(content)
    b32 = base64.b32encode(cid_bytes).decode().lower().rstrip("=")
    return f"b{b32}"


async def run_verify(
    record: PoeRecord,
    confirmations: int,
    content: dict[str, bytes] | None = None,
    fetch_content: bool = True,
) -> VerifyReport:
    tx_hash, tx_cbor = build_bound_tx(encode_poe_record(record))
    return await verify_tx(
        VerifyTxInput(
            tx_hash=tx_hash,
            cardano_gateway_chain=(CARDANO_GATEWAY,),
            arweave_gateway_chain=(ARWEAVE_GATEWAY,),
            ipfs_gateway_chain=(IPFS_GATEWAY,),
            fetch_outbound=make_gateway_stub(tx_hash, tx_cbor, confirmations, content),
            fetch_content=fetch_content,
        )
    )


def issue_codes(report: VerifyReport) -> str:
    return ",".join(sorted({i.code for i in report.issues}))


# -- The tour --------------------------------------------------------------------


async def main() -> None:
    content = b"verify-offline example content"
    wrong_bytes = b"NOT the committed content"
    ar_uri = f"ar://{ARWEAVE_TXID}"

    # 1. valid — the transaction resolves, the record validates, the signature
    #    verifies, and the fetched ar:// bytes satisfy every committed digest.
    record = build_signed_record({"hashes": {"sha2-256": sha2_256(content)}, "uris": [ar_uri]})
    valid = await run_verify(record, 50, content={f"{ARWEAVE_GATEWAY}/{ARWEAVE_TXID}": content})
    print("--- verdict: valid ---")
    print(json.dumps(verify_report_to_dict(valid), indent=2))
    check("valid: verdict valid, exit 0", valid.verdict == "valid" and valid.exit_code == 0)
    check("valid: item content checked", valid.items[0].content_check == "checked")
    check(
        "valid: signature verified",
        valid.signatures is not None and valid.signatures[0].verdict == "valid",
    )
    check(
        "valid: audit trail records every outbound call",
        len(valid.audit_trail) >= 3 and any(c.purpose == "arweave" for c in valid.audit_trail),
    )

    # 2. pending — below the confirmation-depth threshold (default 15 blocks)
    #    the pipeline halts: no result from a record that may yet be orphaned
    #    may be presented as final.
    pending = await run_verify(record, 3)
    check(
        "pending: verdict pending, exit 3", pending.verdict == "pending" and pending.exit_code == 3
    )
    check(
        "pending: INSUFFICIENT_CONFIRMATIONS raised",
        any(i.code == "INSUFFICIENT_CONFIRMATIONS" for i in pending.issues),
    )
    check(
        "pending: depth and threshold reported",
        pending.confirmation_depth == 3 and pending.confirmation_threshold == 15,
    )

    # 3. fetch_content=False — the master content-fetch switch. The record
    #    renders offline from the chain-resolved CBOR alone; every content
    #    claim is reported not_checked (an unchecked claim can never
    #    masquerade as a verified one), and no content egress happens.
    offline = await run_verify(record, 50, fetch_content=False)
    check("fetch_content off: verdict still valid", offline.verdict == "valid")
    check("fetch_content off: claim not_checked", offline.items[0].content_check == "not_checked")
    check(
        "fetch_content off: no content fetch in the audit trail",
        all(c.purpose == "cardano" for c in offline.audit_trail),
    )

    # 4. unverifiable — the gateway serves bytes that fail the digest, but an
    #    ar:// fetch carries no offline binding proof, so the mismatch indicts
    #    the provider, not the record: URI_PROVIDER_INTEGRITY_MISMATCH
    #    (warning), then CONTENT_UNAVAILABLE once every source is exhausted.
    provider_mismatch = await run_verify(
        record, 50, content={f"{ARWEAVE_GATEWAY}/{ARWEAVE_TXID}": wrong_bytes}
    )
    check(
        "provider mismatch: verdict unverifiable, exit 2",
        provider_mismatch.verdict == "unverifiable" and provider_mismatch.exit_code == 2,
    )
    check(
        "provider mismatch: URI_PROVIDER_INTEGRITY_MISMATCH + CONTENT_UNAVAILABLE",
        any(i.code == "URI_PROVIDER_INTEGRITY_MISMATCH" for i in provider_mismatch.issues)
        and any(i.code == "CONTENT_UNAVAILABLE" for i in provider_mismatch.issues),
        issue_codes(provider_mismatch),
    )
    check(
        "provider mismatch: claim stays not_checked",
        provider_mismatch.items[0].content_check == "not_checked",
    )

    # 5. failed — the same wrong bytes behind an ipfs:// raw CIDv1 whose
    #    multihash recomputes over them: now the bytes provably belong to the
    #    URI the producer published, so the digest failure is
    #    record-attributable: URI_INTEGRITY_MISMATCH, verdict failed.
    wrong_cid = raw_sha256_cid_v1(wrong_bytes)
    lying_record = build_signed_record(
        {"hashes": {"sha2-256": sha2_256(content)}, "uris": [f"ipfs://{wrong_cid}"]}
    )
    attributable = await run_verify(
        lying_record, 50, content={f"{IPFS_GATEWAY}/ipfs/{wrong_cid}": wrong_bytes}
    )
    check(
        "attributable mismatch: verdict failed, exit 1",
        attributable.verdict == "failed" and attributable.exit_code == 1,
    )
    check(
        "attributable mismatch: URI_INTEGRITY_MISMATCH raised",
        any(i.code == "URI_INTEGRITY_MISMATCH" for i in attributable.issues),
        issue_codes(attributable),
    )
    check(
        "attributable mismatch: claim reported mismatched",
        attributable.items[0].content_check == "mismatched",
    )

    if failures:
        print(f"\n{failures} check(s) FAILED")
        sys.exit(1)
    print("\nALL verifier-tour checks PASSED")


if __name__ == "__main__":
    asyncio.run(main())
