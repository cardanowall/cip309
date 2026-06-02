"""CIP-309 v1 reference implementation — standalone CIP-309 verifier.

Service-independent: depends only on caller-supplied Cardano + Arweave
gateways (public block explorers and content gateways). No issuer server is
required at any step.

Key invariants this verifier upholds:
  - Fetch RAW tx CBOR (Koios /tx_cbor or Blockfrost /txs/{hash}/cbor), NOT the
    JSON metadata projection — the JSON path is lossy and breaks signature
    verification.
  - Enforce confirmation depth >= threshold (default 15 blocks). Below
    threshold surfaces as `INSUFFICIENT_CONFIRMATIONS` with verdict `pending`.
  - Build `to_sign = SIG_DOMAIN_RECORD_V1 || canonical_cbor(record_body)` and
    pass `external_aad = h''` to the COSE Sig_structure. Signatures attach at
    the record level only — only `record.sigs[]` is verified.
  - Use the COSE_Sign1's preserved protected_bytes verbatim, NOT a re-encoded
    form.
  - Use strict Ed25519 (libsodium default) — wired in ed25519.py.
  - Route every outbound call through fetch_outbound; record into
    VerifyReport.http_calls.

Cross-language parity: mirrors the TypeScript reference (standalone-verifier.ts).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import cbor2
import httpx

from .cbor_walker import slice_label309_value
from .cose_sign1 import build_sig_structure, decode_cose_sign1
from .ecies_sealed_poe import (
    MlKem768X25519Slot,
    SealedEnvelope,
    SealedSlot,
    ecies_sealed_poe_unwrap,
)
from .ed25519 import verify_ed25519
from .hash_dual import blake2b_256, sha2_256
from .merkle_leaves_list import (
    SchemaMerkleLeavesFormatUnsupported,
    decode_leaves_list,
)
from .merkle_sha2_256 import merkle_root
from .passphrase_kdf_unwrap import (
    PassphraseArgon2idEnvelope,
    ecies_passphrase_unwrap,
)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# The 25-byte UTF-8 prefix prepended to canonical-CBOR(record_body) to form
# Sig_structure[3] (`to_sign`). Sig_structure[2] (`external_aad`) is the empty
# bstr in v1 — this is the entire CIP-30-compatibility path.
SIG_DOMAIN_RECORD_V1 = b"cardano-poe-record-sig-v1"
EMPTY_EXTERNAL_AAD = b""

NetworkId = Literal["cardano:mainnet", "cardano:preprod", "cardano:preview"]
Verdict = Literal["valid", "pending", "failed"]

KOIOS_DEFAULTS: dict[str, str] = {
    "cardano:mainnet": "https://api.koios.rest/api/v1",
    "cardano:preprod": "https://preprod.koios.rest/api/v1",
    "cardano:preview": "https://preview.koios.rest/api/v1",
}

BLOCKFROST_HOSTS: dict[str, str] = {
    "cardano:mainnet": "https://cardano-mainnet.blockfrost.io/api/v0",
    "cardano:preprod": "https://cardano-preprod.blockfrost.io/api/v0",
    "cardano:preview": "https://cardano-preview.blockfrost.io/api/v0",
}

DEFAULT_ARWEAVE_GATEWAYS = [
    "https://arweave.net",
    "https://ar-io.net",
    "https://g8way.io",
]


# -----------------------------------------------------------------------------
# Public types
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchOutboundResult:
    status: int
    body: bytes
    duration_ms: float


# An outbound fetch function: (url, method, headers, body, purpose) -> result.
FetchOutbound = Callable[..., FetchOutboundResult]


@dataclass
class HttpCall:
    url: str
    method: str
    status: int
    bytes: int
    duration_ms: float
    purpose: str


@dataclass
class RecordSignatureCheck:
    index: int
    valid: bool
    signer_pub: str | None = None
    signer_type: str | None = None
    reason: str | None = None


@dataclass
class ItemDecryption:
    item_index: int
    ok: bool
    plaintext_hash_ok: bool | None = None
    note: str | None = None
    reason: str | None = None


@dataclass
class MerkleCheck:
    merkle_index: int
    alg: str
    root_ok: bool | None = None
    reason: str | None = None


@dataclass
class VerifyReport:
    tx_hash: str
    network: NetworkId
    num_confirmations: int
    confirmation_depth_threshold: int
    metadata_present: bool
    validation: dict[str, Any]
    verdict: Verdict
    http_calls: list[HttpCall] = field(default_factory=list)
    block_time: int | None = None
    block_slot: int | None = None
    record: dict[str, Any] | None = None
    record_signatures: list[RecordSignatureCheck] | None = None
    item_hash_checks: list[dict[str, Any]] | None = None
    merkle_checks: list[MerkleCheck] | None = None
    item_decryptions: list[ItemDecryption] | None = None


# Discriminated decryption input: either a recipient secret key or a passphrase.
@dataclass(frozen=True)
class RecipientKeyDecryption:
    item_index: int
    recipient_secret_key: bytes


@dataclass(frozen=True)
class PassphraseDecryption:
    item_index: int
    passphrase: str


DecryptionInput = RecipientKeyDecryption | PassphraseDecryption


@dataclass
class VerifyTxInput:
    tx_hash: str
    network: NetworkId = "cardano:mainnet"
    cardano_gateway_chain: list[str] | None = None
    blockfrost_project_id: str | None = None
    arweave_gateway_chain: list[str] | None = None
    confirmation_depth_threshold: int = 15
    deny_hosts: list[str] | None = None
    decryption: list[DecryptionInput] | None = None
    # Out-of-band ciphertext bytes, keyed by items[i] index.
    ciphertext_bytes: dict[int, bytes] | None = None
    # Out-of-band Merkle companion leaves-list bytes, keyed by merkle[i] index.
    merkle_leaves: dict[int, bytes] | None = None
    fetch_outbound: FetchOutbound | None = None


@dataclass(frozen=True)
class _ResolvedTx:
    tx_cbor: bytes
    num_confirmations: int
    block_time: int
    block_slot: int


# -----------------------------------------------------------------------------
# fetch_outbound wrapper (single egress point + deny_hosts + audit trail)
# -----------------------------------------------------------------------------


def _default_fetch_outbound(
    url: str,
    *,
    method: str,
    purpose: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> FetchOutboundResult:
    t0 = time.monotonic()
    resp = httpx.request(method, url, headers=headers, content=body, timeout=30.0)
    return FetchOutboundResult(
        status=resp.status_code,
        body=resp.content,
        duration_ms=(time.monotonic() - t0) * 1000.0,
    )


def _wrap_fetch_outbound(
    inner: FetchOutbound,
    audit: list[HttpCall],
    deny_hosts: list[str] | None,
) -> FetchOutbound:
    # Two responsibilities:
    #   1. deny_hosts — service-independence guard: refuse to call hosts the
    #      operator has declared off-limits. Match is exact-host or `*.suffix`.
    #   2. Audit trail — every outbound call (success or failure) is recorded
    #      so the report is a complete record of what the verifier touched.
    def wrapped(
        url: str,
        *,
        method: str,
        purpose: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> FetchOutboundResult:
        if deny_hosts:
            host = urlparse(url).hostname or ""
            blocked = any(
                host == d or (d.startswith("*.") and host.endswith(d[1:])) for d in deny_hosts
            )
            if blocked:
                audit.append(HttpCall(url, method, 0, 0, 0.0, purpose))
                raise RuntimeError(f"SERVICE_INDEPENDENCE_VIOLATION: {host} is in deny_hosts")
        t0 = time.monotonic()
        try:
            result = inner(url, method=method, purpose=purpose, headers=headers, body=body)
            audit.append(
                HttpCall(url, method, result.status, len(result.body), result.duration_ms, purpose)
            )
            return result
        except Exception:
            audit.append(HttpCall(url, method, 0, 0, (time.monotonic() - t0) * 1000.0, purpose))
            raise

    return wrapped


# -----------------------------------------------------------------------------
# Cardano gateway resolution + tx_cbor fetch
# -----------------------------------------------------------------------------


def _hex_to_bytes(hex_str: str) -> bytes:
    clean = hex_str[2:] if hex_str.startswith("0x") else hex_str
    return bytes.fromhex(clean)


def _resolve_via_koios(tx_hash: str, koios_url: str, fetch_fn: FetchOutbound) -> _ResolvedTx:
    cbor_res = fetch_fn(
        f"{koios_url}/tx_cbor",
        method="POST",
        headers={"content-type": "application/json", "accept": "application/json"},
        body=json.dumps({"_tx_hashes": [tx_hash]}),
        purpose="cardano",
    )
    if cbor_res.status != 200:
        raise RuntimeError(f"koios_tx_cbor_{cbor_res.status}")
    cbor_json = json.loads(cbor_res.body.decode())
    if not isinstance(cbor_json, list) or len(cbor_json) == 0:
        raise RuntimeError("koios_tx_cbor_empty")
    tx_cbor = _hex_to_bytes(cbor_json[0]["cbor"])

    info_res = fetch_fn(
        f"{koios_url}/tx_info",
        method="POST",
        headers={"content-type": "application/json", "accept": "application/json"},
        body=json.dumps({"_tx_hashes": [tx_hash]}),
        purpose="cardano",
    )
    if info_res.status != 200:
        raise RuntimeError(f"koios_tx_info_{info_res.status}")
    info_json = json.loads(info_res.body.decode())
    if not isinstance(info_json, list) or len(info_json) == 0:
        raise RuntimeError("koios_tx_info_empty")
    info = info_json[0]
    return _ResolvedTx(
        tx_cbor=tx_cbor,
        num_confirmations=info["num_confirmations"],
        block_time=info["tx_timestamp"],
        block_slot=info["absolute_slot"],
    )


def _resolve_via_blockfrost(
    tx_hash: str, network: NetworkId, project_id: str, fetch_fn: FetchOutbound
) -> _ResolvedTx:
    base = BLOCKFROST_HOSTS[network]
    headers = {"project_id": project_id, "accept": "application/json"}

    cbor_res = fetch_fn(
        f"{base}/txs/{tx_hash}/cbor", method="GET", headers=headers, purpose="cardano"
    )
    if cbor_res.status != 200:
        raise RuntimeError(f"blockfrost_cbor_{cbor_res.status}")
    tx_cbor = _hex_to_bytes(json.loads(cbor_res.body.decode())["cbor"])

    info_res = fetch_fn(f"{base}/txs/{tx_hash}", method="GET", headers=headers, purpose="cardano")
    if info_res.status != 200:
        raise RuntimeError(f"blockfrost_info_{info_res.status}")
    info_json = json.loads(info_res.body.decode())

    tip_res = fetch_fn(f"{base}/blocks/latest", method="GET", headers=headers, purpose="cardano")
    if tip_res.status != 200:
        raise RuntimeError(f"blockfrost_tip_{tip_res.status}")
    tip_slot = json.loads(tip_res.body.decode())["slot"]
    num_confirmations = max(0, tip_slot - info_json["slot"])
    return _ResolvedTx(
        tx_cbor=tx_cbor,
        num_confirmations=num_confirmations,
        block_time=info_json["block_time"],
        block_slot=info_json["slot"],
    )


def _resolve_cardano_tx(input_: VerifyTxInput, fetch_fn: FetchOutbound) -> _ResolvedTx:
    koios_chain = input_.cardano_gateway_chain or [KOIOS_DEFAULTS[input_.network]]
    for koios_url in koios_chain:
        try:
            return _resolve_via_koios(input_.tx_hash, koios_url, fetch_fn)
        except Exception:
            continue  # try next gateway
    if input_.blockfrost_project_id:
        return _resolve_via_blockfrost(
            input_.tx_hash, input_.network, input_.blockfrost_project_id, fetch_fn
        )
    raise RuntimeError("all_providers_failed")


# -----------------------------------------------------------------------------
# Signature verification
# -----------------------------------------------------------------------------


def _extract_ed25519_pub_from_cose_key(chunks: list[bytes]) -> bytes | None:
    # RFC 8152 §7 COSE_Key shape for Ed25519:
    #   { 1 (kty): 1 (OKP), -1 (crv): 6 (Ed25519), -2 (x): <bytes:32> }
    try:
        blob = b"".join(chunks)
        decoded = cbor2.loads(blob)
        if not isinstance(decoded, dict):
            return None
        if decoded.get(1) != 1:  # MUST be OKP
            return None
        if decoded.get(-1) != 6:  # MUST be Ed25519
            return None
        x = decoded.get(-2)
        if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
            return None
        return bytes(x)
    except Exception:
        return None


def _verify_one_signature(
    sig_chunks: list[bytes],
    payload: bytes,
    cose_key_chunks: list[bytes] | None,
) -> RecordSignatureCheck:
    try:
        cose = decode_cose_sign1(b"".join(sig_chunks))
    except Exception:
        return RecordSignatureCheck(index=-1, valid=False, reason="MALFORMED_SIG_COSE_SIGN1")
    # RFC 9052 §4.1: detached form MUST encode payload as nil; a zero-length
    # byte string is NOT equivalent and MUST be rejected.
    if cose.get("payload") is not None:
        return RecordSignatureCheck(index=-1, valid=False, reason="MALFORMED_SIG_COSE_SIGN1")
    ph = cose.get("protected_header") or {}
    alg = ph.get(1) if isinstance(ph, dict) else None
    if alg != -8:
        # Unrecognised-alg is info severity on the entry; the record-as-a-whole
        # verdict for a public hash-only PoE remains passed.
        return RecordSignatureCheck(index=-1, valid=False, reason="SIGNATURE_UNSUPPORTED")

    # Signer-key resolution priority:
    #   1. Protected-header `kid` if exactly 32 bytes (raw Ed25519 pubkey).
    #   2. Inline `cose_key` carrying cbor<COSE_Key> (CIP-30 wallet path).
    # Unprotected-header `kid` values are NOT a sanctioned resolution path.
    protected_kid = ph.get(4) if isinstance(ph, dict) else None
    signer_pub: bytes | None = None
    signer_type: str | None = None
    if isinstance(protected_kid, (bytes, bytearray)) and len(protected_kid) == 32:
        signer_pub = bytes(protected_kid)
        signer_type = "in-signature-kid"
    elif cose_key_chunks is not None:
        extracted = _extract_ed25519_pub_from_cose_key(cose_key_chunks)
        if extracted is not None:
            signer_pub = extracted
            signer_type = "wallet-inline-key"
    if signer_pub is None or len(signer_pub) != 32:
        return RecordSignatureCheck(index=-1, valid=False, reason="SIGNER_KEY_UNRESOLVED")

    # CIP-8 `hashed` mode: a hardware co-signer may set unprotected
    # "hashed": true. The slot at Sig_structure index 3 then becomes
    # Blake2b-224(to_sign), not to_sign itself.
    unprotected = cose.get("unprotected_header") or {}
    hashed = isinstance(unprotected, dict) and unprotected.get("hashed") is True
    import hashlib

    sig_struct_payload = hashlib.blake2b(payload, digest_size=28).digest() if hashed else payload

    # Build Sig_structure with the PRESERVED original protected_bytes (RFC 9052
    # §4.4) and the v1 empty external_aad — the cross-protocol replay defence is
    # the domain-separator prefix embedded inside `payload`.
    sig_struct = build_sig_structure(
        context="Signature1",
        body_protected_bytes=cose["protected_bytes"],
        external_aad=EMPTY_EXTERNAL_AAD,
        payload=sig_struct_payload,
    )
    ok = verify_ed25519(cose["signature"], sig_struct, signer_pub)
    if ok:
        return RecordSignatureCheck(
            index=-1, valid=True, signer_pub=signer_pub.hex(), signer_type=signer_type
        )
    return RecordSignatureCheck(
        index=-1,
        valid=False,
        signer_pub=signer_pub.hex(),
        signer_type=signer_type,
        reason="SIGNATURE_INVALID",
    )


def _verify_record_signatures(record: dict[str, Any]) -> list[RecordSignatureCheck]:
    # Strip `sigs` from the signed payload. The optional CIP-30 `cose_key` lives
    # inside each sigs entry.
    from .cbor_canonical import encode_canonical_cbor

    record_body = {k: v for k, v in record.items() if k != "sigs"}
    record_body_bytes = encode_canonical_cbor(record_body)
    to_sign = SIG_DOMAIN_RECORD_V1 + record_body_bytes

    out: list[RecordSignatureCheck] = []
    for i, entry in enumerate(record.get("sigs", [])):
        cose_key_chunks = entry.get("cose_key") if isinstance(entry, dict) else None
        result = _verify_one_signature(entry["cose_sign1"], to_sign, cose_key_chunks)
        result.index = i
        out.append(result)
    return out


# -----------------------------------------------------------------------------
# Ciphertext acquisition + decryption + Merkle commitments
# -----------------------------------------------------------------------------


def _fetch_uri_ciphertext(
    uris: list[list[str]],
    arweave_gateways: list[str],
    fetch_fn: FetchOutbound,
) -> bytes:
    # Each entry of `uris` is itself an array of tstr chunks; join the chunks
    # before testing the scheme. The v1 fetch set is exactly {ar://, ipfs://}.
    reconstructed = ["".join(chunks) for chunks in uris]
    uri = next((u for u in reconstructed if u.startswith(("ar://", "ipfs://"))), None)
    if uri is None:
        raise RuntimeError("URI_TARGET_FORBIDDEN")
    if uri.startswith("ar://"):
        txid = uri[5:]
        gateways = arweave_gateways or DEFAULT_ARWEAVE_GATEWAYS
        for gw in gateways:
            try:
                res = fetch_fn(f"{gw}/{txid}", method="GET", purpose="arweave")
                if res.status == 200:
                    return res.body
            except Exception:
                continue
        raise RuntimeError("CONTENT_UNAVAILABLE")
    # ipfs:// — no gateway wired in this reference verifier.
    raise RuntimeError("CONTENT_UNAVAILABLE")


def _envelope_from_enc(enc: dict[str, Any]) -> SealedEnvelope:
    kem = enc["kem"]
    if kem == "x25519":
        slots: Any = tuple(SealedSlot(epk=s["epk"], wrap=s["wrap"]) for s in enc["slots"])
    else:
        slots = tuple(
            MlKem768X25519Slot(kem_ct=tuple(s["kem_ct"]), wrap=s["wrap"]) for s in enc["slots"]
        )
    return SealedEnvelope(
        scheme=enc["scheme"],
        aead=enc["aead"],
        kem=kem,
        nonce=enc["nonce"],
        slots=slots,
        slots_mac=enc["slots_mac"],
    )


def _check_item_hashes(hashes: dict[str, bytes], plaintext: bytes) -> bool:
    recompute = {"sha2-256": sha2_256, "blake2b-256": blake2b_256}
    for alg, claimed in hashes.items():
        fn = recompute.get(alg)
        # Unknown algorithms cannot reach here — the structural validator rejects
        # them upstream with UNSUPPORTED_HASH_ALG.
        if fn is not None and fn(plaintext) != claimed:
            return False
    return True


def _try_decryptions(
    record: dict[str, Any], input_: VerifyTxInput, fetch_fn: FetchOutbound
) -> list[ItemDecryption]:
    out: list[ItemDecryption] = []
    items = record["items"]
    for dec in input_.decryption or []:
        item = items[dec.item_index] if dec.item_index < len(items) else None
        if not item or "enc" not in item:
            out.append(ItemDecryption(dec.item_index, ok=False, reason="no_enc_envelope"))
            continue
        enc = item["enc"]
        has_slots = "slots" in enc
        has_passphrase = "passphrase" in enc
        entry_has_secret = isinstance(dec, RecipientKeyDecryption)
        entry_has_passphrase = isinstance(dec, PassphraseDecryption)
        if has_slots and not entry_has_secret:
            out.append(
                ItemDecryption(dec.item_index, ok=False, reason="WRONG_DECRYPTION_INPUT_SHAPE")
            )
            continue
        if has_passphrase and not entry_has_passphrase:
            out.append(
                ItemDecryption(dec.item_index, ok=False, reason="WRONG_DECRYPTION_INPUT_SHAPE")
            )
            continue

        # Ciphertext acquisition: prefer the out-of-band bytes, else fetch URIs.
        local_bytes = (input_.ciphertext_bytes or {}).get(dec.item_index)
        uris = item.get("uris")
        if local_bytes is not None:
            ciphertext = local_bytes
        elif uris:
            try:
                ciphertext = _fetch_uri_ciphertext(
                    uris, input_.arweave_gateway_chain or [], fetch_fn
                )
            except Exception as e:
                code = (
                    "URI_TARGET_FORBIDDEN"
                    if str(e) == "URI_TARGET_FORBIDDEN"
                    else "CONTENT_UNAVAILABLE"
                )
                out.append(ItemDecryption(dec.item_index, ok=False, reason=code))
                continue
        else:
            out.append(ItemDecryption(dec.item_index, ok=False, reason="CIPHERTEXT_UNAVAILABLE"))
            continue

        try:
            if isinstance(dec, RecipientKeyDecryption):
                plaintext = ecies_sealed_poe_unwrap(
                    envelope=_envelope_from_enc(enc),
                    ciphertext=ciphertext,
                    recipient_secret_key=dec.recipient_secret_key,
                )
            else:
                envelope = PassphraseArgon2idEnvelope(
                    scheme=enc["scheme"],
                    aead=enc["aead"],
                    nonce=enc["nonce"],
                    passphrase=enc["passphrase"],
                )
                plaintext = ecies_passphrase_unwrap(
                    envelope=envelope, ciphertext=ciphertext, passphrase=dec.passphrase
                )
        except Exception as e:
            reason = getattr(e, "code", None) or "TAMPERED_CIPHERTEXT"
            out.append(ItemDecryption(dec.item_index, ok=False, reason=reason))
            continue

        if _check_item_hashes(item["hashes"], plaintext):
            out.append(ItemDecryption(dec.item_index, ok=True, plaintext_hash_ok=True))
        else:
            out.append(
                ItemDecryption(
                    dec.item_index,
                    ok=True,
                    plaintext_hash_ok=False,
                    reason="URI_INTEGRITY_MISMATCH",
                )
            )
    return out


def _check_merkle_commitments(
    record: dict[str, Any], input_: VerifyTxInput, fetch_fn: FetchOutbound
) -> list[MerkleCheck]:
    out: list[MerkleCheck] = []
    for i, commit in enumerate(record.get("merkle", [])):
        leaves_bytes = (input_.merkle_leaves or {}).get(i)
        if leaves_bytes is None:
            uris = commit.get("uris")
            if not uris:
                out.append(MerkleCheck(i, commit["alg"], reason="MERKLE_LEAVES_UNAVAILABLE"))
                continue
            try:
                leaves_bytes = _fetch_uri_ciphertext(
                    uris, input_.arweave_gateway_chain or [], fetch_fn
                )
            except Exception:
                out.append(MerkleCheck(i, commit["alg"], reason="MERKLE_LEAVES_UNAVAILABLE"))
                continue
        try:
            decoded = decode_leaves_list(leaves_bytes)
        except SchemaMerkleLeavesFormatUnsupported:
            out.append(
                MerkleCheck(i, commit["alg"], reason="SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED")
            )
            continue
        except Exception:
            out.append(MerkleCheck(i, commit["alg"], reason="MERKLE_LEAVES_UNAVAILABLE"))
            continue
        if commit["alg"] != "rfc9162-sha256" or decoded.tree_alg != "rfc9162-sha256":
            out.append(MerkleCheck(i, commit["alg"], reason="UNSUPPORTED_MERKLE_COMMIT_ALG"))
            continue
        if commit["leaf_count"] != decoded.leaf_count:
            out.append(MerkleCheck(i, commit["alg"], reason="SCHEMA_MERKLE_LEAF_COUNT_MISMATCH"))
            continue
        recomputed = merkle_root(list(decoded.leaves))
        ok = recomputed == commit["root"]
        out.append(
            MerkleCheck(i, commit["alg"], root_ok=ok, reason=None if ok else "MERKLE_ROOT_MISMATCH")
        )
    return out


# -----------------------------------------------------------------------------
# Main entry
# -----------------------------------------------------------------------------


def verify_tx(input_: VerifyTxInput) -> VerifyReport:
    from .cip_309_validator import validate_poe_record

    threshold = input_.confirmation_depth_threshold
    http_calls: list[HttpCall] = []
    fetch_fn = _wrap_fetch_outbound(
        input_.fetch_outbound or _default_fetch_outbound, http_calls, input_.deny_hosts
    )

    def base_report(verdict: Verdict, **over: Any) -> VerifyReport:
        defaults: dict[str, Any] = {
            "tx_hash": input_.tx_hash,
            "network": input_.network,
            "num_confirmations": 0,
            "confirmation_depth_threshold": threshold,
            "metadata_present": False,
            "validation": {"valid": False},
            "http_calls": http_calls,
            "verdict": verdict,
        }
        defaults.update(over)
        return VerifyReport(**defaults)

    # 1. Resolve gateway, fetch raw tx CBOR + confirmation depth.
    try:
        resolved = _resolve_cardano_tx(input_, fetch_fn)
    except Exception as e:
        return base_report(
            "failed",
            validation={
                "valid": False,
                "issues": [{"path": [], "code": "PROVIDER_UNAVAILABLE", "message": str(e)}],
            },
        )

    # 2. Extract label-309 metadata bytes from the tx CBOR.
    try:
        metadata_bytes = slice_label309_value(resolved.tx_cbor)
    except Exception as e:
        return base_report(
            "failed",
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            num_confirmations=resolved.num_confirmations,
            validation={
                "valid": False,
                "issues": [{"path": [], "code": "MALFORMED_CBOR", "message": str(e)}],
            },
        )
    if metadata_bytes is None:
        return base_report(
            "failed",
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            num_confirmations=resolved.num_confirmations,
            validation={
                "valid": False,
                "issues": [
                    {
                        "path": [],
                        "code": "METADATA_NOT_FOUND",
                        "message": "no label-309 metadata on this tx",
                    }
                ],
            },
        )

    # 3. Validator (pure function). Reassemble the chunked record body first.
    from .cbor_walker import reassemble_record_body

    record_body_bytes = reassemble_record_body(metadata_bytes)
    validation = validate_poe_record(record_body_bytes)
    if not validation["valid"]:
        return base_report(
            "failed",
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            num_confirmations=resolved.num_confirmations,
            metadata_present=True,
            validation={"valid": False, "issues": validation["issues"]},
        )
    record = validation["record"]

    # 4. Confirmation depth (INSUFFICIENT_CONFIRMATIONS → verdict 'pending').
    if resolved.num_confirmations < threshold:
        return base_report(
            "pending",
            block_time=resolved.block_time,
            block_slot=resolved.block_slot,
            num_confirmations=resolved.num_confirmations,
            metadata_present=True,
            record=record,
            validation={
                "valid": False,
                "issues": [
                    {
                        "path": [],
                        "code": "INSUFFICIENT_CONFIRMATIONS",
                        "message": f"{resolved.num_confirmations} < threshold {threshold}",
                    }
                ],
            },
        )

    validation_out: dict[str, Any] = {"valid": True}
    if validation.get("warnings"):
        validation_out["warnings"] = validation["warnings"]

    report = VerifyReport(
        tx_hash=input_.tx_hash,
        network=input_.network,
        num_confirmations=resolved.num_confirmations,
        confirmation_depth_threshold=threshold,
        block_time=resolved.block_time,
        block_slot=resolved.block_slot,
        metadata_present=True,
        validation=validation_out,
        record=record,
        http_calls=http_calls,
        verdict="valid",
    )

    # 5. Record-level signature verification (strict Ed25519, detached, AAD).
    if record.get("sigs"):
        report.record_signatures = _verify_record_signatures(record)
        # SIGNATURE_UNSUPPORTED is info severity and does NOT by itself fail a
        # public hash-only PoE. Any other invalid reason fails the record.
        hard_fail = any(
            not s.valid and s.reason != "SIGNATURE_UNSUPPORTED" for s in report.record_signatures
        )
        if hard_fail:
            report.verdict = "failed"

    # 7. Decryption (optional).
    if input_.decryption:
        report.item_decryptions = _try_decryptions(record, input_, fetch_fn)
        if any(not d.ok or d.plaintext_hash_ok is False for d in report.item_decryptions):
            report.verdict = "failed"

    # 8. Merkle list commitments (optional).
    if record.get("merkle"):
        report.merkle_checks = _check_merkle_commitments(record, input_, fetch_fn)
        if any(m.root_ok is False or m.reason is not None for m in report.merkle_checks):
            report.verdict = "failed"

    return report


__all__ = [
    "SIG_DOMAIN_RECORD_V1",
    "FetchOutboundResult",
    "PassphraseDecryption",
    "RecipientKeyDecryption",
    "VerifyReport",
    "VerifyTxInput",
    "verify_tx",
]
