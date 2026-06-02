# CIP-309 v1 reference implementation — COSE_Sign1 encode/decode + Sig_structure.
# References: RFC 9052 (COSE), CIP-8 (Cardano message signing).

from typing import TypedDict

import cbor2

from .cbor_canonical import encode_canonical_cbor


class CoseSign1Decoded(TypedDict):
    protected_header: dict | None
    protected_bytes: bytes  # original encoding (h'' for empty header)
    unprotected_header: dict
    payload: bytes | None  # None for detached
    signature: bytes


def encode_cose_sign1(
    *,
    protected_header: dict,
    unprotected_header: dict,
    payload: bytes | None,
    signature: bytes,
) -> bytes:
    protected_bytes = b"" if not protected_header else encode_canonical_cbor(protected_header)
    return encode_canonical_cbor([protected_bytes, unprotected_header, payload, signature])


def decode_cose_sign1(data: bytes) -> CoseSign1Decoded:
    arr = cbor2.loads(data)
    if not isinstance(arr, list) or len(arr) != 4:
        raise ValueError("CoseMalformedError: expected 4-element array")
    protected_bytes, unprotected_header, payload, signature = arr
    protected_header = None if len(protected_bytes) == 0 else cbor2.loads(protected_bytes)
    return {
        "protected_header": protected_header,
        "protected_bytes": protected_bytes,
        "unprotected_header": unprotected_header,
        "payload": payload,
        "signature": signature,
    }


def build_sig_structure(
    *,
    context: str,
    body_protected_bytes: bytes,
    external_aad: bytes = b"",
    payload: bytes,
) -> bytes:
    """RFC 9052 §4.4: Sig_structure = [context, body_protected, external_aad, payload].

    The Sig_structure is canonical-CBOR-encoded (RFC 8949 §4.2.1) so producer
    and verifier agree bit-for-bit even if either side switches CBOR libraries.
    """
    return encode_canonical_cbor([context, body_protected_bytes, external_aad, payload])
