# Label 309 v1 reference implementation — IPFS CID structural validator.
# Governs the `ipfs://<cid>` shape rules for PoE storage URIs.
#
# Per the CID multiformats spec (https://github.com/multiformats/cid),
# conformant Label 309 validators MUST parse the CID — multibase decode →
# version byte → codec varint → multihash (hash-function code varint +
# length varint + digest) — and reject malformed input with INVALID_URI
# (reason `ipfs_cid_invalid`). A regex-only shape check is insufficient
# because IPFS's self-authentication property (the URI itself binds the
# bytes via the multihash) is enforceable only through full CID parsing.
#
# Both forms MUST be accepted:
#   - CIDv0: `Qm` prefix, exactly 46 base58btc chars, decodes to 34 bytes
#     starting with 0x12 0x20 (sha2-256 multihash, length 32).
#   - CIDv1: multibase prefix character + base-decoded payload
#     [version=0x01 || codec_varint || multihash_code_varint
#      || multihash_length_varint || digest].
#
# Pure stdlib — no external CID/multihash/multibase library, to keep the
# reference implementation dependency-free and auditable.

from __future__ import annotations

# === Recognised codecs (subset; rejection-by-allowlist) ===
# Per multicodec table; PoE realistically uses raw / dag-pb / dag-cbor.
RECOGNISED_CIDV1_CODECS: set[int] = {0x55, 0x70, 0x71}  # raw, dag-pb, dag-cbor

# === Recognised multihash codes → digest length (bytes) ===
# 0x12 = sha2-256 (length 32); 0xb220 = blake2b-256 (length 32); both 32-byte.
# Multihash codes are themselves varint-encoded inside the CID payload, so a
# blake2b-256 entry on the wire reads as varint(0xb220) → bytes 0xa0 0xe4 0x02.
RECOGNISED_MULTIHASH: dict[int, int] = {
    0x12: 32,  # sha2-256
    0xB220: 32,  # blake2b-256
}

# === Base58btc alphabet (Bitcoin variant) ===
_B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHA)}

# === Base32 alphabet (RFC 4648 §6, lowercase per multibase 'b'; uppercase per 'B') ===
_B32_ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz234567"
_B32_INDEX_LOWER = {c: i for i, c in enumerate(_B32_ALPHA_LOWER)}
_B32_ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_INDEX_UPPER = {c: i for i, c in enumerate(_B32_ALPHA_UPPER)}


def _b58_decode(s: str) -> bytes | None:
    """Decode base58btc. Returns None on invalid input."""
    if not s:
        return None
    n = 0
    for ch in s:
        v = _B58_INDEX.get(ch)
        if v is None:
            return None
        n = n * 58 + v
    # Convert big-int to bytes
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    # Each leading '1' encodes a leading zero byte
    leading = 0
    for ch in s:
        if ch == "1":
            leading += 1
        else:
            break
    return b"\x00" * leading + body


def _b32_decode_no_pad(s: str, alpha_index: dict[str, int]) -> bytes | None:
    """Decode RFC 4648 base32 (no padding required, multibase form)."""
    if not s:
        return b""
    bits = 0
    buffer = 0
    out = bytearray()
    for ch in s:
        v = alpha_index.get(ch)
        if v is None:
            return None
        buffer = (buffer << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    # Trailing bits are 0-padding from the encoder; ignore (must be < 8)
    return bytes(out)


def _b16_decode(s: str, *, upper: bool) -> bytes | None:
    """Decode base16 (hex). Multibase 'f' = lowercase, 'F' = uppercase."""
    if len(s) % 2 != 0:
        return None
    try:
        if upper:
            if any(c not in "0123456789ABCDEF" for c in s):
                return None
        else:
            if any(c not in "0123456789abcdef" for c in s):
                return None
        return bytes.fromhex(s)
    except ValueError:
        return None


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    """Read a multiformats unsigned varint starting at `offset`.

    Returns (value, bytes_consumed) on success, None on truncation/overflow.
    Caps at 9 bytes (multiformats spec ceiling) to prevent unbounded input.
    """
    value = 0
    shift = 0
    consumed = 0
    while consumed < 9:
        if offset + consumed >= len(data):
            return None
        b = data[offset + consumed]
        value |= (b & 0x7F) << shift
        consumed += 1
        if (b & 0x80) == 0:
            return (value, consumed)
        shift += 7
    return None  # varint too long


def _is_valid_cidv0(s: str) -> bool:
    """CIDv0: 46-char base58btc, decodes to 34 bytes [0x12, 0x20, <32-B digest>]."""
    if len(s) != 46 or not s.startswith("Qm"):
        return False
    decoded = _b58_decode(s)
    if decoded is None or len(decoded) != 34:
        return False
    return decoded[0] == 0x12 and decoded[1] == 0x20


def _is_valid_cidv1(s: str) -> bool:
    """CIDv1: multibase prefix + base-decoded [0x01, codec_varint, multihash]."""
    if len(s) < 2:
        return False
    prefix = s[0]
    rest = s[1:]
    if prefix == "b":
        payload = _b32_decode_no_pad(rest, _B32_INDEX_LOWER)
    elif prefix == "B":
        payload = _b32_decode_no_pad(rest, _B32_INDEX_UPPER)
    elif prefix == "f":
        payload = _b16_decode(rest, upper=False)
    elif prefix == "F":
        payload = _b16_decode(rest, upper=True)
    elif prefix == "z":
        payload = _b58_decode(rest)
    else:
        # 'm' (base64) / 'M' (base64url-upper) / other bases not in the v1 fetch
        # set — explicitly reject. base32 and base58btc are the operationally
        # common forms; producers writing other bases SHOULD re-encode.
        return False
    if payload is None or len(payload) < 2:
        return False
    if payload[0] != 0x01:  # version byte
        return False
    # Read codec varint
    cv = _read_varint(payload, 1)
    if cv is None:
        return False
    codec, codec_len = cv
    if codec not in RECOGNISED_CIDV1_CODECS:
        return False
    # Read multihash code varint
    mh_off = 1 + codec_len
    mc = _read_varint(payload, mh_off)
    if mc is None:
        return False
    mh_code, mh_code_len = mc
    if mh_code not in RECOGNISED_MULTIHASH:
        return False
    expected_digest_len = RECOGNISED_MULTIHASH[mh_code]
    # Read multihash length varint
    ml = _read_varint(payload, mh_off + mh_code_len)
    if ml is None:
        return False
    mh_len, mh_len_len = ml
    if mh_len != expected_digest_len:
        return False
    # Confirm digest is exactly the right number of trailing bytes
    digest_off = mh_off + mh_code_len + mh_len_len
    return len(payload) - digest_off == mh_len


def is_valid_cid(s: str) -> bool:
    """Return True iff `s` is a structurally valid IPFS CID (v0 or v1)."""
    if not s:
        return False
    # CIDv0 short-circuit (`Qm` prefix is unambiguous; CIDv1 multibase
    # prefixes never start with 'Q').
    if s.startswith("Qm"):
        return _is_valid_cidv0(s)
    return _is_valid_cidv1(s)


__all__ = ["is_valid_cid"]


# ---------------------------------------------------------------------------
# Self-tests (run: python -m label309_examples.cid_validator)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # CIDv0 fixture: well-known IPFS empty-directory CID
    CIDV0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    assert is_valid_cid(CIDV0), "CIDv0 should validate"
    # CIDv1 base32 (lowercase 'b' prefix, raw codec, sha2-256 multihash)
    CIDV1 = "bafkreigh2akiscaildc6mn7vmrk5xkucb6w5dfgo7tukbmpzxoa64yjebq"
    assert is_valid_cid(CIDV1), "CIDv1 base32 should validate"

    # Negative cases
    assert not is_valid_cid(""), "empty string"
    assert not is_valid_cid("Qm"), "too-short Qm prefix"
    assert not is_valid_cid("Qm" + "1" * 44), "wrong length Qm-prefix"
    # Wrong base58 alphabet ('0' not in alphabet)
    assert not is_valid_cid("Qm0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "invalid b58 char"
    # Garbage CIDv1
    assert not is_valid_cid("babcdefg"), "invalid CIDv1 base32 payload"
    # CIDv1 with unknown multibase prefix (base64url-upper M is allowed by some
    # decoders but not in this validator's accept-list)
    assert not is_valid_cid("Mxxx"), "unrecognised multibase prefix"

    print("cid_validator self-tests OK")
