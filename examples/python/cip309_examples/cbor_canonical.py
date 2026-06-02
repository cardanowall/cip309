# CIP-309 v1 reference implementation — Canonical CBOR encode/decode.
# Canonical form follows RFC 8949 §4.2.1 (NOT the §4.2.3 length-first ordering).
#
# The decoder rejects any CBOR float (major type 7, additional info 25/26/27)
# anywhere in the byte stream. The CIP-309 v1 schema uses no floats — every
# numeric field is a CBOR unsigned integer — so a float-encoded value
# (including integer-valued forms such as `f9 3c 00` for 1.0) is malformed
# and surfaces as `MALFORMED_CBOR`. Both the TypeScript and Python reference
# impls share this rule for byte-identical accept/reject behaviour on every
# input, canonical or otherwise.

import cbor2


def encode_canonical_cbor(value: object) -> bytes:
    # cbor2's canonical=True implements RFC 8949 §4.2.1: shortest-form integers,
    # definite-length encoding, bytewise lex-sorted map keys, no duplicates.
    return cbor2.dumps(value, canonical=True)


def _reject_floats(data: bytes, pos: int) -> int:
    """Walk one CBOR data item starting at `pos`. Returns the position after
    the item. Raises ValueError on any float (major type 7, ai 25/26/27),
    indefinite-length encoding, or truncated input."""
    if pos >= len(data):
        raise ValueError("MALFORMED_CBOR: truncated input")
    head = data[pos]
    mt = head >> 5
    ai = head & 0x1F
    pos += 1

    if mt == 7:
        if ai in (25, 26, 27):
            raise ValueError(
                f"MALFORMED_CBOR: CBOR float encountered (major type 7, ai={ai}); "
                "CIP-309 v1 schema uses no floats"
            )
        if 28 <= ai <= 30:
            raise ValueError(f"MALFORMED_CBOR: reserved CBOR major-type-7 ai={ai}")
        if ai == 31:
            raise ValueError("MALFORMED_CBOR: indefinite-length break outside indefinite container")
        if ai == 24:
            return pos + 1  # 1-byte simple value
        return pos  # simple value 20-23 (false, true, null, undefined)

    if ai < 24:
        size = ai
    elif ai == 24:
        if pos + 1 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 1-byte length")
        size = data[pos]
        pos += 1
    elif ai == 25:
        if pos + 2 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 2-byte length")
        size = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
    elif ai == 26:
        if pos + 4 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 4-byte length")
        size = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
    elif ai == 27:
        if pos + 8 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 8-byte length")
        size = int.from_bytes(data[pos : pos + 8], "big")
        pos += 8
    elif ai == 31:
        raise ValueError(
            "MALFORMED_CBOR: indefinite-length encoding not allowed under canonical CBOR"
        )
    else:
        raise ValueError(f"MALFORMED_CBOR: reserved additional info {ai}")

    if mt in (0, 1):
        return pos
    if mt in (2, 3):
        return pos + size
    if mt == 4:
        for _ in range(size):
            pos = _reject_floats(data, pos)
        return pos
    if mt == 5:
        for _ in range(size * 2):
            pos = _reject_floats(data, pos)
        return pos
    if mt == 6:
        # CIP-309 doesn't use semantic tags; if one appears, walk its content
        # — the structural validator's "no tags" rule emits a typed error later.
        return _reject_floats(data, pos)
    raise ValueError(f"MALFORMED_CBOR: unknown major type {mt}")


def decode_canonical_cbor(data: bytes) -> object:
    # Pre-walk: reject any CBOR float at any position. Without this, an input
    # encoding e.g. `v` as `f9 3c 00` (float16 1.0) decodes to a Python float
    # 1.0; the validator's `isinstance(int)` check would catch it on the
    # Python side, but the TypeScript side's cbor2 silently normalises it to
    # a JS integer 1 and the float would slip past every typed check. Catching
    # it here keeps both impls byte-identical in accept/reject behaviour.
    _reject_floats(data, 0)
    # cbor2 raises on duplicate keys by default in strict mode.
    return cbor2.loads(data)
