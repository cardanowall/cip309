# Label 309 v1 reference implementation — position-aware CBOR walker.
# Extracts and reassembles the label-309 record body from a serialised Cardano
# transaction without ever decode-then-re-encoding.
#
# Two transport-layer operations live here:
#   1. slice_label309_value  — unwrap Conway auxiliary_data (CBOR tag 259) and
#      return the ORIGINAL on-chain bytes of the label-309 value VERBATIM.
#   2. reassemble_record_body — byte-concatenate the ≤64-byte chunk array that
#      the value carries into the canonical-CBOR record body the validator
#      consumes. Chunk boundaries carry no semantic meaning.
#
# Why a stdlib walker (no cbor2 dependency)?
#   The whole point of this module is to return the ORIGINAL on-chain bytes of
#   the record body, not a re-encoded form. cbor2's decoder normalises
#   non-canonical input (sorts map keys, collapses indefinite-length, etc.);
#   re-encoding the decoded value would silently launder a non-conformant
#   on-chain record into a conformant one. The structural validator's
#   canonical-CBOR check only catches the violation if it sees the original
#   bytes. Both functions below return raw byte slices / concatenations — never
#   a decode-then-re-encode — so that guarantee holds end to end.
#
# The walker rejects indefinite-length encodings (Label 309 mandates
# definite-length); the structural validator's canonical-CBOR decode performs
# the rest of the deterministic-encoding checks (preferred integer encoding,
# sorted map keys, no duplicate keys).

from __future__ import annotations

from dataclasses import dataclass

# -----------------------------------------------------------------------------
# Head reader
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CborHead:
    """Decoded CBOR data-item head (RFC 8949 §3)."""

    mt: int  # major type, 0..7
    ai: int  # additional information, 0..27 (28-31 rejected)
    payload_start: int  # position immediately after the head and inline length
    value_u64: int  # the unsigned value encoded in the head (semantics per mt)


def read_head(data: bytes, pos: int) -> CborHead:
    """Read the CBOR data-item head at `data[pos]`. Returns the decoded head plus
    the position immediately after any inline length bytes.

    Raises ValueError on indefinite-length encodings (ai=31), reserved ai
    (28-30), and truncated input.
    """
    if pos >= len(data):
        raise ValueError("MALFORMED_CBOR: truncated input (no head byte)")
    head = data[pos]
    mt = head >> 5
    ai = head & 0x1F
    p = pos + 1

    if ai < 24:
        value_u64 = ai
    elif ai == 24:
        if p + 1 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 1-byte argument")
        value_u64 = data[p]
        p += 1
    elif ai == 25:
        if p + 2 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 2-byte argument")
        value_u64 = int.from_bytes(data[p : p + 2], "big")
        p += 2
    elif ai == 26:
        if p + 4 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 4-byte argument")
        value_u64 = int.from_bytes(data[p : p + 4], "big")
        p += 4
    elif ai == 27:
        if p + 8 > len(data):
            raise ValueError("MALFORMED_CBOR: truncated 8-byte argument")
        value_u64 = int.from_bytes(data[p : p + 8], "big")
        p += 8
    elif ai == 31:
        raise ValueError(
            "MALFORMED_CBOR: indefinite-length encoding (ai=31) not allowed under canonical CBOR"
        )
    else:
        # ai 28..30 are reserved per RFC 8949 §3 Table 1.
        raise ValueError(f"MALFORMED_CBOR: reserved additional info ai={ai}")

    return CborHead(mt=mt, ai=ai, payload_start=p, value_u64=value_u64)


# -----------------------------------------------------------------------------
# Item skipper
# -----------------------------------------------------------------------------


def skip_cbor_item(data: bytes, pos: int) -> int:
    """Return the byte position immediately AFTER the CBOR data item that starts
    at `data[pos]`. Recurses through arrays, maps, and tags. Raises ValueError
    on malformed input or any encoding feature this walker cannot represent
    (indefinite-length, reserved ai, truncated input).
    """
    h = read_head(data, pos)
    p = h.payload_start
    if h.mt in (0, 1):  # unsigned / negative int — head only
        return p
    if h.mt in (2, 3):  # byte / text string — head + payload
        if p + h.value_u64 > len(data):
            kind = "byte" if h.mt == 2 else "text"
            raise ValueError(f"MALFORMED_CBOR: truncated {kind} string payload")
        return p + h.value_u64
    if h.mt == 4:  # array — head + N items
        for _ in range(h.value_u64):
            p = skip_cbor_item(data, p)
        return p
    if h.mt == 5:  # map — head + N pairs (2N items)
        for _ in range(h.value_u64 * 2):
            p = skip_cbor_item(data, p)
        return p
    if h.mt == 6:  # tag — head + tagged content (one item)
        return skip_cbor_item(data, p)
    if h.mt == 7:
        # Simple values. Floats are not expected inside Cardano tx CBOR; the
        # payload (if any) was already consumed by read_head.
        if h.ai < 24:
            return p
        if h.ai == 24:
            if p + 1 > len(data):
                raise ValueError("MALFORMED_CBOR: truncated simple value")
            return p + 1
        if h.ai in (25, 26, 27):
            return p  # float widths: payload already consumed by read_head
        raise ValueError(f"MALFORMED_CBOR: unsupported major-7 ai={h.ai}")
    raise ValueError(f"MALFORMED_CBOR: unknown major type {h.mt}")


# -----------------------------------------------------------------------------
# Label-309 byte-slice extractor
# -----------------------------------------------------------------------------

# CBOR tag wrapping post-Alonzo Cardano auxiliary_data (Conway).
CARDANO_AUX_DATA_TAG = 259

# Cardano metadata label this verifier targets.
POE_LABEL = 309


def _decode_int_key(h: CborHead) -> int:
    if h.mt == 0:
        return h.value_u64
    if h.mt == 1:
        return -1 - h.value_u64
    raise ValueError(
        f"MALFORMED_CBOR: metadata map key has major type {h.mt}; expected unsigned integer"
    )


def slice_label309_value(tx_cbor: bytes) -> bytes | None:
    """Extract the byte slice corresponding to the value under metadata label 309
    in a serialised Cardano transaction.

    Cardano post-Conway tx CBOR is a 4-element array:
      [transaction_body, transaction_witness_set, is_valid, auxiliary_data]
    where `auxiliary_data` is either a CBOR tag-259 wrapper around a map
    (post-Alonzo) or a bare map (pre-Alonzo fallback). Inside the (un)tagged
    map, key 0 is `metadata`, itself a map of integer label → value. We find
    label 309's value and return the byte range it occupies in the input
    VERBATIM — no re-encode pass.

    Returns `None` when auxiliary_data is null, has no `metadata` map, or the
    metadata map has no entry for label 309. Raises ValueError when the tx CBOR
    shape is invalid.
    """
    tx_head = read_head(tx_cbor, 0)
    if tx_head.mt != 4:
        raise ValueError(f"MALFORMED_CBOR: tx CBOR is not a CBOR array (major type {tx_head.mt})")
    if tx_head.value_u64 < 4:
        raise ValueError(
            f"MALFORMED_CBOR: tx CBOR array has {tx_head.value_u64} elements; expected >= 4 "
            "(post-Conway: [body, witness_set, is_valid, auxiliary_data])"
        )

    # Skip body, witness_set, is_valid — the first three array elements.
    pos = tx_head.payload_start
    pos = skip_cbor_item(tx_cbor, pos)  # body
    pos = skip_cbor_item(tx_cbor, pos)  # witness_set
    pos = skip_cbor_item(tx_cbor, pos)  # is_valid

    # auxiliary_data starts at `pos`. May be null, a tag-259 wrapper, or a bare map.
    if pos >= len(tx_cbor):
        raise ValueError("MALFORMED_CBOR: truncated tx (auxiliary_data missing)")
    aux_first_byte = tx_cbor[pos]
    # CBOR null = 0xf6; CBOR undefined = 0xf7. Either means "no auxiliary data".
    if aux_first_byte in (0xF6, 0xF7):
        return None

    aux_map_pos = pos
    aux_head = read_head(tx_cbor, pos)
    if aux_head.mt == 6:
        # Tagged auxiliary_data. Alonzo+ uses tag 259; the bare-map fallback
        # (Mary and earlier) is also accepted. Other tag numbers are not legal
        # at this position — reject.
        if aux_head.value_u64 != CARDANO_AUX_DATA_TAG:
            raise ValueError(
                f"MALFORMED_CBOR: auxiliary_data carries unexpected CBOR tag {aux_head.value_u64}; "
                f"expected {CARDANO_AUX_DATA_TAG} or bare map"
            )
        aux_map_pos = aux_head.payload_start

    # aux_map_pos now points at the auxiliary_data map (post-tag if tagged).
    # Post-Alonzo tagged map: { 0 => metadata, 1 => native_scripts, ... }.
    # Pre-Alonzo bare map: just metadata directly.
    map_head = read_head(tx_cbor, aux_map_pos)
    if map_head.mt != 5:
        raise ValueError(
            f"MALFORMED_CBOR: auxiliary_data is not a CBOR map (major type {map_head.mt})"
        )
    entry_pos = map_head.payload_start
    metadata_map_pos: int | None = None

    if aux_head.mt == 6:
        # Tagged: walk pairs to find integer key 0.
        for _ in range(map_head.value_u64):
            key_head = read_head(tx_cbor, entry_pos)
            key_val = _decode_int_key(key_head)
            value_pos = key_head.payload_start  # mt=0/1 have no payload
            if key_val == 0:
                metadata_map_pos = value_pos
                break
            entry_pos = skip_cbor_item(tx_cbor, entry_pos)  # skip key
            entry_pos = skip_cbor_item(tx_cbor, entry_pos)  # skip value
        if metadata_map_pos is None:
            return None
    else:
        # Bare-map fallback: the whole map IS the metadata map.
        metadata_map_pos = aux_map_pos

    # Walk the metadata map to find integer key 309.
    meta_head = read_head(tx_cbor, metadata_map_pos)
    if meta_head.mt != 5:
        raise ValueError(f"MALFORMED_CBOR: metadata is not a CBOR map (major type {meta_head.mt})")
    pair_pos = meta_head.payload_start
    for _ in range(meta_head.value_u64):
        key_head = read_head(tx_cbor, pair_pos)
        key_val = _decode_int_key(key_head)
        # After the key item, skip_cbor_item from `pair_pos` lands on the value start.
        value_start = skip_cbor_item(tx_cbor, pair_pos)
        value_end = skip_cbor_item(tx_cbor, value_start)
        if key_val == POE_LABEL:
            return tx_cbor[value_start:value_end]
        pair_pos = value_end
    return None


# -----------------------------------------------------------------------------
# Record-body reassembly
# -----------------------------------------------------------------------------


def reassemble_record_body(value: bytes) -> bytes:
    """Reassemble the Label 309 record body from the verbatim label-309 value bytes
    returned by `slice_label309_value`.

    The Cardano ledger caps every metadata byte string at 64 bytes, so the
    canonical-CBOR record body is transported under label 309 as a CBOR array of
    ≤ 64-byte byte strings. This function reconstructs the body:

      - **Chunked-bytes array** (major type 4 of byte strings, the production
        shape): byte-concatenate the chunk contents in order. Chunk boundaries
        carry no semantic meaning. A non-byte-string array element is rejected
        as MALFORMED_CBOR.
      - **Single byte string** (a degenerate body that fits 64 bytes): its
        contents ARE the record body.
      - **Bare CBOR map** (legacy / degenerate records where the map sits
        directly under label 309): the value bytes ARE the body — passed through
        unchanged, no reassembly.

    The returned bytes are a raw slice / concatenation — never a
    decode-then-re-encode — so the structural validator sees the exact on-chain
    encoding.
    """
    head = read_head(value, 0)

    # Bare map under the label (legacy / degenerate): the value IS the body.
    if head.mt == 5:
        return value

    # Single byte string: its contents are the body.
    if head.mt == 2:
        end = head.payload_start + head.value_u64
        if end > len(value):
            raise ValueError("MALFORMED_CBOR: truncated label-309 byte string")
        return value[head.payload_start : end]

    # Chunked-bytes array: concatenate each ≤64-byte byte-string element.
    if head.mt == 4:
        chunks: list[bytes] = []
        pos = head.payload_start
        for _ in range(head.value_u64):
            chunk_head = read_head(value, pos)
            if chunk_head.mt != 2:
                raise ValueError(
                    f"MALFORMED_CBOR: label-309 chunk array element has major type {chunk_head.mt}; "
                    "expected byte string"
                )
            end = chunk_head.payload_start + chunk_head.value_u64
            if end > len(value):
                raise ValueError("MALFORMED_CBOR: truncated label-309 chunk payload")
            chunks.append(value[chunk_head.payload_start : end])
            pos = end
        return b"".join(chunks)

    raise ValueError(
        f"MALFORMED_CBOR: label-309 value has major type {head.mt}; "
        "expected a chunked-bytes array, a single byte string, or a bare map"
    )


__all__ = [
    "CARDANO_AUX_DATA_TAG",
    "POE_LABEL",
    "CborHead",
    "read_head",
    "reassemble_record_body",
    "skip_cbor_item",
    "slice_label309_value",
]
