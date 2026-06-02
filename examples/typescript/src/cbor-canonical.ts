// CIP-309 v1 reference implementation — Canonical CBOR encode/decode
// Spec: RFC 8949 §4.2.1 Core Deterministic Encoding Requirements
// - Preferred (shortest-form) integer/float encoding
// - Definite-length encoding for arrays and maps
// - No semantic tags (CIP-309 doesn't use them)
// - Map keys sorted in bytewise lexicographic order of their CBOR encoding (§4.2.1, NOT §4.2.3 length-first)
// - No duplicate keys in any map
// - UTF-8 for text strings
// - **No CBOR float major-type-7 (subtype 25/26/27) values anywhere.** The
//   CIP-309 v1 schema uses no floats — every numeric field (`v`, `enc.scheme`,
//   `merkle[i].leaf_count`, Argon2id params, recipient counts, chunk lengths)
//   is a CBOR unsigned integer.
//   The decoder rejects any float-encoded value as `MALFORMED_CBOR` so
//   integer-valued floats (e.g. `f9 3c 00` for 1.0) cannot slip past the
//   typed checks in the validator. cbor2 silently normalises such floats to
//   JS integers; this byte-level pre-walk catches them before that happens.

import {
  cdeDecodeOptions,
  cdeEncodeOptions,
  decode,
  encode,
} from 'cbor2';

export function encodeCanonicalCbor(value: unknown): Uint8Array {
  return encode(value, {
    ...cdeEncodeOptions,
    collapseBigInts: true,
    rejectDuplicateKeys: true,
  });
}

/**
 * Walk one CBOR data item at `bytes[pos]` and reject any float
 * (major type 7, additional info 25/26/27). Returns the position after the
 * item. Throws `RangeError("MALFORMED_CBOR: ...")` on any float or malformed
 * input.
 */
function rejectFloats(bytes: Uint8Array, pos: number): number {
  if (pos >= bytes.length) throw new RangeError('MALFORMED_CBOR: truncated input');
  const head = bytes[pos]!;
  const mt = head >> 5;
  const ai = head & 0x1f;
  pos += 1;

  if (mt === 7) {
    if (ai === 25 || ai === 26 || ai === 27) {
      throw new RangeError(
        `MALFORMED_CBOR: CBOR float encountered (major type 7, ai=${ai}); CIP-309 v1 schema uses no floats`,
      );
    }
    if (ai >= 28 && ai <= 30) {
      throw new RangeError(`MALFORMED_CBOR: reserved CBOR major-type-7 ai=${ai}`);
    }
    if (ai === 31) {
      throw new RangeError('MALFORMED_CBOR: indefinite-length break outside indefinite container');
    }
    if (ai === 24) return pos + 1; // 1-byte simple value
    return pos; // simple value 20-23 (false, true, null, undefined)
  }

  let size: number;
  if (ai < 24) {
    size = ai;
  } else if (ai === 24) {
    if (pos >= bytes.length) throw new RangeError('MALFORMED_CBOR: truncated 1-byte length');
    size = bytes[pos]!;
    pos += 1;
  } else if (ai === 25) {
    if (pos + 2 > bytes.length) throw new RangeError('MALFORMED_CBOR: truncated 2-byte length');
    size = (bytes[pos]! << 8) | bytes[pos + 1]!;
    pos += 2;
  } else if (ai === 26) {
    if (pos + 4 > bytes.length) throw new RangeError('MALFORMED_CBOR: truncated 4-byte length');
    size = bytes[pos]! * 0x1000000 + ((bytes[pos + 1]! << 16) | (bytes[pos + 2]! << 8) | bytes[pos + 3]!);
    pos += 4;
  } else if (ai === 27) {
    if (pos + 8 > bytes.length) throw new RangeError('MALFORMED_CBOR: truncated 8-byte length');
    let n = 0;
    for (let k = 0; k < 8; k++) n = n * 256 + bytes[pos + k]!;
    size = n;
    pos += 8;
  } else if (ai === 31) {
    throw new RangeError('MALFORMED_CBOR: indefinite-length encoding not allowed under canonical CBOR');
  } else {
    throw new RangeError(`MALFORMED_CBOR: reserved additional info ${ai}`);
  }

  if (mt === 0 || mt === 1) return pos;
  if (mt === 2 || mt === 3) return pos + size;
  if (mt === 4) {
    for (let k = 0; k < size; k++) pos = rejectFloats(bytes, pos);
    return pos;
  }
  if (mt === 5) {
    for (let k = 0; k < size * 2; k++) pos = rejectFloats(bytes, pos);
    return pos;
  }
  if (mt === 6) {
    // CIP-309 doesn't use semantic tags, but if one appears, walk its content
    // — the structural validator's "no tags" rule emits a typed error later.
    return rejectFloats(bytes, pos);
  }
  throw new RangeError(`MALFORMED_CBOR: unknown major type ${mt}`);
}

export function decodeCanonicalCbor(bytes: Uint8Array): unknown {
  // Pre-walk: reject any CBOR float at any position. cbor2's CDE decoder
  // silently normalises e.g. `f9 3c 00` (float16 1.0) to JS integer 1, which
  // would let a malformed record bypass the integer-strictness checks in the
  // structural validator (and creates a parity gap with Python where
  // `isinstance(1.0, int)` is False). Catching floats here keeps both impls
  // byte-identical in their accept/reject behaviour.
  rejectFloats(bytes, 0);
  return decode(bytes, {
    ...cdeDecodeOptions,
    rejectDuplicateKeys: true,
  });
}
