// Position-aware CBOR walker for CIP-309 verifiers.
// Spec: CIP-309 §4.9 (canonical CBOR), §7 (standalone verification).
//
// Extracts and reassembles the label-309 record body from a serialised
// Cardano transaction.
//
// Two transport-layer operations live here (CIP-309 §4.1 "Wire transport of the
// record body", CIP-309 §4.8):
//   1. sliceLabel309Value  — unwrap Conway auxiliary_data (CBOR tag 259) and
//      return the ORIGINAL on-chain bytes of the label-309 value VERBATIM.
//   2. reassembleRecordBody — byte-concatenate the ≤64-byte chunk array that
//      the value carries into the canonical-CBOR record body the validator
//      consumes. Chunk boundaries carry no semantic meaning.
//
// Why a stdlib walker (no cbor2 dependency)?
//   The whole point of this module is to return the ORIGINAL on-chain bytes
//   of the record body, not a re-encoded form. cbor2's decoder normalises
//   non-canonical input (sorts map keys, collapses indefinite-length, etc.);
//   re-encoding the decoded value would silently launder a non-conformant
//   on-chain record into a conformant one. The structural validator's
//   canonical-CBOR check (`decodeCanonicalCbor` + cbor2 CDE options) only
//   catches the violation if it sees the original bytes. Both functions below
//   return raw byte slices / concatenations — never a decode-then-re-encode —
//   so that guarantee holds end to end.
//
// Mirrors the byte-walker style of `cbor-canonical.ts:rejectFloats`. Pure
// stdlib, no third-party deps. Walker rejects indefinite-length encodings
// (CIP-309 §4.9 mandates definite-length); the structural validator's
// `decodeCanonicalCbor` performs the rest of the deterministic-encoding
// checks (preferred integer encoding, sorted map keys, no duplicate keys).

// -----------------------------------------------------------------------------
// Head reader
// -----------------------------------------------------------------------------

interface CborHead {
  /** Major type, 0..7 (RFC 8949 §3). */
  mt: number;
  /** Additional information, 0..27 (28-31 are rejected as reserved/indefinite). */
  ai: number;
  /** Position immediately after the head (and any inline length bytes). */
  payloadStart: number;
  /**
   * The unsigned value encoded in the head. Semantics depend on `mt`:
   *   - mt=0: the unsigned integer value
   *   - mt=1: the raw value n; the negative integer is `-1 - n`
   *   - mt=2,3: the byte/text-string length
   *   - mt=4: the array length
   *   - mt=5: the map length (number of key/value PAIRS)
   *   - mt=6: the tag number
   *   - mt=7: subtype (only `false`/`true`/`null`/`undefined`/`simple(0..23)`
   *           paths are exercised — floats are rejected by the structural
   *           validator's pre-walk; this walker accepts only ai<24 simple
   *           values and ai=24 1-byte simple values).
   * Cardano transaction bodies fit comfortably below 2^53; we use a JS
   * number throughout. The 8-byte length path (ai=27) accepts up to 2^53-1
   * and throws on anything larger (defence in depth — a real Cardano tx
   * never exceeds the protocol max-tx-size).
   */
  valueU64: number;
}

/**
 * Read the CBOR data-item head at `bytes[pos]`. Returns the decoded head plus
 * the position immediately after any inline length bytes (where the payload
 * begins for mt 2/3/4/5/6/7, or where the next item begins for mt 0/1).
 * Throws on indefinite-length encodings (ai=31), reserved ai (28-30), and
 * truncated input. Throws on 8-byte lengths that exceed `Number.MAX_SAFE_INTEGER`.
 */
export function readHead(bytes: Uint8Array, pos: number): CborHead {
  if (pos >= bytes.length) {
    throw new RangeError('MALFORMED_CBOR: truncated input (no head byte)');
  }
  const head = bytes[pos]!;
  const mt = head >> 5;
  const ai = head & 0x1f;
  let p = pos + 1;
  let valueU64: number;

  if (ai < 24) {
    valueU64 = ai;
  } else if (ai === 24) {
    if (p + 1 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 1-byte argument');
    }
    valueU64 = bytes[p]!;
    p += 1;
  } else if (ai === 25) {
    if (p + 2 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 2-byte argument');
    }
    valueU64 = (bytes[p]! << 8) | bytes[p + 1]!;
    p += 2;
  } else if (ai === 26) {
    if (p + 4 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 4-byte argument');
    }
    valueU64 =
      bytes[p]! * 0x1000000 + ((bytes[p + 1]! << 16) | (bytes[p + 2]! << 8) | bytes[p + 3]!);
    p += 4;
  } else if (ai === 27) {
    if (p + 8 > bytes.length) {
      throw new RangeError('MALFORMED_CBOR: truncated 8-byte argument');
    }
    let n = 0;
    for (let k = 0; k < 8; k++) n = n * 256 + bytes[p + k]!;
    if (n > Number.MAX_SAFE_INTEGER) {
      throw new RangeError('MALFORMED_CBOR: 8-byte argument exceeds JavaScript safe integer range');
    }
    valueU64 = n;
    p += 8;
  } else if (ai === 31) {
    throw new RangeError(
      'MALFORMED_CBOR: indefinite-length encoding (ai=31) not allowed under canonical CBOR (CIP-309 §4.9)',
    );
  } else {
    // ai 28..30 are reserved per RFC 8949 §3 Table 1.
    throw new RangeError(`MALFORMED_CBOR: reserved additional info ai=${ai}`);
  }

  return { mt, ai, payloadStart: p, valueU64 };
}

// -----------------------------------------------------------------------------
// Item skipper
// -----------------------------------------------------------------------------

/**
 * Return the byte position immediately AFTER the CBOR data item that starts
 * at `bytes[pos]`. Recurses through arrays, maps, and tags. Throws on
 * malformed input or any encoding feature this walker cannot represent
 * (indefinite-length, reserved ai, truncated input).
 */
export function skipCborItem(bytes: Uint8Array, pos: number): number {
  const h = readHead(bytes, pos);
  let p = h.payloadStart;
  switch (h.mt) {
    case 0: // unsigned int — head only
    case 1: // negative int — head only
      return p;
    case 2: // byte string — head + payload
    case 3: // text string — head + payload
      if (p + h.valueU64 > bytes.length) {
        throw new RangeError(
          `MALFORMED_CBOR: truncated ${h.mt === 2 ? 'byte' : 'text'} string payload`,
        );
      }
      return p + h.valueU64;
    case 4: // array — head + N items
      for (let i = 0; i < h.valueU64; i++) p = skipCborItem(bytes, p);
      return p;
    case 5: // map — head + N pairs (2N items)
      for (let i = 0; i < h.valueU64 * 2; i++) p = skipCborItem(bytes, p);
      return p;
    case 6: // tag — head + tagged content (one item)
      return skipCborItem(bytes, p);
    case 7: {
      // Simple values + floats. Floats are not expected inside Cardano tx
      // CBOR (the schema is bool/null only at major-7); we accept only
      // ai<24 simple values, ai=24 1-byte simple, and the three float widths
      // (ai=25/26/27). Float widths consume 2/4/8 bytes of payload.
      if (h.ai < 24) return p;
      if (h.ai === 24) {
        if (p + 1 > bytes.length) {
          throw new RangeError('MALFORMED_CBOR: truncated simple value');
        }
        return p + 1;
      }
      if (h.ai === 25) return p; // float16: payload already consumed by readHead
      if (h.ai === 26) return p; // float32: ditto
      if (h.ai === 27) return p; // float64: ditto
      throw new RangeError(`MALFORMED_CBOR: unsupported major-7 ai=${h.ai}`);
    }
    default:
      throw new RangeError(`MALFORMED_CBOR: unknown major type ${h.mt}`);
  }
}

// -----------------------------------------------------------------------------
// Label-309 byte-slice extractor
// -----------------------------------------------------------------------------

/** CBOR tag wrapping post-Alonzo Cardano auxiliary_data (CIP-29 / Conway). */
const CARDANO_AUX_DATA_TAG = 259;

/** Cardano metadata label this verifier targets. */
const POE_LABEL = 309;

/**
 * Extract the byte slice corresponding to the value under metadata label 309
 * in a serialised Cardano transaction.
 *
 * Cardano post-Conway tx CBOR is a 4-element array:
 *   [transaction_body, transaction_witness_set, is_valid, auxiliary_data]
 * where `auxiliary_data` is either a CBOR tag-259 wrapper around a map
 * (post-Alonzo) or a bare map (pre-Alonzo fallback). Inside the (un)tagged
 * map, key 0 is `metadata`, itself a map of integer label → value. We find
 * label 309's value and return the byte range it occupies in the input
 * VERBATIM — no re-encode pass.
 *
 * Returns `null` when:
 *   - auxiliary_data is `null` / `undefined` (no metadata at all), OR
 *   - auxiliary_data has no `metadata` map (key 0 absent), OR
 *   - the metadata map has no entry for label 309.
 *
 * Throws `RangeError("MALFORMED_CBOR: ...")` when the tx CBOR shape is
 * invalid (not a >=4-element array, malformed item structure, etc.).
 *
 * IMPORTANT: this function returns the ORIGINAL on-chain bytes. If those
 * bytes are non-canonical (unsorted map keys, non-preferred integer
 * encoding, indefinite-length, etc.), the structural validator MUST detect
 * the violation downstream — that is the whole point of byte-slice
 * extraction over decode-then-re-encode.
 */
export function sliceLabel309Value(txCbor: Uint8Array): Uint8Array | null {
  // Outer shape: array of >= 4 items.
  const txHead = readHead(txCbor, 0);
  if (txHead.mt !== 4) {
    throw new RangeError(`MALFORMED_CBOR: tx CBOR is not a CBOR array (major type ${txHead.mt})`);
  }
  if (txHead.valueU64 < 4) {
    throw new RangeError(
      `MALFORMED_CBOR: tx CBOR array has ${txHead.valueU64} elements; expected >= 4 (post-Conway: [body, witness_set, is_valid, auxiliary_data])`,
    );
  }

  // Skip body, witness_set, is_valid — the first three array elements.
  let pos = txHead.payloadStart;
  pos = skipCborItem(txCbor, pos); // body
  pos = skipCborItem(txCbor, pos); // witness_set
  pos = skipCborItem(txCbor, pos); // is_valid

  // auxiliary_data starts at `pos`. May be null, a tag-259 wrapper, or a bare map.
  if (pos >= txCbor.length) {
    throw new RangeError('MALFORMED_CBOR: truncated tx (auxiliary_data missing)');
  }
  const auxFirstByte = txCbor[pos]!;
  // CBOR null = 0xf6; CBOR undefined = 0xf7. Either indicates "no auxiliary data".
  if (auxFirstByte === 0xf6 || auxFirstByte === 0xf7) return null;

  let auxMapPos = pos;
  const auxHead = readHead(txCbor, pos);
  if (auxHead.mt === 6) {
    // Tagged auxiliary_data. CIP-29 / Alonzo+ uses tag 259; the bare-map
    // fallback (Mary and earlier) is also accepted per Cardano CDDL. Other
    // tag numbers are not legal at this position — reject.
    if (auxHead.valueU64 !== CARDANO_AUX_DATA_TAG) {
      throw new RangeError(
        `MALFORMED_CBOR: auxiliary_data carries unexpected CBOR tag ${auxHead.valueU64}; expected ${CARDANO_AUX_DATA_TAG} or bare map`,
      );
    }
    auxMapPos = auxHead.payloadStart;
  }

  // auxMapPos now points at the auxiliary_data map (post-tag if tagged).
  // Pre-Alonzo bare map: just metadata directly. Post-Alonzo tagged map:
  // { 0 => metadata, 1 => native_scripts, 2 => plutus_v1_scripts, ... }
  // — but pre-Alonzo emitted the metadata map at the tx position directly
  // (no key-0 wrapper). Disambiguate by inspecting the map: if it carries
  // any of the known structural keys (0/1/2/3), treat it as post-Alonzo;
  // otherwise treat the whole map as the metadata map (pre-Alonzo).
  //
  // For modern txs (Conway era and later, the only case this verifier
  // sees in production), the map is always tag-259-wrapped and key 0 is
  // metadata. We code the bare-map fallback for completeness — it is the
  // pre-Alonzo shape and will appear in historical-tx replays only.
  const mapHead = readHead(txCbor, auxMapPos);
  if (mapHead.mt !== 5) {
    throw new RangeError(
      `MALFORMED_CBOR: auxiliary_data is not a CBOR map (major type ${mapHead.mt})`,
    );
  }
  let entryPos = mapHead.payloadStart;
  let metadataMapPos: number | null = null;

  // For the tagged shape (post-Alonzo), find key 0 → metadata map.
  // For the bare shape (pre-Alonzo), the auxiliary_data MAP IS the metadata map directly.
  if (auxHead.mt === 6) {
    // Tagged: walk pairs to find integer key 0.
    for (let i = 0; i < mapHead.valueU64; i++) {
      const keyHead = readHead(txCbor, entryPos);
      const keyVal = decodeIntKey(keyHead);
      const valuePos = keyHead.payloadStart; // mt=0/1 have no payload
      if (keyVal === 0) {
        metadataMapPos = valuePos;
        break;
      }
      entryPos = skipCborItem(txCbor, entryPos); // skip key
      entryPos = skipCborItem(txCbor, entryPos); // skip value
    }
    if (metadataMapPos === null) return null;
  } else {
    // Bare-map fallback: the whole map IS the metadata map.
    metadataMapPos = auxMapPos;
  }

  // Walk the metadata map to find integer key 309.
  const metaHead = readHead(txCbor, metadataMapPos);
  if (metaHead.mt !== 5) {
    throw new RangeError(`MALFORMED_CBOR: metadata is not a CBOR map (major type ${metaHead.mt})`);
  }
  let pairPos = metaHead.payloadStart;
  for (let i = 0; i < metaHead.valueU64; i++) {
    const keyHead = readHead(txCbor, pairPos);
    const keyVal = decodeIntKey(keyHead);
    // After the key item, skipCborItem from `pairPos` lands on the value start.
    const valueStart = skipCborItem(txCbor, pairPos);
    const valueEnd = skipCborItem(txCbor, valueStart);
    if (keyVal === POE_LABEL) {
      return txCbor.slice(valueStart, valueEnd);
    }
    pairPos = valueEnd;
  }
  return null;
}

// -----------------------------------------------------------------------------
// Internal: integer key decoder (Cardano metadata keys are uints per CDDL)
// -----------------------------------------------------------------------------

function decodeIntKey(h: CborHead): number {
  if (h.mt === 0) return h.valueU64;
  if (h.mt === 1) return -1 - h.valueU64;
  throw new RangeError(
    `MALFORMED_CBOR: metadata map key has major type ${h.mt}; expected unsigned integer`,
  );
}

// -----------------------------------------------------------------------------
// Record-body reassembly
// -----------------------------------------------------------------------------

/**
 * Reassemble the CIP-309 record body from the verbatim label-309 value bytes
 * returned by `sliceLabel309Value`.
 *
 * The Cardano ledger caps every metadata byte string at 64 bytes, so the
 * canonical-CBOR record body is transported under label 309 as a CBOR array
 * of ≤ 64-byte byte strings (CIP-309 §4.1 "Wire transport of the record body",
 * CIP-309 §4.8). This function reconstructs the body:
 *
 *   - **Chunked-bytes array** (major type 4 of byte strings, the production
 *     shape): byte-concatenate the chunk contents in order. Chunk boundaries
 *     carry no semantic meaning; the returned bytes are the original
 *     canonical-CBOR record body. A non-byte-string array element is rejected
 *     as MALFORMED_CBOR.
 *   - **Single byte string** (a degenerate body that fits 64 bytes): its
 *     contents ARE the record body.
 *   - **Bare CBOR map** (legacy / degenerate records where the map sits
 *     directly under label 309): the value bytes ARE the body — passed through
 *     unchanged, no reassembly.
 *
 * The returned bytes are a raw slice / concatenation — never a
 * decode-then-re-encode — so the structural validator sees the exact on-chain
 * encoding (the canonical-CBOR check in CIP-309 §4.9 depends on this).
 */
export function reassembleRecordBody(value: Uint8Array): Uint8Array {
  const head = readHead(value, 0);

  // Bare map under the label (legacy / degenerate): the value IS the body.
  if (head.mt === 5) return value;

  // Single byte string: its contents are the body.
  if (head.mt === 2) {
    const end = head.payloadStart + head.valueU64;
    if (end > value.length) {
      throw new RangeError('MALFORMED_CBOR: truncated label-309 byte string');
    }
    return value.slice(head.payloadStart, end);
  }

  // Chunked-bytes array: concatenate each ≤64-byte byte-string element.
  if (head.mt === 4) {
    const chunks: Uint8Array[] = [];
    let total = 0;
    let pos = head.payloadStart;
    for (let i = 0; i < head.valueU64; i++) {
      const chunkHead = readHead(value, pos);
      if (chunkHead.mt !== 2) {
        throw new RangeError(
          `MALFORMED_CBOR: label-309 chunk array element has major type ${chunkHead.mt}; expected byte string`,
        );
      }
      const end = chunkHead.payloadStart + chunkHead.valueU64;
      if (end > value.length) {
        throw new RangeError('MALFORMED_CBOR: truncated label-309 chunk payload');
      }
      const chunk = value.slice(chunkHead.payloadStart, end);
      chunks.push(chunk);
      total += chunk.length;
      pos = end;
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    return body;
  }

  throw new RangeError(
    `MALFORMED_CBOR: label-309 value has major type ${head.mt}; expected a chunked-bytes array, a single byte string, or a bare map`,
  );
}
