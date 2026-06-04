// Label 309 v1 — byte-slice extraction smoke test
// Spec: Label 309 §4.9 (canonical CBOR), §7 (standalone verification).
//
// Validates `sliceLabel309Value` from `cbor-walker.ts`:
//   (a) canonical tx CBOR        → byte-identical record returned
//   (b) NON-canonical label-309  → returned unmodified; downstream validator
//                                  flags MALFORMED_CBOR (proves we don't launder)
//   (c) tag-259 wrapper vs bare-map auxiliary_data — both extract correctly
//   (d) metadata without label 309 → null
//
// Run: `npx tsx src/smoke-tx-extract.ts` (exits non-zero on any failure).

import { sha256 } from '@noble/hashes/sha2.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { sliceLabel309Value } from './cbor-walker.ts';
import { validatePoeRecord } from './label-309-validator.ts';

// === Helpers ===

const enc = new TextEncoder();

function hex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u8(...bytes: number[]): Uint8Array {
  return Uint8Array.from(bytes);
}

const failures: string[] = [];
function record(label: string, pass: boolean, detail: string): void {
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${label}: ${detail}`);
  if (!pass) failures.push(label);
}

// === Hand-rolled CBOR helpers (definite-length only) ===
//
// We deliberately bypass cbor2 for the OUTER tx wrapper so we can:
//   (1) place the label-309 value bytes at a known offset and prove byte-slice
//       extraction is positional (not "decode → look up → re-encode"),
//   (2) construct a NON-canonical inner record (test b) without the encoder
//       silently sorting the map keys.

/** CBOR uint head + payload (definite-length, preferred-shortest). */
function cborUint(n: number): Uint8Array {
  if (n < 24) return u8(n);
  if (n < 0x100) return u8(0x18, n);
  if (n < 0x10000) return u8(0x19, (n >> 8) & 0xff, n & 0xff);
  if (n < 0x100000000) {
    return u8(0x1a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }
  throw new Error(`uint ${n} too large for this helper`);
}

function cborHead(mt: number, n: number): Uint8Array {
  const u = cborUint(n);
  // Tweak the major-type bits in the first byte.
  const head = (mt << 5) | (u[0]! & 0x1f);
  const out = new Uint8Array(u.length);
  out[0] = head;
  out.set(u.subarray(1), 1);
  return out;
}

function cborArray(items: Uint8Array[]): Uint8Array {
  return concat(cborHead(4, items.length), ...items);
}

function cborMap(pairs: Array<[Uint8Array, Uint8Array]>): Uint8Array {
  const flat: Uint8Array[] = [];
  for (const [k, v] of pairs) {
    flat.push(k);
    flat.push(v);
  }
  return concat(cborHead(5, pairs.length), ...flat);
}

function cborTag(tag: number, body: Uint8Array): Uint8Array {
  return concat(cborHead(6, tag), body);
}

function cborTstr(s: string): Uint8Array {
  const b = enc.encode(s);
  return concat(cborHead(3, b.length), b);
}

function cborBstr(b: Uint8Array): Uint8Array {
  return concat(cborHead(2, b.length), b);
}

function cborBool(v: boolean): Uint8Array {
  return u8(v ? 0xf5 : 0xf4);
}

const CBOR_NULL = u8(0xf6);

/** Build a tx CBOR with a placeholder body/witness_set, given is_valid +
 *  auxiliary_data bytes. The body and witness_set are deliberately tiny but
 *  validly shaped maps — we only care that `sliceLabel309Value` skips them
 *  correctly. */
function buildTx(auxData: Uint8Array): Uint8Array {
  const body = cborMap([]); // empty map
  const witnessSet = cborMap([]); // empty map
  const isValid = cborBool(true);
  return cborArray([body, witnessSet, isValid, auxData]);
}

// === (a) Canonical tx with label-309 record → byte-identical extraction ===

function checkA(): void {
  const digest = sha256(enc.encode('extract-fixture-a'));
  const recordBytes = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': digest } }],
  });
  // auxiliary_data: tag(259, { 0: { 309: <record> } })
  const metadataMap = cborMap([[cborUint(309), recordBytes]]);
  const auxMap = cborMap([[cborUint(0), metadataMap]]);
  const auxData = cborTag(259, auxMap);
  const tx = buildTx(auxData);

  const extracted = sliceLabel309Value(tx);
  if (extracted === null) {
    record('(a) canonical tx → byte-identical extraction', false, 'extractor returned null');
    return;
  }
  const same = bytesEqual(extracted, recordBytes);
  record(
    '(a) canonical tx → byte-identical extraction',
    same,
    same
      ? `${extracted.length}B identical to encoded record`
      : `lengths got=${extracted.length} expected=${recordBytes.length}; got=${hex(extracted)} expected=${hex(recordBytes)}`,
  );

  // Also confirm the validator accepts it.
  const v = validatePoeRecord(extracted);
  record(
    '(a) extracted bytes pass structural validation',
    v.valid,
    v.valid ? 'valid=true' : `valid=false issues=${v.issues.map((i) => i.code).join(',')}`,
  );
}

// === (b) Non-canonical label-309 value → returned unmodified, validator flags MALFORMED_CBOR ===

function checkB(): void {
  // Hand-roll a minimal Label 309 record with the OUTER MAP KEYS in NON-canonical
  // order. Canonical (RFC 8949 §4.2.1 bytewise) order for tstr keys "v" and
  // "items" is: "v" (61 76) < "items" (65 69 74 65 6d 73) — RFC 8949 §4.2.1
  // is strict bytewise of the entire CBOR encoding, so the shorter encoding
  // always wins because the head byte differs first (`61` < `65`).
  // Below we deliberately emit "items" before "v" — a clear violation that
  // cbor2's CDE decoder MUST reject.
  const digest = sha256(enc.encode('extract-fixture-b'));
  const itemsArr = cborArray([
    cborMap([[cborTstr('hashes'), cborMap([[cborTstr('sha2-256'), cborBstr(digest)]])]]),
  ]);
  const nonCanonRecord = cborMap([
    [cborTstr('items'), itemsArr], //   <-- emitted FIRST (wrong)
    [cborTstr('v'), cborUint(1)], //   <-- should have come first
  ]);

  const metadataMap = cborMap([[cborUint(309), nonCanonRecord]]);
  const auxMap = cborMap([[cborUint(0), metadataMap]]);
  const auxData = cborTag(259, auxMap);
  const tx = buildTx(auxData);

  const extracted = sliceLabel309Value(tx);
  if (extracted === null) {
    record('(b) non-canonical record → unmodified extraction', false, 'extractor returned null');
    return;
  }
  // The walker MUST return the byte slice verbatim — i.e., the same `nonCanonRecord` bytes.
  const sameAsInput = bytesEqual(extracted, nonCanonRecord);
  record(
    '(b) non-canonical record → unmodified extraction (no laundering)',
    sameAsInput,
    sameAsInput
      ? `${extracted.length}B byte-identical to non-canonical input`
      : `MISMATCH — laundered? got=${hex(extracted)} expected=${hex(nonCanonRecord)}`,
  );

  // The structural validator MUST flag this as MALFORMED_CBOR (cbor2 CDE rejects
  // out-of-order map keys). If the laundering bug were present, this would
  // succeed silently — exactly the failure mode the byte-slice fix prevents.
  const v = validatePoeRecord(extracted);
  const flaggedMalformed = !v.valid && v.issues.some((i) => i.code === 'MALFORMED_CBOR');
  record(
    '(b) validator on non-canonical bytes → MALFORMED_CBOR',
    flaggedMalformed,
    v.valid
      ? 'BUG: validator accepted non-canonical input (laundering not caught)'
      : `valid=false codes=${v.issues.map((i) => i.code).join(',')}`,
  );
}

// === (c) Tag-259 wrapper vs bare-map auxiliary_data — both extract correctly ===

function checkC(): void {
  const digest = sha256(enc.encode('extract-fixture-c'));
  const recordBytes = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': digest } }],
  });

  // (c.1) Tagged shape: tag(259, { 0: { 309: <record> } })
  {
    const metadataMap = cborMap([[cborUint(309), recordBytes]]);
    const auxMap = cborMap([[cborUint(0), metadataMap]]);
    const auxData = cborTag(259, auxMap);
    const tx = buildTx(auxData);
    const extracted = sliceLabel309Value(tx);
    const ok = extracted !== null && bytesEqual(extracted, recordBytes);
    record(
      '(c.1) tag-259 wrapper extracts correctly',
      ok,
      ok ? `${extracted!.length}B identical` : `extracted=${extracted ? hex(extracted) : 'null'}`,
    );
  }

  // (c.2) Bare-map shape (pre-Alonzo): the auxiliary_data position holds the
  //       metadata map directly — { 309: <record> }. No tag, no key-0 wrapper.
  {
    const metadataMap = cborMap([[cborUint(309), recordBytes]]);
    // Bare-map fallback: auxiliary_data = metadata map directly.
    const auxData = metadataMap;
    const tx = buildTx(auxData);
    const extracted = sliceLabel309Value(tx);
    const ok = extracted !== null && bytesEqual(extracted, recordBytes);
    record(
      '(c.2) bare-map auxiliary_data extracts correctly',
      ok,
      ok ? `${extracted!.length}B identical` : `extracted=${extracted ? hex(extracted) : 'null'}`,
    );
  }
}

// === (d) Metadata without label 309 → null ===

function checkD(): void {
  // Metadata map carries only label 1234 (some unrelated record).
  const otherRecord = cborTstr('not a poe record');
  const metadataMap = cborMap([[cborUint(1234), otherRecord]]);
  const auxMap = cborMap([[cborUint(0), metadataMap]]);
  const auxData = cborTag(259, auxMap);
  const tx = buildTx(auxData);

  const extracted = sliceLabel309Value(tx);
  record(
    '(d) metadata without label 309 → null',
    extracted === null,
    extracted === null ? 'returned null' : `BUG: returned ${extracted.length}B = ${hex(extracted)}`,
  );

  // Bonus sanity: tx with no auxiliary_data at all (CBOR null) → also null.
  const txNoAux = buildTx(CBOR_NULL);
  const extractedNoAux = sliceLabel309Value(txNoAux);
  record(
    '(d) tx with auxiliary_data=null → null',
    extractedNoAux === null,
    extractedNoAux === null ? 'returned null' : `BUG: returned ${extractedNoAux.length}B`,
  );
}

// === Driver ===

function main(): void {
  checkA();
  checkB();
  checkC();
  checkD();

  if (failures.length > 0) {
    console.log(`\n${failures.length} smoke check(s) FAILED: ${failures.join(' | ')}`);
    process.exit(1);
  }
  console.log('\nALL smoke-tx-extract checks PASSED');
}

main();
