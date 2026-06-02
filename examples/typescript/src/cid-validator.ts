// CIP-309 v1 reference implementation — IPFS CID structural validator.
// Spec: CIP-309 §4.8.1 (`ipfs://<cid>` shape rules).
//
// Per the CID multiformats spec (https://github.com/multiformats/cid),
// conformant CIP-309 validators MUST parse the CID — multibase decode →
// version byte → codec varint → multihash (hash-function code varint +
// length varint + digest) — and reject malformed input with INVALID_URI
// (reason `ipfs_cid_invalid`). A regex-only shape check is insufficient
// because IPFS's self-authentication property (the URI itself binds the
// bytes via the multihash) is enforceable only through full CID parsing.
//
// Both forms MUST be accepted:
//   - CIDv0: `Qm` prefix, exactly 46 base58btc chars, decodes to 34 bytes
//     starting with 0x12 0x20 (sha2-256 multihash, length 32).
//   - CIDv1: multibase prefix character + base-decoded payload
//     [version=0x01 || codec_varint || multihash_code_varint
//      || multihash_length_varint || digest].
//
// Pure TS — no external CID/multihash/multibase library, to keep the
// reference implementation dependency-free and auditable. Accept/reject
// behaviour matches its Python twin exactly.

// === Recognised codecs (subset; rejection-by-allowlist) ===
// Per multicodec table; PoE realistically uses raw / dag-pb / dag-cbor.
const RECOGNISED_CIDV1_CODECS: ReadonlySet<number> = new Set([0x55, 0x70, 0x71]);

// === Recognised multihash codes → digest length (bytes) ===
// 0x12 = sha2-256 (length 32); 0xb220 = blake2b-256 (length 32); both 32-byte.
// Multihash codes are themselves varint-encoded inside the CID payload, so a
// blake2b-256 entry on the wire reads as varint(0xb220) → bytes 0xa0 0xe4 0x02.
const RECOGNISED_MULTIHASH: ReadonlyMap<number, number> = new Map([
  [0x12, 32],   // sha2-256
  [0xb220, 32], // blake2b-256
]);

// === Base58btc alphabet (Bitcoin variant) ===
const B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX: ReadonlyMap<string, number> = new Map(
  Array.from(B58_ALPHA, (c, i) => [c, i] as const),
);

// === Base32 alphabet (RFC 4648 §6, lowercase per multibase 'b'; uppercase per 'B') ===
const B32_ALPHA_LOWER = 'abcdefghijklmnopqrstuvwxyz234567';
const B32_INDEX_LOWER: ReadonlyMap<string, number> = new Map(
  Array.from(B32_ALPHA_LOWER, (c, i) => [c, i] as const),
);
const B32_ALPHA_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B32_INDEX_UPPER: ReadonlyMap<string, number> = new Map(
  Array.from(B32_ALPHA_UPPER, (c, i) => [c, i] as const),
);

function b58Decode(s: string): Uint8Array | null {
  if (s.length === 0) return null;
  let n = 0n;
  for (const ch of s) {
    const v = B58_INDEX.get(ch);
    if (v === undefined) return null;
    n = n * 58n + BigInt(v);
  }
  // Convert big-int to bytes (big-endian).
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  bytes.reverse();
  // Each leading '1' encodes a leading zero byte.
  let leading = 0;
  for (const ch of s) {
    if (ch === '1') leading += 1;
    else break;
  }
  const out = new Uint8Array(leading + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[leading + i] = bytes[i]!;
  return out;
}

function b32DecodeNoPad(
  s: string,
  alphaIndex: ReadonlyMap<string, number>,
): Uint8Array | null {
  if (s.length === 0) return new Uint8Array(0);
  let bits = 0;
  let buffer = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = alphaIndex.get(ch);
    if (v === undefined) return null;
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  // Trailing bits are 0-padding from the encoder; ignore (must be < 8).
  return Uint8Array.from(out);
}

function b16Decode(s: string, upper: boolean): Uint8Array | null {
  if (s.length % 2 !== 0) return null;
  const re = upper ? /^[0-9A-F]+$/ : /^[0-9a-f]+$/;
  if (!re.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Read a multiformats unsigned varint starting at `offset`.
 *
 * Returns `[value, bytesConsumed]` on success, or `null` on truncation/
 * overflow. Caps at 9 bytes (multiformats spec ceiling) to prevent
 * unbounded input.
 */
function readVarint(data: Uint8Array, offset: number): [number, number] | null {
  let value = 0;
  let shift = 0;
  let consumed = 0;
  while (consumed < 9) {
    if (offset + consumed >= data.length) return null;
    const b = data[offset + consumed]!;
    value |= (b & 0x7f) << shift;
    consumed += 1;
    if ((b & 0x80) === 0) return [value >>> 0, consumed];
    shift += 7;
  }
  return null;
}

function isValidCidv0(s: string): boolean {
  // CIDv0: 46-char base58btc, decodes to 34 bytes [0x12, 0x20, <32-B digest>].
  if (s.length !== 46 || !s.startsWith('Qm')) return false;
  const decoded = b58Decode(s);
  if (decoded === null || decoded.length !== 34) return false;
  return decoded[0] === 0x12 && decoded[1] === 0x20;
}

function isValidCidv1(s: string): boolean {
  // CIDv1: multibase prefix + base-decoded [0x01, codec_varint, multihash].
  if (s.length < 2) return false;
  const prefix = s.charAt(0);
  const rest = s.slice(1);
  let payload: Uint8Array | null;
  switch (prefix) {
    case 'b':
      payload = b32DecodeNoPad(rest, B32_INDEX_LOWER);
      break;
    case 'B':
      payload = b32DecodeNoPad(rest, B32_INDEX_UPPER);
      break;
    case 'f':
      payload = b16Decode(rest, false);
      break;
    case 'F':
      payload = b16Decode(rest, true);
      break;
    case 'z':
      payload = b58Decode(rest);
      break;
    default:
      // 'm' (base64) / 'M' (base64url-upper) / other bases not in the v1 fetch
      // set — explicitly reject. CIP-309 §4.8.1 names base32 and base58btc
      // as the operationally common forms; producers writing other bases
      // SHOULD re-encode.
      return false;
  }
  if (payload === null || payload.length < 2) return false;
  if (payload[0] !== 0x01) return false; // version byte
  // Read codec varint.
  const cv = readVarint(payload, 1);
  if (cv === null) return false;
  const [codec, codecLen] = cv;
  if (!RECOGNISED_CIDV1_CODECS.has(codec)) return false;
  // Read multihash code varint.
  const mhOff = 1 + codecLen;
  const mc = readVarint(payload, mhOff);
  if (mc === null) return false;
  const [mhCode, mhCodeLen] = mc;
  const expectedDigestLen = RECOGNISED_MULTIHASH.get(mhCode);
  if (expectedDigestLen === undefined) return false;
  // Read multihash length varint.
  const ml = readVarint(payload, mhOff + mhCodeLen);
  if (ml === null) return false;
  const [mhLen, mhLenLen] = ml;
  if (mhLen !== expectedDigestLen) return false;
  // Confirm digest is exactly the right number of trailing bytes.
  const digestOff = mhOff + mhCodeLen + mhLenLen;
  if (payload.length - digestOff !== mhLen) return false;
  return true;
}

/**
 * Return `true` iff `s` is a structurally valid IPFS CID (v0 or v1).
 *
 * See `CIP-309 §4.8.1` for the normative shape rules.
 */
export function isValidCid(s: string): boolean {
  if (s.length === 0) return false;
  // CIDv0 short-circuit (`Qm` prefix is unambiguous; CIDv1 multibase
  // prefixes never start with 'Q').
  if (s.startsWith('Qm')) return isValidCidv0(s);
  return isValidCidv1(s);
}

/**
 * Self-test runner — invoked when this module is run directly via
 * `npx tsx src/cid-validator.ts`.
 *
 * Throws on the first failed assertion so test failures are loud.
 */
export function runSelfTest(): void {
  const assert = (cond: boolean, msg: string): void => {
    if (!cond) throw new Error(`assertion failed: ${msg}`);
  };

  // CIDv0 fixture: well-known IPFS empty-directory CID.
  const CIDV0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG';
  assert(isValidCid(CIDV0), 'CIDv0 should validate');
  // CIDv1 base32 (lowercase 'b' prefix, raw codec, sha2-256 multihash).
  const CIDV1 = 'bafkreigh2akiscaildc6mn7vmrk5xkucb6w5dfgo7tukbmpzxoa64yjebq';
  assert(isValidCid(CIDV1), 'CIDv1 base32 should validate');

  // Negative cases.
  assert(!isValidCid(''), 'empty string');
  assert(!isValidCid('Qm'), 'too-short Qm prefix');
  assert(!isValidCid('Qm' + '1'.repeat(44)), 'wrong length Qm-prefix');
  // Wrong base58 alphabet ('0' not in alphabet).
  assert(
    !isValidCid('Qm0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    'invalid b58 char',
  );
  // Garbage CIDv1.
  assert(!isValidCid('babcdefg'), 'invalid CIDv1 base32 payload');
  // CIDv1 with unknown multibase prefix (base64url-upper M is allowed by some
  // decoders but not in this validator's accept-list).
  assert(!isValidCid('Mxxx'), 'unrecognised multibase prefix');

  console.log('cid-validator self-tests OK');
}

// Run self-tests when invoked directly. Guards against `import.meta.main`
// being undefined under tsx; falls back to URL-based detection.
if (import.meta.url === `file://${process.argv[1]}`) {
  runSelfTest();
}
