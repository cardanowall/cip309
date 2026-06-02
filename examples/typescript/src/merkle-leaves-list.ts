// Merkle leaves-list CBOR codec for CIP-309.
// Spec: CIP-309 §6.5 (canonical CBOR wire form),
//       CIP-309 §4.5 (on-chain commitment).
//
// CBOR is the normative wire form of the leaves-list file published to the
// content-addressed substrate referenced by `merkle[i].uris[]`. The JSON
// projection emitted by `toJsonProjection` is informative only: it is a
// human-readable companion view (CLI dumps, doc examples) and MUST NOT be
// used as the byte-normative form when both forms are present.
//
// Final CDDL (CIP-309 §6.5):
//
//   leaves-list = {
//     "format":     "cardano-poe-merkle-leaves-v1",
//     "tree_alg":   "rfc9162-sha256",
//     "root":       bytes .size 32,
//     "leaves":     [ + bytes .size 32 ],
//     "leaf_count": uint,
//     ? "leaf_alg": tstr,
//   }
//
// Unknown / mismatched `format` values throw `SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED`
// (CIP-309).

import { decodeCanonicalCbor, encodeCanonicalCbor } from './cbor-canonical.ts';

// === Constants ===

const LEAVES_LIST_FORMAT = 'cardano-poe-merkle-leaves-v1';
const TREE_ALG_RFC9162 = 'rfc9162-sha256';
const DIGEST_LENGTH = 32;
const REGISTERED_FORMATS = new Set<string>([LEAVES_LIST_FORMAT]);

// === Types ===

export interface DecodedLeavesList {
  readonly format: typeof LEAVES_LIST_FORMAT;
  readonly treeAlg: 'rfc9162-sha256';
  readonly root: Uint8Array;
  readonly leaves: Uint8Array[];
  readonly leafCount: number;
  readonly leafAlg?: string;
}

export interface EncodeLeavesListArgs {
  root: Uint8Array;
  leaves: Uint8Array[];
  leafCount: number;
  leafAlg?: string;
}

export type LeavesListErrorCode =
  | 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED'
  | 'SCHEMA_MERKLE_LEAVES_MALFORMED';

export class LeavesListError extends Error {
  readonly code: LeavesListErrorCode;
  constructor(code: LeavesListErrorCode, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.code = code;
    this.name = 'LeavesListError';
  }
}

// === Encode ===

/**
 * Emit canonical CBOR bytes for a leaves-list. The returned bytes are byte-
 * stable across producers per RFC 8949 §4.2.1.
 *
 * Map-key order is implied by `cbor-canonical.ts`; the keys sort as:
 *   `root` (4B) < `format` (6B) < `leaves` (6B) < `leaf_alg` (8B)
 *   < `tree_alg` (8B) < `leaf_count` (10B).
 */
export function encodeLeavesList(args: EncodeLeavesListArgs): Uint8Array {
  if (args.root.length !== DIGEST_LENGTH) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `root length ${args.root.length} != ${DIGEST_LENGTH}`,
    );
  }
  if (args.leaves.length < 1) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaves array MUST be non-empty',
    );
  }
  for (let i = 0; i < args.leaves.length; i++) {
    const leaf = args.leaves[i]!;
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new LeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        `leaves[${i}] MUST be a Uint8Array(${DIGEST_LENGTH})`,
      );
    }
  }
  if (!Number.isInteger(args.leafCount) || args.leafCount < 1) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `leaf_count must be a positive integer; got ${String(args.leafCount)}`,
    );
  }
  const map: Record<string, unknown> = {
    format: LEAVES_LIST_FORMAT,
    tree_alg: TREE_ALG_RFC9162,
    root: args.root,
    leaves: args.leaves,
    leaf_count: args.leafCount,
  };
  if (args.leafAlg !== undefined) {
    map['leaf_alg'] = args.leafAlg;
  }
  return encodeCanonicalCbor(map);
}

// === Decode ===

/**
 * Parse canonical CBOR bytes as a leaves-list and validate the schema. The
 * `format` field is the version hook (CIP-309 §6.5); a value not in the
 * registered set raises `SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED`
 * (CIP-309).
 */
export function decodeLeavesList(bytes: Uint8Array): DecodedLeavesList {
  const decoded = decodeCanonicalCbor(bytes);
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'top-level leaves-list MUST be a CBOR map',
    );
  }
  const m = decoded as Record<string, unknown>;
  const format = m['format'];
  if (typeof format !== 'string') {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'format MUST be a tstr',
    );
  }
  if (!REGISTERED_FORMATS.has(format)) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
      `format '${format}' is not in the registered set`,
    );
  }
  const treeAlg = m['tree_alg'];
  if (treeAlg !== TREE_ALG_RFC9162) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `tree_alg '${String(treeAlg)}' is not '${TREE_ALG_RFC9162}'`,
    );
  }
  const root = m['root'];
  if (!(root instanceof Uint8Array) || root.length !== DIGEST_LENGTH) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'root MUST be a 32-byte bstr',
    );
  }
  const leavesRaw = m['leaves'];
  if (!Array.isArray(leavesRaw) || leavesRaw.length < 1) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaves MUST be a non-empty array',
    );
  }
  const leaves: Uint8Array[] = leavesRaw.map((leaf, i) => {
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new LeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        `leaves[${i}] MUST be a 32-byte bstr`,
      );
    }
    return leaf;
  });
  const leafCount = m['leaf_count'];
  if (typeof leafCount !== 'number' || !Number.isInteger(leafCount) || leafCount < 1) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaf_count MUST be a positive CBOR uint',
    );
  }
  const out: DecodedLeavesList = {
    format: LEAVES_LIST_FORMAT,
    treeAlg: TREE_ALG_RFC9162,
    root,
    leaves,
    leafCount,
    ...(typeof m['leaf_alg'] === 'string' ? { leafAlg: m['leaf_alg'] as string } : {}),
  };
  return out;
}

// === JSON projection (informative; NOT for verification) ===

/**
 * Render a decoded leaves-list as a JCS-canonicalised JSON string for
 * inspection (CLI dumps, doc examples, debugging). The output is human-
 * readable and stable for byte-level diffing but is NOT the wire form.
 * A verifier MUST NOT use the JSON projection as the byte-normative
 * leaves-list (CIP-309 §6.5).
 */
export function toJsonProjection(decoded: DecodedLeavesList): string {
  const obj: Record<string, unknown> = {
    format: decoded.format,
    tree_alg: decoded.treeAlg,
    root: bytesToHex(decoded.root),
    leaves: decoded.leaves.map(bytesToHex),
    leaf_count: decoded.leafCount,
  };
  if (decoded.leafAlg !== undefined) {
    obj['leaf_alg'] = decoded.leafAlg;
  }
  // JCS (RFC 8785) requires sorted keys + canonical number forms. The keys
  // here are alphabetised by construction.
  const sorted = sortKeysRecursive(obj);
  return JSON.stringify(sorted);
}

/**
 * Inverse of `toJsonProjection`. Provided for completeness; NOT for
 * verification: callers using this function in a verification context
 * MUST treat the result as informative and emit
 * `MERKLE_LEAVES_INFORMATIVE_FORM` (info-severity) per CIP-309.
 */
export function fromJsonProjection(json: string): DecodedLeavesList {
  // eslint-disable-next-line no-console
  if (typeof process !== 'undefined' && process.env?.['CIP309_VERIFICATION_CTX']) {
    console.warn(
      'merkle-leaves-list: fromJsonProjection used in a verification context; ' +
        'CBOR is the normative wire form per CIP-309 §6.5. Emit MERKLE_LEAVES_INFORMATIVE_FORM.',
    );
  }
  const parsed = JSON.parse(json) as Record<string, unknown>;
  const format = parsed['format'];
  if (typeof format !== 'string' || !REGISTERED_FORMATS.has(format)) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
      `format '${String(format)}' is not in the registered set`,
    );
  }
  const treeAlg = parsed['tree_alg'];
  if (treeAlg !== TREE_ALG_RFC9162) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      `tree_alg '${String(treeAlg)}' is not '${TREE_ALG_RFC9162}'`,
    );
  }
  const rootHex = parsed['root'];
  if (typeof rootHex !== 'string') {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'root MUST be a hex string',
    );
  }
  const root = hexToBytes(rootHex);
  const leavesRaw = parsed['leaves'];
  if (!Array.isArray(leavesRaw) || leavesRaw.length < 1) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaves MUST be a non-empty array of hex strings',
    );
  }
  const leaves = leavesRaw.map((h, i) => {
    if (typeof h !== 'string') {
      throw new LeavesListError(
        'SCHEMA_MERKLE_LEAVES_MALFORMED',
        `leaves[${i}] MUST be a hex string`,
      );
    }
    return hexToBytes(h);
  });
  const leafCount = parsed['leaf_count'];
  if (typeof leafCount !== 'number' || !Number.isInteger(leafCount) || leafCount < 1) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'leaf_count MUST be a positive integer',
    );
  }
  const out: DecodedLeavesList = {
    format: LEAVES_LIST_FORMAT,
    treeAlg: TREE_ALG_RFC9162,
    root,
    leaves,
    leafCount,
    ...(typeof parsed['leaf_alg'] === 'string'
      ? { leafAlg: parsed['leaf_alg'] as string }
      : {}),
  };
  return out;
}

// === Helpers ===

function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new LeavesListError(
      'SCHEMA_MERKLE_LEAVES_MALFORMED',
      'hex string has odd length',
    );
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function sortKeysRecursive(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysRecursive);
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort();
    for (const k of keys) {
      out[k] = sortKeysRecursive((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}
