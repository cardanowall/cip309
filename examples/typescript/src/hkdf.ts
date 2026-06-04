// Label 309 v1 reference implementation — HKDF-SHA-256 wrapper
// Spec: RFC 5869 (HKDF). Used by seed-derive.ts and the ECIES constructions
// (Label 309).

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

// RFC 5869 §2.3 caps L (output length) at 255 × HashLen.
// For SHA-256 HashLen = 32, so the maximum is 8160 bytes.
const MAX_OUTPUT_BYTES = 255 * 32;

export function hkdfSha256(args: {
  ikm: Uint8Array;
  salt?: Uint8Array; // empty/absent → HashLen zero bytes per RFC 5869 §2.2
  info?: Uint8Array;
  length: number; // ≤ 255 × 32 = 8160 bytes for SHA-256
}): Uint8Array {
  const { ikm, salt, info, length } = args;

  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('hkdfSha256: length must be a positive integer');
  }
  if (length > MAX_OUTPUT_BYTES) {
    throw new Error(`hkdfSha256: length must be ≤ ${MAX_OUTPUT_BYTES} (RFC 5869 §2.3)`);
  }

  // RFC 5869 §2.2: when salt is omitted/empty, HKDF-Extract zero-pads it to HashLen
  // internally. We pass an empty Uint8Array; @noble/hashes performs the zero-pad.
  const effectiveSalt = salt ?? new Uint8Array(0);
  const effectiveInfo = info ?? new Uint8Array(0);

  return hkdf(sha256, ikm, effectiveSalt, effectiveInfo, length);
}
