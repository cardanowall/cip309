// Label 309 v1 reference implementation — SHA-256 + BLAKE2b-256 dual-hash
// Spec: Label 309 §4.3 dual-hash recommendation.

import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';

export interface DualHash {
  'sha2-256': Uint8Array; // 32 bytes
  'blake2b-256': Uint8Array; // 32 bytes
}

// Two independent 256-bit digests guard against a future second-preimage
// break in either family: an adversary would need to collide both
// SHA-2 (Merkle–Damgård) and BLAKE2b (HAIFA) simultaneously.
export function dualHash(data: Uint8Array): DualHash {
  return {
    'sha2-256': sha256(data),
    'blake2b-256': blake2b(data, { dkLen: 32 }),
  };
}

// Convenience single-algorithm helpers — exported so callers can pick the
// digest they need without re-importing @noble/hashes.
export const sha2_256 = (data: Uint8Array): Uint8Array => sha256(data);
export const blake2b_256 = (data: Uint8Array): Uint8Array => blake2b(data, { dkLen: 32 });
