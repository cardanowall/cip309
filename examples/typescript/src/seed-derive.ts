// CIP-309 v1 reference implementation — seed → Ed25519 + X25519 + X-Wing keypairs
// Spec: CIP-309
// HKDF info constants:
//   "cardano-poe-ed25519-v1"        (22 bytes) → Ed25519 secret seed (RFC 8032 §5.1.5)
//   "cardano-poe-x25519-v1"         (21 bytes) → X25519 secret seed (clamped inside the library)
//   "cardano-poe-mlkem768x25519-v1" (29 bytes) → X-Wing root seed (post-quantum hybrid recipient key)

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { hkdfSha256 } from './hkdf.ts';
import { mlkem768x25519Keygen, type Mlkem768X25519KeyPair } from './mlkem768x25519.ts';
import { x25519PublicKey } from './x25519.ts';

// Mirror the injection from ed25519.ts — this module calls ed.getPublicKey
// directly, so it must guarantee the SHA-512 backend is wired before use.
ed.hashes.sha512 = sha512;

// Distinct HKDF info strings give domain separation: the same seed produces
// independent key material for signing vs ECDH, even though both branches
// share the same IKM and salt.
const ED25519_INFO = new TextEncoder().encode('cardano-poe-ed25519-v1'); // 22 bytes
const X25519_INFO = new TextEncoder().encode('cardano-poe-x25519-v1'); // 21 bytes
const MLKEM768X25519_INFO = new TextEncoder().encode('cardano-poe-mlkem768x25519-v1'); // 29 bytes
const EMPTY_SALT = new Uint8Array(0);

export interface DerivedKeyPair {
  secretKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

export function deriveEd25519KeypairFromSeed(seed: Uint8Array): DerivedKeyPair {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const secretKey = hkdfSha256({
    ikm: seed,
    salt: EMPTY_SALT,
    info: ED25519_INFO,
    length: 32,
  });
  // RFC 8032 §5.1.5: HKDF returns the 32-byte secret SEED. The library
  // computes the expanded private key (SHA-512 of the seed → low half clamped
  // to produce the curve scalar; high half is signing-prefix randomness).
  const publicKey = ed.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

export function deriveX25519KeypairFromSeed(seed: Uint8Array): DerivedKeyPair {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const secretKey = hkdfSha256({
    ikm: seed,
    salt: EMPTY_SALT,
    info: X25519_INFO,
    length: 32,
  });
  // x25519PublicKey clamps per RFC 7748 §5 before scalar-multiplying the base.
  const publicKey = x25519PublicKey(secretKey);
  return { secretKey, publicKey };
}

// Derive the X-Wing (ML-KEM-768 + X25519) recipient keypair so every identity
// can RECEIVE post-quantum sealed records (CIP-309 §3). The 32-byte HKDF output IS
// the X-Wing root seed: X-Wing key-gen re-expands the ML-KEM coins and the
// X25519 scalar from it via SHAKE-256, so the returned `secretSeed` equals this
// HKDF value. The 1216-byte `publicKey` is the on-record hybrid recipient key
// (`mlkem768x25519_pub`).
export function deriveMlKem768X25519KeypairFromSeed(seed: Uint8Array): Mlkem768X25519KeyPair {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const xwingSeed = hkdfSha256({
    ikm: seed,
    salt: EMPTY_SALT,
    info: MLKEM768X25519_INFO,
    length: 32,
  });
  return mlkem768x25519Keygen(xwingSeed);
}
