// Label 309 v1 reference implementation — X-Wing hybrid KEM (ML-KEM-768 + X25519).
// Spec: Label 309 (KEM registry), Label 309.
// Construction: draft-connolly-cfrg-xwing-kem-06 / IACR ePrint 2024/039.
//
// X-Wing combines a post-quantum KEM (ML-KEM-768) with a classical one (X25519):
// an attacker must break BOTH to recover the shared secret, so the hybrid is no
// weaker than either part. The 32-byte combined secret is fed straight into the
// sealed-PoE per-slot KEK derivation, exactly where the classical X25519 ECDH
// output goes — only the KEK info label differs (Label 309 §3).
//
// This module is a thin, length-pinned wrapper over @noble/post-quantum's
// `XWing` (its alias for ml_kem768_x25519). The combiner, the SHAKE-256 seed
// expansion, and the ML-KEM-FIRST / X25519-LAST byte ordering all live inside
// the noble primitive; the wire lengths below are asserted so a divergent build
// fails loudly instead of silently emitting the wrong number of bytes.

import { XWing } from '@noble/post-quantum/hybrid.js';

// Wire lengths (bytes). ML-KEM-768 sizes are fixed by FIPS 203; X25519 by
// RFC 7748; the seed/secret-key and eseed lengths by the X-Wing draft.
export const MLKEM768X25519_PUBLIC_KEY_LENGTH = 1216 as const; // ML-KEM ek (1184) ‖ X25519 pub (32)
export const MLKEM768X25519_ENC_LENGTH = 1120 as const; //        ML-KEM ct (1088) ‖ X25519 eph (32)
export const MLKEM768X25519_SHARED_SECRET_LENGTH = 32 as const;
export const MLKEM768X25519_SEED_LENGTH = 32 as const;
// 64-byte encapsulation randomness = 32-byte ML-KEM message ‖ 32-byte X25519
// ephemeral seed. noble rejects a 32-byte value, so the length is pinned here.
export const MLKEM768X25519_ESEED_LENGTH = 64 as const;

export interface Mlkem768X25519KeyPair {
  /**
   * The 32-byte root seed IS the secret key in draft-06: the ML-KEM coins and
   * the X25519 scalar are re-expanded from it via SHAKE-256 at decapsulation.
   */
  readonly secretSeed: Uint8Array;
  readonly publicKey: Uint8Array;
}

export interface Mlkem768X25519Encapsulation {
  /** ML-KEM-768 ciphertext (1088 B) ‖ X25519 ephemeral public key (32 B) = 1120 B. */
  readonly enc: Uint8Array;
  /** 32-byte X-Wing combined shared secret. */
  readonly ss: Uint8Array;
}

/** Derive an X-Wing keypair from a 32-byte root seed. */
export function mlkem768x25519Keygen(seed: Uint8Array): Mlkem768X25519KeyPair {
  if (seed.length !== MLKEM768X25519_SEED_LENGTH) {
    throw new Error(
      `mlkem768x25519 seed must be ${MLKEM768X25519_SEED_LENGTH} bytes, got ${seed.length}`,
    );
  }
  const { secretKey, publicKey } = XWing.keygen(seed);
  if (publicKey.length !== MLKEM768X25519_PUBLIC_KEY_LENGTH) {
    throw new Error(
      `derived public key is ${publicKey.length} bytes, expected ${MLKEM768X25519_PUBLIC_KEY_LENGTH}`,
    );
  }
  return { secretSeed: secretKey, publicKey };
}

/**
 * Encapsulate to an X-Wing public key. When `eseed` (the 64-byte encapsulation
 * randomness) is supplied the `enc` and `ss` are fully deterministic — that is
 * the test-vector injection point. Production callers MUST omit it so noble
 * samples fresh randomness.
 */
export function mlkem768x25519Encapsulate(args: {
  publicKey: Uint8Array;
  eseed?: Uint8Array;
}): Mlkem768X25519Encapsulation {
  if (args.publicKey.length !== MLKEM768X25519_PUBLIC_KEY_LENGTH) {
    throw new Error(
      `mlkem768x25519 public key must be ${MLKEM768X25519_PUBLIC_KEY_LENGTH} bytes, got ${args.publicKey.length}`,
    );
  }
  if (args.eseed !== undefined && args.eseed.length !== MLKEM768X25519_ESEED_LENGTH) {
    throw new Error(
      `mlkem768x25519 eseed must be ${MLKEM768X25519_ESEED_LENGTH} bytes, got ${args.eseed.length}`,
    );
  }
  const { cipherText, sharedSecret } = XWing.encapsulate(args.publicKey, args.eseed);
  if (cipherText.length !== MLKEM768X25519_ENC_LENGTH) {
    throw new Error(
      `mlkem768x25519 enc is ${cipherText.length} bytes, expected ${MLKEM768X25519_ENC_LENGTH}`,
    );
  }
  return { enc: cipherText, ss: sharedSecret };
}

/**
 * Decapsulate an X-Wing ciphertext to the 32-byte shared secret.
 *
 * Constant work: ML-KEM-768 implicit rejection means a corrupted ciphertext
 * yields a pseudorandom (but deterministic) secret rather than an error, so this
 * NEVER throws on bad ciphertext content. A wrong shared secret is the correct,
 * indistinguishable failure mode — callers MUST treat it as a non-match (the
 * per-slot `wrap` AEAD then rejects), not expect an exception. It throws only on
 * a structurally wrong-length `secretSeed` or `enc` (caller misuse).
 */
export function mlkem768x25519Decapsulate(args: {
  secretSeed: Uint8Array;
  enc: Uint8Array;
}): Uint8Array {
  // Pre-check both lengths before calling noble: decapsulation must perform a
  // constant amount of work for any caller-supplied ciphertext, which requires
  // the inputs to be the exact expected sizes (partitioning-oracle defence).
  if (args.secretSeed.length !== MLKEM768X25519_SEED_LENGTH) {
    throw new Error(
      `mlkem768x25519 secret seed must be ${MLKEM768X25519_SEED_LENGTH} bytes, got ${args.secretSeed.length}`,
    );
  }
  if (args.enc.length !== MLKEM768X25519_ENC_LENGTH) {
    throw new Error(
      `mlkem768x25519 enc must be ${MLKEM768X25519_ENC_LENGTH} bytes, got ${args.enc.length}`,
    );
  }
  // noble's signature is decapsulate(cipherText, secretKey) — ciphertext first.
  return XWing.decapsulate(args.enc, args.secretSeed);
}
