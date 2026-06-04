// Label 309 v1 reference implementation — X25519 keygen + ECDH
// Spec: RFC 7748. @noble/curves rejects all-zero shared secret per §6.1 (contributory check).

import { x25519 } from '@noble/curves/ed25519.js';

export interface X25519KeyPair {
  secretKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

export function generateX25519KeyPair(): X25519KeyPair {
  // x25519.keygen() draws 32 bytes from CSPRNG and applies the RFC 7748 §5
  // clamping internally before deriving the public key.
  const { secretKey, publicKey } = x25519.keygen();
  return { secretKey, publicKey };
}

export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 32) {
    throw new Error('x25519PublicKey: secretKey must be 32 bytes (RFC 7748 §5)');
  }
  // Multiplies the clamped scalar by the standard base point u=9 (RFC 7748 §6.1).
  return x25519.getPublicKey(secretKey);
}

export function x25519SharedSecret(secretKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 32) {
    throw new Error('x25519SharedSecret: secretKey must be 32 bytes');
  }
  if (theirPublicKey.length !== 32) {
    throw new Error('x25519SharedSecret: theirPublicKey must be 32 bytes');
  }
  // RFC 7748 §6.1: implementations MUST reject the all-zero output, which
  // signals a small-subgroup peer key. @noble/curves throws internally when
  // this contributory-behaviour check fails — we propagate that error.
  return x25519.getSharedSecret(secretKey, theirPublicKey);
}
