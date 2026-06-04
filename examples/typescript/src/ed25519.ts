// Label 309 v1 reference implementation — Ed25519 sign / verify / keygen
// Spec: RFC 8032. @noble/ed25519 v3 dropped bundled SHA-512; we inject from @noble/hashes.

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

// REQUIRED: @noble/ed25519 v3 needs sha512 injection at module load.
// Without this, every sign/verify/getPublicKey throws "sha512 not set".
ed.hashes.sha512 = sha512;

export interface Ed25519KeyPair {
  secretKey: Uint8Array; // 32 bytes
  publicKey: Uint8Array; // 32 bytes
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  // ed.keygen() pulls 32 bytes from a CSPRNG (RFC 8032 §5.1.5 step 1).
  const { secretKey, publicKey } = ed.keygen();
  return { secretKey, publicKey };
}

export function signEd25519(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 32) {
    throw new Error('signEd25519: secretKey must be 32 bytes (RFC 8032 §5.1.5)');
  }
  // 64-byte signature: R (32) || S (32) per RFC 8032 §5.1.6.
  return ed.sign(message, secretKey);
}

export function verifyEd25519(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  if (publicKey.length !== 32) return false;
  // zip215:false → strict RFC 8032 §5.1.7 verification (reject non-canonical
  // encodings and small-subgroup keys). ZIP-215 relaxes those checks for
  // consensus systems; our PoE pipeline wants the strict form.
  return ed.verify(signature, message, publicKey, { zip215: false });
}
