// Label 309 v1 reference implementation — Passphrase-derived sealed-PoE unwrap.
// Spec: Label 309 §4.4 (sealed-PoE passphrase path) and the passphrase-KDF registry.
//
// Construction (passphrase path):
//   CEK         ← Argon2id(passphrase_NFKC_ws, salt, m, t, p, hashLen=32)
//   plaintext   ← XChaCha20-Poly1305_Decrypt(CEK, nonce=enc.nonce, aad=h'',
//                                             ciphertext)
//
// AAD on the passphrase path is the EMPTY byte string per the Label 309 §4.4
// AAD-selection rule. Distinct from the sealed-recipient path (which uses
// `nonce || slots_mac`).

import { argon2id } from 'hash-wasm';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

// ----- Passphrase normalisation -----

// Normalise the entered phrase before feeding it to the KDF: NFKC + collapse
// internal whitespace + trim. Case is preserved (no ASCII case-fold), so the
// passphrase stays case-sensitive. Producer and verifier MUST apply the
// identical normalisation or the derived CEK will not match.
export function normalizePassphrase(input: string): string {
  return input.normalize('NFKC').replace(/\s+/g, ' ').trim();
}

// ----- Types -----

export interface PassphraseArgon2idEnvelope {
  readonly scheme: 1;
  readonly aead: 'xchacha20-poly1305';
  readonly nonce: Uint8Array;
  readonly passphrase: {
    readonly alg: 'argon2id';
    readonly salt: Uint8Array;
    readonly params: { readonly m: number; readonly t: number; readonly p: number };
  };
}

// Type alias kept for API-surface clarity ("this is the sealed envelope on the
// passphrase path") and for forward-extensibility under the algorithm-agility
// registry in Label 309 §4.10.0 (any additive passphrase-KDF identifier becomes a new
// interface and the alias widens to a union — call sites that consume the alias
// do not change).
export type PassphraseSealedEnvelope = PassphraseArgon2idEnvelope;

export type PassphraseUnwrapErrorCode =
  | 'UNSUPPORTED_ENVELOPE_SCHEME'
  | 'UNSUPPORTED_AEAD_ALG'
  | 'ENC_PASSPHRASE_ALG_UNSUPPORTED'
  | 'INVALID_ENVELOPE_SHAPE'
  | 'KDF_DERIVATION_FAILED'
  | 'TAMPERED_CIPHERTEXT';

export class PassphraseUnwrapError extends Error {
  readonly code: PassphraseUnwrapErrorCode;
  constructor(code: PassphraseUnwrapErrorCode, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.code = code;
    this.name = 'PassphraseUnwrapError';
  }
}

export interface PassphraseUnwrapArgs {
  envelope: PassphraseSealedEnvelope;
  ciphertext: Uint8Array;
  passphrase: string;
}

export interface PassphraseWrapArgs {
  plaintext: Uint8Array;
  passphrase: string;
  /** Argon2id KDF parameters; used to derive the CEK from the passphrase. */
  passphraseBlock: {
    alg: 'argon2id';
    salt: Uint8Array;
    params: { m: number; t: number; p: number };
  };
  /** AEAD nonce (24 B for XChaCha20-Poly1305). */
  nonce: Uint8Array;
}

export interface PassphraseWrapOutput {
  readonly envelope: PassphraseSealedEnvelope;
  readonly ciphertext: Uint8Array;
}

// ----- CEK derivation -----

async function deriveCekArgon2id(
  passphraseBytes: Uint8Array,
  salt: Uint8Array,
  params: { m: number; t: number; p: number },
): Promise<Uint8Array> {
  try {
    return await argon2id({
      password: passphraseBytes,
      salt,
      memorySize: params.m,
      iterations: params.t,
      parallelism: params.p,
      hashLength: 32,
      outputType: 'binary' as const,
    });
  } catch (e) {
    throw new PassphraseUnwrapError(
      'KDF_DERIVATION_FAILED',
      e instanceof Error ? e.message : 'argon2id derive failed',
    );
  }
}

async function deriveCek(
  envelope: PassphraseSealedEnvelope,
  passphrase: string,
): Promise<Uint8Array> {
  const normalised = normalizePassphrase(passphrase);
  const passphraseBytes = new TextEncoder().encode(normalised);
  if (envelope.passphrase.alg === 'argon2id') {
    return deriveCekArgon2id(passphraseBytes, envelope.passphrase.salt, envelope.passphrase.params);
  }
  throw new PassphraseUnwrapError(
    'ENC_PASSPHRASE_ALG_UNSUPPORTED',
    `unknown passphrase alg: ${(envelope.passphrase as { alg: string }).alg}`,
  );
}

// ----- Public API: passphrase-path unwrap -----

/**
 * Decrypt a sealed-PoE ciphertext whose `enc` carries `passphrase` (passphrase path).
 *
 * Per Label 309 §4.4 AAD-selection rule: the passphrase path uses the EMPTY byte string
 * as AEAD AAD (distinct from the sealed-recipient path's `nonce || slots_mac` AAD).
 *
 * Failure modes are surfaced as `PassphraseUnwrapError` with one of:
 *   - UNSUPPORTED_ENVELOPE_SCHEME / UNSUPPORTED_AEAD_ALG /
 *     ENC_PASSPHRASE_ALG_UNSUPPORTED
 *   - INVALID_ENVELOPE_SHAPE (e.g. nonce wrong length)
 *   - KDF_DERIVATION_FAILED  (KDF rejected params at runtime)
 *   - TAMPERED_CIPHERTEXT    (AEAD tag verify failed; covers wrong passphrase)
 */
export async function eciesKdfUnwrap(args: PassphraseUnwrapArgs): Promise<Uint8Array> {
  const { envelope, ciphertext, passphrase } = args;

  if (envelope.scheme !== 1) {
    throw new PassphraseUnwrapError('UNSUPPORTED_ENVELOPE_SCHEME', `enc.scheme=${envelope.scheme}`);
  }
  if (envelope.aead !== 'xchacha20-poly1305') {
    throw new PassphraseUnwrapError('UNSUPPORTED_AEAD_ALG', envelope.aead);
  }
  if (envelope.nonce.length !== 24) {
    throw new PassphraseUnwrapError('INVALID_ENVELOPE_SHAPE', 'nonce length');
  }
  if (envelope.passphrase === undefined || envelope.passphrase === null) {
    throw new PassphraseUnwrapError('INVALID_ENVELOPE_SHAPE', 'envelope has no passphrase block');
  }

  const cek = await deriveCek(envelope, passphrase);

  const emptyAad = new Uint8Array(0);
  try {
    return xchacha20poly1305(cek, envelope.nonce, emptyAad).decrypt(ciphertext);
  } catch (e) {
    throw new PassphraseUnwrapError(
      'TAMPERED_CIPHERTEXT',
      e instanceof Error ? e.message : 'aead failure',
    );
  }
}

// ----- Public API: passphrase-path wrap (companion to unwrap, for tests / SDK callers) -----

/**
 * Encrypt plaintext under a passphrase-derived CEK, producing the on-wire
 * `enc` envelope and the AEAD ciphertext. AAD is the empty byte string.
 */
export async function eciesKdfWrap(args: PassphraseWrapArgs): Promise<PassphraseWrapOutput> {
  const { plaintext, passphrase, passphraseBlock, nonce } = args;

  if (nonce.length !== 24) {
    throw new PassphraseUnwrapError('INVALID_ENVELOPE_SHAPE', 'nonce MUST be 24 bytes');
  }

  if (passphraseBlock.alg !== 'argon2id') {
    throw new PassphraseUnwrapError(
      'ENC_PASSPHRASE_ALG_UNSUPPORTED',
      `unknown passphrase alg: ${(passphraseBlock as { alg: string }).alg}`,
    );
  }

  // Build the envelope first so deriveCek can read .passphrase off it (same
  // code path as unwrap).
  const envelope: PassphraseSealedEnvelope = {
    scheme: 1,
    aead: 'xchacha20-poly1305',
    nonce,
    passphrase: {
      alg: 'argon2id',
      salt: passphraseBlock.salt,
      params: passphraseBlock.params,
    },
  };

  const cek = await deriveCek(envelope, passphrase);
  const emptyAad = new Uint8Array(0);
  const ciphertext = xchacha20poly1305(cek, nonce, emptyAad).encrypt(plaintext);
  return { envelope, ciphertext };
}
