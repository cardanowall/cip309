// Label 309 reference implementation — Passphrase-derived sealed-PoE unwrap.
// Spec: Label 309 §4.4 (sealed-PoE passphrase path) and the passphrase-KDF registry.
//
// Construction (passphrase path, scheme 1):
//   CEK         ← Argon2id(normalize(passphrase), salt, m, t, p, hashLen=32)
//   payload_key ← HKDF-SHA-256(ikm=CEK, salt=enc.nonce,
//                              info="cardano-poe-payload-passphrase-v1", L=32)
//   AAD_CONTENT ← canonicalCBOR({ scheme, path: "passphrase", aead, nonce,
//                                 passphrase: { alg, salt, params,
//                                               normalization } })
//   plaintext   ← XChaCha20-Poly1305_Decrypt(payload_key, enc.nonce,
//                                             aad=AAD_CONTENT, ciphertext)
//
// The content is encrypted under a payload_key derived from the CEK, never under
// the CEK directly. The content AAD binds the KDF parameters and the
// normalization profile id; there is NO `kem` key on this path, and the
// normalization id is a scheme-fixed AAD constant, never serialised on the wire.

import { argon2id } from 'hash-wasm';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { hkdfSha256 } from './hkdf.ts';

// ----- Passphrase normalization (cardano-poe-pw-norm-v1) -----

// The passphrase normalization profile fed into the content AAD. Pinned into the
// AAD so the verifier proves the CEK was derived under exactly this profile;
// never serialised on the wire.
const PW_NORM_PROFILE = 'cardano-poe-pw-norm-v1' as const;

// HKDF info for the passphrase-path content payload_key.
const INFO_PAYLOAD_PASSPHRASE_V1 = new TextEncoder().encode('cardano-poe-payload-passphrase-v1'); // 33 ASCII bytes

// XChaCha20-Poly1305 single-shot bound (2^38 - 64 plaintext bytes; ciphertext + 16).
const MAX_SEALED_PLAINTEXT = 2 ** 38 - 64;
const MAX_SEALED_CIPHERTEXT = MAX_SEALED_PLAINTEXT + 16;

// Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE normalization
// and the Argon2id KDF. An oversized passphrase would otherwise drive unbounded
// NFKC / whitespace-collapse work and a large Argon2id input before any
// cost-bounded primitive runs; capping the raw input closes that pre-KDF DoS. The
// bound is byte length of the raw UTF-8 encoding, not code-point count, so a short
// string of wide multi-byte characters is still measured by its encoded size.
// 4096 bytes is far above any human-chosen passphrase. It is a verifier-enforced,
// deployment-pinned constant — not a wire field — and deployments MAY tighten it.
export const MAX_PASSPHRASE_INPUT_BYTES = 4096;

// The Unicode `White_Space` property set — exactly these 25 codepoints. The
// normalization profile collapses every maximal run of these to a single U+0020.
// This is spelled out explicitly rather than via the `\s` regex class, which
// matches a different set (e.g. it excludes U+0085 NEL), and would otherwise
// derive a different CEK from the same passphrase and break cross-implementation
// decryption.
const WHITE_SPACE: ReadonlySet<number> = new Set([
  0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680, 0x2000, 0x2001, 0x2002,
  0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f,
  0x3000,
]);

/**
 * Apply the `cardano-poe-pw-norm-v1` profile: NFKC, then collapse every maximal
 * run of `White_Space` codepoints to a single U+0020, then trim leading/trailing
 * space. Case is preserved (no ASCII case-fold), so the passphrase stays
 * case-sensitive. Producer and verifier MUST apply identical normalization or
 * the derived CEK will not match.
 */
export function normalizePassphrase(input: string): string {
  const nfkc = input.normalize('NFKC');
  let out = '';
  let inRun = false;
  for (const ch of nfkc) {
    if (WHITE_SPACE.has(ch.codePointAt(0)!)) {
      if (!inRun) {
        out += ' ';
        inRun = true;
      }
    } else {
      out += ch;
      inRun = false;
    }
  }
  let start = 0;
  let end = out.length;
  while (start < end && out[start] === ' ') start++;
  while (end > start && out[end - 1] === ' ') end--;
  return out.slice(start, end);
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
  | 'PAYLOAD_TOO_LARGE'
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
  // Pre-KDF input cap: reject an oversized raw passphrase BEFORE normalization or
  // Argon2id, so it cannot drive unbounded pre-KDF work. Byte length of the raw
  // UTF-8 encoding, not code-point count.
  const rawPassphraseBytes = new TextEncoder().encode(passphrase).length;
  if (rawPassphraseBytes > MAX_PASSPHRASE_INPUT_BYTES) {
    throw new PassphraseUnwrapError(
      'KDF_DERIVATION_FAILED',
      `passphrase length ${rawPassphraseBytes} bytes exceeds the maximum ${MAX_PASSPHRASE_INPUT_BYTES} bytes`,
    );
  }
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

/** Passphrase-path content key: HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-passphrase-v1). */
function passphrasePayloadKey(cek: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdfSha256({ ikm: cek, salt: nonce, info: INFO_PAYLOAD_PASSPHRASE_V1, length: 32 });
}

/** canonicalCBOR(AD_CONTENT_PASSPHRASE): the closed content-AEAD AAD for the
 * passphrase path. It binds the passphrase KDF parameters into the content tag,
 * so tampering with `salt` or any `params` value after encryption changes the
 * AAD and the AEAD open fails. The `normalization` profile id is a scheme-fixed
 * constant pinned into the AAD, never serialised on the wire. There is NO `kem`
 * key on this path. */
function adContentPassphrase(
  nonce: Uint8Array,
  passphraseBlock: PassphraseArgon2idEnvelope['passphrase'],
): Uint8Array {
  return encodeCanonicalCbor({
    scheme: 1,
    path: 'passphrase',
    aead: 'xchacha20-poly1305',
    nonce,
    passphrase: {
      alg: passphraseBlock.alg,
      salt: passphraseBlock.salt,
      params: {
        m: passphraseBlock.params.m,
        t: passphraseBlock.params.t,
        p: passphraseBlock.params.p,
      },
      normalization: PW_NORM_PROFILE,
    },
  });
}

// ----- Public API: passphrase-path unwrap -----

/**
 * Decrypt a sealed-PoE ciphertext whose `enc` carries `passphrase` (passphrase path).
 *
 * The content is opened under a `payload_key` derived from the Argon2id CEK, with
 * a structured AAD that binds the KDF parameters and the normalization profile id
 * (distinct from the sealed-recipient path's slots-bound AAD).
 *
 * Failure modes are surfaced as `PassphraseUnwrapError` with one of:
 *   - UNSUPPORTED_ENVELOPE_SCHEME / UNSUPPORTED_AEAD_ALG /
 *     ENC_PASSPHRASE_ALG_UNSUPPORTED
 *   - INVALID_ENVELOPE_SHAPE (e.g. nonce wrong length)
 *   - KDF_DERIVATION_FAILED  (KDF rejected params at runtime)
 *   - PAYLOAD_TOO_LARGE      (ciphertext at/above the single-shot bound)
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
  // Reject a ciphertext at or above the single-shot bound before the AEAD runs.
  if (ciphertext.length >= MAX_SEALED_CIPHERTEXT) {
    throw new PassphraseUnwrapError(
      'PAYLOAD_TOO_LARGE',
      `ciphertext length ${ciphertext.length} is at or above the single-shot bound ${MAX_SEALED_CIPHERTEXT}`,
    );
  }

  const cek = await deriveCek(envelope, passphrase);

  // Content is opened under a payload_key derived from the CEK, with the
  // structured passphrase-path AAD; the CEK never keys the content AEAD directly.
  const payloadKey = passphrasePayloadKey(cek, envelope.nonce);
  const aad = adContentPassphrase(envelope.nonce, envelope.passphrase);
  try {
    return xchacha20poly1305(payloadKey, envelope.nonce, aad).decrypt(ciphertext);
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
 * `enc` envelope and the AEAD ciphertext. The content is encrypted under a
 * payload_key derived from the CEK, with the structured passphrase-path AAD.
 */
export async function eciesKdfWrap(args: PassphraseWrapArgs): Promise<PassphraseWrapOutput> {
  const { plaintext, passphrase, passphraseBlock, nonce } = args;

  if (nonce.length !== 24) {
    throw new PassphraseUnwrapError('INVALID_ENVELOPE_SHAPE', 'nonce MUST be 24 bytes');
  }
  // Reject a plaintext at or above the single-shot bound before the AEAD runs.
  if (plaintext.length >= MAX_SEALED_PLAINTEXT) {
    throw new PassphraseUnwrapError(
      'PAYLOAD_TOO_LARGE',
      `plaintext length ${plaintext.length} is at or above the single-shot bound ${MAX_SEALED_PLAINTEXT}`,
    );
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
  const payloadKey = passphrasePayloadKey(cek, nonce);
  const aad = adContentPassphrase(nonce, envelope.passphrase);
  const ciphertext = xchacha20poly1305(payloadKey, nonce, aad).encrypt(plaintext);
  return { envelope, ciphertext };
}
