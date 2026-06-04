// Label 309 v2 reference implementation — multi-recipient sealed-PoE.
// Spec: Label 309 (multi-recipient sealed PoE), Label 309 §4.4.
//
// Two KEM branches share ONE envelope shape, discriminated on the envelope-level
// `kem` field:
//
//   • kem: 'x25519'         — classical age-style ECIES. Per-slot { epk(32), wrap(48) }.
//   • kem: 'mlkem768x25519' — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot the
//                             1120-byte X-Wing enc carried as a chunked byte-string
//                             array (`kem_ct`) + wrap(48). NO per-slot epk.
//
// Construction (n >= 1 recipients):
//   For each recipient i — classical (x25519):
//     priv_eph_i  ← randomBytes(32)
//     shared_i    ← X25519(priv_eph_i, pub_R_i)
//     KEK_i       ← HKDF-SHA-256(ikm=shared_i, salt=epk_i||pub_R_i,
//                                  info="cardano-poe-kek-v1", L=32)
//     wrap_i      ← ChaCha20-Poly1305(KEK_i, nonce=zeros(12),
//                                      aad="cardano-poe-kek-v1", CEK)
//     slot_i      = { epk: epk_i, wrap: wrap_i }
//   For each recipient i — hybrid (mlkem768x25519):
//     (enc_i, shared_i) ← X-Wing.Encapsulate(pub_R_i; eseed_i)  # enc = 1120 B, ss = 32 B
//     KEK_i       ← HKDF-SHA-256(ikm=shared_i, salt="",
//                                  info="cardano-poe-kek-mlkem768x25519-v1", L=32)
//     wrap_i      ← ChaCha20-Poly1305(KEK_i, nonce=zeros(12),
//                                      aad="cardano-poe-kek-mlkem768x25519-v1", CEK)
//     slot_i      = { kem_ct: chunk64(enc_i), wrap: wrap_i }
//   CSPRNG-shuffle the slot array (security-critical — prevents ordering leak).
//   HMAC_KEY      ← HKDF-SHA-256(CEK, info="cardano-poe-slots-mac-v1", L=32)
//   slots_mac     ← HMAC-SHA-256(HMAC_KEY, canonicalCBOR(slots))   # KEM-driven slot CBOR
//   nonce         ← randomBytes(24)
//   ciphertext    ← XChaCha20-Poly1305(CEK, nonce, aad=nonce||slots_mac, plaintext)
//
// Everything outside the per-slot KEM — the content AEAD, slots_mac, AAD layout,
// and the CSPRNG shuffle — is byte-identical across the two KEMs.
//
// NOT RFC 9180 HPKE: this is age v1 stanza pattern transposed to CBOR with
// Label 309-specific HKDF constants. Recipient pubkeys are NOT on the wire —
// age-style trial-decrypt. Review against age v1 spec + Bellare-Rogaway DHIES;
// RFC 9180's analysis does NOT apply byte-exact.

import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { hkdfSha256 } from './hkdf.ts';
import {
  mlkem768x25519Decapsulate,
  mlkem768x25519Encapsulate,
  MLKEM768X25519_ENC_LENGTH,
  MLKEM768X25519_ESEED_LENGTH,
  MLKEM768X25519_PUBLIC_KEY_LENGTH,
  MLKEM768X25519_SEED_LENGTH,
} from './mlkem768x25519.ts';

// ----- Constants -----
const enc = new TextEncoder();
const INFO_KEK_V1: Uint8Array = enc.encode('cardano-poe-kek-v1'); // 18 ASCII bytes
// Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a
// KEK derived under one KEM can never collide with the other. Reused verbatim
// as the per-slot wrap AEAD AAD, exactly as the classical path reuses its own.
const INFO_KEK_MLKEM768X25519_V1: Uint8Array = enc.encode('cardano-poe-kek-mlkem768x25519-v1'); // 33 ASCII bytes
const INFO_SLOTS_MAC_V1: Uint8Array = enc.encode('cardano-poe-slots-mac-v1'); // 24 ASCII bytes
const ZERO_NONCE_12: Uint8Array = new Uint8Array(12);
export const MAX_RECIPIENTS = 32;

// Cardano ledger CDDL caps every transaction_metadatum byte string at 64 bytes,
// so the 1120-byte X-Wing `enc` is carried as an array of <=64-byte chunks
// (`kem_ct`). This is the identical split rule the record encoder applies to
// chunked COSE bytes.
const CHUNK_MAX_BYTES = 64;

/** Split a logical byte string into <=64-byte chunks (X-Wing `enc` → `kem_ct`). */
export function chunkKemCt(value: Uint8Array): Uint8Array[] {
  if (value.length === 0) throw new Error('chunkKemCt: refusing to chunk an empty byte string');
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < value.length; i += CHUNK_MAX_BYTES) {
    chunks.push(value.subarray(i, Math.min(i + CHUNK_MAX_BYTES, value.length)));
  }
  return chunks;
}

/** Inverse of chunkKemCt: concatenate the chunked `kem_ct` back into the flat enc. */
export function joinKemCt(chunks: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

// ----- Types -----
// The envelope-level KEM discriminator.
export type SealedKem = 'x25519' | 'mlkem768x25519';

/** Classical per-slot wire shape: { epk: bstr(32), wrap: bstr(48) }. */
export interface X25519Slot {
  /** Per-slot ephemeral public key (32 bytes for x25519). */
  readonly epk: Uint8Array;
  /** Wrapped CEK = 32-byte CEK ciphertext + 16-byte ChaCha20-Poly1305 tag = 48 bytes. */
  readonly wrap: Uint8Array;
}

/**
 * Hybrid per-slot wire shape: { kem_ct: [ bstr .size (1..64), ... ], wrap: bstr(48) }.
 * `kem_ct` is the 1120-byte X-Wing enc carried as a chunked byte-string array.
 * There is NO per-slot epk and NO per-slot kem field — the KEM identifier is
 * hoisted to envelope scope (every slot shares it). The X25519 ephemeral lives
 * inside the trailing 32 bytes of the reassembled `kem_ct`.
 */
export interface Mlkem768X25519Slot {
  readonly kem_ct: ReadonlyArray<Uint8Array>;
  /** Wrapped CEK = 48 bytes, identical layout to the classical slot. */
  readonly wrap: Uint8Array;
}

/**
 * Sealed envelope wire shape, discriminated on `kem`. The slot array type is
 * KEM-specific so every consumer is forced — at compile time — to branch on the
 * KEM before touching kem-specific fields.
 *
 * Wire field name: `slots` (per Label 309 §4.4 — recipient pubkeys are NOT on-wire;
 * the array carries opaque wrapped-CEK slots that recipients trial-decrypt with
 * their own private keys). User-facing API parameters (`recipientPublicKeys`,
 * `recipientSecretKey`) keep the "recipient" terminology because those describe
 * identities, not slots. At least one entry; no upper bound is enforced here.
 */
export type SealedEnvelope =
  | {
      readonly scheme: 1;
      readonly aead: 'xchacha20-poly1305';
      readonly kem: 'x25519';
      readonly nonce: Uint8Array;
      readonly slots: ReadonlyArray<X25519Slot>;
      readonly slots_mac: Uint8Array;
    }
  | {
      readonly scheme: 1;
      readonly aead: 'xchacha20-poly1305';
      readonly kem: 'mlkem768x25519';
      readonly nonce: Uint8Array;
      readonly slots: ReadonlyArray<Mlkem768X25519Slot>;
      readonly slots_mac: Uint8Array;
    };

export interface SealedPoeOutput {
  readonly envelope: SealedEnvelope;
  readonly ciphertext: Uint8Array;
}

/**
 * Decryption error codes for the sealed-PoE unwrap path (Label 309 §4.4).
 * Codes use SCREAMING_SNAKE so callers can branch on a stable taxonomy.
 */
export type DecryptErrorCode =
  | 'UNSUPPORTED_ENVELOPE_SCHEME'
  | 'UNSUPPORTED_AEAD_ALG'
  | 'UNSUPPORTED_KEM_ALG'
  | 'INVALID_ENVELOPE_SHAPE'
  | 'ENC_SLOTS_EMPTY'
  // (mlkem768x25519) a slot's `kem_ct` reassembles to a byte string whose
  // length != 1120; checked BEFORE any X-Wing decapsulation (partitioning-
  // oracle defence; the hybrid analogue of the classical epk-length check).
  | 'KEM_CT_LENGTH_MISMATCH'
  | 'INVALID_RECIPIENT_KEY'
  | 'WRONG_RECIPIENT_KEY'
  | 'TAMPERED_HEADER'
  | 'TAMPERED_CIPHERTEXT';

export class SealedPoeDecryptError extends Error {
  readonly code: DecryptErrorCode;
  constructor(code: DecryptErrorCode, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.code = code;
    this.name = 'SealedPoeDecryptError';
  }
}

// ----- Internal helpers -----
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** CSPRNG-shuffle in place using crypto.getRandomValues (Fisher-Yates). */
function csprngShuffle<T>(arr: T[]): void {
  const buf = new Uint32Array(1);
  for (let i = arr.length - 1; i > 0; i--) {
    crypto.getRandomValues(buf);
    const j = (buf[0] ?? 0) % (i + 1);
    const tmp = arr[i]!;
    arr[i] = arr[j]!;
    arr[j] = tmp;
  }
}

/** Encode the slot set as canonical CBOR — input to slots_mac. KEM-driven so the
 * hybrid `kem_ct` is committed by the MAC exactly as it appears on the wire:
 *
 *   • x25519:         each slot → { epk: bstr, wrap: bstr }
 *   • mlkem768x25519: each slot → { kem_ct: [ bstr, ... ], wrap: bstr }
 *
 * The HMAC-SHA-256 input is `canonical_cbor(slots)` — independent of whether the
 * local variable in the call site is named `slots` or `recipients`. The wire
 * field name (Label 309 §4.4) is `slots`. */
function slotsToCborInput(
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  kem: SealedKem,
): Uint8Array {
  if (kem === 'x25519') {
    return encodeCanonicalCbor(
      (slots as ReadonlyArray<X25519Slot>).map((s) => ({ epk: s.epk, wrap: s.wrap })),
    );
  }
  return encodeCanonicalCbor(
    (slots as ReadonlyArray<Mlkem768X25519Slot>).map((s) => ({
      // Spread the chunk views into a fresh array so the encoder receives a
      // plain array of byte strings (the wire form).
      kem_ct: s.kem_ct.map((c) => c),
      wrap: s.wrap,
    })),
  );
}

// ----- Public API: wrap -----
export interface WrapArgs {
  /** Plaintext file content (any length, including zero). */
  plaintext: Uint8Array;
  /**
   * Recipient public keys (>= 1). For kem='x25519' each MUST be exactly 32
   * bytes; for kem='mlkem768x25519' each MUST be exactly 1216 bytes (the X-Wing
   * recipient key). The length is validated against the chosen KEM.
   */
  recipientPublicKeys: ReadonlyArray<Uint8Array>;
  /** KEM branch selector. Defaults to 'x25519' (the classical path). */
  kem?: SealedKem;
  /** Test-only deterministic injection — production callers MUST NOT pass these. */
  cek?: Uint8Array;
  nonce?: Uint8Array;
  /** Deterministic X25519 ephemeral scalars (32 B each) — x25519 branch only. */
  ephemeralSecrets?: ReadonlyArray<Uint8Array>;
  /** Deterministic X-Wing encapsulation randomness (64 B each) — hybrid branch only. */
  eseeds?: ReadonlyArray<Uint8Array>;
  /** Test-only: skip the CSPRNG shuffle for deterministic vector reproducibility. */
  skipShuffle?: boolean;
}

/** Wrap the CEK for one classical recipient: age-style ECIES stanza. */
function wrapSlotX25519(args: {
  pubR: Uint8Array;
  privEph: Uint8Array;
  cek: Uint8Array;
  slotIdx: number;
}): X25519Slot {
  if (args.privEph.length !== 32) {
    throw new RangeError(`ephemeralSecrets[${args.slotIdx}] MUST be 32 bytes`);
  }
  const epk = x25519.getPublicKey(args.privEph);
  const shared = x25519.getSharedSecret(args.privEph, args.pubR);
  // age-style salt: epk || pub_R
  const kek = hkdfSha256({
    ikm: shared,
    salt: concat(epk, args.pubR),
    info: INFO_KEK_V1,
    length: 32,
  });
  const wrap = chacha20poly1305(kek, ZERO_NONCE_12, INFO_KEK_V1).encrypt(args.cek);
  if (wrap.length !== 48) throw new Error(`internal: wrap length ${wrap.length}, expected 48`);
  return { epk, wrap };
}

/** Wrap the CEK for one hybrid recipient: X-Wing encapsulation → HKDF → AEAD.
 * The KEK info label doubles as the wrap AEAD AAD, mirroring the classical path. */
function wrapSlotMlkem768X25519(args: {
  pubR: Uint8Array;
  eseed?: Uint8Array;
  cek: Uint8Array;
}): Mlkem768X25519Slot {
  const { enc: kemCt, ss } = mlkem768x25519Encapsulate({
    publicKey: args.pubR,
    ...(args.eseed !== undefined ? { eseed: args.eseed } : {}),
  });
  if (kemCt.length !== MLKEM768X25519_ENC_LENGTH) {
    throw new Error(`internal: enc length ${kemCt.length}, expected ${MLKEM768X25519_ENC_LENGTH}`);
  }
  // Empty salt: the X-Wing combiner already binds the transcript.
  const kek = hkdfSha256({
    ikm: ss,
    salt: new Uint8Array(0),
    info: INFO_KEK_MLKEM768X25519_V1,
    length: 32,
  });
  const wrap = chacha20poly1305(kek, ZERO_NONCE_12, INFO_KEK_MLKEM768X25519_V1).encrypt(args.cek);
  if (wrap.length !== 48) throw new Error(`internal: wrap length ${wrap.length}, expected 48`);
  return { kem_ct: chunkKemCt(kemCt), wrap };
}

export function eciesSealedPoeWrap(args: WrapArgs): SealedPoeOutput {
  const { plaintext, recipientPublicKeys } = args;
  const kem: SealedKem = args.kem ?? 'x25519';
  const n = recipientPublicKeys.length;
  if (n < 1) {
    throw new RangeError(`recipientPublicKeys.length=${n} must be >= 1`);
  }
  const expectedPubLen = kem === 'x25519' ? 32 : MLKEM768X25519_PUBLIC_KEY_LENGTH;
  for (let i = 0; i < n; i++) {
    const pubR = recipientPublicKeys[i];
    if (pubR === undefined || pubR.length !== expectedPubLen) {
      throw new RangeError(
        `recipientPublicKeys[${i}] MUST be exactly ${expectedPubLen} bytes for kem='${kem}'`,
      );
    }
  }
  if (kem === 'x25519') {
    if (args.eseeds !== undefined) {
      throw new RangeError("eseeds is an mlkem768x25519 override; do not pass it for kem='x25519'");
    }
    if (args.ephemeralSecrets && args.ephemeralSecrets.length !== n) {
      throw new RangeError('ephemeralSecrets length must match recipientPublicKeys');
    }
  } else {
    if (args.ephemeralSecrets !== undefined) {
      throw new RangeError(
        "ephemeralSecrets is an x25519 override; do not pass it for kem='mlkem768x25519'",
      );
    }
    if (args.eseeds !== undefined) {
      if (args.eseeds.length !== n) {
        throw new RangeError('eseeds length must match recipientPublicKeys');
      }
      for (let i = 0; i < n; i++) {
        if (args.eseeds[i]!.length !== MLKEM768X25519_ESEED_LENGTH) {
          throw new RangeError(`eseeds[${i}] MUST be ${MLKEM768X25519_ESEED_LENGTH} bytes`);
        }
      }
    }
  }

  const cek = args.cek ?? randomBytes(32);
  const nonce = args.nonce ?? randomBytes(24);
  if (cek.length !== 32) throw new RangeError('CEK MUST be 32 bytes');
  if (nonce.length !== 24) throw new RangeError('nonce MUST be 24 bytes');

  let envelope: SealedEnvelope;
  if (kem === 'x25519') {
    const slots: X25519Slot[] = [];
    for (let i = 0; i < n; i++) {
      slots.push(
        wrapSlotX25519({
          pubR: recipientPublicKeys[i]!,
          privEph: args.ephemeralSecrets ? args.ephemeralSecrets[i]! : randomBytes(32),
          cek,
          slotIdx: i,
        }),
      );
    }
    // CSPRNG-shuffle to prevent ordering leak (security-critical).
    if (!args.skipShuffle) csprngShuffle(slots);
    const slotsMac = computeSlotsMac(cek, slots, 'x25519');
    envelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'x25519',
      nonce,
      slots,
      slots_mac: slotsMac,
    };
  } else {
    const slots: Mlkem768X25519Slot[] = [];
    for (let i = 0; i < n; i++) {
      slots.push(
        wrapSlotMlkem768X25519({
          pubR: recipientPublicKeys[i]!,
          ...(args.eseeds ? { eseed: args.eseeds[i]! } : {}),
          cek,
        }),
      );
    }
    if (!args.skipShuffle) csprngShuffle(slots);
    const slotsMac = computeSlotsMac(cek, slots, 'mlkem768x25519');
    envelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'mlkem768x25519',
      nonce,
      slots,
      slots_mac: slotsMac,
    };
  }

  // Content layer. AAD = nonce || slots_mac (24 + 32 = 56 bytes). KEM-independent.
  const aadContent = concat(nonce, envelope.slots_mac);
  const ciphertext = xchacha20poly1305(cek, nonce, aadContent).encrypt(plaintext);
  return { envelope, ciphertext };
}

/** Slot-set MAC binds canonical-CBOR(slots) to the CEK (KEM-driven slot CBOR). */
function computeSlotsMac(
  cek: Uint8Array,
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  kem: SealedKem,
): Uint8Array {
  const hmacKey = hkdfSha256({
    ikm: cek,
    salt: new Uint8Array(0),
    info: INFO_SLOTS_MAC_V1,
    length: 32,
  });
  return hmac(sha256, hmacKey, slotsToCborInput(slots, kem));
}

// ----- Public API: unwrap (trial-decrypt) -----
export interface UnwrapArgs {
  envelope: SealedEnvelope;
  ciphertext: Uint8Array;
  /**
   * For kem='x25519' this is the recipient's 32-byte X25519 private key; for
   * kem='mlkem768x25519' it is the recipient's 32-byte X-Wing secret seed.
   * Both are 32 bytes; which one applies is selected from `envelope.kem`.
   */
  recipientSecretKey: Uint8Array;
}

/**
 * Attempt to open one classical slot. Returns the candidate CEK on AEAD-tag
 * success, or null on any non-match (low-order epk rejection / AEAD failure).
 */
function tryOpenX25519Slot(
  slot: X25519Slot,
  privR: Uint8Array,
  pubRLocal: Uint8Array,
): Uint8Array | null {
  if (slot.epk.length !== 32 || slot.wrap.length !== 48) return null;
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privR, slot.epk);
  } catch {
    return null; // low-order epk (RFC 7748 §6.1 contributory-check rejection)
  }
  const kek = hkdfSha256({
    ikm: shared,
    salt: concat(slot.epk, pubRLocal),
    info: INFO_KEK_V1,
    length: 32,
  });
  try {
    return chacha20poly1305(kek, ZERO_NONCE_12, INFO_KEK_V1).decrypt(slot.wrap);
  } catch {
    return null;
  }
}

/**
 * Attempt to open one hybrid slot. X-Wing.Decapsulate NEVER throws on attacker
 * wire data (ML-KEM implicit rejection yields a pseudorandom shared secret), so
 * a wrong seed simply produces a KEK whose AEAD tag fails — returned as a
 * non-match (null). The slot's `kem_ct` MUST already have been length-checked.
 */
function tryOpenMlkem768X25519Slot(
  slot: Mlkem768X25519Slot,
  secretSeed: Uint8Array,
): Uint8Array | null {
  if (slot.wrap.length !== 48) return null;
  const ss = mlkem768x25519Decapsulate({ secretSeed, enc: joinKemCt(slot.kem_ct) });
  // Empty salt: the X-Wing combiner already binds the transcript.
  const kek = hkdfSha256({
    ikm: ss,
    salt: new Uint8Array(0),
    info: INFO_KEK_MLKEM768X25519_V1,
    length: 32,
  });
  try {
    return chacha20poly1305(kek, ZERO_NONCE_12, INFO_KEK_MLKEM768X25519_V1).decrypt(slot.wrap);
  } catch {
    return null;
  }
}

export function eciesSealedPoeUnwrap(args: UnwrapArgs): Uint8Array {
  const { envelope, ciphertext, recipientSecretKey: privR } = args;

  if (envelope.scheme !== 1) {
    throw new SealedPoeDecryptError('UNSUPPORTED_ENVELOPE_SCHEME', `enc.scheme=${envelope.scheme}`);
  }
  if (envelope.aead !== 'xchacha20-poly1305') {
    throw new SealedPoeDecryptError('UNSUPPORTED_AEAD_ALG', envelope.aead);
  }
  if (envelope.kem !== 'x25519' && envelope.kem !== 'mlkem768x25519') {
    throw new SealedPoeDecryptError('UNSUPPORTED_KEM_ALG', (envelope as { kem: string }).kem);
  }
  if (envelope.nonce.length !== 24) {
    throw new SealedPoeDecryptError('INVALID_ENVELOPE_SHAPE', 'nonce length');
  }
  if (envelope.slots_mac.length !== 32) {
    throw new SealedPoeDecryptError('INVALID_ENVELOPE_SHAPE', 'slots_mac length');
  }
  if (envelope.slots.length < 1) {
    throw new SealedPoeDecryptError('ENC_SLOTS_EMPTY', String(envelope.slots.length));
  }
  // Both branches use a 32-byte recipient secret (X25519 private key / X-Wing seed).
  if (privR.length !== MLKEM768X25519_SEED_LENGTH) {
    throw new SealedPoeDecryptError('INVALID_RECIPIENT_KEY', 'recipient secret length');
  }
  // Partitioning-oracle defence (hybrid): every `kem_ct` MUST reassemble to the
  // exact X-Wing enc length BEFORE any decapsulation, so malformed records
  // cannot probe per-slot failure ordering.
  if (envelope.kem === 'mlkem768x25519') {
    for (const slot of envelope.slots) {
      if (joinKemCt(slot.kem_ct).length !== MLKEM768X25519_ENC_LENGTH) {
        throw new SealedPoeDecryptError('KEM_CT_LENGTH_MISMATCH', 'kem_ct reassembled length');
      }
    }
  }

  // Pre-compute slots_mac inputs once (constant across slots), KEM-driven.
  const slotsCbor = slotsToCborInput(
    envelope.slots as ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
    envelope.kem,
  );
  // X25519 recipient public key, needed only by the classical salt.
  const pubRLocal = envelope.kem === 'x25519' ? x25519.getPublicKey(privR) : undefined;

  // Distinguish "no slot ever opened under the recipient secret" (WRONG_RECIPIENT_KEY)
  // from "some slot opened but no opened slot's CEK satisfies slots_mac"
  // (TAMPERED_HEADER). A malicious sender can inject a slot opening under the
  // recipient secret with an attacker-controlled CEK; early-exit on first
  // AEAD-success would let the forged slot shadow the real one. We therefore
  // continue scanning until an opened slot's CEK verifies slots_mac or the slot
  // list is exhausted.
  let cek: Uint8Array | null = null;
  let openedAny = false;

  for (const slot of envelope.slots) {
    const candidateCek =
      envelope.kem === 'x25519'
        ? tryOpenX25519Slot(slot as X25519Slot, privR, pubRLocal!)
        : tryOpenMlkem768X25519Slot(slot as Mlkem768X25519Slot, privR);
    if (candidateCek === null) continue;
    openedAny = true;
    // Verify slots_mac under THIS candidate CEK. Only the slot whose CEK matches
    // the sender's HMAC_KEY can produce the on-wire slots_mac.
    const hmacKey = hkdfSha256({
      ikm: candidateCek,
      salt: new Uint8Array(0),
      info: INFO_SLOTS_MAC_V1,
      length: 32,
    });
    const slotsMacCalc = hmac(sha256, hmacKey, slotsCbor);
    if (constantTimeEqual(slotsMacCalc, envelope.slots_mac)) {
      cek = candidateCek;
      break;
    }
    // Otherwise this is a forged or tampered slot — keep scanning.
  }

  if (cek === null) {
    if (!openedAny) {
      throw new SealedPoeDecryptError(
        'WRONG_RECIPIENT_KEY',
        'no slot opened under recipient secret',
      );
    }
    throw new SealedPoeDecryptError('TAMPERED_HEADER', 'opened slot(s) did not satisfy slots_mac');
  }

  // Decrypt content (KEM-independent).
  const aadContent = concat(envelope.nonce, envelope.slots_mac);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(cek, envelope.nonce, aadContent).decrypt(ciphertext);
  } catch (e) {
    throw new SealedPoeDecryptError(
      'TAMPERED_CIPHERTEXT',
      e instanceof Error ? e.message : 'aead failure',
    );
  }
  return plaintext;
}
