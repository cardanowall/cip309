// Label 309 reference implementation — multi-recipient sealed-PoE (scheme 1).
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
//     salt_i      ← SHA-256("cardano-poe-xwing-kek-salt-v1" || enc_i || pub_R_i)
//     KEK_i       ← HKDF-SHA-256(ikm=shared_i, salt=salt_i,
//                                  info="cardano-poe-kek-mlkem768x25519-v1", L=32)
//     wrap_i      ← ChaCha20-Poly1305(KEK_i, nonce=zeros(12),
//                                      aad="cardano-poe-kek-mlkem768x25519-v1", CEK)
//     slot_i      = { kem_ct: chunk64(enc_i), wrap: wrap_i }
//   CSPRNG-shuffle the slot array (security-critical — prevents ordering leak).
//   Reject duplicate per-slot KEM material so the zero-nonce wrap never reuses
//   a (KEK, nonce) pair.
//
//   slots_hash  ← SHA-256("cardano-poe-slots-transcript-v1" || canonicalCBOR(TRANSCRIPT))
//                  where TRANSCRIPT is the closed map
//                  { scheme, path: "slots", aead, kem, nonce, slots }.
//   HMAC_KEY    ← HKDF-SHA-256(ikm=CEK, salt="", info="cardano-poe-slots-mac-v1", L=32)
//   slots_mac   ← HMAC-SHA-256(HMAC_KEY, slots_hash)
//   nonce       ← randomBytes(24)
//   payload_key ← HKDF-SHA-256(ikm=CEK, salt=nonce, info="cardano-poe-payload-v1", L=32)
//   AAD_CONTENT ← canonicalCBOR({ scheme, path: "slots", aead, kem, nonce,
//                                 slots_hash, slots_mac })
//   ciphertext  ← XChaCha20-Poly1305(payload_key, nonce, aad=AAD_CONTENT, plaintext)
//
// The content is encrypted under a payload_key derived from the CEK, never under
// the CEK directly. The slots transcript hash binds the cross-KEM header fields
// to the slot set; the content AAD re-binds the same header plus both the
// transcript hash and the CEK-keyed MAC.
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
  mlkem768x25519Keygen,
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
// SHA-256 prefix over the slots transcript; the resulting slots_hash is the
// constant-across-the-loop message the CEK-keyed HMAC signs.
const SLOTS_TRANSCRIPT_PREFIX_V1: Uint8Array = enc.encode('cardano-poe-slots-transcript-v1'); // 31 ASCII bytes
// HKDF info for the slots-path content payload_key (derived from the CEK; the
// content is never encrypted under the CEK directly).
const INFO_PAYLOAD_V1: Uint8Array = enc.encode('cardano-poe-payload-v1'); // 22 ASCII bytes
// SHA-256 prefix binding the reassembled hybrid kem_ct and the recipient X-Wing
// public key into the per-slot KEK salt, mirroring the classical salt's two
// bindings (slot-unique value + recipient public key) through a fixed-length
// digest because the hybrid inputs are oversized.
const XWING_KEK_SALT_PREFIX_V1: Uint8Array = enc.encode('cardano-poe-xwing-kek-salt-v1'); // 29 ASCII bytes
const ZERO_NONCE_12: Uint8Array = new Uint8Array(12);
const EMPTY_SALT: Uint8Array = new Uint8Array(0);

// XChaCha20-Poly1305 is a single-shot AEAD over the whole plaintext; its 32-bit
// internal block counter bounds one (key, nonce) invocation at 2^32 64-byte
// ChaCha20 blocks, the first of which is consumed by the Poly1305 one-time key.
// MAX_SEALED_PLAINTEXT is therefore (2^32 - 1) * 64 = 2^38 - 64 bytes; a payload
// at or above it risks a counter-overflow keystream collision and MUST be
// rejected before the AEAD runs on either side. The ciphertext carries an extra
// 16-byte Poly1305 tag, so the ciphertext bound is + 16.
export const MAX_SEALED_PLAINTEXT = 2 ** 38 - 64;
const MAX_SEALED_CIPHERTEXT = MAX_SEALED_PLAINTEXT + 16;

// Verifier-side resource bounds enforced BEFORE any KEM/AEAD primitive runs, so a
// malformed envelope cannot drive unbounded per-slot work. Both are
// deployment-pinned reference constants (not wire fields); deployments MAY tighten
// them. They sit far above the ~16 KiB Cardano transaction-metadata ceiling that
// bounds honest records, so a conformant record never trips them.
//   • MAX_SLOTS — the maximum slot count; an envelope with more slots is rejected.
//   • MAX_DECODED_ENVELOPE_BYTES — a backstop on the decoded envelope's aggregate
//     byte size (nonce + slots_mac + per-slot wire fields).
export const MAX_SLOTS = 1024;
export const MAX_DECODED_ENVELOPE_BYTES = 65536;

// Component sizes the decoded-envelope backstop adds up.
const NONCE_LENGTH = 24;
const SLOTS_MAC_LENGTH = 32;
const X25519_PUBLIC_KEY_LENGTH = 32;
const WRAP_LENGTH = 48;

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
 * identities, not slots. At least one entry; the producer polices its own
 * per-record byte budget, while the verifier enforces `MAX_SLOTS` /
 * `MAX_DECODED_ENVELOPE_BYTES` before any primitive runs.
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
  // Resource bounds tripped before any KEM/AEAD primitive: more than MAX_SLOTS
  // slots, or a decoded envelope larger than MAX_DECODED_ENVELOPE_BYTES.
  | 'ENC_SLOTS_TOO_MANY'
  | 'ENC_ENVELOPE_TOO_LARGE'
  // (mlkem768x25519) a slot's `kem_ct` reassembles to a byte string whose
  // length != 1120; checked BEFORE any X-Wing decapsulation (partitioning-
  // oracle defence; the hybrid analogue of the classical epk-length check).
  | 'KEM_CT_LENGTH_MISMATCH'
  // Two slots carry identical per-slot KEM material (duplicate `epk` for
  // x25519, or duplicate reassembled `kem_ct` for the hybrid path). The
  // zero-nonce per-slot wrap is sound only under per-slot KEK uniqueness;
  // repeated KEM material can repeat the (KEK, nonce) pair, so the envelope is
  // rejected before any decapsulation.
  | 'ENC_SLOTS_DUPLICATE_KEM_MATERIAL'
  // A payload at or above the XChaCha20-Poly1305 single-shot keystream bound;
  // enforced on both encrypt and decrypt before the AEAD primitive runs.
  | 'PAYLOAD_TOO_LARGE'
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

/** Canonicalise the slot set — the value bound under the `slots` key of the
 * slots transcript and the slots_mac. KEM-driven so the hybrid `kem_ct` is
 * committed exactly as it appears on the wire:
 *
 *   • x25519:         each slot → { epk: bstr, wrap: bstr }
 *   • mlkem768x25519: each slot → { kem_ct: [ bstr, ... ], wrap: bstr }
 *
 * The hybrid form re-chunks `kem_ct` into its canonical <=64-byte sequence so
 * the transcript depends on the kem_ct BYTES, not on whatever chunk boundaries
 * arrived on the wire: a record re-chunked in transit still verifies, and any
 * byte flip in kem_ct still changes the transcript. */
function canonicalizeSlots(
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  kem: SealedKem,
): unknown {
  if (kem === 'x25519') {
    return (slots as ReadonlyArray<X25519Slot>).map((s) => ({ epk: s.epk, wrap: s.wrap }));
  }
  return (slots as ReadonlyArray<Mlkem768X25519Slot>).map((s) => ({
    kem_ct: chunkKemCt(joinKemCt(s.kem_ct)),
    wrap: s.wrap,
  }));
}

/** slots_hash = SHA-256("cardano-poe-slots-transcript-v1" || canonicalCBOR(TRANSCRIPT)).
 * TRANSCRIPT is the closed six-key map binding the cross-KEM header fields
 * (scheme, path, aead, kem, nonce) to the canonicalised slot set, so a relay
 * that flips any header field while leaving slot shapes valid yields a different
 * `slots_hash` and the MAC fails. The map keys are a SET — their wire order is
 * fixed by the canonical-encode sort, never hand-arranged here. Computed ONCE
 * per envelope and held constant across the recipient trial-decrypt loop. */
function computeSlotsHash(
  nonce: Uint8Array,
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  kem: SealedKem,
): Uint8Array {
  const transcript = {
    scheme: 1,
    path: 'slots',
    aead: 'xchacha20-poly1305',
    kem,
    nonce,
    slots: canonicalizeSlots(slots, kem),
  };
  const encoded = encodeCanonicalCbor(transcript);
  return sha256(concat(SLOTS_TRANSCRIPT_PREFIX_V1, encoded));
}

/** slots_mac = HMAC-SHA-256(HKDF(CEK, "", "cardano-poe-slots-mac-v1", 32), slots_hash). */
function computeSlotsMac(cek: Uint8Array, slotsHash: Uint8Array): Uint8Array {
  const hmacKey = hkdfSha256({ ikm: cek, salt: EMPTY_SALT, info: INFO_SLOTS_MAC_V1, length: 32 });
  return hmac(sha256, hmacKey, slotsHash);
}

/** canonicalCBOR(AD_CONTENT_SLOTS): the closed seven-key content-AEAD AAD for the
 * slots path. It re-binds the slots-path header AND carries both `slots_hash`
 * (binding to the exact transcript) and `slots_mac` (tying the content layer to
 * the CEK-keyed MAC the recipient matched). */
function adContentSlots(
  nonce: Uint8Array,
  kem: SealedKem,
  slotsHash: Uint8Array,
  slotsMac: Uint8Array,
): Uint8Array {
  return encodeCanonicalCbor({
    scheme: 1,
    path: 'slots',
    aead: 'xchacha20-poly1305',
    kem,
    nonce,
    slots_hash: slotsHash,
    slots_mac: slotsMac,
  });
}

/** Slots-path content key: HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-v1). */
function slotsPayloadKey(cek: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdfSha256({ ikm: cek, salt: nonce, info: INFO_PAYLOAD_V1, length: 32 });
}

/** Hybrid (X-Wing) per-slot KEK salt:
 * SHA-256("cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R). `kem_ct` is the
 * reassembled 1120-byte X-Wing ciphertext (anchoring the KEK to a slot-unique
 * value) and `pub_R` the 1216-byte recipient public key (binding the KEK to the
 * specific recipient) — the same two bindings the classical `epk || pub_R` salt
 * provides, through a fixed-length digest because the hybrid inputs are
 * oversized. Computed over the slot's own wire bytes, so X-Wing stays a
 * black-box KEM. */
function xwingKekSalt(kemCt: Uint8Array, pubR: Uint8Array): Uint8Array {
  return sha256(concat(XWING_KEK_SALT_PREFIX_V1, kemCt, pubR));
}

/** Reject duplicate per-slot KEM material — a repeated `epk` (x25519) or a
 * repeated reassembled `kem_ct` (hybrid). The zero-nonce wrap is sound only when
 * every slot's KEK is unique; the KEK is a deterministic function of the slot's
 * KEM material, so two slots with identical material against the same recipient
 * repeat the (KEK, nonce) pair. Enforced on both the producer side (before the
 * wire) and the verifier side (before any decapsulation). */
function assertUniqueSlotKemMaterial(
  slots: ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
  kem: SealedKem,
): void {
  const seen = new Set<string>();
  for (let i = 0; i < slots.length; i++) {
    const slot = slots[i]!;
    const material =
      kem === 'x25519' ? (slot as X25519Slot).epk : joinKemCt((slot as Mlkem768X25519Slot).kem_ct);
    const key = hex(material);
    if (seen.has(key)) {
      const field = kem === 'x25519' ? 'epk' : 'kem_ct';
      throw new SealedPoeDecryptError(
        'ENC_SLOTS_DUPLICATE_KEM_MATERIAL',
        `slots[${i}].${field} duplicates an earlier slot; per-slot KEK uniqueness is violated`,
      );
    }
    seen.add(key);
  }
}

function hex(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i++) out += (b[i] ?? 0).toString(16).padStart(2, '0');
  return out;
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
  // Salt binds the reassembled kem_ct and the recipient public key, so both
  // KEMs uniformly anchor the KEK to a slot-unique value and to the recipient.
  const kek = hkdfSha256({
    ikm: ss,
    salt: xwingKekSalt(kemCt, args.pubR),
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

  // Reject before any keystream is drawn: a payload at or above the single-shot
  // bound cannot be safely encrypted.
  if (plaintext.length >= MAX_SEALED_PLAINTEXT) {
    throw new SealedPoeDecryptError(
      'PAYLOAD_TOO_LARGE',
      `plaintext length ${plaintext.length} is at or above the single-shot bound ${MAX_SEALED_PLAINTEXT}`,
    );
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
    // Per-slot KEK uniqueness is the safety condition for the zero-nonce wrap;
    // reject a duplicate epk before committing anything to the wire.
    assertUniqueSlotKemMaterial(slots, 'x25519');
    // CSPRNG-shuffle to prevent ordering leak (security-critical). The slots_mac
    // is computed AFTER the shuffle, binding the on-wire order.
    if (!args.skipShuffle) csprngShuffle(slots);
    const slotsHash = computeSlotsHash(nonce, slots, 'x25519');
    const slotsMac = computeSlotsMac(cek, slotsHash);
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
    assertUniqueSlotKemMaterial(slots, 'mlkem768x25519');
    if (!args.skipShuffle) csprngShuffle(slots);
    const slotsHash = computeSlotsHash(nonce, slots, 'mlkem768x25519');
    const slotsMac = computeSlotsMac(cek, slotsHash);
    envelope = {
      scheme: 1,
      aead: 'xchacha20-poly1305',
      kem: 'mlkem768x25519',
      nonce,
      slots,
      slots_mac: slotsMac,
    };
  }

  // Content layer. The content is encrypted under a payload_key derived from the
  // CEK (never the CEK directly), with a structured AAD that re-binds the
  // slots-path header plus both slots_hash and slots_mac.
  const slotsHash = computeSlotsHash(nonce, envelope.slots, envelope.kem);
  const payloadKey = slotsPayloadKey(cek, nonce);
  const aadContent = adContentSlots(nonce, envelope.kem, slotsHash, envelope.slots_mac);
  const ciphertext = xchacha20poly1305(payloadKey, nonce, aadContent).encrypt(plaintext);
  return { envelope, ciphertext };
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

// All-zero IKM for the dummy KEK an invalid-ECDH slot derives so it pays the same
// HKDF work as a live slot (see tryOpenX25519Slot).
const ZERO_IKM_32: Uint8Array = new Uint8Array(32);

/**
 * Attempt to open one classical slot. Returns the candidate CEK on AEAD-tag
 * success, or null on any non-match.
 *
 * Acceptance is `kem_ok AND open_ok`. `kem_ok` is the X25519 validity bit: a
 * small-order epk drives the shared secret to all-zero, which RFC 7748 §6.1
 * rejects. @noble signals that all-zero case by throwing, so a fully branchless
 * ct-select over the shared secret is not expressible against this library API.
 * The equivalent form is taken instead: on the all-zero rejection the slot
 * derives a DUMMY KEK from `ikm=0^32` (same salt/info) so it performs the
 * identical HKDF work, then returns a non-match WITHOUT attempting the AEAD — so
 * an invalid-ECDH slot can never be accepted regardless of the wrap outcome
 * (`kem_ok=false` ⟹ the AEAD is never reached), while the failed path still
 * costs the same per-slot KEK derivation as a live one.
 */
function tryOpenX25519Slot(
  slot: X25519Slot,
  privR: Uint8Array,
  pubRLocal: Uint8Array,
): Uint8Array | null {
  if (slot.epk.length !== 32 || slot.wrap.length !== 48) return null;
  const salt = concat(slot.epk, pubRLocal);
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privR, slot.epk);
  } catch {
    // kem_ok = false (low-order epk; RFC 7748 §6.1 contributory-check rejection).
    // Derive the dummy KEK so the failed slot pays the same HKDF cost a live slot
    // would, then short-circuit to a non-match: the AEAD is never attempted, so
    // this slot can never be accepted.
    hkdfSha256({ ikm: ZERO_IKM_32, salt, info: INFO_KEK_V1, length: 32 });
    return null;
  }
  // kem_ok = true. Derive the real KEK and attempt the wrap AEAD.
  const kek = hkdfSha256({ ikm: shared, salt, info: INFO_KEK_V1, length: 32 });
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
 * `pubRLocal` is the recipient's own 1216-byte X-Wing public key, recomputed
 * from the held seed — the same value the producer bound into the KEK salt.
 */
function tryOpenMlkem768X25519Slot(
  slot: Mlkem768X25519Slot,
  secretSeed: Uint8Array,
  pubRLocal: Uint8Array,
): Uint8Array | null {
  if (slot.wrap.length !== 48) return null;
  const kemCt = joinKemCt(slot.kem_ct);
  const ss = mlkem768x25519Decapsulate({ secretSeed, enc: kemCt });
  // Salt binds the reassembled kem_ct and the recipient public key, computed
  // over the slot's own wire bytes (X-Wing stays a black-box KEM).
  const kek = hkdfSha256({
    ikm: ss,
    salt: xwingKekSalt(kemCt, pubRLocal),
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
  // Resource bound: reject an envelope with more than MAX_SLOTS slots before any
  // KEM/AEAD primitive runs, so a malformed record cannot drive unbounded
  // per-slot work.
  if (envelope.slots.length > MAX_SLOTS) {
    throw new SealedPoeDecryptError(
      'ENC_SLOTS_TOO_MANY',
      `slots.length=${envelope.slots.length} exceeds MAX_SLOTS=${MAX_SLOTS}`,
    );
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
  // Decoded-envelope byte backstop. Every per-slot field is fixed-length, so the
  // decoded envelope's aggregate size is determined here: nonce + slots_mac +
  // per-slot (epk|kem_ct + wrap). Reject before any KEM/AEAD primitive when it
  // exceeds the bound — the byte cap a parser that can see the decoded size
  // enforces, alongside the slot-count cap above.
  const perSlotBytes =
    envelope.kem === 'x25519'
      ? X25519_PUBLIC_KEY_LENGTH + WRAP_LENGTH
      : MLKEM768X25519_ENC_LENGTH + WRAP_LENGTH;
  const decodedEnvelopeBytes =
    NONCE_LENGTH + SLOTS_MAC_LENGTH + envelope.slots.length * perSlotBytes;
  if (decodedEnvelopeBytes > MAX_DECODED_ENVELOPE_BYTES) {
    throw new SealedPoeDecryptError(
      'ENC_ENVELOPE_TOO_LARGE',
      `decoded envelope size ${decodedEnvelopeBytes} exceeds MAX_DECODED_ENVELOPE_BYTES=${MAX_DECODED_ENVELOPE_BYTES}`,
    );
  }
  // Per-slot KEK uniqueness — rejected before any decapsulation so a duplicate
  // never enters the trial-decrypt loop.
  assertUniqueSlotKemMaterial(
    envelope.slots as ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
    envelope.kem,
  );

  // The slots transcript hash is constant across every trial-decrypt pass
  // (depends only on the envelope), so it is computed once here.
  const slotsHash = computeSlotsHash(
    envelope.nonce,
    envelope.slots as ReadonlyArray<X25519Slot | Mlkem768X25519Slot>,
    envelope.kem,
  );
  // Recipient public key, recomputed from the held secret. The classical salt
  // is `epk || pub_R`; the hybrid salt binds the recipient's X-Wing public key.
  const pubRLocal =
    envelope.kem === 'x25519' ? x25519.getPublicKey(privR) : mlkem768x25519Keygen(privR).publicKey;

  // Trial-decrypt loop. Iterate ALL slots — no early break on a match — so the
  // acceptance follows the spec loop shape:
  //
  //   ok           = kem_ok AND open_ok AND mac_ok        ; mac folded in
  //   first        = ok AND NOT found                      ; first matching slot
  //   cek_conflict = cek_conflict OR (ok AND found AND NOT ctEq(cand, selected))
  //   selected_CEK = first ? cand : selected
  //   found        = found OR ok
  //
  // Folding the slots_mac check into acceptance is load-bearing: a malicious
  // sender can inject a slot that opens under the recipient secret with an
  // attacker-chosen CEK; requiring the candidate CEK to also reproduce the
  // on-wire slots_mac over the constant slots_hash defeats slot substitution,
  // removal, and reorder. Multiple matching slots are PERMITTED (a producer may
  // seal the same CEK to one recipient in several slots to pad the count); the
  // FIRST match's CEK is selected. The narrow anomaly rejected is two matching
  // slots that recover DIFFERENT CEKs (constant-time compare) — a commitment
  // collision that fails the record closed (cekConflict), distinct from the
  // within-record duplicate-KEM-material rejection above.
  let cek: Uint8Array | null = null;
  let openedAny = false; // a wrap AEAD opened under the recipient secret (no MAC yet)
  let cekConflict = false;

  for (const slot of envelope.slots) {
    const candidateCek =
      envelope.kem === 'x25519'
        ? tryOpenX25519Slot(slot as X25519Slot, privR, pubRLocal)
        : tryOpenMlkem768X25519Slot(slot as Mlkem768X25519Slot, privR, pubRLocal);
    if (candidateCek === null) continue;
    openedAny = true;
    // Verify slots_mac under THIS candidate CEK over the constant slots_hash.
    // Only a slot whose CEK matches the sender's HMAC_KEY can produce the on-wire
    // slots_mac, so `ok` includes the MAC check.
    const slotsMacCalc = computeSlotsMac(candidateCek, slotsHash);
    if (!constantTimeEqual(slotsMacCalc, envelope.slots_mac)) {
      continue; // a forged or tampered slot — keep scanning
    }
    if (cek === null) {
      cek = candidateCek; // first matching slot
    } else if (!constantTimeEqual(candidateCek, cek)) {
      // A later matching slot recovered a CEK that differs from the selected one.
      // Fail closed (defence-in-depth against a commitment collision).
      cekConflict = true;
    }
  }

  if (cekConflict) {
    throw new SealedPoeDecryptError('TAMPERED_HEADER', 'matching slots recovered conflicting CEKs');
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

  // Guard the single-shot bound before invoking the AEAD.
  if (ciphertext.length >= MAX_SEALED_CIPHERTEXT) {
    throw new SealedPoeDecryptError(
      'PAYLOAD_TOO_LARGE',
      `ciphertext length ${ciphertext.length} is at or above the single-shot bound ${MAX_SEALED_CIPHERTEXT}`,
    );
  }

  // Content is opened under a payload_key derived from the recovered CEK, with
  // the structured slots-path AAD recomputed from the envelope (KEM-independent).
  const payloadKey = slotsPayloadKey(cek, envelope.nonce);
  const aadContent = adContentSlots(envelope.nonce, envelope.kem, slotsHash, envelope.slots_mac);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(payloadKey, envelope.nonce, aadContent).decrypt(ciphertext);
  } catch (e) {
    throw new SealedPoeDecryptError(
      'TAMPERED_CIPHERTEXT',
      e instanceof Error ? e.message : 'aead failure',
    );
  }
  return plaintext;
}
