// CIP-309 v1 reference implementation — structural record validator
// Spec: CIP-309 (record schema + structural validation).
// Pure-function validator: takes CBOR bytes, returns ValidationResult.
// Does NOT touch network. Does NOT verify signatures cryptographically (only
// decodes + structural checks).
//
// Issue codes are SCREAMING_SNAKE_CASE and form a stable structural-error
// taxonomy. `SIGNATURE_UNSUPPORTED` is an info-severity diagnostic on the
// offending `sigs[i]` entry; attached payloads are MALFORMED_SIG_COSE_SIGN1.

import { decode as decodeCbor } from 'cbor2';
import { z } from 'zod';
import { decodeCanonicalCbor } from './cbor-canonical.ts';
import { decodeCoseSign1 } from './cose-sign1.ts';
import { isValidCid } from './cid-validator.ts';

// === Constants ===

// EdDSA (M., RFC 9053 §2.2). This reference verifier ships the mandatory
// baseline only. OPT-INFO-tier `-19` (Ed25519, fully-specified per RFC 9864)
// is registered in CIP-309 §4.10.7; a deployment wishing to accept `-19`
// extends this set — verification under the Ed25519 primitive is identical
// for the two codepoints.
const KNOWN_SIG_ALG_IDS = new Set([-8]);
const AEAD_NONCE_LENGTHS: Record<string, number> = {
  'xchacha20-poly1305': 24,
};

// Registered content-hash algorithms (per CIP-309 §4.10.2). `hashes` is a CBOR
// map keyed by these identifiers; canonical CBOR map-key sort gives a single
// byte-stable ordering. CBOR map-key uniqueness (RFC 8949 §3.1) guarantees
// one digest per algorithm — duplicates surface at canonical decode as
// MALFORMED_CBOR. Every identifier here is a content-hash; list commitments
// (Merkle roots) live in the separate top-level `merkle[]` field
// (CIP-309 §4.5) and are governed by MERKLE_COMMIT_ALGS below.
const HASH_ALGS: Record<string, number> = {
  'sha2-256': 32,
  'blake2b-256': 32,
};
const KNOWN_HASH_ALGS = new Set<string>(Object.keys(HASH_ALGS));

// Registered Merkle list-commitment algorithms (per CIP-309 §4.10.3). The
// top-level `merkle[]` field carries one entry per list commitment, each
// with `{alg, root, leaf_count, uris?}`; `alg` MUST be a key here and `root`
// MUST match the pinned digest length. The identifier `rfc9162-sha256` is
// the IANA COSE Verifiable Data Structure Algorithms registry name
// (codepoint 1, draft-ietf-cose-merkle-tree-proofs-18). Unknown `alg`
// surfaces as `UNSUPPORTED_MERKLE_COMMIT_ALG` per CIP-309.
const MERKLE_COMMIT_ALGS: Record<string, number> = {
  'rfc9162-sha256': 32,
};
const KNOWN_MERKLE_COMMIT_ALGS = new Set<string>(
  Object.keys(MERKLE_COMMIT_ALGS),
);

// Forward-compat extension-key tolerance (CIP-309 §4.1.4). Keys matching either
// regex are extension keys (vendor / experimental for `^x-.+`; companion-CIP
// namespace for `^[a-z]+-.+`) and MUST be preserved by v1 verifiers without
// claiming verification of their contents.
const EXTENSION_KEY_VENDOR_RE = /^x-.+/;
const EXTENSION_KEY_COMPANION_RE = /^[a-z]+-.+/;

function isExtensionKey(k: string): boolean {
  return EXTENSION_KEY_VENDOR_RE.test(k) || EXTENSION_KEY_COMPANION_RE.test(k);
}

// Top-level base keys defined in CIP-309 §4.1. Any unknown key that is NOT an
// extension key is a `SCHEMA_UNKNOWN_FIELD` (e.g. typos like `supersedess`
// or `Sigs`).
const TOP_LEVEL_BASE_KEYS = new Set<string>([
  'v',
  'items',
  'merkle',
  'supersedes',
  'sigs',
  'crit',
]);

// === Schemas ===

// Per CIP-309 §4.8 and the CDDL `bstr .size (1..64)` / `tstr .size (1..64)` shapes,
// each chunk MUST be between 1 and 64 bytes inclusive. Zero-length chunks are
// rejected with the same code as oversized ones.
const ChunkedBytesArraySchema = z
  .array(
    z
      .instanceof(Uint8Array)
      .refine((b) => b.length >= 1 && b.length <= 64, {
        params: { code: 'CHUNK_TOO_LARGE' },
      }),
  )
  .min(1);

const ChunkedTstrArraySchema = z
  .array(
    z.string().refine(
      (s) => {
        const n = new TextEncoder().encode(s).length;
        return n >= 1 && n <= 64;
      },
      { params: { code: 'CHUNK_TOO_LARGE' } },
    ),
  )
  .min(1);

// Each entry of `record.sigs` is a closed CBOR map { cose_sign1, cose_key? } per CIP-309 §4.6.3.
// Path 1 (in-signature kid):       { cose_sign1: <chunks> }
// Path 2 (CIP-30 wallet sidecar):  { cose_sign1: <chunks>, cose_key: <chunks of cbor<COSE_Key>> }
//
// Canonical CBOR map-key ordering: `cose_key` (length-8 tstr, header `0x68`)
// precedes `cose_sign1` (length-10 tstr, header `0x6a`).
const SigEntrySchema = z
  .object({
    cose_key: ChunkedBytesArraySchema.optional(),
    cose_sign1: ChunkedBytesArraySchema,
  })
  .strict();

// Per CIP-309 §4.2: `hashes` is a non-empty CBOR map of <hash-alg-id> → <digest>.
// cbor2 surfaces a CBOR map with text-string keys as a plain JS object (not a
// Map). The schema is z.record(string -> Uint8Array); domain checks
// (registry-membership + digest length) happen in the superRefine pass and
// emit the typed UNSUPPORTED_HASH_ALG / HASH_DIGEST_LENGTH_MISMATCH codes.
//
// Duplicate keys are impossible by CBOR map-key uniqueness (RFC 8949 §3.1;
// canonical decode rejects duplicates as MALFORMED_CBOR upstream), so no
// duplicate-detection path exists here.
const HashesMapSchema = z
  .record(z.string(), z.instanceof(Uint8Array))
  .superRefine((hashes, ctx) => {
    const entries = Object.entries(hashes);
    if (entries.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message: 'hashes must be a non-empty CBOR map of <alg-id> → <digest>',
        params: { code: 'SCHEMA_TYPE_MISMATCH' },
      });
      return;
    }
    for (const [alg, digest] of entries) {
      if (!KNOWN_HASH_ALGS.has(alg)) {
        ctx.addIssue({
          code: 'custom',
          path: [alg],
          message: `unknown hash alg: ${alg}`,
          params: { code: 'UNSUPPORTED_HASH_ALG' },
        });
        continue;
      }
      const expected = HASH_ALGS[alg]!;
      if (digest.length !== expected) {
        ctx.addIssue({
          code: 'custom',
          path: [alg],
          message: `hashes['${alg}'] digest length ${digest.length} != ${expected}`,
          params: { code: 'HASH_DIGEST_LENGTH_MISMATCH' },
        });
      }
    }
  });

const SupersedesSchema = z
  .instanceof(Uint8Array)
  .refine((b) => b.length === 32, { params: { code: 'SUPERSEDES_TX_INVALID_LENGTH' } });

// Passphrase-KDF-algorithm identifier is structurally tstr (see
// HashesMapSchema rationale). Final identifier per CIP-309 §4.10.6.
const KNOWN_PASSPHRASE_KDF_ALGS = new Set(['argon2id']);

// ENC_PASSPHRASE_PARAMS_EXCEED_POLICY (CIP-309, citing CIP-309 §4.10.6) is
// operator-policy dependent: it fires when a producer-supplied Argon2id
// parameter (`m`, `t`, or `p`) exceeds the verifier's deployment-configured
// upper bound (memory cap, wall-clock cap, etc.). The spec floor is enforced
// by `ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW`; the upper bound is non-normative
// and depends on deployment hardware, so the reference validator does NOT
// emit `ENC_PASSPHRASE_PARAMS_EXCEED_POLICY`. Production deployments MAY add
// an operator-policy gate (e.g. read an env var
// `CARDANOWALL_PASSPHRASE_ARGON2_M_MAX` and emit the code when params exceed
// it) before invoking the KDF.
const PassphraseBlockSchema = z
  .object({
    alg: z.string(),
    salt: z.instanceof(Uint8Array),
    params: z.record(z.string(), z.unknown()),
  })
  .strict()
  .superRefine((block, ctx) => {
    if (!KNOWN_PASSPHRASE_KDF_ALGS.has(block.alg)) {
      ctx.addIssue({
        code: 'custom',
        path: ['alg'],
        message: `unknown passphrase kdf alg: ${block.alg}`,
        params: { code: 'ENC_PASSPHRASE_ALG_UNSUPPORTED' },
      });
      return;
    }
    if (block.salt.length < 16) {
      ctx.addIssue({
        code: 'custom',
        path: ['salt'],
        message: `passphrase.salt length ${block.salt.length} < 16`,
        params: { code: 'ENC_PASSPHRASE_SALT_TOO_SHORT' },
      });
    } else if (block.salt.length > 64) {
      ctx.addIssue({
        code: 'custom',
        path: ['salt'],
        message: `passphrase.salt length ${block.salt.length} > 64`,
        params: { code: 'ENC_PASSPHRASE_SALT_TOO_LONG' },
      });
    }
    if (block.alg === 'argon2id') {
      // Closed params: { m: uint, t: uint, p: uint } — reject any extra keys
      // per CIP-309 §4.11 / CIP-309.
      const allowed = new Set(['m', 't', 'p']);
      for (const k of Object.keys(block.params)) {
        if (!allowed.has(k)) {
          ctx.addIssue({
            code: 'custom',
            path: ['params', k],
            message: `unknown argon2id params field: ${k}`,
            params: { code: 'SCHEMA_UNKNOWN_FIELD' },
          });
        }
      }
      const p = block.params as { m?: unknown; t?: unknown; p?: unknown };
      // Each Argon2id param MUST be a CBOR unsigned integer; reject floats so
      // a non-integer surfaces as SCHEMA_TYPE_MISMATCH instead of TOO_LOW.
      const argonInt = (val: unknown, name: 'm' | 't' | 'p'): number | null => {
        if (typeof val !== 'number' || !Number.isInteger(val)) {
          ctx.addIssue({
            code: 'custom',
            path: ['params', name],
            message: `argon2id params.${name} must be a CBOR unsigned integer`,
            params: { code: 'SCHEMA_TYPE_MISMATCH' },
          });
          return null;
        }
        return val;
      };
      const mVal = argonInt(p.m, 'm');
      const tVal = argonInt(p.t, 't');
      const pVal = argonInt(p.p, 'p');
      if (mVal !== null && mVal < 65_536) {
        ctx.addIssue({
          code: 'custom',
          path: ['params', 'm'],
          message: 'argon2id requires m >= 65536 KiB',
          params: { code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' },
        });
      }
      if (tVal !== null && tVal < 3) {
        ctx.addIssue({
          code: 'custom',
          path: ['params', 't'],
          message: 'argon2id requires t >= 3',
          params: { code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' },
        });
      }
      if (pVal !== null && pVal < 1) {
        ctx.addIssue({
          code: 'custom',
          path: ['params', 'p'],
          message: 'argon2id requires p >= 1',
          params: { code: 'ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW' },
        });
      }
    }
  });

// Per-slot recipient schema — the wire field name (in `enc.slots`) is
// "slot", not "recipient": the array carries opaque wrapped-CEK slots, not
// recipient identities. The user-facing API ("recipientPublicKeys" /
// "recipientSecretKey") keeps the "recipient" terminology because those
// describe identities, not slots.
const SealedSlotSchema = z
  .object({
    epk: z.instanceof(Uint8Array).optional(),
    wrap: z.instanceof(Uint8Array).optional(),
  })
  .strict()
  .superRefine((slot, ctx) => {
    if (slot.epk === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['epk'],
        message: 'recipient slot missing epk',
        params: { code: 'ENC_SLOT_INVALID_SHAPE' },
      });
    } else if (slot.epk.length !== 32) {
      ctx.addIssue({
        code: 'custom',
        path: ['epk'],
        message: `epk length ${slot.epk.length} != 32`,
        params: { code: 'KEM_EPK_LENGTH_MISMATCH' },
      });
    }

    if (slot.wrap === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['wrap'],
        message: 'recipient slot missing wrap',
        params: { code: 'ENC_SLOT_INVALID_SHAPE' },
      });
    } else if (slot.wrap.length !== 48) {
      ctx.addIssue({
        code: 'custom',
        path: ['wrap'],
        message: `wrap length ${slot.wrap.length} != 48`,
        params: { code: 'WRAP_LENGTH_MISMATCH' },
      });
    }
  });

const EncryptionEnvelopeSchema = z
  .object({
    scheme: z.unknown().optional(),
    aead: z.string(),
    // Envelope-level `kem` governs every entry in `slots[]` (per CIP-309 §4.4).
    kem: z.string().optional(),
    nonce: z.instanceof(Uint8Array),
    // Wire field name: `slots` (per CIP-309 §4.4 — recipient pubkeys are NOT
    // on-wire; the array carries opaque wrapped-CEK slots that recipients
    // trial-decrypt with their own private keys).
    slots: z.array(SealedSlotSchema).optional(),
    slots_mac: z
      .instanceof(Uint8Array)
      .refine((b) => b.length === 32, { params: { code: 'ENC_SLOTS_MAC_INVALID_LENGTH' } })
      .optional(),
    passphrase: PassphraseBlockSchema.optional(),
  })
  .strict()
  .superRefine((enc, ctx) => {
    // `enc.scheme` MUST be the unsigned integer 1 (CIP-309 §4.4). Reject CBOR
    // floats or any other type that happens to compare `=== 1` in JS (see
    // VersionLiteralSchema rationale).
    if (
      typeof enc.scheme !== 'number' ||
      !Number.isInteger(enc.scheme) ||
      enc.scheme !== 1
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['scheme'],
        message: `enc.scheme must be the unsigned integer 1; got ${String(enc.scheme)}`,
        params: { code: 'UNSUPPORTED_ENVELOPE_SCHEME' },
      });
    }

    // AEAD identifier + nonce-length checks
    if (/aes-cbc/i.test(enc.aead)) {
      ctx.addIssue({
        code: 'custom',
        path: ['aead'],
        message: 'AES-CBC is unauthenticated; CIP-309 mandates an authenticated cipher',
        params: { code: 'UNAUTHENTICATED_CIPHER_FORBIDDEN' },
      });
      return;
    }
    if (!(enc.aead in AEAD_NONCE_LENGTHS)) {
      ctx.addIssue({
        code: 'custom',
        path: ['aead'],
        message: `unknown aead alg: ${enc.aead}`,
        params: { code: 'UNSUPPORTED_AEAD_ALG' },
      });
      return;
    }

    // Envelope-level `kem` shape + registry check. Required when `slots` is
    // present (enforced below in path-exclusivity).
    if (enc.kem !== undefined && enc.kem !== 'x25519') {
      ctx.addIssue({
        code: 'custom',
        path: ['kem'],
        message: `unknown kem alg: ${enc.kem}`,
        params: { code: 'UNSUPPORTED_KEM_ALG' },
      });
    }

    const expectedNonce = AEAD_NONCE_LENGTHS[enc.aead]!;
    if (enc.nonce.length !== expectedNonce) {
      ctx.addIssue({
        code: 'custom',
        path: ['nonce'],
        message: `nonce length ${enc.nonce.length} != ${expectedNonce} for ${enc.aead}`,
        params: { code: 'NONCE_LENGTH_MISMATCH' },
      });
    }

    if (enc.slots !== undefined && enc.slots.length < 1) {
      ctx.addIssue({
        code: 'custom',
        path: ['slots'],
        message: `slots length ${enc.slots.length} < 1`,
        params: { code: 'ENC_SLOTS_EMPTY' },
      });
    }

    // Key-path exclusivity: exactly one of (slots + slots_mac) or passphrase
    const hasSlots = enc.slots !== undefined;
    const hasSlotsMac = enc.slots_mac !== undefined;
    const hasPassphrase = enc.passphrase !== undefined;

    if (hasSlots && hasPassphrase) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message: 'enc combines slots with passphrase; pick one',
        params: { code: 'ENC_EXCLUSIVITY_VIOLATION' },
      });
    }
    if (hasSlots && !hasSlotsMac) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message: 'enc.slots present but enc.slots_mac absent',
        params: { code: 'ENC_SLOTS_MAC_REQUIRED' },
      });
    }
    if (hasSlotsMac && !hasSlots) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message: 'enc.slots_mac present but enc.slots absent',
        params: { code: 'ENC_SLOTS_REQUIRED' },
      });
    }
    if (hasSlots && enc.kem === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message: 'enc.slots present but enc.kem absent',
        params: { code: 'ENC_KEM_REQUIRED' },
      });
    }
    if (!hasSlots && !hasPassphrase) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message: 'enc requires either slots or passphrase — no on-chain key path otherwise',
        params: { code: 'ENC_NO_KEY_PATH' },
      });
    }
  });

// Content-hash identifiers (per CIP-309 §4.10.2). An `enc`-bearing item's
// `hashes` map MUST contain at least one entry from this set — see
// CIP-309 §4.4. Every entry of HASH_ALGS is a content-hash; list commitments
// live in `merkle[]` and are validated separately via MerkleCommitSchema.
const CONTENT_HASH_ALGS = new Set<string>(Object.keys(HASH_ALGS));

const ItemEntrySchema = z
  .object({
    hashes: HashesMapSchema,
    // Per CIP-309 §4.8, every URI is a chunked-tstr-array; the outer `uris` array
    // holds one or more such chunked URIs (each chunked independently).
    uris: z.array(ChunkedTstrArraySchema).min(1).optional(),
    // `enc` shape validation runs in `superRefine` AFTER the
    // `ENC_REQUIRES_CONTENT_HASH` pre-check (CIP-309 §4.4); the field is captured
    // here as `unknown` so that the pre-check can fire ahead of any inner
    // shape errors and the validator surfaces the most informative code first.
    enc: z.unknown().optional(),
    // Signatures attach at the record level only; the item map has no `sig` field.
  })
  .strict()
  .superRefine((item, ctx) => {
    // CIP-309 §4.4 content-hash pre-check: when `enc` is present, `item.hashes`
    // MUST carry at least one entry from CONTENT_HASH_ALGS (`sha2-256` or
    // `blake2b-256`). The check fires BEFORE any inner `enc`-shape validation
    // so the validator surfaces the most informative code first.
    const itemHasEnc = item.enc !== undefined;
    let encGateRejected = false;
    if (
      itemHasEnc &&
      typeof item.hashes === 'object' &&
      item.hashes !== null &&
      Object.keys(item.hashes).length > 0
    ) {
      const hasContentHash = Object.keys(item.hashes).some((alg) =>
        CONTENT_HASH_ALGS.has(alg),
      );
      if (!hasContentHash) {
        ctx.addIssue({
          code: 'custom',
          path: ['enc'],
          message:
            'item carries `enc` but `hashes` has no content-hash entry (sha2-256 or blake2b-256) per CIP-309 §4.4',
          params: { code: 'ENC_REQUIRES_CONTENT_HASH' },
        });
        encGateRejected = true;
      }
    }

    // `enc` shape validation (deferred until after the pre-check above).
    if (itemHasEnc && !encGateRejected) {
      const encParse = EncryptionEnvelopeSchema.safeParse(item.enc);
      if (!encParse.success) {
        for (const issue of encParse.error.issues) {
          ctx.addIssue({
            ...issue,
            path: ['enc', ...(issue.path as (string | number)[])],
          });
        }
      }
    }

    // Per CIP-309 §4.2 and CIP-309: `uris` is
    // OPTIONAL throughout, including when `enc` is present. A sealed item
    // with `uris` omitted is well-formed; the producer expects ciphertext to
    // be delivered out-of-band via the verifier's `ciphertextBytes` input
    // (CIP-309). The structural validator MUST NOT reject on that ground;
    // the verifier-input layer fires `CIPHERTEXT_UNAVAILABLE` at verify time
    // when neither a URI nor a local ciphertext is available.
    //
    // 4d — URI integrity: reconstruct each URI and confirm it's absolute and
    // does not contain a fragment identifier.
    if (item.uris) {
      item.uris.forEach((chunks, ui) => {
        const reconstructed = chunks.join('');
        if (reconstructed.includes('#')) {
          ctx.addIssue({
            code: 'custom',
            path: ['uris', ui],
            message: 'URI contains fragment identifier (`#`) — forbidden per CIP-309 §4.2',
            params: { code: 'INVALID_URI' },
          });
        }
        // Absolute-URI check: must start with `<scheme>://`
        if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(reconstructed)) {
          ctx.addIssue({
            code: 'custom',
            path: ['uris', ui],
            message: 'URI is not absolute (missing scheme://hierarchical-part)',
            params: { code: 'INVALID_URI' },
          });
        } else if (!/^(ar|ipfs):\/\//i.test(reconstructed)) {
          // Per CIP-309 §4.2 and CIP-309, the v1 fetch set is exactly
          // {ar://, ipfs://}. Producers MUST NOT emit other schemes; the
          // structural validator is the primary line of defense, ahead of the
          // verifier-side URI_TARGET_FORBIDDEN guard at CIP-309.
          ctx.addIssue({
            code: 'custom',
            path: ['uris', ui],
            message:
              'unsupported URI scheme; v1 fetch set is {ar://, ipfs://}',
            params: { code: 'INVALID_URI' },
          });
        } else {
          // Per-scheme shape rules (CIP-309 §4.8.1).
          if (reconstructed.startsWith('ar://')) {
            if (!/^ar:\/\/[A-Za-z0-9_-]{43}$/.test(reconstructed)) {
              ctx.addIssue({
                code: 'custom',
                path: ['uris', ui],
                message: 'ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` (43-char base64url txid)',
                params: { code: 'INVALID_URI' },
              });
            }
          } else if (reconstructed.startsWith('ipfs://')) {
            // Per CIP-309 §4.8.1, conformant validators MUST do full CID parsing
            // (multibase → version → codec → multihash) rather than a regex
            // shape check. Failure → INVALID_URI with reason `ipfs_cid_invalid`.
            // A trailing `/path` suffix is permitted (standard IPFS URI
            // semantics: the CID commits to a DAG, the path navigates within
            // it); the CID-shape check applies only to the authority
            // component before the first `/`.
            const rest = reconstructed.slice('ipfs://'.length);
            const slashIdx = rest.indexOf('/');
            const cid = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
            if (!isValidCid(cid)) {
              ctx.addIssue({
                code: 'custom',
                path: ['uris', ui],
                message: 'ipfs:// URI is not a valid CID (reason: ipfs_cid_invalid)',
                params: { code: 'INVALID_URI' },
              });
            }
          }
        }
        // A producer MUST NOT split a multi-byte UTF-8 codepoint across chunks.
        // No separate code is needed: the canonical-CBOR decoder rejects any
        // non-UTF-8 text string (MALFORMED_CBOR) before reconstruction, and any
        // concatenation that still fails to decode as valid UTF-8 surfaces as
        // INVALID_URI when the reconstructed string is range-checked above.
      });
    }
  });

// Top-level `merkle[]` list-commitment entry (CIP-309 §4.5). Shape:
//   { alg: tstr, root: bstr, leaf_count: uint, ? uris: [chunked-tstr-array] }
// `alg` MUST be a registered MERKLE_COMMIT_ALGS key (otherwise
// UNSUPPORTED_MERKLE_COMMIT_ALG). `root` digest length MUST match the
// algorithm's pinned size (otherwise HASH_DIGEST_LENGTH_MISMATCH).
// `leaf_count` is REQUIRED (CIP-309 §4.5) and commits the leaf count alongside
// the root; mismatch against the off-chain leaves-list value surfaces at the
// verifier layer as `SCHEMA_MERKLE_LEAF_COUNT_MISMATCH` (CIP-309).
const MerkleCommitSchema = z
  .object({
    alg: z.string(),
    root: z.instanceof(Uint8Array),
    uris: z.array(ChunkedTstrArraySchema).min(1).optional(),
    leaf_count: z.number(),
  })
  .strict()
  .superRefine((commit, ctx) => {
    if (!KNOWN_MERKLE_COMMIT_ALGS.has(commit.alg)) {
      ctx.addIssue({
        code: 'custom',
        path: ['alg'],
        message: `unknown merkle commitment alg: ${commit.alg}`,
        params: { code: 'UNSUPPORTED_MERKLE_COMMIT_ALG' },
      });
      return;
    }
    const expected = MERKLE_COMMIT_ALGS[commit.alg]!;
    if (commit.root.length !== expected) {
      ctx.addIssue({
        code: 'custom',
        path: ['root'],
        message: `merkle entry root length ${commit.root.length} != ${expected} for ${commit.alg}`,
        params: { code: 'HASH_DIGEST_LENGTH_MISMATCH' },
      });
    }
    if (!Number.isInteger(commit.leaf_count) || commit.leaf_count < 1) {
      ctx.addIssue({
        code: 'custom',
        path: ['leaf_count'],
        message: `merkle entry leaf_count must be a positive CBOR unsigned integer; got ${String(commit.leaf_count)}`,
        params: { code: 'SCHEMA_TYPE_MISMATCH' },
      });
    }
  });

// `v` and `enc.scheme` MUST be CBOR unsigned integers per the CDDL in
// CIP-309 §4.11. JavaScript `===` does not distinguish 1 from 1.0, and a
// hand-crafted CBOR record encoding `v` as a major-type-7 float (e.g.
// `f9 3c 00`) decodes to a JS number that satisfies `=== 1`. This refinement
// adds the integer check explicitly so a non-integer `v` is rejected as
// SCHEMA_INVALID_LITERAL rather than silently accepted.
const VersionLiteralSchema = z
  .number()
  .refine((n) => Number.isInteger(n) && n === 1, {
    params: { code: 'SCHEMA_INVALID_LITERAL' },
    message: 'v must be the unsigned integer 1',
  });

// Metadata label 309 is the on-chain record dispatcher; the record itself
// carries no in-band type discriminator. A well-formed record MUST carry at
// least one of `items[]` or `merkle[]` non-empty (CIP-309 §4.2 / CIP-309 §4.5);
// the structural validator rejects an empty record with `SCHEMA_EMPTY_RECORD`.
//
// Forward-compat (CIP-309 §4.1.4): extension keys matching `^x-.+` or
// `^[a-z]+-.+` are tolerated and preserved without verification. Unknown
// keys not matching either pattern (typos like `supersedess`, `Sigs`) are
// rejected as `SCHEMA_UNKNOWN_FIELD`. The top-level `crit: [+ tstr]` array
// names extension keys the producer marks mandatory-to-understand; a v1
// verifier seeing any `crit` entry it does not implement emits
// `EXTENSION_UNSUPPORTED_CRITICAL` (CIP-309) and MUST NOT report valid.
export const PoeRecordSchema = z
  .looseObject({
    v: VersionLiteralSchema,
    items: z.array(ItemEntrySchema).optional(),
    // Top-level Merkle list commitments (CIP-309 §4.5). OPT. Each entry pairs a
    // registered Merkle-commitment alg id with the canonical root, REQUIRED
    // leaf count, and an optional companion-URI set.
    merkle: z.array(MerkleCommitSchema).optional(),
    supersedes: SupersedesSchema.optional(),
    // Each `sigs[i]` is a closed CBOR map { cose_sign1, cose_key? } per
    // CIP-309 §4.6.3. No parallel-array invariant: the optional `cose_key` lives
    // inside the entry.
    sigs: z.array(SigEntrySchema).min(1).optional(),
    // Forward-compat critical-extension array (CIP-309 §4.1.4).
    crit: z.array(z.string()).min(1).optional(),
  })
  .superRefine((record, ctx) => {
    // Reject a record carrying neither items nor merkle.
    const itemsLen = Array.isArray(record.items) ? record.items.length : 0;
    const merkleLen = Array.isArray(record.merkle) ? record.merkle.length : 0;
    if (itemsLen === 0 && merkleLen === 0) {
      ctx.addIssue({
        code: 'custom',
        path: [],
        message:
          'record must carry at least one of items[] or merkle[] non-empty',
        params: { code: 'SCHEMA_EMPTY_RECORD' },
      });
    }
    // Reject unknown top-level keys that are not extension keys (typos).
    for (const k of Object.keys(record)) {
      if (TOP_LEVEL_BASE_KEYS.has(k)) continue;
      if (isExtensionKey(k)) continue;
      ctx.addIssue({
        code: 'custom',
        path: [k],
        message: `unknown top-level field: ${k}`,
        params: { code: 'SCHEMA_UNKNOWN_FIELD' },
      });
    }
  });

export type PoeRecord = z.infer<typeof PoeRecordSchema>;

// === Result types ===

export interface ValidationIssue {
  path: (string | number)[];
  code: string;
  message: string;
}

export type ValidationResult =
  | { valid: true; record: PoeRecord; warnings?: ValidationIssue[] }
  | { valid: false; issues: ValidationIssue[] };

// === Issue mapper: zod-issue -> structural-error-taxonomy code ===

function mapZodIssue(i: z.core.$ZodIssue): ValidationIssue {
  const path = i.path as (string | number)[];
  // Per CIP-309 §4.6.3 / CIP-309: sig-entry structural violations have a
  // dedicated taxonomy code — `SIG_ENTRY_INVALID_SHAPE` — that overrides the
  // generic SCHEMA_* labels when the offending path is under `sigs[i]`. This
  // covers (a) sigs[i] not a map, (b) missing required `cose` key,
  // (c) closed-schema violations (extra keys beyond `cose`/`cose_key`), and
  // (d) `cose`/`cose_key` value-shape errors below the entry.
  const inSigsEntry =
    path.length >= 2 && path[0] === 'sigs' && typeof path[1] === 'number';

  // Refinements that already carry a canonical code in `params.code`
  const explicit = (i as { params?: { code?: string } }).params?.code;
  if (explicit) {
    return { path, code: explicit, message: i.message };
  }
  // Map zod's built-in codes to the structural-error-taxonomy codes
  switch (i.code) {
    case 'invalid_type':
      if (path.includes('slots') && path[path.length - 1] !== 'slots') {
        return { path, code: 'ENC_SLOT_INVALID_SHAPE', message: i.message };
      }
      // Required-field-missing manifests as invalid_type with received: 'undefined'.
      // Per CIP-309, missing top-level required fields emit
      // SCHEMA_MISSING_REQUIRED. SCHEMA_EMPTY_RECORD fires from the top-level
      // superRefine when neither `items[]` nor `merkle[]` is present non-empty.
      if ((i as { input?: unknown }).input === undefined) {
        if (inSigsEntry) {
          return { path, code: 'SIG_ENTRY_INVALID_SHAPE', message: i.message };
        }
        return { path, code: 'SCHEMA_MISSING_REQUIRED', message: i.message };
      }
      if (inSigsEntry) {
        return { path, code: 'SIG_ENTRY_INVALID_SHAPE', message: i.message };
      }
      return { path, code: 'SCHEMA_TYPE_MISMATCH', message: i.message };
    case 'invalid_value':
      // Literal mismatch (v) maps to SCHEMA_INVALID_LITERAL. v1 has no other
      // closed-enum/literal schema: algorithm fields (`enc.aead`, `enc.kem`,
      // `enc.passphrase.alg`, `hashes` map keys, `merkle[i].alg`) are typed
      // as open strings here and routed to their field-specific
      // `UNSUPPORTED_*_ALG` / `ENC_PASSPHRASE_ALG_UNSUPPORTED` code by the
      // superRefine layer (see EncryptionEnvelopeSchema, HashesMapSchema,
      // MerkleCommitSchema, PassphraseBlockSchema). Any other `invalid_value`
      // path is unreachable in v1 — the schema would have to be extended
      // with a new closed enum to trigger it.
      if (path.length === 1 && path[0] === 'v') {
        return { path, code: 'SCHEMA_INVALID_LITERAL', message: i.message };
      }
      throw new Error(
        `unreachable: zod 'invalid_value' at path [${path.map(String).join('.')}] — v1 has no closed-enum schema outside the algorithm registries`,
      );
    case 'unrecognized_keys':
      if (inSigsEntry) {
        return { path, code: 'SIG_ENTRY_INVALID_SHAPE', message: i.message };
      }
      return { path, code: 'SCHEMA_UNKNOWN_FIELD', message: i.message };
    case 'invalid_format':
    case 'too_big':
    case 'too_small':
      if (inSigsEntry) {
        return { path, code: 'SIG_ENTRY_INVALID_SHAPE', message: i.message };
      }
      return { path, code: 'SCHEMA_TYPE_MISMATCH', message: i.message };
    default:
      if (inSigsEntry) {
        return { path, code: 'SIG_ENTRY_INVALID_SHAPE', message: i.message };
      }
      return { path, code: 'SCHEMA_TYPE_MISMATCH', message: i.message };
  }
}

// === Public validator ===

export function validatePoeRecord(bytes: Uint8Array): ValidationResult {
  let decoded: unknown;
  try {
    decoded = decodeCanonicalCbor(bytes);
  } catch (e) {
    // Per CIP-309, duplicate-key violations are a subclass of `MALFORMED_CBOR`.
    const msg = (e as Error).message;
    return { valid: false, issues: [{ path: [], code: 'MALFORMED_CBOR', message: msg }] };
  }

  const parse = PoeRecordSchema.safeParse(decoded);
  if (!parse.success) {
    const issues = parse.error.issues
      .map(mapZodIssue)
      .sort((a, b) => a.path.join('.').localeCompare(b.path.join('.')));
    return { valid: false, issues };
  }

  const record = parse.data;
  const issues: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  // Note: CIP-309 v1 requires `hashes` to carry at least one entry from the
  // §4.10.2 registry; single-hash records are fully conformant and structural
  // validators emit no `SINGLE_HASH`-style warning (CIP-309 §4.3, Rationale).

  // `crit[]` shape checks (CIP-309 §4.1.4 / CIP-309, code
  // `CRIT_SHAPE_INVALID`). Three structural rules fire BEFORE the per-entry
  // `EXTENSION_UNSUPPORTED_CRITICAL` lookup:
  //   (a) each entry MUST match the extension-key regex (`^x-.+` or
  //       `^[a-z]+-.+`); base keys MUST NOT appear in `crit[]`;
  //   (b) each entry MUST be present as a key in the decoded record map;
  //   (c) `crit[]` MUST NOT contain duplicate entries.
  // Producer-side bugs (typos, dangling references, accidental repeats) are
  // reported here regardless of which extensions the verifier supports.
  const recordWithCrit = record as typeof record & { crit?: string[] };
  const decodedTopKeys = new Set<string>(
    decoded && typeof decoded === 'object' ? Object.keys(decoded as Record<string, unknown>) : [],
  );
  const critShapeInvalidIndices = new Set<number>();
  if (Array.isArray(recordWithCrit.crit)) {
    const seen = new Set<string>();
    for (let i = 0; i < recordWithCrit.crit.length; i++) {
      const critName = recordWithCrit.crit[i]!;
      let invalid = false;
      let reason = '';
      if (TOP_LEVEL_BASE_KEYS.has(critName)) {
        invalid = true;
        reason = `'${critName}' is a base key and MUST NOT appear in crit[]`;
      } else if (!/^x-.+/.test(critName) && !/^[a-z]+-.+/.test(critName)) {
        invalid = true;
        reason = `'${critName}' does not match the extension-key regex (^x-.+ or ^[a-z]+-.+)`;
      } else if (!decodedTopKeys.has(critName)) {
        invalid = true;
        reason = `'${critName}' is named in crit but absent from the record map`;
      } else if (seen.has(critName)) {
        invalid = true;
        reason = `'${critName}' appears more than once in crit[]`;
      }
      seen.add(critName);
      if (invalid) {
        critShapeInvalidIndices.add(i);
        issues.push({
          path: ['crit', i],
          code: 'CRIT_SHAPE_INVALID',
          message: reason,
        });
      }
    }
  }

  // Forward-compat `crit` enforcement (CIP-309 §4.1.4 / CIP-309). A v1
  // verifier seeing any well-formed `crit` entry it does not implement MUST
  // emit `EXTENSION_UNSUPPORTED_CRITICAL` and MUST NOT report `valid: true`.
  // The v1 reference verifier implements no extension keys, so any
  // shape-valid `crit` entry is unsupported by definition. Entries that
  // already failed the shape check above are NOT re-reported here.
  if (Array.isArray(recordWithCrit.crit)) {
    for (let i = 0; i < recordWithCrit.crit.length; i++) {
      if (critShapeInvalidIndices.has(i)) continue;
      const critName = recordWithCrit.crit[i]!;
      issues.push({
        path: ['crit', i],
        code: 'EXTENSION_UNSUPPORTED_CRITICAL',
        message: `crit lists extension '${critName}' that this verifier does not implement`,
      });
    }
  }

  // 4g — COSE_Sign1 structural decode for record-level sigs.
  // Each sigs[i] is a closed CBOR map `{ cose_sign1: <chunks>, ? cose_key: <chunks> }`
  // per CIP-309 §4.6.3. We decode COSE_Sign1 from the joined `cose_sign1` chunks here.
  //
  // The optional `cose_key` (chunked cbor<COSE_Key>, path 2) MUST also be
  // structurally inspected here: per CIP-309 §4.6.3, the validator MUST decode
  // the concatenated public-key bytes as a CBOR map and MUST reject any entry
  // whose map contains COSE_Key label `-4` (the private scalar `d` for OKP /
  // EC2, RFC 9052 §7.1) with `SIG_PRIVATE_KEY_LEAKED`. Publishing a private
  // key on the permanent ledger is a catastrophic, irreversible key-leak
  // event; the structural validator is the last layer that can stop the
  // publication chain before the record reaches the network.
  if (record.sigs) {
    record.sigs.forEach((entry, i) => {
      if (entry.cose_key !== undefined) {
        const keyIssue = inspectCoseKey(entry.cose_key, i);
        if (keyIssue) {
          issues.push(keyIssue);
          return;
        }
      }
      try {
        const merged = concatChunks(entry.cose_sign1);
        const cose = decodeCoseSign1(merged);
        // Detached-only: payload field MUST be null. Any non-null payload —
        // including a zero-length byte string (`h''`) — is forbidden, per
        // CIP-309 §4.6.1 and CIP-309.
        if (cose.payload !== null) {
          issues.push({
            path: ['sigs', i],
            code: 'MALFORMED_SIG_COSE_SIGN1',
            message: 'COSE_Sign1 payload must be null (detached); attached form forbidden',
          });
          return;
        }
        const alg = cose.protectedHeader.get(1);
        if (typeof alg !== 'number' || !KNOWN_SIG_ALG_IDS.has(alg)) {
          // CIP-309: info severity. The content claim under `hashes`
          // remains structurally valid regardless of which signature
          // algorithms a given verifier supports — the offending entry is
          // tagged unverifiable, the record-as-a-whole is NOT failed here.
          warnings.push({
            path: ['sigs', i],
            code: 'SIGNATURE_UNSUPPORTED',
            message: `alg ${alg} not in KNOWN_SIG_ALG_IDS = {-8} (EdDSA)`,
          });
        }
        // Path 1 / path 2 mutual exclusion at the wire level (CIP-309 §4.6.3).
        // If the protected header carries a 32-byte `kid` (raw Ed25519 pubkey,
        // path 1) AND the parent sigs[i] map also carries an inline `cose_key`
        // (chunked cbor<COSE_Key>, path 2) → reject as
        // SIG_ENTRY_KID_COSE_KEY_CONFLICT. The check fires here, AFTER COSE_Sign1
        // structural decode (CIP-309).
        const protectedKid = cose.protectedHeader.get(4) as Uint8Array | undefined;
        if (
          protectedKid instanceof Uint8Array &&
          protectedKid.length === 32 &&
          entry.cose_key !== undefined
        ) {
          issues.push({
            path: ['sigs', i],
            code: 'SIG_ENTRY_KID_COSE_KEY_CONFLICT',
            message:
              'sigs[i] carries both a 32-byte protected `kid` (path 1) and an inline `cose_key` (path 2); paths are mutually exclusive per CIP-309 §4.6.3',
          });
        }
      } catch (e) {
        issues.push({
          path: ['sigs', i],
          code: 'MALFORMED_SIG_COSE_SIGN1',
          message: (e as Error).message,
        });
      }
    });
  }

  if (issues.length > 0) {
    return { valid: false, issues: issues.sort((a, b) => a.path.join('.').localeCompare(b.path.join('.'))) };
  }

  if (warnings.length > 0) {
    return {
      valid: true,
      record,
      warnings: warnings.sort((a, b) => a.path.join('.').localeCompare(b.path.join('.'))),
    };
  }

  return { valid: true, record };
}

// === Helpers ===

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  return chunks.reduce<Uint8Array>((acc, chunk) => {
    const out = new Uint8Array(acc.length + chunk.length);
    out.set(acc, 0);
    out.set(chunk, acc.length);
    return out;
  }, new Uint8Array(0));
}

// COSE_Key inspector for the CIP-30 wallet path-2 `sigs[i].cose_key` blob
// (CIP-309 §4.6.3). Concatenates the chunks and decodes the bytes as a CBOR map,
// then performs two classes of structural check:
//
//   1. Private-key-material guard — if the map carries COSE_Key label `-4`
//      (the private scalar `d` for OKP / EC2 per RFC 9052 §7.1), emit
//      `SIG_PRIVATE_KEY_LEAKED`. The presence of the label alone is the
//      disqualifier, regardless of value type. Publishing a private key on
//      the permanent ledger is a catastrophic, irreversible key-leak event;
//      the structural validator is the last line of defence.
//
//   2. Positive-shape guard — confirm the map is a well-formed Ed25519 OKP
//      public-key reference per RFC 9052 §7.1 / RFC 8152 §13.2:
//        - label `-2` (x — Ed25519 public-key bytes) MUST be present,
//        - the `-2` value MUST be a 32-byte byte string,
//        - label `1`  (kty) MUST equal `1` (OKP),
//        - label `-1` (crv) MUST equal `6` (Ed25519).
//      Any of these failures surfaces as `MALFORMED_SIG_COSE_SIGN1` because
//      the verifier cannot proceed with a structurally invalid public-key
//      blob. An undecodable `cose_key` blob also surfaces as
//      `MALFORMED_SIG_COSE_SIGN1`.
function inspectCoseKey(
  keyChunks: Uint8Array[],
  i: number,
): ValidationIssue | null {
  let decoded: unknown;
  try {
    decoded = decodeCbor(concatChunks(keyChunks));
  } catch (e) {
    return {
      path: ['sigs', i, 'cose_key'],
      code: 'MALFORMED_SIG_COSE_SIGN1',
      message: `sigs[${i}].cose_key failed to decode as cbor<COSE_Key>: ${(e as Error).message}`,
    };
  }
  // RFC 9052 §7 carries COSE_Key as a CBOR map; cbor2 surfaces an int-keyed
  // map as a JS Map (not a plain object). Normalise the access pattern.
  const getLabel = (label: number): unknown => {
    if (decoded instanceof Map) return decoded.get(label);
    if (typeof decoded === 'object' && decoded !== null) {
      return (decoded as Record<string, unknown>)[String(label)];
    }
    return undefined;
  };
  const hasLabel = (label: number): boolean => {
    if (decoded instanceof Map) return decoded.has(label);
    if (typeof decoded === 'object' && decoded !== null) {
      return Object.prototype.hasOwnProperty.call(decoded, String(label));
    }
    return false;
  };

  // 1. Private-key-material guard (RFC 9052 §7.1 label -4 = OKP/EC2 `d`).
  if (hasLabel(-4)) {
    return {
      path: ['sigs', i, 'cose_key'],
      code: 'SIG_PRIVATE_KEY_LEAKED',
      message:
        'sigs[' +
        i +
        '].cose_key carries COSE_Key label -4 (private scalar `d`); publishing private-key material on chain is forbidden per CIP-309 §4.6.3',
    };
  }

  // 2. Positive-shape guard — Ed25519 OKP public-key reference shape.
  // 2a. `kty` (label 1) MUST be 1 (OKP).
  const kty = getLabel(1);
  if (kty !== 1) {
    return {
      path: ['sigs', i, 'cose_key'],
      code: 'MALFORMED_SIG_COSE_SIGN1',
      message: `sigs[${i}].cose_key COSE_Key kty (label 1) must be 1 (OKP); got ${String(kty)}`,
    };
  }
  // 2b. `crv` (label -1) MUST be 6 (Ed25519).
  const crv = getLabel(-1);
  if (crv !== 6) {
    return {
      path: ['sigs', i, 'cose_key'],
      code: 'MALFORMED_SIG_COSE_SIGN1',
      message: `sigs[${i}].cose_key COSE_Key crv (label -1) must be 6 (Ed25519); got ${String(crv)}`,
    };
  }
  // 2c. `-2` (x — Ed25519 public-key bytes) MUST be present and 32 bytes.
  if (!hasLabel(-2)) {
    return {
      path: ['sigs', i, 'cose_key'],
      code: 'MALFORMED_SIG_COSE_SIGN1',
      message: `sigs[${i}].cose_key COSE_Key missing label -2 (Ed25519 public-key bytes)`,
    };
  }
  const x = getLabel(-2);
  if (!(x instanceof Uint8Array) || x.length !== 32) {
    const got =
      x instanceof Uint8Array ? `${x.length}-byte bstr` : typeof x;
    return {
      path: ['sigs', i, 'cose_key'],
      code: 'MALFORMED_SIG_COSE_SIGN1',
      message: `sigs[${i}].cose_key COSE_Key label -2 must be a 32-byte byte string (Ed25519 public key); got ${got}`,
    };
  }
  return null;
}
