// CIP-309 v1 reference implementation — end-to-end walkthrough
//
// Ties the primitive modules together into the two flows a real producer and
// verifier run, using only the wire primitives in this directory (no SDK, no
// network):
//
//   1. Publish + verify a SIGNED hash-only PoE record:
//        content → dual-hash → record body → canonical CBOR
//        → record-level COSE_Sign1 (detached, Ed25519)
//        → full record bytes → structural validation
//        → record-level signature verification (strict Ed25519).
//
//   2. Sealed-PoE wrap → unwrap roundtrip (multi-recipient, X25519 KEM):
//        plaintext → CEK + XChaCha20-Poly1305 ciphertext + per-recipient slots
//        → one recipient opens its slot, recovers the CEK, decrypts, and
//          recomputes the on-record content hashes against the plaintext.
//
// Run: `npx tsx src/end-to-end.ts` (exits non-zero on any failed assertion).

import { sha256 } from '@noble/hashes/sha2.js';
import { dualHash } from './hash-dual.ts';
import { encodeCanonicalCbor, decodeCanonicalCbor } from './cbor-canonical.ts';
import {
  encodePoeRecord,
  buildRecordSignaturePayload,
  SIG_DOMAIN_RECORD_V1,
} from './cip-309-encoder.ts';
import { validatePoeRecord, type PoeRecord } from './cip-309-validator.ts';
import {
  encodeCoseSign1,
  decodeCoseSign1,
  buildSigStructure,
} from './cose-sign1.ts';
import {
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
} from './ed25519.ts';
import { generateX25519KeyPair } from './x25519.ts';
import {
  eciesSealedPoeWrap,
  eciesSealedPoeUnwrap,
} from './ecies-sealed-poe.ts';

// ----- Tiny assertion harness -----

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? `: ${detail}` : ''}`);
  if (!ok) failures += 1;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Copy bytes into a fresh array backed by a plain ArrayBuffer. noble's outputs
// are typed `Uint8Array<ArrayBufferLike>`; the record schema's byte fields are
// `Uint8Array<ArrayBuffer>`. This copy is the explicit boundary that reconciles
// the two — it is a demo-author convenience, not a wire requirement.
function u8(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(b);
}

/** Split a logical byte string into ≤64-byte chunks (the Cardano metadata limit). */
function chunkBytes(b: Uint8Array, n = 64): Uint8Array<ArrayBuffer>[] {
  const out: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < b.length; i += n) out.push(new Uint8Array(b.subarray(i, i + n)));
  return out;
}

const enc = new TextEncoder();

// =============================================================================
// Flow 1 — publish + verify a signed hash-only PoE record
// =============================================================================

function signedRecordFlow(): void {
  console.log('\n--- Flow 1: signed hash-only PoE ---');

  // (a) Producer hashes the content. The content hash is the primary claim.
  const content = enc.encode('the quick brown fox — CIP-309 end-to-end demo');
  const digests = dualHash(content);

  // (b) Build the record BODY (everything except `sigs`). Per CIP-309 §4.2,
  // `hashes` is a CBOR map keyed by registered hash-alg ids.
  const body: PoeRecord = {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': u8(digests['sha2-256']),
          'blake2b-256': u8(digests['blake2b-256']),
        },
      },
    ],
  };

  // (c) Sign the body. Authorship is OPTIONAL in CIP-309; when present it is a
  // record-level COSE_Sign1 over `SIG_DOMAIN_RECORD_V1 || canonical_cbor(body)`
  // with an empty external_aad (CIP-309 §4.6.1). We use the path-1 convention:
  // the signer's raw 32-byte Ed25519 public key is carried as the protected
  // `kid` (COSE label 4).
  const signer = generateEd25519KeyPair();
  const toSign = buildRecordSignaturePayload(body);
  check(
    'to_sign carries the 25-byte domain separator prefix',
    bytesEqual(toSign.slice(0, SIG_DOMAIN_RECORD_V1.length), SIG_DOMAIN_RECORD_V1),
  );

  const protectedHeader = new Map<number | string, unknown>([
    [1, -8], // alg = EdDSA
    [4, signer.publicKey], // kid = raw Ed25519 public key (path 1)
  ]);
  const sigStruct = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: encodeCanonicalCbor(protectedHeader),
    externalAad: new Uint8Array(0),
    payload: toSign,
  });
  const signature = signEd25519(sigStruct, signer.secretKey);
  const coseSign1 = encodeCoseSign1({
    protectedHeader,
    unprotectedHeader: new Map(),
    payload: null, // detached — the payload is reconstructed, never carried
    signature,
  });

  // (d) Assemble the full record and canonical-CBOR-encode it. This is the byte
  // string that goes under Cardano metadata label 309 (chunked to ≤64 B in the
  // real transport; here we keep the whole record for the demo).
  const fullRecord: PoeRecord = {
    ...body,
    sigs: [{ cose_sign1: chunkBytes(coseSign1) }],
  };
  const recordBytes = encodePoeRecord(fullRecord);
  check('record encodes to canonical CBOR', recordBytes.length > 0, `${recordBytes.length} B`);

  // (e) A verifier decodes + structurally validates the record bytes. This is a
  // pure function — no network, no crypto signature check yet.
  const decoded = decodeCanonicalCbor(recordBytes);
  check('record round-trips through canonical CBOR decode', decoded !== null && typeof decoded === 'object');

  const validation = validatePoeRecord(recordBytes);
  check(
    'structural validation passes',
    validation.valid,
    validation.valid ? '' : validation.issues.map((i) => i.code).join(','),
  );

  // (f) The verifier reconstructs `to_sign` from the record body (minus `sigs`)
  // and checks each record-level COSE_Sign1 with strict Ed25519. It reuses the
  // PRESERVED protected_bytes from the decoded COSE_Sign1, not a re-encoded form.
  if (validation.valid) {
    const { sigs, ...recoveredBody } = validation.record;
    const recoveredToSign = buildRecordSignaturePayload(recoveredBody as PoeRecord);
    let allSigsValid = sigs !== undefined && sigs.length > 0;
    for (const entry of sigs ?? []) {
      const merged = concatChunks(entry.cose_sign1);
      const cose = decodeCoseSign1(merged);
      const signerPub = cose.protectedHeader.get(4) as Uint8Array;
      const verifyStruct = buildSigStructure({
        context: 'Signature1',
        bodyProtectedBytes: cose.protectedBytes,
        externalAad: new Uint8Array(0),
        payload: recoveredToSign,
      });
      const ok = verifyEd25519(cose.signature, verifyStruct, signerPub);
      allSigsValid &&= ok;
    }
    check('record-level Ed25519 signature verifies', allSigsValid);
  }

  // (g) Tamper check: flipping a byte of the signed content MUST break the
  // signature. The verifier rebuilds `to_sign` from the (now-different) body
  // and the Ed25519 check fails.
  const tamperedBody: PoeRecord = {
    v: 1,
    items: [{ hashes: { 'sha2-256': u8(sha256(enc.encode('different content'))) } }],
  };
  const tamperedToSign = buildRecordSignaturePayload(tamperedBody);
  const tamperedStruct = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: encodeCanonicalCbor(protectedHeader),
    externalAad: new Uint8Array(0),
    payload: tamperedToSign,
  });
  check(
    'signature does NOT verify over tampered content',
    !verifyEd25519(signature, tamperedStruct, signer.publicKey),
  );
}

// =============================================================================
// Flow 2 — sealed-PoE wrap → unwrap roundtrip (multi-recipient)
// =============================================================================

function sealedPoeFlow(): void {
  console.log('\n--- Flow 2: sealed-PoE wrap/unwrap (3 recipients, X25519) ---');

  // (a) Three recipients each have an X25519 keypair. The sender knows only
  // their PUBLIC keys.
  const recipients = [generateX25519KeyPair(), generateX25519KeyPair(), generateX25519KeyPair()];
  const recipientPubs = recipients.map((r) => r.publicKey);

  // (b) Sender wraps the plaintext: fresh CEK, XChaCha20-Poly1305 ciphertext,
  // and one wrapped-CEK slot per recipient. The CEK and nonce are sampled from
  // the CSPRNG inside the wrap (we let it pick them).
  const plaintext = enc.encode('sealed content for the inbox — only recipients can read this');
  const { envelope, ciphertext } = eciesSealedPoeWrap({
    plaintext,
    recipientPublicKeys: recipientPubs,
  });
  check('envelope KEM is x25519', envelope.kem === 'x25519');
  check('one slot per recipient', envelope.slots.length === recipients.length, `${envelope.slots.length} slots`);
  check('slots_mac is 32 bytes', envelope.slots_mac.length === 32);

  // (c) The producer publishes the digests of the PLAINTEXT on-chain (the
  // content claim), with the ciphertext referenced off-chain by a URI. We model
  // only the record-build step here — the digests commit to the plaintext.
  // Narrow the envelope union on `kem` so the slot shape ({epk, wrap}) is known.
  if (envelope.kem !== 'x25519') throw new Error('demo expects the x25519 KEM');
  const digests = dualHash(plaintext);
  const sealedRecord: PoeRecord = {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': u8(digests['sha2-256']),
          'blake2b-256': u8(digests['blake2b-256']),
        },
        uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
        enc: {
          scheme: envelope.scheme,
          aead: envelope.aead,
          kem: envelope.kem,
          nonce: u8(envelope.nonce),
          slots: envelope.slots.map((s) => ({ epk: u8(s.epk), wrap: u8(s.wrap) })),
          slots_mac: u8(envelope.slots_mac),
        },
      },
    ],
  };
  const sealedRecordBytes = encodePoeRecord(sealedRecord);
  const sealedValidation = validatePoeRecord(sealedRecordBytes);
  check(
    'sealed record passes structural validation',
    sealedValidation.valid,
    sealedValidation.valid ? '' : sealedValidation.issues.map((i) => i.code).join(','),
  );

  // (d) Each recipient trial-decrypts: opens its slot, recovers the CEK,
  // verifies slots_mac, and AEAD-decrypts the ciphertext. All three recover the
  // identical plaintext.
  let allRecovered = true;
  for (let i = 0; i < recipients.length; i++) {
    const recovered = eciesSealedPoeUnwrap({
      envelope,
      ciphertext,
      recipientSecretKey: recipients[i]!.secretKey,
    });
    allRecovered &&= bytesEqual(recovered, plaintext);
  }
  check('every recipient recovers the plaintext', allRecovered);

  // (e) Recipient verifier obligation: recompute the plaintext hashes and check
  // them against the on-record `hashes` map (the producer's content claim).
  const recoveredByR0 = eciesSealedPoeUnwrap({
    envelope,
    ciphertext,
    recipientSecretKey: recipients[0]!.secretKey,
  });
  const recomputed = dualHash(recoveredByR0);
  check(
    'recomputed plaintext hashes match the on-record claim',
    bytesEqual(recomputed['sha2-256'], digests['sha2-256']) &&
      bytesEqual(recomputed['blake2b-256'], digests['blake2b-256']),
  );

  // (f) A non-recipient (fresh keypair) cannot open any slot → WRONG_RECIPIENT_KEY.
  const stranger = generateX25519KeyPair();
  let rejected = false;
  try {
    eciesSealedPoeUnwrap({ envelope, ciphertext, recipientSecretKey: stranger.secretKey });
  } catch (e) {
    rejected = (e as { code?: string }).code === 'WRONG_RECIPIENT_KEY';
  }
  check('a non-recipient is rejected (WRONG_RECIPIENT_KEY)', rejected);
}

// ----- shared helper -----

function concatChunks(chunks: Uint8Array[]): Uint8Array {
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

// =============================================================================
// Driver
// =============================================================================

signedRecordFlow();
sealedPoeFlow();

if (failures > 0) {
  console.log(`\n${failures} assertion(s) FAILED`);
  process.exit(1);
}
console.log('\nALL end-to-end assertions PASSED');
