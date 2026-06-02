// CIP-309 v1 — structural-validator behaviour smoke tests
// Verifies the structural validator: hashes-as-CBOR-map, enc.slots wire field,
// full IPFS CID validation, optional uris on enc-bearing items (CIP-309 §4.2),
// single-algorithm hash entries, and the COSE_Key private-material rejection
// (CIP-309 §4.6.3). Run: `npx tsx src/smoke-validator.ts`.

import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { validatePoeRecord, type ValidationResult } from './cip-309-validator.ts';
import { eciesSealedPoeWrap } from './ecies-sealed-poe.ts';
import { x25519PublicKey } from './x25519.ts';

const enc = new TextEncoder();

function sha256Of(b: Uint8Array): Uint8Array {
  return sha256(b);
}
function blake2b256Of(b: Uint8Array): Uint8Array {
  return blake2b(b, { dkLen: 32 });
}

const PT = enc.encode('smoke');
const SHA = sha256Of(PT);
const BLAKE = blake2b256Of(PT);

const results: { label: string; pass: boolean; detail: string }[] = [];

function record(label: string, pass: boolean, detail: string): void {
  results.push({ label, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${label}: ${detail}`);
}

function codes(r: ValidationResult): string[] {
  if (r.valid) {
    return (r.warnings ?? []).map((w) => w.code);
  }
  return r.issues.map((i) => i.code);
}

// (a) Valid: hashes map { sha2-256, blake2b-256 }
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE } }],
  });
  const r = validatePoeRecord(cbor);
  record(
    '(a) valid dual-hash map',
    r.valid && (r.warnings ?? []).length === 0,
    `valid=${r.valid}, warnings=${codes(r).join(',') || '(none)'}`,
  );
}

// (b) Single-hash record is fully conformant (no SINGLE_HASH warning per CIP-309 §4.3).
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
  });
  const r = validatePoeRecord(cbor);
  record(
    '(b) single-hash record passes with no warnings',
    r.valid && (r.warnings ?? []).length === 0,
    `valid=${r.valid}, warnings=${codes(r).join(',') || '(none)'}`,
  );
}

// (c) Unknown alg → UNSUPPORTED_HASH_ALG
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'md5': new Uint8Array(16) } }],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'UNSUPPORTED_HASH_ALG');
  record('(c) unknown alg → UNSUPPORTED_HASH_ALG', has, `codes=${codes(r).join(',')}`);
}

// (d) Wrong digest length → HASH_DIGEST_LENGTH_MISMATCH
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': new Uint8Array(20) } }],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'HASH_DIGEST_LENGTH_MISMATCH');
  record('(d) wrong digest length → HASH_DIGEST_LENGTH_MISMATCH', has, `codes=${codes(r).join(',')}`);
}

// (e) Sealed envelope with enc.slots → valid
{
  const slot = {
    epk: new Uint8Array(32).fill(0xaa),
    wrap: new Uint8Array(48).fill(0xbb),
  };
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
        enc: {
          scheme: 1,
          aead: 'xchacha20-poly1305',
          kem: 'x25519',
          nonce: new Uint8Array(24),
          slots: [slot],
          slots_mac: new Uint8Array(32),
        },
      },
    ],
  });
  const r = validatePoeRecord(cbor);
  record(
    '(e) sealed envelope with enc.slots',
    r.valid,
    `valid=${r.valid}, codes=${codes(r).join(',') || '(none)'}`,
  );
}

// (f) Old array form for hashes → invalid (SCHEMA_TYPE_MISMATCH)
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: [{ alg: 'sha2-256', h: SHA }] }],
  });
  const r = validatePoeRecord(cbor);
  const isReject = !r.valid && r.issues.some((i) => i.code.startsWith('SCHEMA_'));
  record('(f) old array-form hashes rejected', isReject, `codes=${codes(r).join(',')}`);
}

// (g) IPFS CID validation
{
  // (g.i) bogus short ipfs://Qm — should fail INVALID_URI
  const bad = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        uris: [['ipfs://Qm']],
      },
    ],
  });
  const rBad = validatePoeRecord(bad);
  const badRej = !rBad.valid && rBad.issues.some((i) => i.code === 'INVALID_URI');
  record('(g.i) bogus ipfs://Qm short → INVALID_URI', badRej, `codes=${codes(rBad).join(',')}`);

  // (g.ii) Real CIDv0
  const goodV0 = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        uris: [['ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG']],
      },
    ],
  });
  const rGoodV0 = validatePoeRecord(goodV0);
  record('(g.ii) real CIDv0 passes', rGoodV0.valid, `valid=${rGoodV0.valid}, codes=${codes(rGoodV0).join(',') || '(none)'}`);

  // (g.iii) Real CIDv1 — chunked because the URI exceeds 64 bytes
  // (`ipfs://` + 59-char CID = 66B; the CDDL chunk limit is 64B per piece).
  const cidV1Uri = 'ipfs://bafkreigh2akiscaildc6mn7vmrk5xkucb6w5dfgo7tukbmpzxoa64yjebq';
  const goodV1 = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        uris: [[cidV1Uri.slice(0, 64), cidV1Uri.slice(64)]],
      },
    ],
  });
  const rGoodV1 = validatePoeRecord(goodV1);
  record('(g.iii) real CIDv1 passes', rGoodV1.valid, `valid=${rGoodV1.valid}, codes=${codes(rGoodV1).join(',') || '(none)'}`);
}

// (h) Wrap output exposes the slot-set MAC under the wire field name `slots_mac`
{
  const recipientSk = new Uint8Array(32);
  recipientSk[0] = 0x01;
  const recipientPub = x25519PublicKey(recipientSk);
  const out = eciesSealedPoeWrap({
    plaintext: PT,
    recipientPublicKeys: [recipientPub],
  });
  const env = out.envelope as unknown as Record<string, unknown>;
  const macField = env['slots_mac'];
  const hasSlotsMac = macField instanceof Uint8Array && macField.length === 32;
  record(
    '(h) wrap envelope wire field is slots_mac',
    hasSlotsMac,
    `slots_mac=${hasSlotsMac}, length=${macField instanceof Uint8Array ? macField.length : 'n/a'}`,
  );
}

// (i) enc.slots present but enc.slots_mac absent → ENC_SLOTS_MAC_REQUIRED
{
  const slot = {
    epk: new Uint8Array(32).fill(0xaa),
    wrap: new Uint8Array(48).fill(0xbb),
  };
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
        enc: {
          scheme: 1,
          aead: 'xchacha20-poly1305',
          kem: 'x25519',
          nonce: new Uint8Array(24),
          slots: [slot],
          // slots_mac intentionally omitted
        },
      },
    ],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'ENC_SLOTS_MAC_REQUIRED');
  record(
    '(i) enc.slots without enc.slots_mac → ENC_SLOTS_MAC_REQUIRED',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (j) enc.slots_mac length 31 → ENC_SLOTS_MAC_INVALID_LENGTH
{
  const slot = {
    epk: new Uint8Array(32).fill(0xaa),
    wrap: new Uint8Array(48).fill(0xbb),
  };
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
        enc: {
          scheme: 1,
          aead: 'xchacha20-poly1305',
          kem: 'x25519',
          nonce: new Uint8Array(24),
          slots: [slot],
          slots_mac: new Uint8Array(31), // wrong length
        },
      },
    ],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'ENC_SLOTS_MAC_INVALID_LENGTH');
  record(
    '(j) enc.slots_mac length 31 → ENC_SLOTS_MAC_INVALID_LENGTH',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (k) enc present without uris validates cleanly — `uris` is OPTIONAL throughout
//     per CIP-309 §4.2. Out-of-band ciphertext delivery is a deployment choice;
//     the structural record remains well-formed (verifier-input layer raises
//     `CIPHERTEXT_UNAVAILABLE` at verify time if neither URI nor local
//     ciphertext is available, but the validator does not).
{
  const slot = {
    epk: new Uint8Array(32).fill(0xaa),
    wrap: new Uint8Array(48).fill(0xbb),
  };
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA, 'blake2b-256': BLAKE },
        // uris intentionally omitted — sealed item with out-of-band delivery.
        enc: {
          scheme: 1,
          aead: 'xchacha20-poly1305',
          kem: 'x25519',
          nonce: new Uint8Array(24),
          slots: [slot],
          slots_mac: new Uint8Array(32),
        },
      },
    ],
  });
  const r = validatePoeRecord(cbor);
  record(
    '(k) enc without uris validates cleanly (out-of-band ciphertext)',
    r.valid && (r.warnings ?? []).length === 0,
    `valid=${r.valid}, codes=${codes(r).join(',') || '(none)'}`,
  );
}

// (l) Item carrying only `blake2b-256` (no `sha2-256`) validates cleanly —
//     per CIP-309 §4.3, single-hash records are fully conformant. The verifier's
//     plaintext-hash recomputation iterates `item.hashes` keys and uses the
//     declared algorithm, so a blake2b-only item is supported end-to-end.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'blake2b-256': BLAKE } }],
  });
  const r = validatePoeRecord(cbor);
  record(
    '(l) blake2b-256-only item validates cleanly',
    r.valid && (r.warnings ?? []).length === 0,
    `valid=${r.valid}, codes=${codes(r).join(',') || '(none)'}`,
  );
}

// (m) sigs[i].cose_key carrying a COSE_Key with label -4 (private scalar `d`)
//     → SIG_PRIVATE_KEY_LEAKED per CIP-309 §4.6.3.
//
//     Build a synthetic CBOR<COSE_Key> map:
//       { 1 (kty): 1 (OKP),
//        -1 (crv): 6 (Ed25519),
//        -2 (x):   <32-byte pub>,
//        -4 (d):   <32-byte fake private> }   ← the disqualifier
//     chunk it (here 64-byte chunks; the blob fits in two), wrap into the
//     sigs[i].cose_key field, and confirm the validator emits the typed code.
{
  // CBOR<COSE_Key> with int keys → build as a Map so cbor2 emits an int-keyed
  // CBOR map verbatim (objects in cbor2 emit tstr-keyed maps).
  const coseKey = new Map<number, unknown>();
  coseKey.set(1, 1); // kty = OKP
  coseKey.set(-1, 6); // crv = Ed25519
  coseKey.set(-2, new Uint8Array(32).fill(0x11)); // x (pub)
  coseKey.set(-4, new Uint8Array(32).fill(0xff)); // d (private) — forbidden
  const coseKeyBytes = encodeCanonicalCbor(coseKey);
  // Chunk into ≤64-byte pieces.
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < coseKeyBytes.length; i += 64) {
    chunks.push(coseKeyBytes.slice(i, i + 64));
  }

  // The sigs entry MUST still carry a `cose_sign1` chunk-array; supply a
  // placeholder (the validator surfaces the private-material code FIRST so
  // the COSE_Sign1 structural decode is not consulted in this fixture).
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    sigs: [{ cose_sign1: [new Uint8Array(16).fill(0xab)], cose_key: chunks }],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'SIG_PRIVATE_KEY_LEAKED');
  record(
    '(m) sigs[i].cose_key with COSE_Key label -4 → SIG_PRIVATE_KEY_LEAKED',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (p) Top-level `merkle[]` commitment paired with an items[] companion
//     content-hash entry validates cleanly per CIP-309 §4.5. The Merkle root
//     lives on the record-level `merkle[i]` entry; the companion
//     `leaves.json` content-hash lives on a regular items[] entry alongside
//     the retrieval URI. `leaf_count` is REQUIRED per CIP-309 §4.5.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [
      {
        hashes: { 'sha2-256': SHA },
        uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
      },
    ],
    merkle: [
      {
        alg: 'rfc9162-sha256',
        root: new Uint8Array(32).fill(0xcd),
        uris: [['ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0']],
        leaf_count: 4,
      },
    ],
  });
  const r = validatePoeRecord(cbor);
  record(
    '(p) top-level merkle[] + items[] companion validates cleanly',
    r.valid && (r.warnings ?? []).length === 0,
    `valid=${r.valid}, codes=${codes(r).join(',') || '(none)'}`,
  );
}

// (q) merkle[] entry missing the REQUIRED `leaf_count` field → invalid.
//     Per CIP-309 §4.5 / CIP-309, the structural validator MUST reject
//     a merkle[] commit without `leaf_count`.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    merkle: [
      {
        alg: 'rfc9162-sha256',
        root: new Uint8Array(32).fill(0xcd),
        // leaf_count intentionally omitted
      },
    ],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'SCHEMA_MISSING_REQUIRED');
  record(
    '(q) merkle[] entry without leaf_count → SCHEMA_MISSING_REQUIRED',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (r) Record with unrecognised top-level `crit` extension → invalid with
//     EXTENSION_UNSUPPORTED_CRITICAL (CIP-309 §4.1.4 / CIP-309).
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    crit: ['x-required-foo'],
    'x-required-foo': 'opaque-extension-value',
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'EXTENSION_UNSUPPORTED_CRITICAL');
  record(
    '(r) record with unknown crit extension → EXTENSION_UNSUPPORTED_CRITICAL',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (s) Record with tolerated extension key (no crit) validates cleanly per
//     CIP-309 §4.1.4. Vendor / experimental keys matching `^x-.+` are
//     preserved without verification.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    'x-vendor-note': 'opaque-extension-value',
  });
  const r = validatePoeRecord(cbor);
  record(
    '(s) record with non-critical x-* extension validates cleanly',
    r.valid && (r.warnings ?? []).length === 0,
    `valid=${r.valid}, codes=${codes(r).join(',') || '(none)'}`,
  );
}

// (t) Record with a typo of a base key (e.g. `supersedess`) → SCHEMA_UNKNOWN_FIELD.
//     Per CIP-309 §4.1.4, unknown keys NOT matching `^x-.+` / `^[a-z]+-.+` are
//     rejected as schema errors.
//     `supersedess` matches `^[a-z]+-.+`? No — it has no hyphen. It is a typo.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    supersedess: new Uint8Array(32),
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'SCHEMA_UNKNOWN_FIELD');
  record(
    '(t) typo of base key (supersedess) → SCHEMA_UNKNOWN_FIELD',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (u) `crit[]` entry that names a base key → CRIT_SHAPE_INVALID
//     (CIP-309 §4.1.4 / CIP-309). Base keys (`v`, `items`, `merkle`,
//     `supersedes`, `sigs`, `crit`) MUST NOT appear in `crit[]`.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    crit: ['v'],
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'CRIT_SHAPE_INVALID');
  record(
    '(u) crit references base key → CRIT_SHAPE_INVALID',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (v) `crit[]` entry that names a field absent from the record map →
//     CRIT_SHAPE_INVALID. Each entry MUST be present as a key in the
//     decoded record map.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    crit: ['x-required-foo'],
    // Note: no `x-required-foo` field — the crit entry is a dangling reference.
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'CRIT_SHAPE_INVALID');
  record(
    '(v) crit references missing field → CRIT_SHAPE_INVALID',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

// (w) `crit[]` with duplicate entries → CRIT_SHAPE_INVALID. The duplicate
//     check fires regardless of whether the named extension is implemented.
{
  const cbor = encodeCanonicalCbor({
    v: 1,
    items: [{ hashes: { 'sha2-256': SHA } }],
    crit: ['x-a', 'x-a'],
    'x-a': 1,
  });
  const r = validatePoeRecord(cbor);
  const has = !r.valid && r.issues.some((i) => i.code === 'CRIT_SHAPE_INVALID');
  record(
    '(w) crit duplicate entries → CRIT_SHAPE_INVALID',
    has,
    `codes=${codes(r).join(',')}`,
  );
}

const failed = results.filter((r) => !r.pass);
if (failed.length > 0) {
  console.log(`\n${failed.length} smoke test(s) FAILED: ${failed.map((f) => f.label).join('; ')}`);
  process.exit(1);
}
console.log('\nALL validator smoke tests PASSED');
