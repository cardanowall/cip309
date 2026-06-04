// Label 309 v1 — canonical-CBOR byte-parity smoke test
// Asserts the canonical-CBOR encoder reproduces pinned wire bytes for three
// fixtures. The expected bytes below are the cross-language conformance
// vectors; any implementation (TS, Python, Rust, …) MUST emit them byte-for-
// byte. Run: `npx tsx src/smoke-parity.ts` (exits non-zero on any mismatch).
//
// Fixtures covered:
//   minimal record         — exercises hashes-as-CBOR-map
//   signed record          — exercises hashes map + URI list under
//                            sigs[].cose_sign1
//   sealed multi-recipient — exercises the enc.slots wire field with the
//                            final `scheme: 1` envelope identifier

import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { eciesSealedPoeWrap } from './ecies-sealed-poe.ts';
import { x25519PublicKey } from './x25519.ts';
import { signEd25519 } from './ed25519.ts';
import * as ed from '@noble/ed25519';
import { buildSigStructure, encodeCoseSign1 } from './cose-sign1.ts';

// === Helpers ===

const enc = new TextEncoder();

function hex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function sha256Of(b: Uint8Array): Uint8Array {
  return sha256(b);
}

function blake2b256Of(b: Uint8Array): Uint8Array {
  return blake2b(b, { dkLen: 32 });
}

function chunkBytes(b: Uint8Array, n = 64): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += n) out.push(b.slice(i, i + n));
  return out;
}

function chunkText(s: string, n = 64): string[] {
  if (s.length === 0) return [''];
  const out: string[] = [];
  let cur = '';
  let curLen = 0;
  for (const ch of s) {
    const chB = enc.encode(ch).length;
    if (curLen + chB > n) {
      out.push(cur);
      cur = ch;
      curLen = chB;
    } else {
      cur += ch;
      curLen += chB;
    }
  }
  if (cur) out.push(cur);
  return out;
}

const failures: string[] = [];

function checkParity(label: string, got: Uint8Array, expected: Uint8Array): void {
  if (bytesEqual(got, expected)) {
    console.log(`PASS  ${label}: ${got.length}B byte-parity confirmed`);
  } else {
    failures.push(label);
    console.log(`FAIL  ${label}: byte-mismatch`);
    console.log(`  expected (${expected.length}B): ${hex(expected)}`);
    console.log(`  got      (${got.length}B): ${hex(got)}`);
  }
}

// === Minimal record ===

function checkA1(): void {
  const PLAINTEXT_A1 = enc.encode('minimal fixture content 2026-04-18');
  const digestSha = sha256Of(PLAINTEXT_A1);
  const digestBlake = blake2b256Of(PLAINTEXT_A1);

  // Per Label 309 §4.2, hashes is a CBOR map keyed by alg id; cbor2 encodes a JS
  // object with string keys identically to a Map with the same string keys.
  const record = {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': digestSha,
          'blake2b-256': digestBlake,
        },
      },
    ],
  };
  const cborBytes = encodeCanonicalCbor(record);

  // Expected wire bytes are the pinned cross-language conformance vector.
  const expected = fromHex(
    'a2617601656974656d7381a166686173686573a268736861322d3235365820acbd2db1c365826ec7' +
      '9328a30c46418396121ca457bcb28f6f4275ebff7635e86b626c616b6532622d32353658204933a7' +
      '70ca4423edb274f3d660c2c8ae88e55331bb7eaf622c7a78d52128bae8',
  );
  checkParity('minimal record', cborBytes, expected);
}

// === Signed record ===

const SIG_DOMAIN_RECORD_V1 = enc.encode('cardano-poe-record-sig-v1');
const SIGNER_SK_RFC = fromHex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');

const A2_SHA = fromHex('97a7881ce48f5bf457261797e06e3387a904f0ee70488d3c03090635800320ee');
const A2_BLAKE = fromHex('2d3b9520f17f6be4e26361b18afc8d7bbdbc2cd4209319a77f014f2fd0d409a4');

async function ed25519PublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
  return await ed.getPublicKeyAsync(secretKey);
}

async function checkA2(): Promise<void> {
  const uri = 'ar://2cYNEzFs3PfGvKCEkx1pYBlAFc-FB6ZJpGvRwQEnGm0';
  const body = {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': A2_SHA,
          'blake2b-256': A2_BLAKE,
        },
        uris: [chunkText(uri)],
      },
    ],
  };
  const recordBodyBytes = encodeCanonicalCbor(body);
  const toSign = new Uint8Array(SIG_DOMAIN_RECORD_V1.length + recordBodyBytes.length);
  toSign.set(SIG_DOMAIN_RECORD_V1, 0);
  toSign.set(recordBodyBytes, SIG_DOMAIN_RECORD_V1.length);

  const pub = await ed25519PublicKey(SIGNER_SK_RFC);
  const protectedMap = new Map<number | string, unknown>();
  protectedMap.set(1, -8);
  protectedMap.set(4, pub); // raw 32-B Ed25519 pubkey
  const protectedBytes = encodeCanonicalCbor(protectedMap);

  const sigStruct = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: protectedBytes,
    externalAad: new Uint8Array(0),
    payload: toSign,
  });
  const signature = signEd25519(sigStruct, SIGNER_SK_RFC);

  const coseBytes = encodeCoseSign1({
    protectedHeader: protectedMap,
    unprotectedHeader: new Map(),
    payload: null,
    signature,
  });

  const fullBody = {
    ...body,
    sigs: [{ cose_sign1: chunkBytes(coseBytes, 64) }],
  };
  const cborBytes = encodeCanonicalCbor(fullBody);

  // Expected wire bytes are the pinned cross-language conformance vector.
  const expected = fromHex(
    'a3617601647369677381a16a636f73655f7369676e31825840845826a201270458203d4017c3e843' +
      '895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660ca0f658403053fdd109f2528ca4b9' +
      'c2077d5b7783a38474582dec1380a2047e1c39845eb9470b312d5f16c2f82c61f62ccdcf023a43e4' +
      'd18475c6f6398422df460f0454b8e503656974656d7381a264757269738181783061723a2f2f3263' +
      '594e457a467333506647764b43456b78317059426c4146632d4642365a4a704776527751456e476d' +
      '3066686173686573a268736861322d323536582097a7881ce48f5bf457261797e06e3387a904f0ee' +
      '70488d3c03090635800320ee6b626c616b6532622d32353658202d3b9520f17f6be4e26361b18afc' +
      '8d7bbdbc2cd4209319a77f014f2fd0d409a4',
  );
  checkParity('signed record', cborBytes, expected);
}

// === Sealed multi-recipient record ===

const A5_RECIPIENT_SECRETS = [
  fromHex('0001010101010101010101010101010101010101010101010101010101010141'),
  fromHex('0002020202020202020202020202020202020202020202020202020202020242'),
  fromHex('0003030303030303030303030303030303030303030303030303030303030343'),
];
const A5_EPHEMERAL_SECRETS = [
  fromHex('e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e060'),
  fromHex('e0e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e161'),
  fromHex('e0e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e262'),
];
const A5_CEK = new Uint8Array(32).fill(0xab);
const A5_NONCE = fromHex('202122232425262728292a2b2c2d2e2f3031323334353637');
const A5_PLAINTEXT = Uint8Array.from({ length: 32 }, (_, i) => i);

function checkA5(): void {
  const recipientPubs = A5_RECIPIENT_SECRETS.map((sk) => x25519PublicKey(sk));
  const out = eciesSealedPoeWrap({
    plaintext: A5_PLAINTEXT,
    recipientPublicKeys: recipientPubs,
    cek: A5_CEK,
    nonce: A5_NONCE,
    ephemeralSecrets: A5_EPHEMERAL_SECRETS,
    skipShuffle: true,
  });

  const env = out.envelope;
  // This vector is the classical x25519 case (wrap uses the default KEM), so the
  // slots are the { epk, wrap } shape; narrow the discriminated union on `kem`.
  if (env.kem !== 'x25519') throw new Error('internal: sealed vector expects kem=x25519');
  const record = {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': sha256Of(A5_PLAINTEXT),
          'blake2b-256': blake2b256Of(A5_PLAINTEXT),
        },
        uris: [chunkText('ar://mr8Hj9KqXp1WnZyV5dC4eBfA2sNxYuI3oP6tQrLkE0w')],
        enc: {
          scheme: env.scheme,
          aead: env.aead,
          // Envelope-level `kem` governs every slot in `slots[]` (per Label 309 §4.4).
          kem: env.kem,
          nonce: env.nonce,
          // Wire field name per Label 309 §4.4. Classical slot map carries `{epk, wrap}`.
          slots: env.slots.map((s) => ({ epk: s.epk, wrap: s.wrap })),
          slots_mac: env.slots_mac,
        },
      },
    ],
  };
  const cborBytes = encodeCanonicalCbor(record);

  // Expected wire bytes are the pinned cross-language conformance vector;
  // every conformant implementation MUST emit them byte-for-byte.
  const expected = fromHex(
    'a2617601656974656d7381a363656e63a6636b656d667832353531396461656164727863686163686132302d706f6c7931333035656e6f6e63655818202122232425262728292a2b2c2d2e2f303132333435363765736c6f747383a26365706b5820ff5d87907f1394b3a131985b894f513de72778ce27b8c10b32f93982a87cda47647772617058302959c1396b5a39e83c490dcaa0f30402af0de5e014ec039efb6f6c8fc285f3edd1d90b68e033346b774cee7e4446afcba26365706b58204c2817a9d668ed844d2f95b93b69ecb8485095783a015a424164b0d09702894f647772617058307a33f052e008726a0d493442cd989a4db003ae03bba17468f24ff28d42a72eaa33c491cdc166b72b1b233bb258d14594a26365706b582019d80204bf85f3e1118e1b23410c88f0d0eeced5156f4c5bdf347b14ed7ec63f64777261705830aff28d0fcebf959b7a965408e9f686080371c3a28192740de6cfc4d8bf9ab3d12e34c272ad28fc9ee0f3af5fe0f7fb4866736368656d650169736c6f74735f6d6163582009de49b54ce73f1dd94827537d215103868fe5a229fb6fa40b5c44b4c23f6e7864757269738181783061723a2f2f6d7238486a394b71587031576e5a7956356443346542664132734e78597549336f50367451724c6b45307766686173686573a268736861322d3235365820630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd6b626c616b6532622d3235365820cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6',
  );
  checkParity('sealed multi-recipient', cborBytes, expected);
}

// === Driver ===

async function main(): Promise<void> {
  checkA1();
  await checkA2();
  checkA5();

  if (failures.length > 0) {
    console.log(`\n${failures.length} parity check(s) FAILED: ${failures.join(', ')}`);
    process.exit(1);
  }
  console.log('\nALL parity checks PASSED');
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
