// CIP-309 v1 reference implementation — standalone verifier example (offline)
//
// Drives the full `verifyTx` standalone verifier end to end WITHOUT any network
// by injecting a `fetchOutbound` that serves a synthetic Cardano transaction.
// In production `fetchOutbound` is the real HTTPS egress to a Koios/Blockfrost
// gateway; here it returns a tx we build ourselves so the example is
// reproducible and self-contained.
//
// The synthetic tx carries a signed hash-only PoE record under metadata
// label 309, wrapped in post-Conway auxiliary_data (CBOR tag 259). The verifier:
//   1. fetches the raw tx CBOR + confirmation depth via `fetchOutbound`,
//   2. byte-slices the label-309 value out of the tx (no re-encode),
//   3. structurally validates the record,
//   4. verifies the record-level Ed25519 signature against the preserved
//      protected bytes,
//   5. emits a VerifyReport with a verdict and an audit trail of every call.
//
// Run: `npx tsx src/standalone-verify-example.ts` (exits non-zero on a bad verdict).

import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { buildRecordSignaturePayload } from './cip-309-encoder.ts';
import { encodeCoseSign1, buildSigStructure } from './cose-sign1.ts';
import { generateEd25519KeyPair, signEd25519 } from './ed25519.ts';
import type { PoeRecord } from './cip-309-validator.ts';
import { verifyTx, type FetchOutbound, type VerifyReport } from './standalone-verifier.ts';

const enc = new TextEncoder();

// ----- Hand-rolled definite-length CBOR helpers for the OUTER tx wrapper -----
// We bypass the canonical encoder for the tx envelope so we can place the
// label-309 value bytes verbatim — exactly the positional byte-slice the
// verifier's extractor must recover.

function u8(...bytes: number[]): Uint8Array {
  return Uint8Array.from(bytes);
}
function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
function cborUint(n: number): Uint8Array {
  if (n < 24) return u8(n);
  if (n < 0x100) return u8(0x18, n);
  if (n < 0x10000) return u8(0x19, (n >> 8) & 0xff, n & 0xff);
  return u8(0x1a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}
function cborHead(mt: number, n: number): Uint8Array {
  const u = cborUint(n);
  const out = new Uint8Array(u.length);
  out[0] = (mt << 5) | (u[0]! & 0x1f);
  out.set(u.subarray(1), 1);
  return out;
}
function cborArray(items: Uint8Array[]): Uint8Array {
  return concat(cborHead(4, items.length), ...items);
}
function cborMap(pairs: Array<[Uint8Array, Uint8Array]>): Uint8Array {
  const flat: Uint8Array[] = [];
  for (const [k, v] of pairs) {
    flat.push(k, v);
  }
  return concat(cborHead(5, pairs.length), ...flat);
}
function cborTag(tag: number, body: Uint8Array): Uint8Array {
  return concat(cborHead(6, tag), body);
}
function cborBool(v: boolean): Uint8Array {
  return u8(v ? 0xf5 : 0xf4);
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}
function chunkBytes(b: Uint8Array, n = 64): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += n) out.push(b.slice(i, i + n));
  return out;
}

// ----- Build a signed hash-only PoE record (the on-chain label-309 value) -----

function buildSignedRecordBytes(): Uint8Array {
  const content = enc.encode('standalone-verifier example content');
  const body: PoeRecord = {
    v: 1,
    items: [
      {
        hashes: {
          'sha2-256': sha256(content),
          'blake2b-256': blake2b(content, { dkLen: 32 }),
        },
      },
    ],
  };

  const signer = generateEd25519KeyPair();
  const toSign = buildRecordSignaturePayload(body);
  const protectedHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, signer.publicKey],
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
    payload: null,
    signature,
  });

  return encodeCanonicalCbor({
    ...body,
    sigs: [{ cose_sign1: chunkBytes(coseSign1) }],
  });
}

// ----- Assemble a synthetic post-Conway tx carrying the record -----

function buildTxCbor(recordBytes: Uint8Array): Uint8Array {
  // auxiliary_data = tag(259, { 0 => { 309 => <record> } })
  const metadataMap = cborMap([[cborUint(309), recordBytes]]);
  const auxMap = cborMap([[cborUint(0), metadataMap]]);
  const auxData = cborTag(259, auxMap);
  // tx = [body, witness_set, is_valid, auxiliary_data]; body/witness are empty
  // maps — the verifier only needs to skip past them to reach auxiliary_data.
  return cborArray([cborMap([]), cborMap([]), cborBool(true), auxData]);
}

// ----- Injected fetchOutbound that serves the synthetic tx -----

function makeFakeGateway(txCbor: Uint8Array): FetchOutbound {
  const txHex = bytesToHex(txCbor);
  return async (url, opts) => {
    const respond = (obj: unknown) => ({
      status: 200,
      bytes: enc.encode(JSON.stringify(obj)),
      durationMs: 1,
    });
    if (url.endsWith('/tx_cbor')) {
      // Koios /tx_cbor returns [{ tx_hash, cbor }]
      return respond([{ tx_hash: 'demo', cbor: txHex }]);
    }
    if (url.endsWith('/tx_info')) {
      // Koios /tx_info returns confirmation depth + block metadata. 100 >> the
      // default 15-block threshold, so the verdict is 'valid' not 'pending'.
      return respond([
        { num_confirmations: 100, tx_timestamp: 1_700_000_000, absolute_slot: 123_456 },
      ]);
    }
    void opts;
    return { status: 404, bytes: new Uint8Array(0), durationMs: 1 };
  };
}

// ----- Driver -----

async function main(): Promise<void> {
  const recordBytes = buildSignedRecordBytes();
  const txCbor = buildTxCbor(recordBytes);

  const report: VerifyReport = await verifyTx({
    txHash: 'demo-tx-hash',
    network: 'cardano:mainnet',
    fetchOutbound: makeFakeGateway(txCbor),
  });

  console.log('--- VerifyReport ---');
  console.log(`verdict           : ${report.verdict}`);
  console.log(`exitCode          : ${report.exitCode}`);
  console.log(`metadataPresent   : ${report.metadataPresent}`);
  console.log(
    `numConfirmations  : ${report.numConfirmations} (threshold ${report.confirmationDepthThreshold})`,
  );
  console.log(`validation.valid  : ${report.validation.valid}`);
  console.log(
    `recordSignatures  : ${(report.recordSignatures ?? [])
      .map((s) => `#${s.index} ${s.valid ? 'valid' : `invalid(${s.reason})`}`)
      .join(', ')}`,
  );
  console.log(`httpCalls         : ${report.httpCalls.length} outbound call(s)`);
  for (const call of report.httpCalls) {
    console.log(`    ${call.method} ${call.url} -> ${call.status} (${call.purpose})`);
  }

  const ok =
    report.verdict === 'valid' &&
    report.exitCode === 0 &&
    report.validation.valid === true &&
    (report.recordSignatures ?? []).every((s) => s.valid);

  console.log(
    `\n${ok ? 'PASS' : 'FAIL'}  standalone verification produced a clean 'valid' verdict`,
  );
  if (!ok) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
