// Label 309 standalone-verifier tour — every verdict, offline.
//
// Drives the full `verifyTx` pipeline with an injected `fetchOutbound` that
// serves a synthetic Cardano transaction and its content, so the example is
// reproducible without any network. In production the same call resolves a
// real transaction through whatever Koios-compatible explorer chain the
// caller configures; nothing else changes.
//
// The synthetic transaction genuinely satisfies the verifier's integrity
// bindings: the requested hash is the blake2b-256 of the transaction body,
// and the body commits to the auxiliary data (which carries the label-309
// chunk array) via `auxiliary_data_hash`.
//
// The tour exercises the four-state verdict and its exit-code mapping —
//
//   valid → 0    failed → 1    unverifiable → 2    pending → 3
//
// — plus the `fetchContent` switch and the attribution split on fetched
// content: bytes that provably belong to the URI (e.g. an ipfs:// raw CID
// whose multihash recomputes) and fail a committed digest condemn the record
// (URI_INTEGRITY_MISMATCH → failed), while bytes a gateway merely served
// (e.g. ar://, no offline binding check) that mismatch indict only the
// provider (URI_PROVIDER_INTEGRITY_MISMATCH, warning) — the claim ends
// unchecked and the verdict is `unverifiable`, never `failed`.
//
// Run: `node src/verify-offline.ts` (exits non-zero on any failed check).

import {
  encodeLabel309Value,
  encodePoeRecord,
  PoeRecordSchema,
  type PoeRecord,
} from '@cardanowall/poe-standard';
import {
  assembleCoseSign1,
  hash,
  prepareSigStructure,
  signerFromSeed,
  verifyReportToDict,
  verifyTx,
  type FetchOutbound,
  type FetchOutboundResult,
  type VerifyReport,
} from '@cardanowall/sdk-ts';

const enc = new TextEncoder();

// Explicit gateway chains keep the demo's routing visible; any
// Koios-compatible explorer and any Arweave/IPFS gateways work the same way.
const CARDANO_GATEWAY = 'https://koios.example/api/v1';
const ARWEAVE_GATEWAY = 'https://arweave-gateway.example';
const IPFS_GATEWAY = 'https://ipfs-gateway.example';
const ARWEAVE_TXID = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok || detail === '' ? '' : ` — ${detail}`}`);
  if (!ok) failures += 1;
}

// ── Synthetic bound transaction ──────────────────────────────────────────────
// Minimal definite-length CBOR writers for the OUTER transaction wrapper. The
// wrapper is the ledger's shape, not this standard's — the record body inside
// it is produced by the SDK encoders above.

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** CBOR header for major type `mt` with argument `n` (n < 2^16 suffices here). */
function cborHead(mt: number, n: number): Uint8Array {
  if (n < 24) return Uint8Array.from([(mt << 5) | n]);
  if (n < 0x100) return Uint8Array.from([(mt << 5) | 24, n]);
  return Uint8Array.from([(mt << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
}

/**
 * Build `(txHash, txCbor)` for a transaction whose auxiliary data carries the
 * record body as the label-309 chunk array, with both integrity bindings the
 * verifier checks satisfied: blake2b-256(body) is the transaction hash, and
 * the body's `auxiliary_data_hash` (key 7) is blake2b-256(aux data).
 */
function buildBoundTx(recordBody: Uint8Array): { txHash: string; txCbor: Uint8Array } {
  // auxiliary data: the plain metadata-map form, { 309: <chunk array> }
  const aux = concat(cborHead(5, 1), cborHead(0, 309), encodeLabel309Value(recordBody));
  // transaction body: { 7: blake2b-256(aux) }
  const body = concat(cborHead(5, 1), cborHead(0, 7), cborHead(2, 32), hash.blake2b256(aux));
  // transaction: [ body, witness_set, is_valid, auxiliary_data ]
  const txCbor = concat(cborHead(4, 4), body, cborHead(5, 0), Uint8Array.from([0xf5]), aux);
  return { txHash: hex(hash.blake2b256(body)), txCbor };
}

// ── Injected fetchOutbound ───────────────────────────────────────────────────

function jsonResponse(value: unknown): FetchOutboundResult {
  return { status: 200, bytes: enc.encode(JSON.stringify(value)), durationMs: 1 };
}

function makeGatewayStub(args: {
  txHash: string;
  txCbor: Uint8Array;
  confirmations: number;
  content?: Readonly<Record<string, Uint8Array>>; // URL → served bytes
}): FetchOutbound {
  return async (url) => {
    if (url === `${CARDANO_GATEWAY}/tx_cbor`) {
      return jsonResponse([{ tx_hash: args.txHash, cbor: hex(args.txCbor) }]);
    }
    if (url === `${CARDANO_GATEWAY}/tx_info`) {
      return jsonResponse([
        {
          tx_hash: args.txHash,
          num_confirmations: args.confirmations,
          tx_timestamp: 1_700_000_000,
          absolute_slot: 99,
        },
      ]);
    }
    const served = args.content?.[url];
    if (served !== undefined) return { status: 200, bytes: served, durationMs: 1 };
    return { status: 404, bytes: new Uint8Array(0), durationMs: 1 };
  };
}

// ── Record builders ──────────────────────────────────────────────────────────

async function buildSignedRecord(item: Record<string, unknown>): Promise<PoeRecord> {
  const unsigned: PoeRecord = PoeRecordSchema.parse({ v: 1, items: [item] });
  const signer = signerFromSeed(new Uint8Array(32).fill(3));
  const { sigStructureBytes } = prepareSigStructure({
    record: unsigned,
    signerPubkey: signer.signerPubkey,
  });
  const { sigEntry } = assembleCoseSign1({
    record: unsigned,
    signerPubkey: signer.signerPubkey,
    signature: await signer.sign(sigStructureBytes),
  });
  return PoeRecordSchema.parse({ ...unsigned, sigs: [sigEntry] });
}

// RFC 4648 lowercase base32, no padding — for raw-codec CIDv1 strings whose
// multihash binding the verifier can recompute offline.
function base32(bytes: Uint8Array): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += alphabet[(acc >> bits) & 0x1f]!;
    }
  }
  if (bits > 0) out += alphabet[(acc << (5 - bits)) & 0x1f]!;
  return out;
}

function rawSha256CidV1(content: Uint8Array): string {
  const digest = hash.sha2256(content);
  // 0x01 CIDv1 | 0x55 raw codec | 0x12 sha2-256 | 0x20 32-byte digest
  return `b${base32(concat(Uint8Array.from([0x01, 0x55, 0x12, 0x20]), digest))}`;
}

async function runVerify(args: {
  record: PoeRecord;
  confirmations: number;
  content?: Readonly<Record<string, Uint8Array>>;
  fetchContent?: boolean;
}): Promise<VerifyReport> {
  const { txHash, txCbor } = buildBoundTx(encodePoeRecord(args.record));
  return verifyTx({
    txHash,
    cardanoGatewayChain: [CARDANO_GATEWAY],
    arweaveGatewayChain: [ARWEAVE_GATEWAY],
    ipfsGatewayChain: [IPFS_GATEWAY],
    fetchOutbound: makeGatewayStub({
      txHash,
      txCbor,
      confirmations: args.confirmations,
      ...(args.content !== undefined ? { content: args.content } : {}),
    }),
    ...(args.fetchContent !== undefined ? { fetchContent: args.fetchContent } : {}),
  });
}

function issueCodes(report: VerifyReport): string[] {
  return [...new Set(report.issues.map((i) => i.code))].sort();
}

// ── The tour ─────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const content = enc.encode('verify-offline example content');
  const wrongBytes = enc.encode('NOT the committed content');
  const arUri = `ar://${ARWEAVE_TXID}`;

  // 1. valid — the transaction resolves, the record validates, the signature
  //    verifies, and the fetched ar:// bytes satisfy every committed digest.
  const record = await buildSignedRecord({
    hashes: { 'sha2-256': hash.sha2256(content) },
    uris: [arUri],
  });
  const valid = await runVerify({
    record,
    confirmations: 50,
    content: { [`${ARWEAVE_GATEWAY}/${ARWEAVE_TXID}`]: content },
  });
  console.log('--- verdict: valid ---');
  console.log(JSON.stringify(verifyReportToDict(valid), null, 2));
  check('valid: verdict valid, exit 0', valid.verdict === 'valid' && valid.exitCode === 0);
  check('valid: item content checked', valid.items[0]?.contentCheck === 'checked');
  check('valid: signature verified', valid.signatures?.[0]?.verdict === 'valid');
  check(
    'valid: audit trail records every outbound call',
    valid.auditTrail.length >= 3 && valid.auditTrail.some((c) => c.purpose === 'arweave'),
  );

  // 2. pending — below the confirmation-depth threshold (default 15 blocks)
  //    the pipeline halts: no result from a record that may yet be orphaned
  //    may be presented as final.
  const pending = await runVerify({ record, confirmations: 3 });
  check(
    'pending: verdict pending, exit 3',
    pending.verdict === 'pending' && pending.exitCode === 3,
  );
  check(
    'pending: INSUFFICIENT_CONFIRMATIONS raised',
    pending.issues.some((i) => i.code === 'INSUFFICIENT_CONFIRMATIONS'),
  );
  check(
    'pending: depth and threshold reported',
    pending.confirmationDepth === 3 && pending.confirmationThreshold === 15,
  );

  // 3. fetchContent: false — the master content-fetch switch. The record
  //    renders offline from the chain-resolved CBOR alone; every content
  //    claim is reported not_checked (an unchecked claim can never
  //    masquerade as a verified one), and no content egress happens.
  const offline = await runVerify({ record, confirmations: 50, fetchContent: false });
  check('fetchContent off: verdict still valid', offline.verdict === 'valid');
  check('fetchContent off: claim not_checked', offline.items[0]?.contentCheck === 'not_checked');
  check(
    'fetchContent off: no content fetch in the audit trail',
    offline.auditTrail.every((c) => c.purpose === 'cardano'),
  );

  // 4. unverifiable — the gateway serves bytes that fail the digest, but an
  //    ar:// fetch carries no offline binding proof, so the mismatch indicts
  //    the provider, not the record: URI_PROVIDER_INTEGRITY_MISMATCH
  //    (warning), then CONTENT_UNAVAILABLE once every source is exhausted.
  const providerMismatch = await runVerify({
    record,
    confirmations: 50,
    content: { [`${ARWEAVE_GATEWAY}/${ARWEAVE_TXID}`]: wrongBytes },
  });
  check(
    'provider mismatch: verdict unverifiable, exit 2',
    providerMismatch.verdict === 'unverifiable' && providerMismatch.exitCode === 2,
  );
  check(
    'provider mismatch: URI_PROVIDER_INTEGRITY_MISMATCH + CONTENT_UNAVAILABLE',
    providerMismatch.issues.some((i) => i.code === 'URI_PROVIDER_INTEGRITY_MISMATCH') &&
      providerMismatch.issues.some((i) => i.code === 'CONTENT_UNAVAILABLE'),
    issueCodes(providerMismatch).join(','),
  );
  check(
    'provider mismatch: claim stays not_checked',
    providerMismatch.items[0]?.contentCheck === 'not_checked',
  );

  // 5. failed — the same wrong bytes behind an ipfs:// raw CIDv1 whose
  //    multihash recomputes over them: now the bytes provably belong to the
  //    URI the producer published, so the digest failure is
  //    record-attributable: URI_INTEGRITY_MISMATCH, verdict failed.
  const wrongCid = rawSha256CidV1(wrongBytes);
  const lyingRecord = await buildSignedRecord({
    hashes: { 'sha2-256': hash.sha2256(content) },
    uris: [`ipfs://${wrongCid}`],
  });
  const attributableMismatch = await runVerify({
    record: lyingRecord,
    confirmations: 50,
    content: { [`${IPFS_GATEWAY}/ipfs/${wrongCid}`]: wrongBytes },
  });
  check(
    'attributable mismatch: verdict failed, exit 1',
    attributableMismatch.verdict === 'failed' && attributableMismatch.exitCode === 1,
  );
  check(
    'attributable mismatch: URI_INTEGRITY_MISMATCH raised',
    attributableMismatch.issues.some((i) => i.code === 'URI_INTEGRITY_MISMATCH'),
    issueCodes(attributableMismatch).join(','),
  );
  check(
    'attributable mismatch: claim reported mismatched',
    attributableMismatch.items[0]?.contentCheck === 'mismatched',
  );

  if (failures > 0) {
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nALL verifier-tour checks PASSED');
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(2);
});
