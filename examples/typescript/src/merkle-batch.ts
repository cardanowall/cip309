// Label 309 batch anchoring — the top-level `merkle[]` list commitment.
//
// One transaction can anchor an ordered list of leaf digests by committing
// only the RFC 9162 Merkle root and the leaf count on chain; the full leaves
// list lives off-chain in the normative CBOR leaves-list document. Anyone
// holding the document can recompute the root; anyone holding a single leaf
// plus an inclusion proof can verify membership without the other leaves.
//
// The example:
//   1. hashes a batch of documents into leaf digests (SHA-256),
//   2. builds the on-chain commitment { alg, root, leaf_count } and
//      validates the record structurally,
//   3. encodes / decodes the off-chain CBOR leaves-list document and
//      recomputes the root from it,
//   4. produces and verifies an RFC 9162 inclusion proof for one leaf,
//   5. hands the leaves-list to the standalone verifier OUT OF BAND
//      (`merkleLeaves`) and reads the per-commitment contentCheck from the
//      report — caller-supplied bytes are attributable by definition and
//      need no fetch.
//
// Run: `node src/merkle-batch.ts` (exits non-zero on any failed check).

import { encodePoeRecord, PoeRecordSchema, validatePoeRecord } from '@cardanowall/poe-standard';
import { hash, merkle, verifyResolved } from '@cardanowall/sdk-ts';

const enc = new TextEncoder();

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

let failures = 0;
function check(label: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok || detail === '' ? '' : ` — ${detail}`}`);
  if (!ok) failures += 1;
}

async function main(): Promise<void> {
  // ── 1. The batch ──────────────────────────────────────────────────────────
  const documents = Array.from({ length: 5 }, (_, i) => enc.encode(`batch document #${i}`));
  const leaves = documents.map((d) => hash.sha2256(d));

  // ── 2. The on-chain commitment ────────────────────────────────────────────
  const root = merkle.merkleSha2256Root(leaves);
  const record = PoeRecordSchema.parse({
    v: 1,
    merkle: [
      {
        alg: merkle.MERKLE_ALG_ID, // 'rfc9162-sha256'
        root,
        leaf_count: leaves.length, // REQUIRED alongside the root
      },
    ],
  });
  console.log(`merkle root         : ${hex(root)} over ${leaves.length} leaves`);
  check(
    'record with a merkle[] commitment validates',
    validatePoeRecord(encodePoeRecord(record)).valid,
  );

  // ── 3. The off-chain leaves-list document (normative CBOR) ───────────────
  // The wire form every implementation must read; a JSON projection of it is
  // a display convenience only.
  const leavesListBytes = merkle.encodeLeavesList({ leaves, root });
  const decoded = merkle.decodeLeavesList(leavesListBytes);
  console.log(
    `leaves-list document: ${leavesListBytes.length} bytes, format ${decoded.format}, tree ${decoded.treeAlg}`,
  );
  check('document round-trips the leaf set', decoded.leafCount === leaves.length);
  check(
    'root recomputes from the decoded leaves',
    bytesEqual(merkle.merkleSha2256Root(decoded.leaves), root),
  );

  // ── 4. Inclusion proof for one leaf ───────────────────────────────────────
  // log2(N) sibling hashes prove membership of leaf 3 without revealing the
  // other documents.
  const index = 3;
  const proof = merkle.merkleSha2256InclusionProof(leaves, index);
  check(
    'inclusion proof verifies',
    merkle.merkleSha2256VerifyInclusion(leaves[index]!, index, leaves.length, proof, root),
  );
  check(
    'proof rejects a different leaf',
    !merkle.merkleSha2256VerifyInclusion(
      hash.sha2256(enc.encode('not in the batch')),
      index,
      leaves.length,
      proof,
      root,
    ),
  );

  // ── 5. The verifier checks the commitment ─────────────────────────────────
  // `merkleLeaves` supplies the document out of band, keyed by `merkle[i]`
  // index: no fetch is issued, the bytes are attributable by definition, and
  // the report's per-commitment entry shows the claim was actually checked
  // (document validated + root recomputed). Had the commitment carried
  // `uris[]`, the verifier would fetch the document from there instead.
  const report = await verifyResolved({
    txHash: '22'.repeat(32),
    metadataCbor: encodePoeRecord(record),
    confirmationDepth: 20,
    blockTime: 1_700_000_000,
    merkleLeaves: { 0: leavesListBytes },
  });
  check('verdict valid', report.verdict === 'valid' && report.exitCode === 0);
  check('one per-commitment report entry', report.merkle.length === 1);
  check('commitment contentCheck is checked', report.merkle[0]?.contentCheck === 'checked');

  // A leaves-list that does not match the on-chain root is record-attributable.
  const wrongList = merkle.encodeLeavesList({
    leaves: [...leaves].reverse(),
    root: merkle.merkleSha2256Root([...leaves].reverse()),
  });
  const mismatch = await verifyResolved({
    txHash: '22'.repeat(32),
    metadataCbor: encodePoeRecord(record),
    confirmationDepth: 20,
    blockTime: 1_700_000_000,
    merkleLeaves: { 0: wrongList },
  });
  check(
    'root mismatch → verdict failed with MERKLE_ROOT_MISMATCH',
    mismatch.verdict === 'failed' &&
      mismatch.issues.some((i) => i.code === 'MERKLE_ROOT_MISMATCH') &&
      mismatch.merkle[0]?.contentCheck === 'mismatched',
    [...new Set(mismatch.issues.map((i) => i.code))].join(','),
  );

  if (failures > 0) {
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nALL merkle-batch checks PASSED');
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(2);
});
