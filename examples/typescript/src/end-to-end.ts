// Label 309 end-to-end walk-through: produce a signed Proof-of-Existence
// record, carry it across the metadata-label-309 transport, and verify it
// standalone — all offline.
//
//   1. Hash the content (SHA-256 + BLAKE2b-256, the dual-hash recommendation).
//   2. Build the record body and attach a record-level COSE_Sign1 signature.
//   3. Encode the body to canonical CBOR and split it into the whole-body
//      ≤ 64-byte chunk array — the only chunking the format performs. Fields
//      inside the body (URIs, signatures, KEM ciphertexts) are ordinary CBOR
//      values with no per-field chunk wrappers.
//   4. Reassemble + structurally validate, exactly as a verifier would.
//   5. Run the standalone verifier (`verifyResolved`) over the record body
//      plus an explorer-asserted block-info tuple and read the four-state
//      verdict and its process exit code.
//   6. Round-trip a sealed PoE: wrap the content to a recipient, unwrap it
//      with the recipient's key bundle, and recheck the plaintext hashes.
//
// Run: `node src/end-to-end.ts` (exits non-zero on any failed check).

import {
  chunkRecordBody,
  encodeLabel309Value,
  encodePoeRecord,
  PoeRecordSchema,
  reassembleLabel309Value,
  validatePoeRecord,
  type PoeRecord,
} from '@cardanowall/poe-standard';
import {
  assembleCoseSign1,
  deriveX25519KeypairFromSeed,
  eciesSealedPoeUnwrap,
  eciesSealedPoeWrap,
  EXIT_CODE_FOR_VERDICT,
  exitCodeForVerdict,
  hash,
  IssueSink,
  prepareSigStructure,
  recipientKeyBundleFromSeed,
  signerFromSeed,
  verifyRecordSignatures,
  verifyResolved,
} from '@cardanowall/sdk-ts';

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
  // ── 1. Hash the content ───────────────────────────────────────────────────
  // The content hash is the primary claim; everything else is metadata about
  // it. Two independent digests (SHA-2 and BLAKE2b families) guard the claim
  // against a future break in either.
  const content = enc.encode('end-to-end example content');
  const hashes = {
    'sha2-256': hash.sha2256(content),
    'blake2b-256': hash.blake2b256(content),
  };
  console.log(`content sha2-256    : ${hex(hashes['sha2-256'])}`);

  // ── 2. Build the record and sign it ───────────────────────────────────────
  // Authorship is an opt-in claim: the record validates with or without
  // `sigs`. The signature covers the canonical CBOR of the body minus `sigs`,
  // domain-separated by the 25-byte prefix "cardano-poe-record-sig-v1"
  // (handled inside the helpers). The signing flow is off-host-friendly:
  // prepare the Sig_structure, sign it anywhere (HSM, air-gap, wallet), then
  // assemble the COSE_Sign1.
  const unsignedRecord: PoeRecord = PoeRecordSchema.parse({
    v: 1,
    items: [{ hashes }],
  });
  const signerSeed = new Uint8Array(32).fill(7);
  const signer = signerFromSeed(signerSeed);
  const { sigStructureBytes } = prepareSigStructure({
    record: unsignedRecord,
    signerPubkey: signer.signerPubkey,
  });
  const signature = await signer.sign(sigStructureBytes);
  const { sigEntry } = assembleCoseSign1({
    record: unsignedRecord,
    signerPubkey: signer.signerPubkey,
    signature,
  });
  const record: PoeRecord = PoeRecordSchema.parse({ ...unsignedRecord, sigs: [sigEntry] });
  // The COSE_Sign1 is one byte string inside the body — no per-field chunking.
  check('sigs[0].cose_sign1 is a single byte string', sigEntry.cose_sign1 instanceof Uint8Array);

  // ── 3. Canonical CBOR + the chunk-array transport ─────────────────────────
  // The body is serialised once to canonical CBOR (RFC 8949 §4.2.1) and
  // crosses the ledger as an opaque whole-body chunk array of ≤ 64-byte byte
  // strings — the ledger's per-metadatum string cap is the only reason the
  // split exists, and chunk boundaries carry no semantics.
  const body = encodePoeRecord(record);
  const chunks = chunkRecordBody(body);
  const label309Value = encodeLabel309Value(body);
  console.log(
    `record body         : ${body.length} bytes → ${chunks.length} transport chunk(s), label-309 value ${label309Value.length} bytes`,
  );

  // ── 4. Reassemble + structural validation ─────────────────────────────────
  // A verifier byte-concatenates the chunk array back into the body, then runs
  // the pure structural validator: no I/O, no signature crypto, no decryption.
  const reassembled = reassembleLabel309Value(label309Value);
  check(
    'transport round-trips byte-identically',
    reassembled.ok && bytesEqual(reassembled.body, body),
  );
  const validation = validatePoeRecord(body);
  check('structural validation accepts the record', validation.valid);

  // The record-level signature verifies against the reassembled bytes alone.
  if (validation.valid) {
    const sigs = verifyRecordSignatures({
      record: validation.record,
      cardanoNetwork: 'mainnet',
      issues: new IssueSink(),
    });
    check(
      'record signature verifies (path 1, in-signature kid)',
      sigs.length === 1 &&
        sigs[0]?.verdict === 'valid' &&
        sigs[0]?.signerPub === hex(signer.signerPubkey),
    );
  }

  // ── 5. Standalone verification ────────────────────────────────────────────
  // `verifyResolved` runs the verifier pipeline from the structural-validator
  // step onward over caller-supplied record-body bytes plus the
  // explorer-asserted block-info tuple (`verifyTx` is the sibling entry point
  // that resolves a live transaction first — see verify-offline.ts). The
  // verdict is four-state and maps to a process exit code so scripts can
  // branch without parsing the report:
  //   valid → 0   failed → 1   unverifiable → 2   pending → 3
  const report = await verifyResolved({
    txHash: '11'.repeat(32),
    metadataCbor: body,
    confirmationDepth: 20,
    blockTime: 1_700_000_000,
    fetchContent: false, // hash-only record: nothing to fetch anyway
  });
  console.log(
    `verdict             : ${report.verdict} (exit code ${report.exitCode}), block_time ${report.block_time}`,
  );
  check('verdict is valid with exit code 0', report.verdict === 'valid' && report.exitCode === 0);
  check(
    'exit code follows the verdict mapping',
    exitCodeForVerdict(report) === EXIT_CODE_FOR_VERDICT[report.verdict],
  );
  check('report carries one per-item entry', report.items.length === 1);
  check(
    'hash-only claim is reported not_checked, never silently "ok"',
    report.items[0]?.contentCheck === 'not_checked',
  );
  check('offline run has an empty audit trail', report.auditTrail.length === 0);

  // ── 6. Sealed PoE round-trip ──────────────────────────────────────────────
  // A sealed PoE keeps the plaintext readable only by intended recipients
  // while the on-chain record still commits to the plaintext hash. The
  // envelope is bound to this item's `hashes` map, so an envelope spliced
  // onto a different hash claim fails before any content work (sealed-poe.ts
  // tours the construction in depth).
  const recipientSeed = new Uint8Array(32).fill(9);
  const recipientPub = deriveX25519KeypairFromSeed(recipientSeed).publicKey;
  const sealed = eciesSealedPoeWrap({
    plaintext: content,
    hashes,
    recipientPublicKeys: [recipientPub],
    kem: 'x25519',
  });
  const opened = eciesSealedPoeUnwrap({
    envelope: sealed.envelope,
    ciphertext: sealed.ciphertext,
    hashes,
    recipientKeyBundle: recipientKeyBundleFromSeed(recipientSeed),
  });
  check('sealed PoE unwraps for the recipient', opened.matched);
  if (opened.matched) {
    check('decrypted plaintext matches the original bytes', bytesEqual(opened.plaintext, content));
    // The post-decryption recheck: recompute every digest in `hashes` over the
    // recovered plaintext. A mismatch is a record-attributable `failed`
    // outcome (URI_INTEGRITY_MISMATCH) — the recipient must refuse to act.
    check(
      'plaintext-hash recheck passes',
      bytesEqual(hash.sha2256(opened.plaintext), hashes['sha2-256']) &&
        bytesEqual(hash.blake2b256(opened.plaintext), hashes['blake2b-256']),
    );
  }

  if (failures > 0) {
    console.log(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nALL end-to-end checks PASSED');
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(2);
});
