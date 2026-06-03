// CIP-309 v1 reference implementation — Standalone CIP-309 verifier
// Spec: CIP-309 (standalone verification; §7)
// Service-independent: depends only on user-supplied Cardano + Arweave gateways.
//
// Key invariants this verifier MUST uphold:
//  - Fetch RAW tx CBOR (Koios /tx_cbor or Blockfrost /txs/{hash}/cbor), NOT the
//    JSON metadata projection — the JSON path is lossy and breaks signature
//    verification.
//  - Enforce confirmation depth ≥ threshold (default 15 blocks). Below threshold
//    surfaces as `INSUFFICIENT_CONFIRMATIONS` with `verdict: 'pending'`.
//  - Build `to_sign = SIG_DOMAIN_RECORD_V1 || canonical_cbor(record_body)` and
//    pass `external_aad = h''` to the COSE Sig_structure (CIP-309 §4.6.1).
//    Signatures attach at the record level only — only `record.sigs[]` is verified.
//  - Use the COSE_Sign1's preserved protectedBytes verbatim,
//    NOT a re-encoded form.
//  - Use strict Ed25519 (zip215: false) — already wired in ed25519.ts.
//  - Route every outbound call through fetchOutbound; record into VerifyReport.httpCalls.

import { decode as decodeCbor } from 'cbor2';
import { sha256 } from '@noble/hashes/sha2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { sliceLabel309Value } from './cbor-walker.ts';
import { validatePoeRecord, type PoeRecord, type ValidationIssue } from './cip-309-validator.ts';
import { decodeCoseSign1, buildSigStructure } from './cose-sign1.ts';
import { verifyEd25519 } from './ed25519.ts';
import { eciesSealedPoeUnwrap } from './ecies-sealed-poe.ts';
import { eciesKdfUnwrap, type PassphraseSealedEnvelope } from './passphrase-kdf-unwrap.ts';
import { merkleRoot } from './merkle-sha2-256.ts';
import { decodeLeavesList } from './merkle-leaves-list.ts';

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

// Per CIP-309 §4.6.1: the 25-byte UTF-8 prefix prepended to canonical-CBOR(record_body)
// to form Sig_structure[3] (`to_sign`). Sig_structure[2] (`external_aad`) is the
// empty bstr in v1 — this is the entire CIP-30-compatibility path.
const SIG_DOMAIN_RECORD_V1 = new TextEncoder().encode('cardano-poe-record-sig-v1');
const EMPTY_EXTERNAL_AAD = new Uint8Array(0);
// Signatures attach at the record level only; the verifier defines no item-level AAD.
const KOIOS_DEFAULTS: Record<NetworkId, string> = {
  'cardano:mainnet': 'https://api.koios.rest/api/v1',
  'cardano:preprod': 'https://preprod.koios.rest/api/v1',
  'cardano:preview': 'https://preview.koios.rest/api/v1',
};

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

export type NetworkId = 'cardano:mainnet' | 'cardano:preprod' | 'cardano:preview';
export type Verdict = 'valid' | 'pending' | 'failed';
export type ExitCode = 0 | 1 | 2 | 3;

export interface FetchOutboundOptions {
  method: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  purpose: 'cardano' | 'arweave' | 'ipfs';
}

export interface FetchOutboundResult {
  status: number;
  bytes: Uint8Array;
  durationMs: number;
}

export type FetchOutbound = (
  url: string,
  opts: FetchOutboundOptions,
) => Promise<FetchOutboundResult>;

export interface VerifyTxInput {
  txHash: string;
  network?: NetworkId;
  cardanoGatewayChain?: string[];
  blockfrostProjectId?: string;
  arweaveGatewayChain?: string[];
  /** Below-threshold confirmations surface as `verdict: 'pending'` with code
   *  `INSUFFICIENT_CONFIRMATIONS`. Defaults to 15 (CIP-309). */
  confirmationDepthThreshold?: number;
  denyHosts?: string[];
  /** Sealed-PoE decryption attempts. Discriminated union per CIP-309:
   *    - `recipientSecretKey` (32 B) for items whose `enc` carries `slots[]`.
   *    - `passphrase` (string) for items whose `enc` carries `passphrase`.
   *  Mismatch surfaces as `WRONG_DECRYPTION_INPUT_SHAPE` (CIP-309). */
  decryption?: Array<
    | { itemIndex: number; recipientSecretKey: Uint8Array }
    | { itemIndex: number; passphrase: string }
  >;
  /** Out-of-band ciphertext bytes, keyed by `items[i]` index. Used when a
   *  producer chose to deliver ciphertext via a private channel rather than
   *  publish a retrieval URI. Per CIP-309 §4.2 and CIP-309, `uris` is OPTIONAL
   *  on `enc`-bearing items; the verifier MUST prefer `ciphertextBytes[i]`
   *  when supplied, fall back to `item.uris[]`, and otherwise emit
   *  `CIPHERTEXT_UNAVAILABLE` (CIP-309). */
  ciphertextBytes?: Record<number, Uint8Array>;
  /** Out-of-band Merkle companion leaves-list bytes, keyed by
   *  `record.merkle[i]` index. CBOR is the normative wire form
   *  (CIP-309 §6.5); JSON projections are parsed with an info-severity
   *  `MERKLE_LEAVES_INFORMATIVE_FORM` warning. Per CIP-309 §4.5, the verifier
   *  decodes the leaves blob, recomputes the canonical root, and compares
   *  it against `merkle[i].root`; the leaf count is also checked against
   *  `merkle[i].leaf_count`. */
  merkleLeaves?: Record<number, Uint8Array>;
  fetchOutbound?: FetchOutbound;
}

export interface VerifyReport {
  txHash: string;
  network: NetworkId;
  numConfirmations: number;
  confirmationDepthThreshold: number;
  blockTime?: number;
  blockSlot?: number;
  metadataPresent: boolean;
  validation: {
    valid: boolean;
    issues?: ValidationIssue[];
    warnings?: ValidationIssue[];
  };
  record?: PoeRecord;
  recordSignatures?: Array<{
    index: number;
    signerPub?: string;
    valid: boolean;
    reason?: string;
  }>;
  // Signatures attach at the record level only; the report carries no `itemSignatures[]` field.
  itemHashChecks?: Array<{ itemIndex: number; alg: string; ok: boolean }>;
  /** One entry per `record.merkle[i]` (CIP-309 §4.5). `rootOk` is `true` when
   *  the recomputed canonical Merkle root matches the on-record value,
   *  `false` on byte mismatch (emits `MERKLE_ROOT_MISMATCH`). `reason` is
   *  set when the off-chain leaves blob could not be obtained
   *  (`MERKLE_LEAVES_UNAVAILABLE`). */
  merkleChecks?: Array<{
    merkleIndex: number;
    alg: string;
    rootOk?: boolean;
    reason?: string;
  }>;
  itemDecryptions?: Array<{
    itemIndex: number;
    ok: boolean;
    /** Plaintext-hash recomputation outcome per CIP-309. Iterates
     *  over `item.hashes` per-algorithm and compares against the recomputed
     *  digest. `true` when every content-hash entry matches, `false` when
     *  any entry mismatches (emits `URI_INTEGRITY_MISMATCH`). Every
     *  `enc`-bearing item carries at least one content-hash entry per
     *  CIP-309 §4.4 (`ENC_REQUIRES_CONTENT_HASH`), so this field is always set
     *  to a boolean on successful decryption. */
    plaintextHashOk?: boolean;
    note?: string;
    reason?: string;
  }>;
  httpCalls: Array<{
    url: string;
    method: 'GET' | 'POST';
    status: number;
    bytes: number;
    durationMs: number;
    purpose: 'cardano' | 'arweave' | 'ipfs';
  }>;
  verdict: Verdict;
  exitCode: ExitCode;
}

// -----------------------------------------------------------------------------
// Main entry
// -----------------------------------------------------------------------------

export async function verifyTx(input: VerifyTxInput): Promise<VerifyReport> {
  const network: NetworkId = input.network ?? 'cardano:mainnet';
  // Default confirmation-depth threshold per CIP-309; callers MAY override
  // via `input.confirmationDepthThreshold` (recorded into `VerifyReport`).
  const threshold = input.confirmationDepthThreshold ?? 15;
  const httpCalls: VerifyReport['httpCalls'] = [];

  const fetchFn = wrapFetchOutbound(
    input.fetchOutbound ?? defaultFetchOutbound,
    httpCalls,
    input.denyHosts,
  );

  const baseReport = (
    over: Partial<VerifyReport> & Pick<VerifyReport, 'verdict' | 'exitCode'>,
  ): VerifyReport => ({
    txHash: input.txHash,
    network,
    numConfirmations: 0,
    confirmationDepthThreshold: threshold,
    metadataPresent: false,
    validation: { valid: false },
    httpCalls,
    ...over,
  });

  // 1. Resolve gateway, fetch raw tx CBOR + confirmation depth
  let resolved: ResolvedTx;
  try {
    resolved = await resolveCardanoTx({
      input,
      network,
      fetchFn,
    });
  } catch (e) {
    const reason = e instanceof Error ? e.message : 'gateway_error';
    return baseReport({
      verdict: 'failed',
      exitCode: 2,
      validation: {
        valid: false,
        issues: [{ path: [], code: 'PROVIDER_UNAVAILABLE', message: reason }],
      },
    });
  }

  // 2. Extract label-309 metadata bytes from the tx CBOR
  let metadataBytes: Uint8Array | null;
  try {
    metadataBytes = extractLabel309Metadata(resolved.txCbor);
  } catch (e) {
    return baseReport({
      verdict: 'failed',
      exitCode: 1,
      blockTime: resolved.blockTime,
      blockSlot: resolved.blockSlot,
      numConfirmations: resolved.numConfirmations,
      validation: {
        valid: false,
        issues: [{ path: [], code: 'MALFORMED_CBOR', message: (e as Error).message }],
      },
    });
  }
  if (metadataBytes === null) {
    return baseReport({
      verdict: 'failed',
      exitCode: 1,
      blockTime: resolved.blockTime,
      blockSlot: resolved.blockSlot,
      numConfirmations: resolved.numConfirmations,
      metadataPresent: false,
      validation: {
        valid: false,
        issues: [
          { path: [], code: 'METADATA_NOT_FOUND', message: 'no label-309 metadata on this tx' },
        ],
      },
    });
  }

  // 3. Validator (pure function)
  const validation = validatePoeRecord(metadataBytes);
  if (!validation.valid) {
    return baseReport({
      verdict: 'failed',
      exitCode: 1,
      blockTime: resolved.blockTime,
      blockSlot: resolved.blockSlot,
      numConfirmations: resolved.numConfirmations,
      metadataPresent: true,
      validation: { valid: false, issues: validation.issues },
    });
  }
  const record = validation.record;

  // 4. confirmation depth (INSUFFICIENT_CONFIRMATIONS → verdict 'pending')
  if (resolved.numConfirmations < threshold) {
    return baseReport({
      verdict: 'pending',
      exitCode: 3,
      blockTime: resolved.blockTime,
      blockSlot: resolved.blockSlot,
      numConfirmations: resolved.numConfirmations,
      metadataPresent: true,
      record,
      validation: {
        valid: false,
        issues: [
          {
            path: [],
            code: 'INSUFFICIENT_CONFIRMATIONS',
            message: `${resolved.numConfirmations} < threshold ${threshold}`,
          },
        ],
      },
    });
  }

  const validationOut: VerifyReport['validation'] = validation.warnings
    ? { valid: true, warnings: validation.warnings }
    : { valid: true };
  const report: VerifyReport = {
    txHash: input.txHash,
    network,
    numConfirmations: resolved.numConfirmations,
    confirmationDepthThreshold: threshold,
    blockTime: resolved.blockTime,
    blockSlot: resolved.blockSlot,
    metadataPresent: true,
    validation: validationOut,
    record,
    httpCalls,
    verdict: 'valid',
    exitCode: 0,
  };

  // 5. Record-level signature verification (strict Ed25519, detached, AAD)
  if (record.sigs) {
    report.recordSignatures = await verifyRecordSignatures(record, input);
    // Verdict policy per CIP-309:
    //   - `SIGNATURE_UNSUPPORTED` is info severity on the offending entry; it
    //     does NOT by itself fail a public hash-only PoE.
    //   - Any other invalid reason (MALFORMED_SIG_COSE_SIGN1,
    //     SIGNER_KEY_UNRESOLVED, SIGNATURE_INVALID) is an error and fails the
    //     record.
    //   - For sealed PoE the deployment policy MAY mandate at least one
    //     verifiable identity binding; this reference verifier surfaces the
    //     per-entry detail so callers can apply that local rule.
    const hardFail = report.recordSignatures.some(
      (s) => !s.valid && s.reason !== 'SIGNATURE_UNSUPPORTED',
    );
    if (hardFail) {
      report.verdict = 'failed';
      report.exitCode = 1;
    }
  }

  // Signatures attach at the record level only — no per-item verification loop.

  // 7. Decryption (optional)
  if (input.decryption && input.decryption.length > 0) {
    const { out: decOut, warnings: decWarnings } = await tryDecryptions(record, input, fetchFn);
    report.itemDecryptions = decOut;
    if (decWarnings.length > 0) {
      const existing = report.validation.warnings ?? [];
      report.validation = {
        ...report.validation,
        warnings: [...existing, ...decWarnings],
      };
    }
    if (report.itemDecryptions.some((d) => !d.ok || d.plaintextHashOk === false)) {
      report.verdict = 'failed';
      // `CONTENT_UNAVAILABLE` is the network-class terminal state (exit code
      // 2 per CIP-309); all other failures here are integrity / structural
      // (exit code 1).
      const networkClass = report.itemDecryptions.some(
        (d) => !d.ok && d.reason === 'CONTENT_UNAVAILABLE',
      );
      report.exitCode = networkClass ? 2 : 1;
    }
  }

  // 8. Merkle list commitments (optional) — recompute each `merkle[i].root`
  // from the companion leaves blob and compare byte-for-byte against the
  // on-record value (CIP-309 §4.5).
  if (record.merkle && record.merkle.length > 0) {
    const { checks, warnings: merkleWarnings } = await checkMerkleCommitments(
      record,
      input,
      fetchFn,
    );
    report.merkleChecks = checks;
    if (merkleWarnings.length > 0) {
      const existing = report.validation.warnings ?? [];
      report.validation = {
        ...report.validation,
        warnings: [...existing, ...merkleWarnings],
      };
    }
    if (report.merkleChecks.some((m) => m.rootOk === false || m.reason !== undefined)) {
      report.verdict = 'failed';
      report.exitCode = 1;
    }
  }

  return report;
}

// -----------------------------------------------------------------------------
// Cardano gateway resolution + tx_cbor fetch
// -----------------------------------------------------------------------------

interface ResolvedTx {
  txCbor: Uint8Array;
  network: NetworkId;
  numConfirmations: number;
  blockTime: number;
  blockSlot: number;
  provider: 'koios' | 'blockfrost';
  providerUrl: string;
}

async function resolveCardanoTx(args: {
  input: VerifyTxInput;
  network: NetworkId;
  fetchFn: FetchOutbound;
}): Promise<ResolvedTx> {
  const { input, network, fetchFn } = args;
  const koiosChain = input.cardanoGatewayChain ?? [KOIOS_DEFAULTS[network]];

  // Try Koios gateways in order.
  for (const koiosUrl of koiosChain) {
    try {
      return await resolveViaKoios(input.txHash, koiosUrl, network, fetchFn);
    } catch {
      // try next gateway
    }
  }

  // Blockfrost fallback
  if (input.blockfrostProjectId) {
    return await resolveViaBlockfrost(input.txHash, network, input.blockfrostProjectId, fetchFn);
  }

  throw new Error('all_providers_failed');
}

async function resolveViaKoios(
  txHash: string,
  koiosUrl: string,
  network: NetworkId,
  fetchFn: FetchOutbound,
): Promise<ResolvedTx> {
  const cborRes = await fetchFn(`${koiosUrl}/tx_cbor`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ _tx_hashes: [txHash] }),
    purpose: 'cardano',
  });
  if (cborRes.status !== 200) throw new Error(`koios_tx_cbor_${cborRes.status}`);
  const cborJson = JSON.parse(new TextDecoder().decode(cborRes.bytes)) as Array<{
    tx_hash: string;
    cbor: string;
  }>;
  if (!Array.isArray(cborJson) || cborJson.length === 0) {
    throw new Error('koios_tx_cbor_empty');
  }
  const txCbor = hexToBytes(cborJson[0]!.cbor);

  const infoRes = await fetchFn(`${koiosUrl}/tx_info`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ _tx_hashes: [txHash] }),
    purpose: 'cardano',
  });
  if (infoRes.status !== 200) throw new Error(`koios_tx_info_${infoRes.status}`);
  const infoJson = JSON.parse(new TextDecoder().decode(infoRes.bytes)) as Array<{
    num_confirmations: number;
    tx_timestamp: number;
    absolute_slot: number;
  }>;
  if (!Array.isArray(infoJson) || infoJson.length === 0) {
    throw new Error('koios_tx_info_empty');
  }
  const info = infoJson[0]!;

  return {
    txCbor,
    network,
    numConfirmations: info.num_confirmations,
    blockTime: info.tx_timestamp,
    blockSlot: info.absolute_slot,
    provider: 'koios',
    providerUrl: koiosUrl,
  };
}

async function resolveViaBlockfrost(
  txHash: string,
  network: NetworkId,
  projectId: string,
  fetchFn: FetchOutbound,
): Promise<ResolvedTx> {
  const baseHost: Record<NetworkId, string> = {
    'cardano:mainnet': 'https://cardano-mainnet.blockfrost.io/api/v0',
    'cardano:preprod': 'https://cardano-preprod.blockfrost.io/api/v0',
    'cardano:preview': 'https://cardano-preview.blockfrost.io/api/v0',
  };
  const base = baseHost[network];
  const headers = { project_id: projectId, accept: 'application/json' };

  const cborRes = await fetchFn(`${base}/txs/${txHash}/cbor`, {
    method: 'GET',
    headers,
    purpose: 'cardano',
  });
  if (cborRes.status !== 200) throw new Error(`blockfrost_cbor_${cborRes.status}`);
  const cborJson = JSON.parse(new TextDecoder().decode(cborRes.bytes)) as { cbor: string };
  const txCbor = hexToBytes(cborJson.cbor);

  const infoRes = await fetchFn(`${base}/txs/${txHash}`, {
    method: 'GET',
    headers,
    purpose: 'cardano',
  });
  if (infoRes.status !== 200) throw new Error(`blockfrost_info_${infoRes.status}`);
  const infoJson = JSON.parse(new TextDecoder().decode(infoRes.bytes)) as {
    block_time: number;
    slot: number;
  };

  // Blockfrost returns the absolute confirmation count via the tip endpoint
  const tipRes = await fetchFn(`${base}/blocks/latest`, {
    method: 'GET',
    headers,
    purpose: 'cardano',
  });
  if (tipRes.status !== 200) throw new Error(`blockfrost_tip_${tipRes.status}`);
  const tipJson = JSON.parse(new TextDecoder().decode(tipRes.bytes)) as { slot: number };
  const numConfirmations = Math.max(0, tipJson.slot - infoJson.slot);

  return {
    txCbor,
    network,
    numConfirmations,
    blockTime: infoJson.block_time,
    blockSlot: infoJson.slot,
    provider: 'blockfrost',
    providerUrl: base,
  };
}

// -----------------------------------------------------------------------------
// CBOR auxiliary-data extraction
// -----------------------------------------------------------------------------

/**
 * Extract the label-309 metadata bytes from a serialised Cardano transaction.
 *
 * A Cardano post-Conway transaction is `[body, witness_set, is_valid, auxiliary_data]`
 * (4-element array). The auxiliary_data is either tagged (CBOR tag 259, post-Alonzo)
 * or a plain map; in either case it carries `metadata: { <label int>: <value> }`.
 *
 * Returns the byte slice of the label-309 value VERBATIM as it appears in the
 * input — no decode-then-re-encode pass. This is critical: a non-canonical
 * on-chain record (unsorted map keys, non-preferred integer encoding,
 * indefinite-length, etc.) violates CIP-309 §4.9 and MUST be rejected by the
 * structural validator. Re-encoding would silently launder it. See
 * `cbor-walker.ts` for the implementation rationale.
 */
function extractLabel309Metadata(txCbor: Uint8Array): Uint8Array | null {
  return sliceLabel309Value(txCbor);
}

// -----------------------------------------------------------------------------
// Signature verification
// -----------------------------------------------------------------------------

async function verifyRecordSignatures(
  record: PoeRecord,
  _input: VerifyTxInput,
): Promise<NonNullable<VerifyReport['recordSignatures']>> {
  const out: NonNullable<VerifyReport['recordSignatures']> = [];
  // Strip `sigs` from the signed payload (CIP-309 §4.6.1). The optional
  // CIP-30 `key` lives inside each sigs entry per CIP-309 §4.6.3.
  const { sigs, ...recordBody } = record;
  void sigs;
  const recordBodyBytes = encodeCanonicalCbor(recordBody);
  // Per CIP-309 §4.6.1: to_sign = SIG_DOMAIN_RECORD_V1 || canonical_cbor(record_body)
  // (the 25-byte domain separator is embedded as a prefix; external_aad stays
  // empty in the COSE Sig_structure).
  const toSign = new Uint8Array(SIG_DOMAIN_RECORD_V1.length + recordBodyBytes.length);
  toSign.set(SIG_DOMAIN_RECORD_V1, 0);
  toSign.set(recordBodyBytes, SIG_DOMAIN_RECORD_V1.length);

  const sigsList = record.sigs ?? [];
  for (let i = 0; i < sigsList.length; i++) {
    const entry = sigsList[i]!;
    const args: VerifySignatureArgs = {
      sigChunks: entry.cose_sign1,
      payload: toSign,
      externalAad: EMPTY_EXTERNAL_AAD,
    };
    // Optional inline `cose_key` (chunked cbor<COSE_Key>) for the CIP-30 wallet
    // path 2. verifySignature consults it only when the in-signature `kid`
    // (path 1) does not yield a 32-byte raw Ed25519 pubkey, per CIP-309 §4.6.3.
    if (entry.cose_key) {
      args.signerPubkeyChunks = entry.cose_key;
    }
    const result = await verifySignature(args);
    out.push({ index: i, ...result });
  }
  return out;
}

// CIP-309 carries signatures at the record level only; there is no
// verifyItemSignatures function. See CIP-309 §4.6 and the Rationale section.

interface SignatureVerification {
  signerPub?: string;
  signerType?: 'in-signature-kid' | 'wallet-inline-key';
  valid: boolean;
  reason?: string;
}

interface VerifySignatureArgs {
  sigChunks: Uint8Array[];
  payload: Uint8Array;
  externalAad: Uint8Array;
  /** Optional CIP-30 wallet inline `sigs[i].cose_key`: chunked-bytes carrying
   *  cbor<COSE_Key>. Consulted only when the in-signature `kid` path does
   *  not yield a 32-byte raw Ed25519 pubkey (per CIP-309 §4.6.3 resolution
   *  priority). */
  signerPubkeyChunks?: Uint8Array[];
}

async function verifySignature(args: VerifySignatureArgs): Promise<SignatureVerification> {
  let cose;
  try {
    cose = decodeCoseSign1(concatChunks(args.sigChunks));
  } catch {
    return { valid: false, reason: 'MALFORMED_SIG_COSE_SIGN1' };
  }
  // RFC 9052 §4.1: detached form MUST encode payload as nil; a zero-length
  // byte string is NOT equivalent and MUST be rejected (CIP-309).
  if (cose.payload !== null) {
    return { valid: false, reason: 'MALFORMED_SIG_COSE_SIGN1' };
  }
  const alg = cose.protectedHeader.get(1);
  if (alg !== -8) {
    // The unrecognised-alg case is info severity on the entry: the per-entry
    // verification reports `valid: false` with reason `SIGNATURE_UNSUPPORTED`,
    // while the record-as-a-whole verdict still passes for a public hash-only
    // PoE (signatures are optional in CIP-309; an unverifiable optional
    // signature does not invalidate the content claim).
    return { valid: false, reason: 'SIGNATURE_UNSUPPORTED' };
  }

  // Signer-key resolution priority per CIP-309 §4.6.3 and CIP-309:
  //   1. Protected-header `kid` if exactly 32 bytes (raw Ed25519 pubkey)
  //      → "in-signature-kid" identity-key path.
  //   2. Inline `sigs[i].cose_key` carrying `cbor<COSE_Key>` (CIP-30 wallet path)
  //      → "wallet-inline-key". Consulted only when path 1 does not yield 32 B.
  //
  // Unprotected-header `kid` values are NOT a sanctioned resolution path
  // (CIP-309 §4.6.3): they sit outside the COSE integrity envelope and could be
  // rewritten by an untrusted indexer or relay without invalidating the
  // signature, which would let a network attacker silently re-attribute a
  // signer's records. This verifier ignores them entirely for resolution
  // purposes (the spec permits surfacing them as a UI diagnostic, but this
  // reference verifier does not emit one).
  //
  // Path 1 / path 2 are mutually exclusive at the wire level (CIP-309 §4.6.3):
  // a record carrying BOTH a 32-byte protected `kid` AND a `sigs[i].cose_key`
  // is structurally rejected by the validator as SIG_ENTRY_KID_COSE_KEY_CONFLICT
  // (CIP-309), so this verifier never sees a conflicting record —
  // the priority order below is a one-of-N selection, not a tie-breaker.
  const protectedKid = cose.protectedHeader.get(4) as Uint8Array | undefined;
  let signerPub: Uint8Array | null = null;
  let signerType: 'in-signature-kid' | 'wallet-inline-key' | undefined;
  if (protectedKid && protectedKid.length === 32) {
    signerPub = protectedKid;
    signerType = 'in-signature-kid';
  } else if (args.signerPubkeyChunks) {
    const extracted = extractEd25519PubFromCoseKeyChunks(args.signerPubkeyChunks);
    if (extracted) {
      signerPub = extracted;
      signerType = 'wallet-inline-key';
    }
  }
  if (!signerPub || signerPub.length !== 32) {
    return { valid: false, reason: 'SIGNER_KEY_UNRESOLVED' };
  }

  // CIP-8 `hashed` mode (RFC 8152 §4.1; CIP-309 §4.6.2). Hardware-wallet
  // co-signers may set unprotected "hashed": true. Per CIP-309 §4.6.2, the
  // substitution happens INSIDE Sig_structure: the slot at index 3 becomes
  // Blake2b224(to_sign), not to_sign itself. Producer and verifier then
  // canonical-CBOR-encode the resulting Sig_structure and Ed25519-sign /
  // verify those bytes.
  const hashed = cose.unprotectedHeader.get('hashed') === true;
  const sigStructPayload = hashed ? blake2b224(args.payload) : args.payload;

  // Build Sig_structure with the PRESERVED original protected_bytes (RFC 9052 §4.4)
  // and the v1 empty external_aad — the cross-protocol replay defence is the
  // domain-separator prefix embedded inside `args.payload` (CIP-309 §4.6.1).
  const sigStruct = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: cose.protectedBytes,
    externalAad: args.externalAad,
    payload: sigStructPayload,
  });

  const ok = verifyEd25519(cose.signature, sigStruct, signerPub);
  const result: SignatureVerification = ok
    ? { valid: true, signerPub: bytesToHex(signerPub) }
    : { valid: false, signerPub: bytesToHex(signerPub), reason: 'SIGNATURE_INVALID' };
  if (signerType) result.signerType = signerType;
  return result;
}

// CIP-8 hashed=true variant: per CIP-309 §4.6.2, producer and verifier substitute
// Blake2b224(to_sign) for Sig_structure[3] before canonical-CBOR-encoding the
// Sig_structure. Output is the 28-byte Blake2b digest of `input`.
function blake2b224(input: Uint8Array): Uint8Array {
  return blake2b(input, { dkLen: 28 });
}

// Extract the 32-byte raw Ed25519 public key from a chunked CIP-30
// `cbor<COSE_Key>` blob (path 2 in CIP-309 §4.6.3). Returns null on any parse
// failure or wrong key shape so the caller can fall through to the next
// resolution path. RFC 8152 §7 COSE_Key shape for Ed25519:
//   { 1 (kty): 1 (OKP), 3 (alg): -8 (EdDSA, optional), -1 (crv): 6 (Ed25519), -2 (x): <bytes:32> }
function extractEd25519PubFromCoseKeyChunks(chunks: Uint8Array[]): Uint8Array | null {
  try {
    const blob = concatChunks(chunks);
    const decoded = decodeCbor(blob) as unknown;
    if (!(decoded instanceof Map)) return null;
    const kty = decoded.get(1);
    if (kty !== 1) return null; // MUST be OKP
    const crv = decoded.get(-1);
    if (crv !== 6) return null; // MUST be Ed25519
    const x = decoded.get(-2);
    if (!(x instanceof Uint8Array) || x.length !== 32) return null;
    return x;
  } catch {
    return null;
  }
}

// -----------------------------------------------------------------------------
// Decryption (sealed-PoE unwrap + plaintext-hash recompute)
// -----------------------------------------------------------------------------

type ItemShape = {
  uris?: string[][];
  enc?: unknown;
  // Per CIP-309 §4.2, `hashes` is a CBOR map keyed by hash-alg-id; cbor2 decodes
  // a string-keyed CBOR map to a plain JS object.
  hashes: Record<string, Uint8Array>;
};

async function tryDecryptions(
  record: PoeRecord,
  input: VerifyTxInput,
  fetchFn: FetchOutbound,
): Promise<{
  out: NonNullable<VerifyReport['itemDecryptions']>;
  warnings: ValidationIssue[];
}> {
  const out: NonNullable<VerifyReport['itemDecryptions']> = [];
  const warnings: ValidationIssue[] = [];
  const items = record.items as ItemShape[];
  for (const dec of input.decryption!) {
    const item = items[dec.itemIndex];
    if (!item?.enc) {
      out.push({ itemIndex: dec.itemIndex, ok: false, reason: 'no_enc_envelope' });
      continue;
    }
    // Discriminate by on-wire `enc` shape per CIP-309. The two key paths
    // (`slots[]` / `passphrase`) are mutually exclusive at the wire level
    // (CIP-309 §4.4); the verifier MUST refuse a mismatched decryption-entry shape.
    const enc = item.enc as { slots?: unknown; passphrase?: unknown };
    const hasSlots = enc.slots !== undefined;
    const hasPassphrase = enc.passphrase !== undefined;
    const entryHasSecret = 'recipientSecretKey' in dec;
    const entryHasPassphrase = 'passphrase' in dec;
    if (hasSlots && !entryHasSecret) {
      out.push({
        itemIndex: dec.itemIndex,
        ok: false,
        reason: 'WRONG_DECRYPTION_INPUT_SHAPE',
      });
      continue;
    }
    if (hasPassphrase && !entryHasPassphrase) {
      out.push({
        itemIndex: dec.itemIndex,
        ok: false,
        reason: 'WRONG_DECRYPTION_INPUT_SHAPE',
      });
      continue;
    }

    // Ciphertext acquisition (per CIP-309): prefer the
    // verifier-input-layer `ciphertextBytes[itemIndex]` when supplied (the
    // out-of-band delivery path defined by CIP-309 §4.2); else iterate the
    // on-record `item.uris[]`; else emit `CIPHERTEXT_UNAVAILABLE` per
    // CIP-309. Within the URI-fetch branch, each individual gateway
    // failure surfaces as a `URI_FETCH_FAILED` warning (per-attempt
    // diagnostic) and only the chain-exhausted terminal state escalates
    // to `CONTENT_UNAVAILABLE` (error, verdict `failed`).
    let ciphertext: Uint8Array;
    const localBytes = input.ciphertextBytes?.[dec.itemIndex];
    const hasUris = Array.isArray(item.uris) && item.uris.length > 0;
    if (localBytes !== undefined) {
      ciphertext = localBytes;
    } else if (hasUris) {
      try {
        ciphertext = await fetchUriCiphertext(
          item,
          input.arweaveGatewayChain ?? [],
          fetchFn,
          warnings,
          ['items', dec.itemIndex],
        );
      } catch (e) {
        const code =
          (e as Error).message === 'URI_TARGET_FORBIDDEN'
            ? 'URI_TARGET_FORBIDDEN'
            : 'CONTENT_UNAVAILABLE';
        out.push({ itemIndex: dec.itemIndex, ok: false, reason: code });
        continue;
      }
    } else {
      out.push({
        itemIndex: dec.itemIndex,
        ok: false,
        reason: 'CIPHERTEXT_UNAVAILABLE',
      });
      continue;
    }
    let plaintext: Uint8Array;
    try {
      if (entryHasSecret) {
        plaintext = eciesSealedPoeUnwrap({
          envelope: item.enc as Parameters<typeof eciesSealedPoeUnwrap>[0]['envelope'],
          ciphertext,
          recipientSecretKey: (dec as { recipientSecretKey: Uint8Array }).recipientSecretKey,
        });
      } else {
        plaintext = await eciesKdfUnwrap({
          envelope: item.enc as PassphraseSealedEnvelope,
          ciphertext,
          passphrase: (dec as { passphrase: string }).passphrase,
        });
      }
    } catch (e) {
      // Surface the typed code from the unwrap layer when available; fall back
      // to the canonical AEAD-verification-failure code from CIP-309. The
      // code `TAMPERED_CIPHERTEXT` covers both wrong-passphrase / wrong-key
      // unwrap and bit-flip tampering — the AEAD tag check fails in both
      // cases and a public verifier cannot disambiguate.
      const reason =
        e &&
        typeof e === 'object' &&
        'code' in e &&
        typeof (e as { code: unknown }).code === 'string'
          ? (e as { code: string }).code
          : 'TAMPERED_CIPHERTEXT';
      out.push({
        itemIndex: dec.itemIndex,
        ok: false,
        reason,
      });
      continue;
    }
    // Per-algorithm plaintext-hash recomputation per CIP-309 §4.2 "Producer
    // obligation (content-hash entries)" and CIP-309. Iterates
    // every entry in `item.hashes` and compares against the recomputed
    // digest; every `enc`-bearing item carries at least one entry per
    // CIP-309 §4.4, so the result is always a definite match / mismatch.
    const hashCheck = checkItemHashes(item.hashes, plaintext);
    if (hashCheck.kind === 'match') {
      out.push({ itemIndex: dec.itemIndex, ok: true, plaintextHashOk: true });
    } else {
      out.push({
        itemIndex: dec.itemIndex,
        ok: true,
        plaintextHashOk: false,
        reason: 'URI_INTEGRITY_MISMATCH',
      });
    }
  }
  return { out, warnings };
}

/**
 * Per-algorithm content-hash check over a fetched plaintext.
 *
 * Iterates the `item.hashes` map keys (CIP-309 §4.2 / CIP-309):
 *   - `sha2-256`:    recompute SHA-256 and compare.
 *   - `blake2b-256`: recompute BLAKE2b-256 and compare.
 *
 * Returns:
 *   - `match`    — every content-hash entry matched.
 *   - `mismatch` — at least one entry mismatched.
 */
function checkItemHashes(
  hashes: Record<string, Uint8Array>,
  plaintext: Uint8Array,
): { kind: 'match' | 'mismatch' } {
  let anyMismatch = false;
  for (const [alg, claimed] of Object.entries(hashes)) {
    if (alg === 'sha2-256') {
      if (!bytesEqual(sha256(plaintext), claimed)) anyMismatch = true;
    } else if (alg === 'blake2b-256') {
      if (!bytesEqual(blake2b(plaintext, { dkLen: 32 }), claimed)) anyMismatch = true;
    }
    // Unknown algorithms cannot reach this function — the structural
    // validator rejects them upstream with UNSUPPORTED_HASH_ALG (CIP-309).
  }
  return anyMismatch ? { kind: 'mismatch' } : { kind: 'match' };
}

// -----------------------------------------------------------------------------
// Merkle list-commitment verification (per CIP-309 §4.5)
// -----------------------------------------------------------------------------

type MerkleCommitShape = {
  alg: string;
  root: Uint8Array;
  leaf_count: number;
  uris?: string[][];
};

/**
 * Walk `record.merkle[]` and recompute each canonical root from the
 * companion leaves-list blob. The verifier prefers `input.merkleLeaves[i]`
 * when supplied; otherwise it fetches the first `merkle[i].uris[]` entry
 * via `fetchOutbound`. CBOR is the normative wire form per CIP-309 §6.5;
 * a fetched JSON projection is parsed with an info-severity
 * `MERKLE_LEAVES_INFORMATIVE_FORM` warning so producer migration is nudged
 * without breaking end-users during the transition window. Each
 * `merkle[i]` returns the comparison outcome, including a leaf-count
 * cross-check (`SCHEMA_MERKLE_LEAF_COUNT_MISMATCH`).
 */
async function checkMerkleCommitments(
  record: PoeRecord,
  input: VerifyTxInput,
  fetchFn: FetchOutbound,
): Promise<{
  checks: NonNullable<VerifyReport['merkleChecks']>;
  warnings: ValidationIssue[];
}> {
  const out: NonNullable<VerifyReport['merkleChecks']> = [];
  const warnings: ValidationIssue[] = [];
  const merkleArr = (record.merkle ?? []) as MerkleCommitShape[];
  for (let i = 0; i < merkleArr.length; i++) {
    const commit = merkleArr[i]!;
    let leavesBytes: Uint8Array | undefined = input.merkleLeaves?.[i];
    if (leavesBytes === undefined) {
      // Fall back to fetching the companion via `merkle[i].uris[]`.
      const hasUris = Array.isArray(commit.uris) && commit.uris.length > 0;
      if (!hasUris) {
        out.push({
          merkleIndex: i,
          alg: commit.alg,
          reason: 'MERKLE_LEAVES_UNAVAILABLE',
        });
        continue;
      }
      try {
        leavesBytes = await fetchUriCiphertext(
          { uris: commit.uris! },
          input.arweaveGatewayChain ?? [],
          fetchFn,
          warnings,
          ['merkle', i],
        );
      } catch {
        // Per CIP-309, an unavailable Merkle companion does NOT escalate
        // to `CONTENT_UNAVAILABLE`: the on-chain root commitment alone is
        // structurally valid, so the per-commit check is recorded as
        // `MERKLE_LEAVES_UNAVAILABLE` (warning, not error). The per-attempt
        // `URI_FETCH_FAILED` diagnostics emitted by `fetchUriCiphertext`
        // remain in the warnings sink for operator triage.
        out.push({
          merkleIndex: i,
          alg: commit.alg,
          reason: 'MERKLE_LEAVES_UNAVAILABLE',
        });
        continue;
      }
    }
    // Decode the companion. CBOR is the normative wire form per CIP-309 §6.5;
    // JSON falls back as an informative projection and triggers
    // `MERKLE_LEAVES_INFORMATIVE_FORM` (info severity).
    let leaves: Uint8Array[];
    const onChainLeafCount: number = commit.leaf_count;
    let fileLeafCount: number;
    let algId: string;
    try {
      const decoded = decodeLeavesList(leavesBytes);
      leaves = decoded.leaves;
      fileLeafCount = decoded.leafCount;
      algId = decoded.treeAlg;
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code === 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED') {
        out.push({
          merkleIndex: i,
          alg: commit.alg,
          reason: 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
        });
        continue;
      }
      // Try JSON projection fallback, with an informative warning (CBOR is the
      // normative wire form; JSON is an informative projection only).
      try {
        const parsed = JSON.parse(new TextDecoder().decode(leavesBytes)) as {
          format?: unknown;
          tree_alg?: unknown;
          leaves?: unknown;
          leaf_count?: unknown;
        };
        if (parsed.format !== 'cardano-poe-merkle-leaves-v1') {
          out.push({
            merkleIndex: i,
            alg: commit.alg,
            reason: 'SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED',
          });
          continue;
        }
        if (!Array.isArray(parsed.leaves)) throw new Error('leaves not array');
        leaves = parsed.leaves.map((h) => {
          if (typeof h !== 'string') throw new Error('leaf not string');
          return hexToBytes(h);
        });
        fileLeafCount = typeof parsed.leaf_count === 'number' ? parsed.leaf_count : leaves.length;
        algId = typeof parsed.tree_alg === 'string' ? parsed.tree_alg : commit.alg;
        warnings.push({
          path: ['merkle', i],
          code: 'MERKLE_LEAVES_INFORMATIVE_FORM',
          message:
            'fetched leaves-list returned JSON; CBOR is the normative wire form per CIP-309 §6.5',
        });
      } catch {
        out.push({
          merkleIndex: i,
          alg: commit.alg,
          reason: 'MERKLE_LEAVES_UNAVAILABLE',
        });
        continue;
      }
    }
    if (commit.alg !== 'rfc9162-sha256' || algId !== 'rfc9162-sha256') {
      // Validator rejects unknown algs upstream; defensive guard only.
      out.push({
        merkleIndex: i,
        alg: commit.alg,
        reason: 'UNSUPPORTED_MERKLE_COMMIT_ALG',
      });
      continue;
    }
    if (onChainLeafCount !== fileLeafCount) {
      out.push({
        merkleIndex: i,
        alg: commit.alg,
        reason: 'SCHEMA_MERKLE_LEAF_COUNT_MISMATCH',
      });
      continue;
    }
    const recomputed = merkleRoot(leaves);
    const ok = bytesEqual(recomputed, commit.root);
    out.push({
      merkleIndex: i,
      alg: commit.alg,
      rootOk: ok,
      ...(ok ? {} : { reason: 'MERKLE_ROOT_MISMATCH' }),
    });
  }
  return { checks: out, warnings };
}

/**
 * Per CIP-309 and CIP-309 step 5: each individual gateway failure on
 * the way to a chain-exhausted terminal state is a per-attempt diagnostic
 * (`URI_FETCH_FAILED`, warning), and only the terminal state escalates to
 * the record-level error code `CONTENT_UNAVAILABLE`. This helper pushes one
 * `URI_FETCH_FAILED` warning per failing gateway into the caller-supplied
 * `warnings` sink, then throws `CONTENT_UNAVAILABLE` when the chain is
 * exhausted so the caller emits the terminal error against the appropriate
 * record path (`items[i]`, `merkle[i]`, etc.).
 */
async function fetchUriCiphertext(
  item: { uris?: string[][] },
  arweaveGateways: string[],
  fetchFn: FetchOutbound,
  warnings: ValidationIssue[],
  issuePath: ValidationIssue['path'],
): Promise<Uint8Array> {
  // Each entry of `uris` is itself an array of tstr chunks per CIP-309 §4.8;
  // join the chunks before testing the scheme. The v1 fetch set is exactly
  // `{ar://, ipfs://}` per CIP-309 §4.2; any other scheme has already been
  // rejected upstream as `INVALID_URI` by the structural validator and is
  // refused here too as defence in depth.
  const reconstructed = (item.uris ?? []).map((chunks) => chunks.join(''));
  const uri = reconstructed.find((u) => /^(ar|ipfs):\/\//.test(u));
  if (!uri) throw new Error('URI_TARGET_FORBIDDEN');
  if (uri.startsWith('ar://')) {
    const txid = uri.slice(5);
    // Arweave gateway HTTPS endpoints are transport for resolving `ar://`,
    // not PoE storage URIs.
    if (arweaveGateways.length === 0) {
      arweaveGateways = ['https://arweave.net', 'https://ar-io.net', 'https://g8way.io'];
    }
    for (const gw of arweaveGateways) {
      try {
        const res = await fetchFn(`${gw}/${txid}`, { method: 'GET', purpose: 'arweave' });
        if (res.status === 200) return res.bytes;
        warnings.push({
          path: issuePath,
          code: 'URI_FETCH_FAILED',
          message: `gateway ${gw} returned status ${res.status} for ${uri}`,
        });
      } catch (e) {
        warnings.push({
          path: issuePath,
          code: 'URI_FETCH_FAILED',
          message: `gateway ${gw} threw for ${uri}: ${(e as Error).message}`,
        });
      }
    }
    throw new Error('CONTENT_UNAVAILABLE');
  }
  // ipfs:// — caller must supply gatewayChain via a future ipfsGatewayChain
  // input. With no gateway available to attempt, no `URI_FETCH_FAILED`
  // per-attempt warning is generated; the terminal state is recorded
  // directly as `CONTENT_UNAVAILABLE`.
  throw new Error('CONTENT_UNAVAILABLE');
}

// -----------------------------------------------------------------------------
// fetchOutbound wrapper (single egress point + denyHosts + audit trail)
// -----------------------------------------------------------------------------
//
// Two responsibilities:
//   1. `denyHosts` — operator-configured service-independence guard: the
//      verifier MUST refuse to call hosts that the operator has declared
//      off-limits (typically the operator's own indexer or catalog domains),
//      so a "standalone" verification provably touched no issuer-controlled
//      service. Match is exact-host or `*.suffix`.
//   2. Audit trail — every outbound call (success or failure) is recorded
//      into the `httpCalls` slice surfaced on `VerifyReport`, so the report
//      is a complete record of what the verifier touched.
//
// The v1 fetch set is `{cardano gateway, arweave gateway, ipfs gateway}`;
// all of those use HTTPS as transport and address well-known public hosts.

function wrapFetchOutbound(
  inner: FetchOutbound,
  audit: VerifyReport['httpCalls'],
  denyHosts?: string[],
): FetchOutbound {
  return async (url, opts) => {
    if (denyHosts?.length) {
      const host = new URL(url).hostname;
      const blocked = denyHosts.some(
        (d) => host === d || (d.startsWith('*.') && host.endsWith(d.slice(1))),
      );
      if (blocked) {
        audit.push({
          url,
          method: opts.method,
          status: 0,
          bytes: 0,
          durationMs: 0,
          purpose: opts.purpose,
        });
        throw new Error(`SERVICE_INDEPENDENCE_VIOLATION: ${host} is in denyHosts`);
      }
    }
    const t0 = Date.now();
    try {
      const result = await inner(url, opts);
      audit.push({
        url,
        method: opts.method,
        status: result.status,
        bytes: result.bytes.length,
        durationMs: result.durationMs,
        purpose: opts.purpose,
      });
      return result;
    } catch (e) {
      audit.push({
        url,
        method: opts.method,
        status: 0,
        bytes: 0,
        durationMs: Date.now() - t0,
        purpose: opts.purpose,
      });
      throw e;
    }
  };
}

const defaultFetchOutbound: FetchOutbound = async (url, opts) => {
  const t0 = Date.now();
  const init: RequestInit = { method: opts.method };
  if (opts.headers) init.headers = opts.headers;
  if (opts.body !== undefined) init.body = opts.body;
  const res = await fetch(url, init);
  const bytes = new Uint8Array(await res.arrayBuffer());
  return { status: res.status, bytes, durationMs: Date.now() - t0 };
};

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  return chunks.reduce<Uint8Array>((acc, chunk) => {
    const out = new Uint8Array(acc.length + chunk.length);
    out.set(acc, 0);
    out.set(chunk, acc.length);
    return out;
  }, new Uint8Array(0));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('hex string has odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
