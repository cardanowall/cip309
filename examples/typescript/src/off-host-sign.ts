// Label 309 v1 reference implementation — off-host signing helper
// Spec: Label 309 §4.6.1 (Sig_structure + 25-byte domain prefix),
//       Label 309 §4.6.2 (COSE_Sign1 layout + CIP-8 hashed = true mode),
//       Label 309 §4.6.3 (path-1 kid-as-public-key convention),
//       Label 309 §4.8 (chunked-bytes-array).
//
// Demonstrates the off-host signing helper and its CIP-8 hashed-mode companion:
// the record body to be signed is prepared here, the signature is produced by a
// signer that holds the private key (HSM/KMS/air-gap), and the COSE_Sign1 is
// reassembled afterwards — the private key never reaches this module.
//
// Use cases — the four supported off-host-signer integration shapes:
//   1. AWS KMS Sign — wrap the KMS API in a `(bytes) => Promise<signature>`
//      closure. The KMS-bound private key never leaves the HSM boundary.
//   2. Google Cloud HSM — same shape via the GCP KMS asymmetric-sign call.
//   3. YubiHSM — local hardware-backed signer addressable from a workstation.
//   4. Air-gapped offline signer — transport the Sig_structure bytes via QR /
//      USB / sneakernet to an offline workstation; transport the 64-byte
//      Ed25519 signature back.
//
// For production use, apply the same Sig_structure and COSE_Sign1 rules from
// Label 309 §4.6. This file is a self-contained reference implementation.
//
// Privacy contract: this module never sees, stores, logs, or transmits any
// byte string that contains the integrator's Ed25519 private signing key.
// The integrator's signer handles the seed; the module's input boundary is
// the 32-byte public key (`signerPubkey`) and the 64-byte Ed25519 signature
// — both PUBLIC data.

import { encodeCanonicalCbor } from './cbor-canonical.ts';
import { encodeCoseSign1, buildSigStructure } from './cose-sign1.ts';
import { signEd25519 } from './ed25519.ts';
import { blake2b_256 } from './hash-dual.ts';
import { blake2b } from '@noble/hashes/blake2.js';

const CARDANO_POE_SIG_DOMAIN_PREFIX = 'cardano-poe-record-sig-v1';
const DOMAIN_PREFIX_BYTES = new TextEncoder().encode(CARDANO_POE_SIG_DOMAIN_PREFIX);
if (DOMAIN_PREFIX_BYTES.length !== 25) {
  throw new Error(`domain prefix must be 25 UTF-8 bytes (got ${DOMAIN_PREFIX_BYTES.length})`);
}

// `record_body` is the canonical CBOR map of the record MINUS `sigs`. The
// production encoder strips `sigs` automatically; for the demo we accept any
// canonical-CBOR-shaped value.
export type RecordBody = Record<string, unknown>;

// The integrator's signer abstraction. Both software (KMS / HSM) and hardware
// (YubiHSM / air-gapped) signers fit the same shape.
export interface OffHostSigner {
  sign(message: Uint8Array): Promise<Uint8Array>; // returns 64-byte Ed25519 signature
}

// A deterministic in-process signer driven by a hard-coded test seed. Useful
// for unit tests and example walkthroughs. In production, replace with a KMS-
// backed closure.
export class MockHsmSigner implements OffHostSigner {
  private readonly seed: Uint8Array;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new Error('MockHsmSigner: seed must be 32 bytes');
    this.seed = seed;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return signEd25519(message, this.seed);
  }
}

function path1ProtectedHeaderBytes(signerPubkey: Uint8Array): Uint8Array {
  // Canonical CBOR of `{1: -8, 4: <signerPubkey>}` — always 38 bytes:
  // `a2 01 27 04 58 20 || <32B pubkey>`.
  const protectedHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, signerPubkey],
  ]);
  return encodeCanonicalCbor(protectedHeader);
}

export function buildToSign(recordBody: RecordBody): Uint8Array {
  const body = encodeCanonicalCbor(recordBody);
  const out = new Uint8Array(DOMAIN_PREFIX_BYTES.length + body.length);
  out.set(DOMAIN_PREFIX_BYTES, 0);
  out.set(body, DOMAIN_PREFIX_BYTES.length);
  return out;
}

export interface PrepareSigStructureResult {
  sigStructureBytes: Uint8Array;
  protectedHeaderBytes: Uint8Array;
}

export function prepareSigStructure(args: {
  recordBody: RecordBody;
  signerPubkey: Uint8Array;
}): PrepareSigStructureResult {
  if (args.signerPubkey.length !== 32) {
    throw new Error('signerPubkey must be 32 bytes (Ed25519 raw public key)');
  }
  const protectedHeaderBytes = path1ProtectedHeaderBytes(args.signerPubkey);
  const toSign = buildToSign(args.recordBody);
  const sigStructureBytes = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: protectedHeaderBytes,
    payload: toSign,
  });
  return { sigStructureBytes, protectedHeaderBytes };
}

export function assembleCoseSign1(args: {
  signerPubkey: Uint8Array;
  signature: Uint8Array;
}): Uint8Array {
  if (args.signerPubkey.length !== 32) throw new Error('signerPubkey must be 32 bytes');
  if (args.signature.length !== 64) throw new Error('signature must be 64 bytes');
  const protectedHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, args.signerPubkey],
  ]);
  return encodeCoseSign1({
    protectedHeader,
    unprotectedHeader: new Map(),
    payload: null,
    signature: args.signature,
  });
}

// CIP-8 hashed = true mode. DISCOURAGED for software off-host
// signers (AWS KMS / GCP HSM / YubiHSM each accept arbitrary-length input);
// use only for hardware co-signers with screen / buffer constraints.
function blake2b224(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 28 });
}

export function prepareSigStructureHashed(args: {
  recordBody: RecordBody;
  signerPubkey: Uint8Array;
}): PrepareSigStructureResult & { toSignHashBytes: Uint8Array } {
  if (args.signerPubkey.length !== 32) throw new Error('signerPubkey must be 32 bytes');
  const protectedHeaderBytes = path1ProtectedHeaderBytes(args.signerPubkey);
  const toSign = buildToSign(args.recordBody);
  const toSignHashBytes = blake2b224(toSign);
  const sigStructureBytes = buildSigStructure({
    context: 'Signature1',
    bodyProtectedBytes: protectedHeaderBytes,
    payload: toSignHashBytes,
  });
  return { sigStructureBytes, protectedHeaderBytes, toSignHashBytes };
}

export function assembleCoseSign1Hashed(args: {
  signerPubkey: Uint8Array;
  signature: Uint8Array;
}): Uint8Array {
  if (args.signerPubkey.length !== 32) throw new Error('signerPubkey must be 32 bytes');
  if (args.signature.length !== 64) throw new Error('signature must be 64 bytes');
  const protectedHeader = new Map<number | string, unknown>([
    [1, -8],
    [4, args.signerPubkey],
  ]);
  const unprotectedHeader = new Map<number | string, unknown>([['hashed', true]]);
  return encodeCoseSign1({
    protectedHeader,
    unprotectedHeader,
    payload: null,
    signature: args.signature,
  });
}

// End-to-end demonstration: build a sample record body → ask the off-host
// signer for a signature over the Sig_structure → assemble the COSE_Sign1.
// In production the assembled bytes get spliced into `record.sigs[i]` and
// submitted on-chain via a Cardano transaction's metadata label-309 entry.
export async function runOffHostSigningDemo(): Promise<{
  coseSign1Bytes: Uint8Array;
  signerPubkey: Uint8Array;
  toSign: Uint8Array;
}> {
  // Sample record body: a single-item hash-only record (matching the
  // V1 KAT vector). The exact seed (0x11 × 32) and pubkey come
  // from the byte-pinned fixture so the demo output is reproducible.
  const seed = new Uint8Array(32).fill(0x11);
  const signerPubkey = new Uint8Array([
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
  ]);
  const recordBody: RecordBody = {
    v: 1,
    items: [{ hashes: { 'sha2-256': blake2b_256(new TextEncoder().encode('demo content')) } }],
  };

  const signer = new MockHsmSigner(seed);
  const toSign = buildToSign(recordBody);
  const { sigStructureBytes } = prepareSigStructure({ recordBody, signerPubkey });
  const signature = await signer.sign(sigStructureBytes);
  const coseSign1Bytes = assembleCoseSign1({ signerPubkey, signature });
  return { coseSign1Bytes, signerPubkey, toSign };
}
