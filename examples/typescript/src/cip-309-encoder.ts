// CIP-309 v1 reference implementation — CIP-309 record encoder
// Spec: CIP-309
// Encodes PoE record objects to canonical CBOR for Cardano metadata label 309.
//
// The encoder is algorithm-agnostic for the `hashes` map: any registered
// content-hash identifier from CIP-309 §4.10.2 round-trips through canonical
// CBOR verbatim.
//
// Top-level `merkle[]` (CIP-309 §4.5, OPT) is peer to `items`/`sigs` and is
// encoded verbatim by the canonical CBOR layer. Canonical CBOR sorts
// top-level map keys by encoded-key length first (RFC 8949 §4.2.1), so
// `merkle` (6-byte text key) sits between `items` / `sigs` (5 bytes) and
// `supersedes` (10 bytes) — the canonical encoder handles this ordering
// without any explicit registration here. Producers are responsible for
// ensuring each `merkle[i].root` is the canonical Merkle root of the
// producer's ordered leaf list under `merkle[i].alg` and that
// `merkle[i].leaf_count` (REQUIRED, CIP-309 §4.5) commits the leaf count
// alongside the root; see `merkle-sha2-256.ts` and `merkle-leaves-list.ts`.
//
// Each `sigs[i]` map carries the chunked COSE_Sign1 under the wire field name
// `cose_sign1` (per CIP-309 §4.6.3); when the optional `cose_key` companion
// (chunked cbor<COSE_Key>) is present, canonical CBOR places `cose_key`
// (length-8 tstr) before `cose_sign1` (length-10 tstr).
//
// The sealed envelope on the passphrase path carries its identifiers under
// the literal field name `passphrase` (per CIP-309 §4.4); the algorithm value
// `argon2id` (final spelling, CIP-309 §4.10.6) replaces any legacy `-v13`
// suffix everywhere.

import { encodeCanonicalCbor } from './cbor-canonical.ts';
import type { PoeRecord } from './cip-309-validator.ts';

// CIP-309 v1 record-level signature domain separator (25 bytes UTF-8).
// Per CIP-309 §4.6.1, this prefix is embedded at the start of Sig_structure[3]
// (`to_sign`) rather than placed in Sig_structure[2] (`external_aad`).
// The empty `external_aad` keeps v1 byte-compatible with CIP-30 `signData`,
// which explicitly forbids `external_aad`.
export const SIG_DOMAIN_RECORD_V1 = new TextEncoder().encode(
  'cardano-poe-record-sig-v1',
);

export function encodePoeRecord(record: PoeRecord): Uint8Array {
  // Records produced for Cardano label 309 metadata MUST use canonical CBOR (RFC 8949 §4.2.1)
  // because record-level signatures sign the canonical encoding of the record minus the `sigs` field.
  return encodeCanonicalCbor(record);
}

// Helper: encode the body to be signed for record-level COSE_Sign1.
// Per CIP-309 §4.6.1, the signed bytes are:
//   to_sign = SIG_DOMAIN_RECORD_V1 || canonical_cbor(record minus sigs)
// The 25-byte UTF-8 prefix `cardano-poe-record-sig-v1` is the cross-protocol-replay
// domain separator; `external_aad` in the COSE Sig_structure is the empty bstr.
// `sigs` is the only field that gets stripped (per CIP-309 §4.6.3, the optional
// CIP-30 `key` lives inside each sigs entry instead of in a separate field).
export function buildRecordSignaturePayload(record: PoeRecord): Uint8Array {
  const { sigs: _, ...body } = record;
  const bodyBytes = encodeCanonicalCbor(body);
  const out = new Uint8Array(SIG_DOMAIN_RECORD_V1.length + bodyBytes.length);
  out.set(SIG_DOMAIN_RECORD_V1, 0);
  out.set(bodyBytes, SIG_DOMAIN_RECORD_V1.length);
  return out;
}

// CIP-309 carries signatures at the record level only; there is no per-item
// signature slot and no per-item payload-encoder. Authorship for multi-author
// content uses one PoE per author. See CIP-309 §4.6 and the Rationale section
// "Why authorship is expressed only at the record level".
