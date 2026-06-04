// Label 309 v1 reference implementation — COSE_Sign1 encode/decode + Sig_structure builder
// Spec: RFC 9052 (COSE), CIP-8 (Cardano Message Signing)
// Label 309 §4.6: signatures are COSE_Sign1 with alg = -8 (EdDSA / Ed25519, RFC 9053 §2.2).

import { decode } from 'cbor2';
import { encodeCanonicalCbor } from './cbor-canonical.ts';

export type CoseHeader = Map<number | string, unknown>;

export interface CoseSign1Decoded {
  protectedHeader: CoseHeader; // decoded from protected_bytes (or empty if 0-length)
  protectedBytes: Uint8Array; // original encoding (preserved for signature verification)
  unprotectedHeader: CoseHeader;
  payload: Uint8Array | null; // null = detached
  signature: Uint8Array;
}

export function encodeCoseSign1(args: {
  protectedHeader: CoseHeader;
  unprotectedHeader: CoseHeader;
  payload: Uint8Array | null; // null for detached
  signature: Uint8Array;
}): Uint8Array {
  // protected is encoded as bstr; if header is empty, protected_bytes MUST be h'' (zero-length bstr)
  // RFC 9052 §3
  const protectedBytes =
    args.protectedHeader.size === 0 ? new Uint8Array(0) : encodeCanonicalCbor(args.protectedHeader);
  const cborArray = [protectedBytes, args.unprotectedHeader, args.payload, args.signature];
  return encodeCanonicalCbor(cborArray);
}

// cbor2 decodes a CBOR map as a JS Map ONLY when at least one key is a
// non-string (e.g. the COSE integer labels 1/4); an empty map or an
// all-string-keyed map (e.g. the unprotected `{ "hashed": true }`) is surfaced
// as a plain object instead. COSE headers can be either shape, so normalise any
// decoded map-like value to a Map keyed by number | string. This keeps every
// downstream `.get(label)` call total regardless of how cbor2 surfaced it.
function toCoseHeader(value: unknown): CoseHeader {
  if (value instanceof Map) return value as CoseHeader;
  if (value !== null && typeof value === 'object') {
    return new Map(Object.entries(value as Record<string, unknown>));
  }
  throw new Error('CoseMalformedError: header is not a CBOR map');
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1Decoded {
  const arr = decode(bytes) as [Uint8Array, unknown, Uint8Array | null, Uint8Array];
  if (!Array.isArray(arr) || arr.length !== 4) {
    throw new Error('CoseMalformedError: expected 4-element array');
  }
  const [protectedBytes, unprotectedHeaderRaw, payload, signature] = arr;
  const protectedHeader: CoseHeader =
    protectedBytes.length === 0 ? new Map() : toCoseHeader(decode(protectedBytes));
  const unprotectedHeader = toCoseHeader(unprotectedHeaderRaw);
  return { protectedHeader, protectedBytes, unprotectedHeader, payload, signature };
}

// Per RFC 9052 §4.4:
//   Sig_structure = [ "Signature1", body_protected, external_aad, payload ]
//   payload field is the actual payload even if "detached" (null) in the COSE_Sign1 array.
export function buildSigStructure(args: {
  context: 'Signature1';
  bodyProtectedBytes: Uint8Array; // the encoded protected header bytes (h'' if empty header)
  externalAad?: Uint8Array; // empty by default
  payload: Uint8Array;
}): Uint8Array {
  const externalAad = args.externalAad ?? new Uint8Array(0);
  const sigStruct = [args.context, args.bodyProtectedBytes, externalAad, args.payload];
  return encodeCanonicalCbor(sigStruct);
}
