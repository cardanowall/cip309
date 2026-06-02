// CIP-309 v1 reference implementation — RFC 6962 §2.1 Merkle tree, SHA-256
// Spec: CIP-309 §6 (byte-exact construction);
//       schema-level rules in CIP-309 §4.5.
// Identifier on-wire: `rfc9162-sha256` (IANA COSE Verifiable Data Structure
// Algorithms registry codepoint 1, draft-ietf-cose-merkle-tree-proofs-18;
// CIP-309 §4.10.3 / §4.5, OPT-INFO).
//
// Construction notes (per CIP-309 §6.1):
//   - Single leaf:   MTH(L) = SHA-256(0x00 || d_0)
//   - Internal node: MTH(L) = SHA-256(0x01 || MTH(L[0:k]) || MTH(L[k:n]))
//     where k = largest power of 2 strictly less than n.
//   - Empty trees (n == 0) are FORBIDDEN.
//   - 1-leaf root != d_0: the 0x00 leaf prefix is what prevents the
//     CVE-2012-2459 family of duplicate-leaf / leaf-vs-internal collisions.
//
// Cross-language parity contract: this module and its Python twin MUST produce
// byte-identical roots and inclusion proofs for the same input list. The
// 0x00/0x01 domain-separation prefixes make the bytes implementation-agnostic.

import { sha256 } from '@noble/hashes/sha2.js';

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const DIGEST_LENGTH = 32;

/** Inclusion-proof envelope per CIP-309 §6.4 "Producer-side proof format". */
export interface InclusionProof {
  /** The 32-byte leaf datum d_i committed under `rfc9162-sha256`. */
  leaf: Uint8Array;
  /** 0-indexed position of the leaf in the producer's ordered list. */
  index: number;
  /** Total number of leaves in the committed tree (n). */
  treeSize: number;
  /** Ordered sibling hashes from leaf to root (m = ceil(log_2(n)) for n > 1, 0 for n == 1). */
  proof: Uint8Array[];
}

/** Merkle root per CIP-309 §6.1 (RFC 6962 §2.1 with SHA-256). */
export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    throw new Error('merkleRoot: empty leaf list (n == 0 is forbidden per CIP-309 §6.1)');
  }
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i]!;
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new Error(
        `merkleRoot: leaf[${i}] must be a Uint8Array(${DIGEST_LENGTH}); got length ${
          leaf instanceof Uint8Array ? leaf.length : 'non-Uint8Array'
        }`,
      );
    }
  }
  return mthRecursive(leaves);
}

/** Inclusion proof per CIP-309 §6.3 (RFC 6962 §2.1.1). */
export function inclusionProof(leaves: Uint8Array[], i: number): InclusionProof {
  if (leaves.length === 0) {
    throw new Error('inclusionProof: empty leaf list (n == 0 is forbidden per CIP-309 §6.1)');
  }
  if (!Number.isInteger(i) || i < 0 || i >= leaves.length) {
    throw new Error(
      `inclusionProof: index ${i} out of range [0, ${leaves.length})`,
    );
  }
  for (let j = 0; j < leaves.length; j++) {
    const leaf = leaves[j]!;
    if (!(leaf instanceof Uint8Array) || leaf.length !== DIGEST_LENGTH) {
      throw new Error(
        `inclusionProof: leaf[${j}] must be a Uint8Array(${DIGEST_LENGTH}); got length ${
          leaf instanceof Uint8Array ? leaf.length : 'non-Uint8Array'
        }`,
      );
    }
  }
  return {
    leaf: leaves[i]!,
    index: i,
    treeSize: leaves.length,
    proof: auditPath(leaves, i),
  };
}

/**
 * Verify an inclusion proof against an expected root per CIP-309 §6.3
 * (RFC 6962 §2.1.1 audit-path verification).
 *
 * The proof is ordered **leaf-to-root**: `proof[0]` is the sibling at the leaf
 * level, `proof[m-1]` is the sibling at the top level (the level whose
 * parent is the full-tree root). This matches RFC 6962 §2.1.1 `PATH(m, D)`
 * recursion semantics (`PATH(...) : MTH(...)` with `:` = list concat).
 *
 * Folding logic at each level uses the "sn / fn" tracking from RFC 6962
 * §2.1.1: `sn` is the leaf index within the current subtree, `fn` is the
 * (size − 1) of the current subtree. At each step, `sn` odd OR `sn == fn`
 * means the current node is a right child (sibling on the left); otherwise
 * it is a left child (sibling on the right). Then both shift right by 1.
 * This formulation handles non-power-of-2 tree sizes correctly, including
 * the "promote a lone right subtree" cases the spec's pseudocode skips over.
 */
export function verifyInclusion(p: InclusionProof, expectedRoot: Uint8Array): boolean {
  if (!(expectedRoot instanceof Uint8Array) || expectedRoot.length !== DIGEST_LENGTH) {
    return false;
  }
  if (!(p.leaf instanceof Uint8Array) || p.leaf.length !== DIGEST_LENGTH) {
    return false;
  }
  if (
    !Number.isInteger(p.index) ||
    !Number.isInteger(p.treeSize) ||
    p.treeSize < 1 ||
    p.index < 0 ||
    p.index >= p.treeSize
  ) {
    return false;
  }
  for (const s of p.proof) {
    if (!(s instanceof Uint8Array) || s.length !== DIGEST_LENGTH) {
      return false;
    }
  }

  // Single-leaf trees admit only the trivial empty-path proof.
  if (p.treeSize === 1) {
    if (p.proof.length !== 0 || p.index !== 0) return false;
    return bytesEqual(hashLeaf(p.leaf), expectedRoot);
  }

  let h = hashLeaf(p.leaf);
  let sn = p.index;
  let fn = p.treeSize - 1;
  for (const s of p.proof) {
    if (fn === 0) return false; // malformed: proof longer than tree depth
    if ((sn & 1) === 1 || sn === fn) {
      // current node is a right child → sibling is on the left
      h = hashNode(s, h);
      // climb past any chain of left-child ancestors (fn even shrinks fn/sn together)
      while ((sn & 1) === 0 && sn !== 0) {
        sn >>>= 1;
        fn >>>= 1;
      }
    } else {
      // current node is a left child → sibling is on the right
      h = hashNode(h, s);
    }
    sn >>>= 1;
    fn >>>= 1;
  }
  if (fn !== 0) return false; // malformed: proof too short
  return bytesEqual(h, expectedRoot);
}

/** Largest power of 2 strictly less than n. Requires n >= 2. */
export function largestPow2Lt(n: number): number {
  if (!Number.isInteger(n) || n < 2) {
    throw new Error(`largestPow2Lt: n must be an integer >= 2; got ${n}`);
  }
  // `k = 2^floor(log_2(n - 1))` per CIP-309 §6.1. Implemented as a bit-walk
  // so we never depend on Math.log2 floating-point rounding at large n.
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/** RFC 6962 leaf hash: SHA-256(0x00 || d). */
export function hashLeaf(d: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + d.length);
  buf[0] = LEAF_PREFIX;
  buf.set(d, 1);
  return sha256(buf);
}

/** RFC 6962 internal-node hash: SHA-256(0x01 || left || right). */
export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = NODE_PREFIX;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256(buf);
}

// === Internals =============================================================

/** Recursive MTH(L) per CIP-309 §6.1. Caller already validated leaf shape. */
function mthRecursive(leaves: Uint8Array[]): Uint8Array {
  const n = leaves.length;
  if (n === 1) {
    return hashLeaf(leaves[0]!);
  }
  const k = largestPow2Lt(n);
  const left = mthRecursive(leaves.slice(0, k));
  const right = mthRecursive(leaves.slice(k, n));
  return hashNode(left, right);
}

/**
 * Recursive audit-path collector per RFC 6962 §2.1.1 `PATH(m, D)`:
 *
 *     PATH(m, D[n]) = PATH(m, D[0:k])   : MTH(D[k:n])    if m < k
 *                   = PATH(m - k, D[k:n]) : MTH(D[0:k])  if m >= k
 *
 * Where `:` is list concatenation. The recursive call ALWAYS comes first,
 * giving **leaf-to-root** order: `proof[0]` is the sibling at the leaf
 * level, `proof[m-1]` is the sibling at the top level.
 */
function auditPath(leaves: Uint8Array[], i: number): Uint8Array[] {
  const n = leaves.length;
  if (n === 1) return [];
  const k = largestPow2Lt(n);
  if (i < k) {
    // leaf is in left subtree; sibling at this level is the right-subtree root.
    return [...auditPath(leaves.slice(0, k), i), mthRecursive(leaves.slice(k, n))];
  }
  // leaf is in right subtree; sibling at this level is the left-subtree root.
  return [...auditPath(leaves.slice(k, n), i - k), mthRecursive(leaves.slice(0, k))];
}

/** Plain byte-equality. Constant-time is not required: roots are public. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// === Self-test =============================================================
// Runs only when invoked directly (e.g. `npx tsx src/merkle-sha2-256.ts`).
// Builds a 4-leaf tree with d_i = SHA-256(UTF-8("merkle-leaf-{i}")) for i in
// [0, 3], then round-trips every inclusion proof and checks tamper rejection.

function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

function selfTest(): void {
  const enc = new TextEncoder();
  const leaves: Uint8Array[] = [
    sha256(enc.encode('merkle-leaf-0')),
    sha256(enc.encode('merkle-leaf-1')),
    sha256(enc.encode('merkle-leaf-2')),
    sha256(enc.encode('merkle-leaf-3')),
  ];

  const root = merkleRoot(leaves);
  console.log(`leaves:`);
  for (let i = 0; i < leaves.length; i++) {
    console.log(`  d_${i} = ${bytesToHex(leaves[i]!)}`);
  }
  console.log(`root  = ${bytesToHex(root)}`);

  let allPass = true;
  for (let i = 0; i < leaves.length; i++) {
    const p = inclusionProof(leaves, i);
    const ok = verifyInclusion(p, root);
    console.log(
      `  proof[${i}] length=${p.proof.length} verify=${ok ? 'PASS' : 'FAIL'}`,
    );
    if (!ok) allPass = false;
  }

  // Negative checks: tampering with leaf, index, root, and proof MUST fail.
  const goodProof = inclusionProof(leaves, 1);
  const tamperedLeaf: InclusionProof = { ...goodProof, leaf: sha256(enc.encode('merkle-leaf-X')) };
  const tamperedIdx: InclusionProof = { ...goodProof, index: 2 };
  const tamperedRoot = new Uint8Array(root);
  tamperedRoot[0] = (tamperedRoot[0]! ^ 0xff) & 0xff;
  const checks: [string, boolean][] = [
    ['tampered-leaf rejected', !verifyInclusion(tamperedLeaf, root)],
    ['tampered-index rejected', !verifyInclusion(tamperedIdx, root)],
    ['tampered-root rejected', !verifyInclusion(goodProof, tamperedRoot)],
  ];
  for (const [label, ok] of checks) {
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
    if (!ok) allPass = false;
  }

  if (!allPass) {
    console.error('merkle-sha2-256 self-test FAILED');
    process.exit(1);
  }
  console.log('merkle-sha2-256 self-test PASSED');
}

// ESM entry-point guard: only run when this file is the script entry point.
if (import.meta.url === `file://${process.argv[1]}`) {
  selfTest();
}
