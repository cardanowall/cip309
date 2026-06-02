"""CIP-309 v1 reference implementation — RFC 6962 §2.1 Merkle tree, SHA-256.

On-wire algorithm identifier: `rfc9162-sha256` (IANA COSE Verifiable Data
Structure Algorithms registry, codepoint 1; draft-ietf-cose-merkle-tree-proofs).

Cross-language parity: this module MUST produce byte-identical roots and
inclusion proofs to the TypeScript reference (merkle-sha2-256.ts) for the same
input list.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# === Public types ============================================================


@dataclass
class InclusionProof:
    """Inclusion proof artefact (informative shape).

    Fields:
      leaf       — the 32-byte leaf datum `d_i` (NOT the leaf hash `L_i`).
      index      — 0-indexed position of `d_i` in the leaf list.
      tree_size  — total number of leaves `n` in the original tree.
      proof      — ordered list of 32-byte sibling hashes from leaf to root.
                   Length is 0 when `tree_size == 1` (trivial proof) and
                   `ceil(log_2(tree_size))` otherwise.
    """

    leaf: bytes
    index: int
    tree_size: int
    proof: list[bytes] = field(default_factory=list)


# === Internal helpers ========================================================


def _largest_pow2_lt(n: int) -> int:
    """Largest `k = 2^j` such that `k < n`. `n` MUST be >= 2.

    Examples:
      _largest_pow2_lt(2) == 1
      _largest_pow2_lt(3) == 2
      _largest_pow2_lt(4) == 2
      _largest_pow2_lt(5) == 4
      _largest_pow2_lt(8) == 4
    """
    if n < 2:
        raise ValueError(f"_largest_pow2_lt requires n >= 2; got {n}")
    return 1 << ((n - 1).bit_length() - 1)


def _hash_leaf(d: bytes) -> bytes:
    """Leaf hash with the RFC 6962 0x00 prefix: `SHA-256(0x00 || d)`."""
    return hashlib.sha256(b"\x00" + d).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    """Internal-node hash with the RFC 6962 0x01 prefix:
    `SHA-256(0x01 || left || right)`."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _validate_leaves(leaves: list[bytes]) -> None:
    """Shared input validation for the public API.

    Empty trees are forbidden (n >= 1); each leaf MUST be exactly 32 bytes.
    Anything else raises `ValueError`.
    """
    if not isinstance(leaves, list):
        raise ValueError("leaves must be a list of 32-byte values")
    if len(leaves) == 0:
        raise ValueError("empty Merkle tree forbidden (n >= 1)")
    for i, d in enumerate(leaves):
        if not isinstance(d, (bytes, bytearray)):
            raise ValueError(f"leaves[{i}] must be bytes; got {type(d).__name__}")
        if len(d) != 32:
            raise ValueError(f"leaves[{i}] must be exactly 32 bytes; got {len(d)}")


def _merkle_root_unchecked(leaves: list[bytes]) -> bytes:
    """Recursive RFC 6962 §2.1 MTH; caller is responsible for input validation.

    Splitting `_validate_leaves` from the recursive worker keeps the per-call
    cost down — only the top-level public entry pays the length checks once.
    """
    n = len(leaves)
    if n == 1:
        return _hash_leaf(leaves[0])
    k = _largest_pow2_lt(n)
    left = _merkle_root_unchecked(leaves[:k])
    right = _merkle_root_unchecked(leaves[k:])
    return _hash_node(left, right)


def _audit_path(leaves: list[bytes], i: int) -> list[bytes]:
    """Standard RFC 6962 §2.1.1 audit-path algorithm. Returns the ordered
    list of sibling hashes from the leaf at index `i` up to the root.

    Caller is responsible for `_validate_leaves(leaves)` and `0 <= i < n`.
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if i < k:
        # leaf is in left subtree; sibling is right subtree's root
        return _audit_path(leaves[:k], i) + [_merkle_root_unchecked(leaves[k:])]
    else:
        # leaf is in right subtree; sibling is left subtree's root
        return _audit_path(leaves[k:], i - k) + [_merkle_root_unchecked(leaves[:k])]


# === Public API ==============================================================


def merkle_root(leaves: list[bytes]) -> bytes:
    """Canonical Merkle root (RFC 6962 §2.1 with SHA-256).

    Each leaf MUST be exactly 32 bytes. Raises `ValueError` on empty input
    or wrong-length leaves.

    For n == 1, returns `SHA-256(0x00 || d_0)`; the leaf prefix prevents
    collision with internal-node-shaped hashes (CVE-2012-2459 family).
    """
    _validate_leaves(leaves)
    return _merkle_root_unchecked(leaves)


def inclusion_proof(leaves: list[bytes], i: int) -> InclusionProof:
    """Inclusion proof for the leaf at index `i`.

    Each leaf MUST be exactly 32 bytes. Raises `ValueError` on empty input,
    wrong-length leaves, or out-of-range index.
    """
    _validate_leaves(leaves)
    if not isinstance(i, int) or isinstance(i, bool):
        raise ValueError(f"index must be an int; got {type(i).__name__}")
    if i < 0 or i >= len(leaves):
        raise ValueError(f"index {i} out of range for tree_size {len(leaves)}")
    return InclusionProof(
        leaf=bytes(leaves[i]),
        index=i,
        tree_size=len(leaves),
        proof=_audit_path(leaves, i),
    )


def verify_inclusion(p: InclusionProof, expected_root: bytes) -> bool:
    """Verify an inclusion proof against an expected root.

    Implements the bottom-up audit-path fold of RFC 9162 §2.1.3.2 (the
    RFC 6962-bis inclusion-proof verifier). The audit path is consumed in
    leaf-to-root order, matching the proof ordering emitted by
    `inclusion_proof`. At each level the direction is derived from the bit
    pattern of `(fn, sn) = (index, tree_size - 1)`: when `fn` is the right
    child of its pair (LSB set, or `fn == sn` — the latter covers a lone
    right-most node carried straight up through one or more levels), the
    sibling sits on the LEFT; otherwise on the RIGHT.

    Returns True iff the proof reconstructs a hash byte-equal to
    `expected_root`. Any structural inconsistency in the proof (wrong leaf
    length, out-of-range index, non-32-byte siblings, length mismatch with
    tree_size, premature exhaustion of the tree during the fold, or a
    1-leaf proof carrying siblings or `index != 0`) returns False rather
    than raising — verification is a Boolean predicate, not a parser.
    """
    # Structural checks on the proof object itself
    if not isinstance(p.leaf, (bytes, bytearray)) or len(p.leaf) != 32:
        return False
    if not isinstance(expected_root, (bytes, bytearray)) or len(expected_root) != 32:
        return False
    if not isinstance(p.tree_size, int) or p.tree_size < 1:
        return False
    if not isinstance(p.index, int) or p.index < 0 or p.index >= p.tree_size:
        return False
    if not isinstance(p.proof, list):
        return False
    for s in p.proof:
        if not isinstance(s, (bytes, bytearray)) or len(s) != 32:
            return False

    if p.tree_size == 1:
        # Trivial single-leaf case: proof MUST be empty and index MUST be 0
        if len(p.proof) != 0 or p.index != 0:
            return False
        return _hash_leaf(p.leaf) == expected_root

    fn = p.index
    sn = p.tree_size - 1
    r = _hash_leaf(p.leaf)
    for s in p.proof:
        if sn == 0:
            # Malformed proof: more siblings supplied than the tree has levels
            return False
        if (fn & 1) == 1 or fn == sn:
            # current node is the RIGHT child of its pair → sibling on LEFT
            r = _hash_node(s, r)
            # When `fn` was a right-most-carried node (LSB clear, fn == sn),
            # walk both fn and sn upward until fn lands on a right child or
            # the root is reached. This is the RFC 9162 §2.1.3.2 inner-loop
            # adjustment.
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            # current node is the LEFT child of its pair → sibling on RIGHT
            r = _hash_node(r, s)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        # Proof shorter than the tree's depth — under-specified path
        return False
    return r == expected_root


# === Self-test ===============================================================


def _self_test() -> None:
    """Build a 4-leaf fixture, verify per-leaf inclusion proofs, and print the
    root hex for cross-language parity comparison against the TypeScript
    implementation.
    """
    plaintexts = [
        b"merkle-leaf-0",
        b"merkle-leaf-1",
        b"merkle-leaf-2",
        b"merkle-leaf-3",
    ]
    leaves = [hashlib.sha256(p).digest() for p in plaintexts]

    print("=== Python merkle_sha2_256 self-test (4-leaf fixture) ===")
    for i, (p, d) in enumerate(zip(plaintexts, leaves, strict=True)):
        print(f"d_{i} = SHA-256({p!r}) = {d.hex()}")

    # Pre-rolled internal nodes for sanity-checking the recursion
    l_hashes = [_hash_leaf(d) for d in leaves]
    h01 = _hash_node(l_hashes[0], l_hashes[1])
    h23 = _hash_node(l_hashes[2], l_hashes[3])
    expected_root = _hash_node(h01, h23)

    for i, lh in enumerate(l_hashes):
        print(f"L{i}  = SHA-256(0x00||d_{i}) = {lh.hex()}")
    print(f"H01 = SHA-256(0x01||L0||L1) = {h01.hex()}")
    print(f"H23 = SHA-256(0x01||L2||L3) = {h23.hex()}")

    root = merkle_root(leaves)
    assert root == expected_root, (
        f"recursive root {root.hex()} != hand-computed {expected_root.hex()}"
    )
    print(f"root = SHA-256(0x01||H01||H23) = {root.hex()}")

    # Per-leaf inclusion proofs
    for i in range(len(leaves)):
        proof = inclusion_proof(leaves, i)
        ok = verify_inclusion(proof, root)
        proof_hex = [s.hex() for s in proof.proof]
        print(f"inclusion_proof[{i}]: tree_size={proof.tree_size}  proof={proof_hex}  verify={ok}")
        assert ok, f"inclusion proof for leaf {i} failed to verify"

    # Negative checks — make sure verify_inclusion is not trivially accepting
    bad_root = bytes(32)
    p0 = inclusion_proof(leaves, 0)
    assert verify_inclusion(p0, bad_root) is False, "must reject wrong root"

    tampered = InclusionProof(
        leaf=p0.leaf,
        index=p0.index,
        tree_size=p0.tree_size,
        proof=[bytes(32), *p0.proof[1:]],
    )
    assert verify_inclusion(tampered, root) is False, "must reject tampered sibling"

    swapped_idx = InclusionProof(
        leaf=p0.leaf,
        index=1,
        tree_size=p0.tree_size,
        proof=p0.proof,
    )
    assert verify_inclusion(swapped_idx, root) is False, "must reject wrong index"

    # Single-leaf identity check (n == 1): root MUST NOT equal d_0
    single = leaves[:1]
    single_root = merkle_root(single)
    assert single_root != single[0], "1-leaf root must NOT equal d_0 — the leaf prefix is required"
    assert single_root == _hash_leaf(single[0])
    p_single = inclusion_proof(single, 0)
    assert p_single.proof == []
    assert verify_inclusion(p_single, single_root) is True

    # Empty input MUST raise
    try:
        merkle_root([])
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("empty leaf list must raise ValueError")

    # Wrong-length leaf MUST raise
    try:
        merkle_root([b"\x00" * 31])
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("non-32-byte leaf must raise ValueError")

    print()
    print("ALL SELF-TESTS PASSED")
    print(f"ROOT_HEX = {root.hex()}")


if __name__ == "__main__":
    _self_test()
