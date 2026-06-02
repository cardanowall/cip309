"""CIP-309 v1 reference implementation — Merkle leaves-list codec.

The on-storage byte-normative form of the leaves-list file is **canonical
CBOR** (RFC 8949 §4.2). Producers publish CBOR bytes to the content-addressed
substrate referenced by `merkle[i].uris[]`; verifiers parse CBOR. A JSON+JCS
projection is a permitted informative companion (CLI dump, documentation
example) but is NOT the wire form and MUST NOT be treated as authoritative if
both forms are present and they disagree byte-for-byte.

Schema (canonical CBOR):

    leaves-list = {
        "format":     "cardano-poe-merkle-leaves-v1",
        "tree_alg":   "rfc9162-sha256",
        "root":       bytes .size 32,
        "leaves":     [ + bytes .size 32 ],
        "leaf_count": uint,
        ? "leaf_alg": tstr,
    }

The JSON projection encodes `root` and every `leaves[i]` as 64-character
lowercase hex strings; the JSON form is JCS-canonicalised (RFC 8785) when
material to byte-stability for inspection-only consumers.

Cross-language parity: byte-identical with the TypeScript reference
(merkle-leaves-list.ts) when fed the same inputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .cbor_canonical import decode_canonical_cbor, encode_canonical_cbor

# === Registered format identifiers ============================================

# The literal `format` value bound to the leaves-list CDDL. Future schema
# revisions bump the suffix (`-v2`, etc.) and add the new value to this set;
# v1 verifiers MUST reject any other value with
# `SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED`.
LEAVES_LIST_FORMAT_V1: str = "cardano-poe-merkle-leaves-v1"
REGISTERED_FORMATS: frozenset[str] = frozenset({LEAVES_LIST_FORMAT_V1})

# On-wire Merkle list-commitment algorithm identifier. The `tree_alg` field of
# the leaves-list pins the tree's hash algorithm; v1 registers a single value.
DEFAULT_TREE_ALG: str = "rfc9162-sha256"


# === Exception types ==========================================================


class SchemaMerkleLeavesFormatUnsupported(Exception):
    """Raised by `decode_leaves_list` when `format` is not in the registered set."""

    code: str = "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED"

    def __init__(self, message: str = "") -> None:
        super().__init__(f"{self.code}: {message}" if message else self.code)


class MerkleLeavesListMalformed(Exception):
    """Raised when the decoded leaves-list violates a structural invariant
    (wrong types, missing required field, wrong-length root / leaf, etc.)."""

    code: str = "SCHEMA_MERKLE_LEAVES_MALFORMED"

    def __init__(self, message: str) -> None:
        super().__init__(f"{self.code}: {message}")


# === Decoded type (returned by `decode_leaves_list`) ==========================


@dataclass(frozen=True)
class LeavesList:
    format: str
    tree_alg: str
    root: bytes
    leaves: tuple[bytes, ...]
    leaf_count: int
    leaf_alg: str | None = None


# === CBOR encode / decode =====================================================


def encode_leaves_list(
    *,
    root: bytes,
    leaves: list[bytes] | tuple[bytes, ...],
    leaf_count: int,
    leaf_alg: str | None = None,
) -> bytes:
    """Emit canonical CBOR bytes for the leaves-list.

    Inputs:
      - `root`        — the 32-byte Merkle root (raw bytes, not hex).
      - `leaves`      — ordered list of 32-byte leaf digests.
      - `leaf_count`  — total leaf count (must equal `len(leaves)`).
      - `leaf_alg`    — OPTIONAL informative leaf-pre-hash algorithm.

    The output is canonical CBOR (RFC 8949 §4.2.1): shortest-form integers,
    definite-length encoding, bytewise lex-sorted map keys, no duplicates.
    """
    if not isinstance(root, (bytes, bytearray)) or len(root) != 32:
        raise MerkleLeavesListMalformed("root must be a 32-byte byte string")
    if not isinstance(leaves, (list, tuple)) or len(leaves) == 0:
        raise MerkleLeavesListMalformed("leaves must be a non-empty list")
    if leaf_count != len(leaves):
        raise MerkleLeavesListMalformed(
            f"leaf_count ({leaf_count}) does not match len(leaves) ({len(leaves)})"
        )
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            raise MerkleLeavesListMalformed(f"leaves[{i}] must be a 32-byte byte string")

    obj: dict[str, Any] = {
        "format": LEAVES_LIST_FORMAT_V1,
        "tree_alg": DEFAULT_TREE_ALG,
        "root": bytes(root),
        "leaves": [bytes(leaf) for leaf in leaves],
        "leaf_count": leaf_count,
    }
    if leaf_alg is not None:
        obj["leaf_alg"] = leaf_alg
    return encode_canonical_cbor(obj)


def decode_leaves_list(data: bytes) -> LeavesList:
    """Parse canonical CBOR bytes into a `LeavesList`.

    Raises:
      - `SchemaMerkleLeavesFormatUnsupported` — `format` not in registered set.
      - `MerkleLeavesListMalformed` — structural violation (wrong types,
        missing required field, wrong-length root / leaf, leaf_count
        disagreement with len(leaves), etc.).
      - `ValueError` from the canonical CBOR decoder for `MALFORMED_CBOR`
        upstream (floats, indefinite-length, etc.).
    """
    decoded = decode_canonical_cbor(data)
    if not isinstance(decoded, dict):
        raise MerkleLeavesListMalformed("leaves-list top-level must be a CBOR map")

    fmt = decoded.get("format")
    if not isinstance(fmt, str):
        raise MerkleLeavesListMalformed("leaves-list `format` must be a text string")
    if fmt not in REGISTERED_FORMATS:
        raise SchemaMerkleLeavesFormatUnsupported(f"unsupported leaves-list format: {fmt!r}")

    tree_alg = decoded.get("tree_alg")
    if not isinstance(tree_alg, str):
        raise MerkleLeavesListMalformed("leaves-list `tree_alg` must be a text string")

    root = decoded.get("root")
    if not isinstance(root, (bytes, bytearray)) or len(root) != 32:
        raise MerkleLeavesListMalformed("leaves-list `root` must be a 32-byte byte string")

    leaves_raw = decoded.get("leaves")
    if not isinstance(leaves_raw, list) or len(leaves_raw) == 0:
        raise MerkleLeavesListMalformed("leaves-list `leaves` must be a non-empty array")
    leaves: list[bytes] = []
    for i, leaf in enumerate(leaves_raw):
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != 32:
            raise MerkleLeavesListMalformed(
                f"leaves-list `leaves[{i}]` must be a 32-byte byte string"
            )
        leaves.append(bytes(leaf))

    leaf_count = decoded.get("leaf_count")
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or leaf_count < 0:
        raise MerkleLeavesListMalformed("leaves-list `leaf_count` must be a non-negative integer")
    if leaf_count != len(leaves):
        raise MerkleLeavesListMalformed(
            f"leaves-list `leaf_count` ({leaf_count}) does not match len(leaves) ({len(leaves)})"
        )

    leaf_alg = decoded.get("leaf_alg")
    if leaf_alg is not None and not isinstance(leaf_alg, str):
        raise MerkleLeavesListMalformed("leaves-list `leaf_alg` (if present) must be a text string")

    return LeavesList(
        format=fmt,
        tree_alg=tree_alg,
        root=bytes(root),
        leaves=tuple(leaves),
        leaf_count=leaf_count,
        leaf_alg=leaf_alg,
    )


# === JSON projection (informative) ============================================


def to_json_projection(decoded: LeavesList) -> str:
    """Return the JCS-canonical (RFC 8785) JSON projection of `decoded`.

    The JSON projection encodes `root` and every `leaves[i]` as 64-character
    lowercase hex strings (no `0x` prefix). This is an INSPECTION-ONLY view;
    verification MUST be performed against the CBOR canonical form.
    """
    obj: dict[str, Any] = {
        "format": decoded.format,
        "tree_alg": decoded.tree_alg,
        "root": decoded.root.hex(),
        "leaves": [leaf.hex() for leaf in decoded.leaves],
        "leaf_count": decoded.leaf_count,
    }
    if decoded.leaf_alg is not None:
        obj["leaf_alg"] = decoded.leaf_alg
    # JCS canonical form (RFC 8785): lexicographic key order, no whitespace,
    # UTF-8 codepoints not escaped.
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def from_json_projection(json_str: str) -> LeavesList:
    """Parse a JSON projection back into a `LeavesList`.

    WARNING: the JSON projection is NOT the wire form. Verifiers MUST parse
    CBOR (`decode_leaves_list`) for any check whose outcome affects record
    validity. This helper exists for CLI tooling and documentation round-trips
    only.

    Raises the same exception classes as `decode_leaves_list`.
    """
    try:
        obj = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise MerkleLeavesListMalformed(f"leaves-list JSON parse failed: {e}") from e
    if not isinstance(obj, dict):
        raise MerkleLeavesListMalformed("leaves-list JSON top-level must be an object")

    fmt = obj.get("format")
    if not isinstance(fmt, str):
        raise MerkleLeavesListMalformed("leaves-list `format` must be a string")
    if fmt not in REGISTERED_FORMATS:
        raise SchemaMerkleLeavesFormatUnsupported(f"unsupported leaves-list format: {fmt!r}")

    tree_alg = obj.get("tree_alg")
    if not isinstance(tree_alg, str):
        raise MerkleLeavesListMalformed("leaves-list `tree_alg` must be a string")

    root_hex = obj.get("root")
    if not isinstance(root_hex, str) or len(root_hex) != 64:
        raise MerkleLeavesListMalformed("leaves-list JSON `root` must be a 64-character hex string")
    try:
        root = bytes.fromhex(root_hex)
    except ValueError as e:
        raise MerkleLeavesListMalformed(f"leaves-list `root` hex decode failed: {e}") from e

    leaves_raw = obj.get("leaves")
    if not isinstance(leaves_raw, list) or len(leaves_raw) == 0:
        raise MerkleLeavesListMalformed("leaves-list `leaves` must be a non-empty array")
    leaves: list[bytes] = []
    for i, leaf_hex in enumerate(leaves_raw):
        if not isinstance(leaf_hex, str) or len(leaf_hex) != 64:
            raise MerkleLeavesListMalformed(
                f"leaves-list JSON `leaves[{i}]` must be a 64-character hex string"
            )
        try:
            leaves.append(bytes.fromhex(leaf_hex))
        except ValueError as e:
            raise MerkleLeavesListMalformed(
                f"leaves-list `leaves[{i}]` hex decode failed: {e}"
            ) from e

    leaf_count = obj.get("leaf_count")
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or leaf_count < 0:
        raise MerkleLeavesListMalformed("leaves-list `leaf_count` must be a non-negative integer")
    if leaf_count != len(leaves):
        raise MerkleLeavesListMalformed(
            f"leaves-list `leaf_count` ({leaf_count}) does not match len(leaves) ({len(leaves)})"
        )

    leaf_alg = obj.get("leaf_alg")
    if leaf_alg is not None and not isinstance(leaf_alg, str):
        raise MerkleLeavesListMalformed("leaves-list `leaf_alg` (if present) must be a string")

    return LeavesList(
        format=fmt,
        tree_alg=tree_alg,
        root=root,
        leaves=tuple(leaves),
        leaf_count=leaf_count,
        leaf_alg=leaf_alg,
    )


__all__ = [
    "DEFAULT_TREE_ALG",
    "LEAVES_LIST_FORMAT_V1",
    "REGISTERED_FORMATS",
    "LeavesList",
    "MerkleLeavesListMalformed",
    "SchemaMerkleLeavesFormatUnsupported",
    "decode_leaves_list",
    "encode_leaves_list",
    "from_json_projection",
    "to_json_projection",
]
