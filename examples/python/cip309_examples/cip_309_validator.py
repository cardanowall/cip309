# CIP-309 v1 reference implementation — CIP-309 record structural validator.
# Pure-function validator: takes CBOR bytes, returns a ValidationResult.
# Does NOT touch the network. Does NOT verify signatures cryptographically — it
# decodes the COSE_Sign1 structurally and runs the structural-error taxonomy.
#
# Codes are SCREAMING_SNAKE_CASE. `SIGNATURE_UNSUPPORTED` is info-only (the
# record's content claim stands regardless of which signature algorithms a
# verifier recognizes); attached payloads are MALFORMED_SIG_COSE_SIGN1.

import re
from typing import Any, Literal, NotRequired, TypedDict, TypeGuard

import cbor2

from .cbor_canonical import decode_canonical_cbor
from .cid_validator import is_valid_cid
from .cose_sign1 import decode_cose_sign1

# COSE_Key map labels reserved for private-key material (RFC 9052 §7.1 and the
# IANA "COSE Key Type Parameters" registry). The structural validator MUST
# decode the chunked `sigs[i].cose_key` blob as `cbor<COSE_Key>` and reject any
# entry whose map carries one of these labels — publishing a private key on the
# permanent ledger is a catastrophic, irreversible key-leak event, and the small
# map decode is cheap. Label `-4` is the private scalar `d` (OKP / EC2); listed
# as a set so future IANA-registered private-material labels can be added without
# touching the call sites.
COSE_KEY_PRIVATE_MATERIAL_LABELS: set[int] = {-4}

# === Constants ===

KNOWN_SIG_ALG_IDS: set[int] = {-8}  # EdDSA (RFC 9053 §2.2). This reference
# verifier ships the mandatory baseline only. The OPT-INFO codepoint `-19`
# (Ed25519, fully-specified per RFC 9864) is also registered in CIP-309; a
# deployment wishing to accept `-19` extends this set — verification under the
# Ed25519 primitive is identical for the two codepoints.
# Registered content-hash algorithms. `hashes` is a CBOR map keyed by these
# identifiers; canonical CBOR map-key sort gives a single byte-stable ordering.
# CBOR map-key uniqueness (RFC 8949 §3.1) guarantees one digest per algorithm —
# duplicates surface at canonical decode as MALFORMED_CBOR. Every identifier in
# this registry is a content-hash; list commitments (Merkle roots) live in the
# separate top-level `merkle[]` field and are governed by MERKLE_COMMIT_ALGS.
HASH_ALGS: dict[str, int] = {
    "sha2-256": 32,
    "blake2b-256": 32,
}
# Every registered hash algorithm in HASH_ALGS is a content-hash; the
# `enc`-bearing-item gate requires at least one entry from this set in the
# item's `hashes` map.
CONTENT_HASH_ALGS: set[str] = set(HASH_ALGS.keys())
# Registered Merkle list-commitment algorithms. The top-level `merkle[]` field
# carries one entry per list commitment, each with `{alg, root, leaf_count,
# uris?}` shape; `alg` MUST be a key here and `root` MUST match the pinned
# digest length. Unknown `alg` surfaces as `UNSUPPORTED_MERKLE_COMMIT_ALG`.
# `rfc9162-sha256` is the sole OPT-INFO identifier in v1 — a verifier without
# RFC 9162 Merkle-fold support reports `MERKLE_UNSUPPORTED` (info) and verifies
# the record's `items[i].hashes` claim normally.
MERKLE_COMMIT_ALGS: dict[str, int] = {"rfc9162-sha256": 32}
AEAD_NONCE_LENGTHS: dict[str, int] = {"xchacha20-poly1305": 24}
# Passphrase-KDF identifiers. The on-wire field is `enc.passphrase.alg`;
# unknown values surface as `ENC_PASSPHRASE_ALG_UNSUPPORTED`.
PASSPHRASE_ALGS: set[str] = {"argon2id"}

# ENC_PASSPHRASE_PARAMS_EXCEED_POLICY is operator-policy dependent: it fires when
# a producer-supplied Argon2id parameter (`m`, `t`, or `p`) exceeds the
# verifier's deployment-configured upper bound (memory cap, wall-clock cap,
# etc.). The spec floor is enforced by `ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW`;
# the upper bound is non-normative and depends on deployment hardware, so the
# reference validator does NOT emit `ENC_PASSPHRASE_PARAMS_EXCEED_POLICY`.
# Production deployments MAY add an operator-policy gate before invoking the KDF.

# Top-level fields registered in v1. Unknown keys are tolerated only when they
# match the forward-compat extension-key pattern; see
# `_check_record_top_level_keys` below. Metadata label 309 is the dispatcher —
# the record map has no `t` discriminator.
REGISTERED_RECORD_KEYS: set[str] = {
    "v",
    "items",
    "merkle",
    "supersedes",
    "sigs",
    "crit",
}
# Extension-key patterns. Vendor / experimental namespace (`^x-.+`) and
# companion-CIP namespace (`^[a-z]+-.+`) are tolerated by base verifiers without
# emitting `SCHEMA_UNKNOWN_FIELD`. Unknown keys NOT matching either pattern
# (typos of base names like `supersedess`, case variants like `Sigs`) MUST be
# rejected.
EXTENSION_KEY_REGEX: re.Pattern[str] = re.compile(r"^(x-.+|[a-z]+-.+)$")
REGISTERED_ITEM_KEYS: set[str] = {
    "hashes",
    "uris",
    "enc",
    # Signatures attach at the record level only; the item map has no
    # `cose_sign1` field.
}
REGISTERED_ENC_KEYS: set[str] = {
    "scheme",
    "aead",
    "kem",
    "nonce",
    "slots",
    "slots_mac",
    "passphrase",
}
REGISTERED_PASSPHRASE_KEYS: set[str] = {"alg", "salt", "params"}
REGISTERED_RECIPIENT_KEYS: set[str] = {"epk", "wrap"}
REGISTERED_SIG_ENTRY_KEYS: set[str] = {"cose_sign1", "cose_key"}
REGISTERED_MERKLE_COMMIT_KEYS: set[str] = {"alg", "root", "leaf_count", "uris"}
KEM_ALGS: set[str] = {"x25519"}

# === Result types ===


class ValidationIssue(TypedDict):
    path: list[str | int]
    code: str
    message: str


class ValidValidationResult(TypedDict):
    valid: Literal[True]
    record: dict[str, Any]
    warnings: NotRequired[list[ValidationIssue]]


class InvalidValidationResult(TypedDict):
    valid: Literal[False]
    issues: list[ValidationIssue]


ValidationResult = ValidValidationResult | InvalidValidationResult

# === Helpers ===


def _issue(path: list[str | int], code: str, message: str) -> ValidationIssue:
    return {"path": path, "code": code, "message": message}


def _is_chunked_bytes_shape(value: Any) -> TypeGuard[list[bytes]]:
    """Shape check only: non-empty list of bytes objects. Per-chunk size is
    enforced separately by `_validate_chunk_lengths` so that the typed code
    `CHUNK_TOO_LARGE` is emitted for [1, 64] violations rather than the
    generic SCHEMA_TYPE_MISMATCH."""
    if not isinstance(value, list) or len(value) == 0:
        return False
    return all(isinstance(c, (bytes, bytearray)) for c in value)


def _is_chunked_tstr_shape(value: Any) -> bool:
    """Shape check only: non-empty list of strings. Per-chunk size is
    enforced separately."""
    if not isinstance(value, list) or len(value) == 0:
        return False
    return all(isinstance(c, str) for c in value)


def _join_chunks(chunks: list[bytes]) -> bytes:
    return b"".join(bytes(c) for c in chunks)


def _check_unknown_keys(obj: dict, allowed: set[str], path: list, issues: list, label: str) -> None:
    for k in obj:
        if k not in allowed:
            issues.append(
                _issue(
                    path + [str(k)],
                    "SCHEMA_UNKNOWN_FIELD",
                    f"unknown {label} field: {k!r}",
                )
            )


def _validate_chunk_lengths(chunks: list, path: list, issues: list) -> None:
    """Per CDDL `bstr .size (1..64)` / `tstr .size (1..64)`, reject chunks
    whose byte length is outside [1, 64]. Applies to both bytes-chunks
    (length is `len(c)`) and tstr-chunks (length is UTF-8 byte count)."""
    for j, c in enumerate(chunks):
        if isinstance(c, (bytes, bytearray)):
            n = len(c)
        elif isinstance(c, str):
            n = len(c.encode("utf-8"))
        else:
            continue
        if n < 1 or n > 64:
            issues.append(_issue(path + [j], "CHUNK_TOO_LARGE", f"chunk length {n} not in [1, 64]"))


def _validate_hash_map_entry(alg: Any, digest: Any, path: list, issues: list) -> None:
    """Validate one (alg → digest) entry of the `hashes` CBOR map.

      - alg key MUST be a registered hash-algorithm identifier (`sha2-256`,
        `blake2b-256`); unknown → UNSUPPORTED_HASH_ALG.
      - digest value MUST be CBOR bytes; non-bytes → SCHEMA_TYPE_MISMATCH.
      - digest length MUST match the algorithm's pinned size (32 B for both
        v1 algorithms); mismatch → HASH_DIGEST_LENGTH_MISMATCH.

    Duplicate algorithms are impossible by CBOR map-key uniqueness (RFC 8949
    §3.1; canonical decode rejects duplicates as MALFORMED_CBOR upstream),
    so no duplicate-detection path exists here.
    """
    if not isinstance(alg, str) or alg not in HASH_ALGS:
        issues.append(_issue(path, "UNSUPPORTED_HASH_ALG", f"unknown hash alg: {alg!r}"))
        return
    if not isinstance(digest, (bytes, bytearray)):
        issues.append(
            _issue(path, "SCHEMA_TYPE_MISMATCH", f"hashes[{alg!r}] value must be CBOR bytes")
        )
        return
    expected = HASH_ALGS[alg]
    if len(digest) != expected:
        issues.append(
            _issue(
                path,
                "HASH_DIGEST_LENGTH_MISMATCH",
                f"hashes[{alg!r}] digest length {len(digest)} != {expected}",
            )
        )


def _validate_passphrase(passphrase: Any, path: list, issues: list) -> None:
    if not isinstance(passphrase, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "passphrase must be a map"))
        return
    _check_unknown_keys(passphrase, REGISTERED_PASSPHRASE_KEYS, path, issues, "passphrase")
    alg = passphrase.get("alg")
    # `enc.passphrase.alg` is an algorithm-registry field, so any value outside
    # `PASSPHRASE_ALGS` — non-string or unknown string alike — surfaces as
    # `ENC_PASSPHRASE_ALG_UNSUPPORTED`. The algorithm-agility invariant requires
    # the field-specific code for every registry miss; v1 exposes no closed-enum
    # field outside the algorithm registries.
    if not isinstance(alg, str) or alg not in PASSPHRASE_ALGS:
        issues.append(
            _issue(
                path + ["alg"],
                "ENC_PASSPHRASE_ALG_UNSUPPORTED",
                f"unknown passphrase alg: {alg!r}",
            )
        )
    salt = passphrase.get("salt")
    if not isinstance(salt, (bytes, bytearray)):
        issues.append(_issue(path + ["salt"], "SCHEMA_TYPE_MISMATCH", "salt must be bytes"))
    elif len(salt) < 16:
        issues.append(
            _issue(
                path + ["salt"],
                "ENC_PASSPHRASE_SALT_TOO_SHORT",
                f"passphrase.salt length {len(salt)} < 16",
            )
        )
    elif len(salt) > 64:
        issues.append(
            _issue(
                path + ["salt"],
                "ENC_PASSPHRASE_SALT_TOO_LONG",
                f"passphrase.salt length {len(salt)} > 64",
            )
        )
    params = passphrase.get("params")
    if not isinstance(params, dict):
        issues.append(_issue(path + ["params"], "SCHEMA_TYPE_MISMATCH", "params must be a map"))
        return
    if alg == "argon2id":
        # Closed params: { m: uint, t: uint, p: uint } — reject any extra keys.
        allowed_argon2 = {"m", "t", "p"}
        for k in params:
            if k not in allowed_argon2:
                issues.append(
                    _issue(
                        path + ["params", str(k)],
                        "SCHEMA_UNKNOWN_FIELD",
                        f"unknown argon2id params field: {k!r}",
                    )
                )

        # Each Argon2id param MUST be a CBOR unsigned integer; type-check first
        # so a float surfaces as SCHEMA_TYPE_MISMATCH instead of TOO_LOW.
        def _argon_int(val: Any, name: str) -> int | None:
            if not isinstance(val, int) or isinstance(val, bool):
                issues.append(
                    _issue(
                        path + ["params", name],
                        "SCHEMA_TYPE_MISMATCH",
                        f"argon2id params.{name} must be a CBOR unsigned integer",
                    )
                )
                return None
            return val

        m = _argon_int(params.get("m"), "m")
        t = _argon_int(params.get("t"), "t")
        p = _argon_int(params.get("p"), "p")
        if m is not None and m < 65_536:
            issues.append(
                _issue(
                    path + ["params", "m"],
                    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                    "argon2id requires m >= 65536 KiB",
                )
            )
        if t is not None and t < 3:
            issues.append(
                _issue(
                    path + ["params", "t"],
                    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                    "argon2id requires t >= 3",
                )
            )
        if p is not None and p < 1:
            issues.append(
                _issue(
                    path + ["params", "p"],
                    "ENC_PASSPHRASE_ARGON2_PARAMS_TOO_LOW",
                    "argon2id requires p >= 1",
                )
            )


def _validate_recipient_slot(slot: Any, path: list, issues: list) -> None:
    if not isinstance(slot, dict):
        issues.append(_issue(path, "ENC_SLOT_INVALID_SHAPE", "recipient slot must be a map"))
        return
    _check_unknown_keys(slot, REGISTERED_RECIPIENT_KEYS, path, issues, "recipient slot")

    epk = slot.get("epk")
    if epk is None:
        issues.append(
            _issue(path + ["epk"], "ENC_SLOT_INVALID_SHAPE", "recipient slot missing epk")
        )
    elif not isinstance(epk, (bytes, bytearray)):
        issues.append(
            _issue(path + ["epk"], "ENC_SLOT_INVALID_SHAPE", "recipient slot epk must be bytes")
        )
    elif len(epk) != 32:
        issues.append(
            _issue(path + ["epk"], "KEM_EPK_LENGTH_MISMATCH", f"epk length {len(epk)} != 32")
        )

    wrap = slot.get("wrap")
    if wrap is None:
        issues.append(
            _issue(path + ["wrap"], "ENC_SLOT_INVALID_SHAPE", "recipient slot missing wrap")
        )
    elif not isinstance(wrap, (bytes, bytearray)):
        issues.append(
            _issue(path + ["wrap"], "ENC_SLOT_INVALID_SHAPE", "recipient slot wrap must be bytes")
        )
    elif len(wrap) != 48:
        issues.append(
            _issue(path + ["wrap"], "WRAP_LENGTH_MISMATCH", f"wrap length {len(wrap)} != 48")
        )


def _validate_encryption(enc: Any, path: list, issues: list) -> None:
    if not isinstance(enc, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "enc must be a map"))
        return
    _check_unknown_keys(enc, REGISTERED_ENC_KEYS, path, issues, "enc")

    enc_scheme = enc.get("scheme")
    # enc.scheme MUST be the CBOR unsigned integer 1. Reject CBOR floats
    # explicitly: `1.0 == 1` evaluates True in Python, and a hand-crafted
    # record with `scheme` encoded as a CBOR float would otherwise be
    # silently accepted.
    if not isinstance(enc_scheme, int) or isinstance(enc_scheme, bool) or enc_scheme != 1:
        issues.append(
            _issue(
                path + ["scheme"],
                "UNSUPPORTED_ENVELOPE_SCHEME",
                f"enc.scheme must be the unsigned integer 1; got {enc_scheme!r}",
            )
        )

    aead = enc.get("aead")
    # `enc.aead` is an algorithm-registry field, so any value outside
    # `AEAD_NONCE_LENGTHS` — non-string or unknown string alike — surfaces as
    # `UNSUPPORTED_AEAD_ALG`. The one exception is the explicit deny rule for
    # unauthenticated ciphers matching `/aes-cbc/i`, which routes to
    # `UNAUTHENTICATED_CIPHER_FORBIDDEN` first. v1 exposes no closed-enum field
    # outside the algorithm registries.
    if not isinstance(aead, str):
        issues.append(
            _issue(path + ["aead"], "UNSUPPORTED_AEAD_ALG", f"unknown aead alg: {aead!r}")
        )
        return
    if "aes-cbc" in aead.lower():
        issues.append(
            _issue(
                path + ["aead"],
                "UNAUTHENTICATED_CIPHER_FORBIDDEN",
                "AES-CBC is unauthenticated; CIP-309 mandates an authenticated cipher",
            )
        )
        return
    if aead not in AEAD_NONCE_LENGTHS:
        issues.append(
            _issue(path + ["aead"], "UNSUPPORTED_AEAD_ALG", f"unknown aead alg: {aead!r}")
        )
        return

    # Envelope-level `kem` governs every entry in `slots[]`. The field is
    # required when the slots key-path is present; on the kdf key-path the field
    # has no role.
    has_kem = "kem" in enc
    if has_kem:
        kem = enc["kem"]
        # `enc.kem` is an algorithm-registry field; any value outside `KEM_ALGS`
        # — non-string or unknown string alike — surfaces as `UNSUPPORTED_KEM_ALG`.
        if not isinstance(kem, str) or kem not in KEM_ALGS:
            issues.append(
                _issue(path + ["kem"], "UNSUPPORTED_KEM_ALG", f"unknown kem alg: {kem!r}")
            )

    nonce = enc.get("nonce")
    if not isinstance(nonce, (bytes, bytearray)):
        issues.append(_issue(path + ["nonce"], "SCHEMA_TYPE_MISMATCH", "nonce must be bytes"))
    elif len(nonce) != AEAD_NONCE_LENGTHS[aead]:
        issues.append(
            _issue(
                path + ["nonce"],
                "NONCE_LENGTH_MISMATCH",
                f"nonce length {len(nonce)} != {AEAD_NONCE_LENGTHS[aead]} for {aead}",
            )
        )

    has_slots = "slots" in enc
    has_slots_mac = "slots_mac" in enc
    has_passphrase = "passphrase" in enc

    if has_slots:
        slots = enc["slots"]
        if not isinstance(slots, list):
            issues.append(
                _issue(path + ["slots"], "SCHEMA_TYPE_MISMATCH", "slots must be an array")
            )
        elif len(slots) < 1:
            issues.append(
                _issue(path + ["slots"], "ENC_SLOTS_EMPTY", "slots must be a non-empty array")
            )
        else:
            for i, slot in enumerate(slots):
                _validate_recipient_slot(slot, path + ["slots", i], issues)

    if has_slots_mac:
        slots_mac = enc["slots_mac"]
        if not isinstance(slots_mac, (bytes, bytearray)):
            issues.append(
                _issue(path + ["slots_mac"], "SCHEMA_TYPE_MISMATCH", "slots_mac must be bytes")
            )
        elif len(slots_mac) != 32:
            issues.append(
                _issue(
                    path + ["slots_mac"],
                    "ENC_SLOTS_MAC_INVALID_LENGTH",
                    f"slots_mac length {len(slots_mac)} != 32",
                )
            )

    if has_slots and has_passphrase:
        issues.append(
            _issue(
                path, "ENC_EXCLUSIVITY_VIOLATION", "enc combines slots with passphrase; pick one"
            )
        )
    if has_slots and not has_slots_mac:
        issues.append(
            _issue(path, "ENC_SLOTS_MAC_REQUIRED", "enc.slots present but enc.slots_mac absent")
        )
    if has_slots_mac and not has_slots:
        issues.append(
            _issue(path, "ENC_SLOTS_REQUIRED", "enc.slots_mac present but enc.slots absent")
        )
    if has_slots and not has_kem:
        issues.append(_issue(path, "ENC_KEM_REQUIRED", "enc.slots present but enc.kem absent"))
    if not has_slots and not has_passphrase:
        issues.append(
            _issue(
                path,
                "ENC_NO_KEY_PATH",
                "enc requires either slots or passphrase — no on-chain key path otherwise",
            )
        )

    if has_passphrase:
        _validate_passphrase(enc["passphrase"], path + ["passphrase"], issues)


def _validate_item_entry(item: Any, path: list, issues: list) -> None:
    if not isinstance(item, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "item entry must be a map"))
        return
    _check_unknown_keys(item, REGISTERED_ITEM_KEYS, path, issues, "item")
    hashes = item.get("hashes")
    # `hashes` is a non-empty CBOR map of <hash-alg-id> → <digest>. Non-map
    # values surface as SCHEMA_TYPE_MISMATCH. CBOR map-key uniqueness (RFC 8949
    # §3.1) guarantees one digest per algorithm — any duplicate is rejected at
    # canonical decode as MALFORMED_CBOR.
    if not isinstance(hashes, dict) or len(hashes) == 0:
        issues.append(
            _issue(
                path + ["hashes"],
                "SCHEMA_TYPE_MISMATCH",
                "hashes must be a non-empty CBOR map of <alg-id> → <digest>",
            )
        )
    else:
        for alg, digest in hashes.items():
            _validate_hash_map_entry(alg, digest, path + ["hashes", str(alg)], issues)
    item_has_enc = "enc" in item
    if "uris" in item:
        u = item["uris"]
        # `uris` is a non-empty array of chunked-tstr-arrays. Each entry is itself
        # a non-empty array of tstr chunks ≤ 64 bytes.
        if not isinstance(u, list) or len(u) == 0:
            issues.append(
                _issue(
                    path + ["uris"],
                    "SCHEMA_TYPE_MISMATCH",
                    "uris must be a non-empty array of chunked-tstr-arrays",
                )
            )
        else:
            for ui, chunks in enumerate(u):
                if not _is_chunked_tstr_shape(chunks):
                    issues.append(
                        _issue(
                            path + ["uris", ui],
                            "SCHEMA_TYPE_MISMATCH",
                            "each URI must be a non-empty array of tstr chunks (≤64B each)",
                        )
                    )
                    continue
                # Reconstruct and validate absoluteness / no-fragment / utf-8 continuity.
                reconstructed = "".join(chunks)
                if "#" in reconstructed:
                    issues.append(
                        _issue(
                            path + ["uris", ui],
                            "INVALID_URI",
                            "URI contains fragment identifier (`#`) — forbidden",
                        )
                    )
                if not re.match(r"^[a-z][a-z0-9+.\-]*://", reconstructed, re.IGNORECASE):
                    issues.append(
                        _issue(
                            path + ["uris", ui],
                            "INVALID_URI",
                            "URI is not absolute (missing scheme://hierarchical-part)",
                        )
                    )
                elif not re.match(r"^(ar|ipfs)://", reconstructed, re.IGNORECASE):
                    # The v1 PoE URI scheme set is exactly {ar://, ipfs://}.
                    # Producers MUST NOT emit other schemes; the structural
                    # validator is the primary line of defence, ahead of the
                    # verifier-side URI_TARGET_FORBIDDEN guard.
                    issues.append(
                        _issue(
                            path + ["uris", ui],
                            "INVALID_URI",
                            "unsupported URI scheme; v1 PoE URI set is {ar://, ipfs://}",
                        )
                    )
                else:
                    # Per-scheme shape rules.
                    if reconstructed.startswith("ar://"):
                        if not re.match(r"^ar://[A-Za-z0-9_-]{43}$", reconstructed):
                            issues.append(
                                _issue(
                                    path + ["uris", ui],
                                    "INVALID_URI",
                                    "ar:// URI does not match `^ar://[A-Za-z0-9_-]{43}$` "
                                    "(43-char base64url txid, no path/query/fragment)",
                                )
                            )
                    elif reconstructed.startswith("ipfs://"):
                        # Conformant validators MUST do full CID parsing (multibase
                        # → version → codec → multihash) rather than a regex shape
                        # check. Failure → INVALID_URI with reason `ipfs_cid_invalid`.
                        # A trailing `/path` suffix is permitted; the CID-shape
                        # check applies to the authority component before the
                        # first `/`.
                        rest = reconstructed[len("ipfs://") :]
                        cid = rest.split("/", 1)[0]
                        if not is_valid_cid(cid):
                            issues.append(
                                _issue(
                                    path + ["uris", ui],
                                    "INVALID_URI",
                                    "ipfs:// URI is not a valid CID (reason: ipfs_cid_invalid)",
                                )
                            )
                # A producer MUST NOT split a multi-byte UTF-8 codepoint across
                # chunks. No separate code is needed: the canonical-CBOR decoder
                # rejects any non-UTF-8 text string (MALFORMED_CBOR) before
                # reconstruction, and any concatenation that still fails to
                # decode as valid UTF-8 surfaces as INVALID_URI via the
                # absolute-URI / scheme checks above.
    # `uris` is OPTIONAL throughout the item map, including when `enc` is
    # present. The structural validator MUST NOT couple `enc` presence to `uris`
    # presence — a sealed record without a public retrieval URI is on-wire
    # valid; the recipient delivers the ciphertext bytes through an out-of-band
    # channel.
    if item_has_enc:
        # Content-hash pre-check: when `enc` is present, `item.hashes` MUST carry
        # at least one entry from CONTENT_HASH_ALGS (`sha2-256` or
        # `blake2b-256`). The check fires BEFORE any inner `enc`-shape validation
        # — the validator surfaces the most informative code first.
        if (
            isinstance(hashes, dict)
            and len(hashes) > 0
            and not any(alg in CONTENT_HASH_ALGS for alg in hashes)
        ):
            issues.append(
                _issue(
                    path + ["enc"],
                    "ENC_REQUIRES_CONTENT_HASH",
                    "item carries `enc` but `hashes` has no content-hash entry "
                    "(sha2-256 or blake2b-256)",
                )
            )
        else:
            _validate_encryption(item["enc"], path + ["enc"], issues)
    # Signatures attach at the record level only; a `cose_sign1` field on an
    # item entry is rejected via SCHEMA_UNKNOWN_FIELD by the closed-schema
    # check above.


def _validate_supersedes(s: Any, path: list, issues: list) -> None:
    if not isinstance(s, (bytes, bytearray)) or len(s) != 32:
        issues.append(
            _issue(
                path,
                "SUPERSEDES_TX_INVALID_LENGTH",
                "supersedes must be a 32-byte transaction hash",
            )
        )


def _validate_merkle_commit(commit: Any, path: list, issues: list) -> None:
    """Validate one `merkle[i]` list-commitment entry.

    Shape: { alg: tstr, root: bstr, leaf_count: uint, ? uris: [
    chunked-tstr-array ] }. The `alg` MUST be a registered key in
    `MERKLE_COMMIT_ALGS`; unknown identifiers emit `UNSUPPORTED_MERKLE_COMMIT_ALG`.
    The `root` digest length MUST match the algorithm's pinned size (32 B for
    `rfc9162-sha256`); mismatch emits `HASH_DIGEST_LENGTH_MISMATCH`. `leaf_count`
    is REQUIRED; the verifier-time cross-check against the off-chain leaves-list
    surfaces as `SCHEMA_MERKLE_LEAF_COUNT_MISMATCH`.
    """
    if not isinstance(commit, dict):
        issues.append(_issue(path, "SCHEMA_TYPE_MISMATCH", "merkle entry must be a map"))
        return
    _check_unknown_keys(commit, REGISTERED_MERKLE_COMMIT_KEYS, path, issues, "merkle entry")
    if "alg" not in commit:
        issues.append(
            _issue(path + ["alg"], "SCHEMA_MISSING_REQUIRED", "merkle entry missing required `alg`")
        )
        alg = None
    else:
        alg = commit["alg"]
        if not isinstance(alg, str):
            issues.append(
                _issue(
                    path + ["alg"],
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `alg` must be a text string",
                )
            )
            alg = None
        elif alg not in MERKLE_COMMIT_ALGS:
            issues.append(
                _issue(
                    path + ["alg"],
                    "UNSUPPORTED_MERKLE_COMMIT_ALG",
                    f"unknown merkle commitment alg: {alg!r}",
                )
            )
            alg = None
    if "root" not in commit:
        issues.append(
            _issue(
                path + ["root"], "SCHEMA_MISSING_REQUIRED", "merkle entry missing required `root`"
            )
        )
    else:
        root = commit["root"]
        if not isinstance(root, (bytes, bytearray)):
            issues.append(
                _issue(
                    path + ["root"],
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `root` must be CBOR bytes",
                )
            )
        elif alg is not None:
            expected = MERKLE_COMMIT_ALGS[alg]
            if len(root) != expected:
                issues.append(
                    _issue(
                        path + ["root"],
                        "HASH_DIGEST_LENGTH_MISMATCH",
                        f"merkle entry `root` length {len(root)} != {expected} for {alg}",
                    )
                )
    # `leaf_count` is REQUIRED. The structural shape check enforces presence +
    # type (uint); the value cross-check against the off-chain leaves-list is a
    # verifier-layer concern (`SCHEMA_MERKLE_LEAF_COUNT_MISMATCH`).
    if "leaf_count" not in commit:
        issues.append(
            _issue(
                path + ["leaf_count"],
                "SCHEMA_MISSING_REQUIRED",
                "merkle entry missing required `leaf_count`",
            )
        )
    else:
        leaf_count = commit["leaf_count"]
        if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or leaf_count < 0:
            issues.append(
                _issue(
                    path + ["leaf_count"],
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `leaf_count` must be a CBOR unsigned integer",
                )
            )
    if "uris" in commit:
        u = commit["uris"]
        if not isinstance(u, list) or len(u) == 0:
            issues.append(
                _issue(
                    path + ["uris"],
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle entry `uris` must be a non-empty array of chunked-tstr-arrays",
                )
            )
        else:
            for ui, chunks in enumerate(u):
                if not _is_chunked_tstr_shape(chunks):
                    issues.append(
                        _issue(
                            path + ["uris", ui],
                            "SCHEMA_TYPE_MISMATCH",
                            "each URI must be a non-empty array of tstr chunks (≤64B each)",
                        )
                    )
                else:
                    _validate_chunk_lengths(chunks, path + ["uris", ui], issues)


# === Public validator ===

# Set of extension keys the reference verifier explicitly implements. Producers
# MAY list extension keys in `crit: [+ tstr]` to mark them
# mandatory-to-understand; a verifier seeing any `crit` entry NOT in this set
# MUST emit `EXTENSION_UNSUPPORTED_CRITICAL` and MUST NOT report `valid: true`.
# The base verifier ships empty — every `x-*` / `<cip>-*` extension key is
# tolerated but not understood.
IMPLEMENTED_EXTENSIONS: frozenset[str] = frozenset()


def _check_record_top_level_keys(
    record: dict,
    issues: list,
    warnings: list,
) -> list[str]:
    """Top-level key gate with forward-compat extension-key tolerance.

    Unknown top-level keys matching `^x-.+` or `^[a-z]+-.+` are tolerated
    (info-severity surface); other unknown keys surface as
    `SCHEMA_UNKNOWN_FIELD`. Returns the list of recognised extension-key names
    so the caller can drive `crit` enforcement.
    """
    extensions: list[str] = []
    for k in record:
        if not isinstance(k, str):
            issues.append(
                _issue(
                    [str(k)], "SCHEMA_TYPE_MISMATCH", f"top-level key {k!r} must be a text string"
                )
            )
            continue
        if k in REGISTERED_RECORD_KEYS:
            continue
        if EXTENSION_KEY_REGEX.match(k):
            extensions.append(k)
            warnings.append(
                _issue(
                    [k],
                    "OUT_OF_PROFILE_SKIPPED",
                    f"top-level extension key {k!r} preserved but not interpreted by base verifier",
                )
            )
        else:
            issues.append(_issue([k], "SCHEMA_UNKNOWN_FIELD", f"unknown record field: {k!r}"))
    return extensions


def validate_poe_record(cbor_bytes: bytes) -> ValidationResult:
    """Validate a CIP-309 PoE record. Returns ValidationResult."""
    try:
        decoded = decode_canonical_cbor(cbor_bytes)
    except Exception as e:
        msg = str(e)
        # Duplicate-key violations are a subclass of `MALFORMED_CBOR`.
        return {"valid": False, "issues": [_issue([], "MALFORMED_CBOR", msg)]}

    issues: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []

    if not isinstance(decoded, dict):
        return {
            "valid": False,
            "issues": [_issue([], "SCHEMA_TYPE_MISMATCH", "top-level must be a CBOR map")],
        }

    # Top-level unknown-key check — closed base schema, open extension-key
    # namespace.
    _check_record_top_level_keys(decoded, issues, warnings)

    # Top-level required: v. Either `items` or `merkle` (non-empty) MUST be
    # present; both absent → SCHEMA_EMPTY_RECORD.
    if "v" not in decoded:
        issues.append(_issue(["v"], "SCHEMA_MISSING_REQUIRED", "v is required"))
    else:
        # v MUST be the CBOR unsigned integer 1. Float 1.0 satisfies `== 1` in
        # Python; reject it explicitly so a malformed record cannot pass via
        # major-type-7 float encoding.
        v_val = decoded["v"]
        if not isinstance(v_val, int) or isinstance(v_val, bool) or v_val != 1:
            issues.append(
                _issue(
                    ["v"],
                    "SCHEMA_INVALID_LITERAL",
                    f"v must be the unsigned integer 1; got {v_val!r}",
                )
            )

    has_items_key = "items" in decoded
    has_merkle_key = "merkle" in decoded

    # items priority rule:
    #   - `items` absent and `merkle` absent → SCHEMA_EMPTY_RECORD
    #   - `items: []` with no `merkle`       → EMPTY_RECORD
    if has_items_key:
        items = decoded["items"]
        if not isinstance(items, list):
            issues.append(_issue(["items"], "SCHEMA_TYPE_MISMATCH", "items must be an array"))
        elif len(items) == 0:
            issues.append(_issue(["items"], "EMPTY_RECORD", "items is present but empty"))
        else:
            for i, f in enumerate(items):
                _validate_item_entry(f, ["items", i], issues)

    # Optional top-level Merkle list commitments. Each entry of `merkle[]`
    # carries an `alg` from MERKLE_COMMIT_ALGS, the canonical root, and an
    # optional companion-URI chunked-tstr-array set.
    if has_merkle_key:
        merkle_arr = decoded["merkle"]
        if not isinstance(merkle_arr, list):
            issues.append(_issue(["merkle"], "SCHEMA_TYPE_MISMATCH", "merkle must be an array"))
        elif len(merkle_arr) == 0:
            issues.append(
                _issue(
                    ["merkle"],
                    "SCHEMA_TYPE_MISMATCH",
                    "merkle must be a non-empty array when present",
                )
            )
        else:
            for i, commit in enumerate(merkle_arr):
                _validate_merkle_commit(commit, ["merkle", i], issues)

    # Record-shape rule: at least one of `items` (non-empty) or `merkle`
    # (non-empty) MUST be present. A record carrying only `v: 1` is empty and
    # emits SCHEMA_EMPTY_RECORD.
    if not has_items_key and not has_merkle_key:
        issues.append(
            _issue(
                [],
                "SCHEMA_EMPTY_RECORD",
                "record carries neither `items` nor `merkle`; at least one MUST be present",
            )
        )

    # optional metadata
    if "supersedes" in decoded:
        _validate_supersedes(decoded["supersedes"], ["supersedes"], issues)
    # `crit` top-level enforcement. Producers MAY mark specified extensions as
    # mandatory-to-understand by listing them in a top-level `crit: [+ tstr]`
    # array.
    #
    # Three structural shape rules fire BEFORE the per-entry
    # `EXTENSION_UNSUPPORTED_CRITICAL` lookup, all surfacing as
    # `CRIT_SHAPE_INVALID`:
    #   (a) each entry MUST match the extension-key regex; base keys MUST NOT
    #       appear in `crit[]`;
    #   (b) each entry MUST be present as a key in the record map;
    #   (c) `crit[]` MUST NOT contain duplicate entries.
    # Producer-side bugs (typos, dangling refs, accidental repeats) are reported
    # here regardless of which extensions the verifier supports.
    #
    # A v1 verifier seeing any shape-valid `crit` entry it does NOT implement
    # MUST then emit `EXTENSION_UNSUPPORTED_CRITICAL` and MUST NOT report
    # `valid: true`.
    if "crit" in decoded:
        crit_arr = decoded["crit"]
        if not isinstance(crit_arr, list) or len(crit_arr) == 0:
            issues.append(
                _issue(
                    ["crit"],
                    "SCHEMA_TYPE_MISMATCH",
                    "crit must be a non-empty array of text strings",
                )
            )
        else:
            seen: set[str] = set()
            decoded_top_keys = set(decoded.keys()) if isinstance(decoded, dict) else set()
            for ci, name in enumerate(crit_arr):
                if not isinstance(name, str):
                    issues.append(
                        _issue(
                            ["crit", ci],
                            "SCHEMA_TYPE_MISMATCH",
                            f"crit[{ci}] must be a text string; got {type(name).__name__}",
                        )
                    )
                    continue
                reason: str | None = None
                if name in REGISTERED_RECORD_KEYS:
                    reason = f"{name!r} is a base key and MUST NOT appear in crit[]"
                elif not EXTENSION_KEY_REGEX.match(name):
                    reason = (
                        f"{name!r} does not match the extension-key regex (^x-.+ or ^[a-z]+-.+)"
                    )
                elif name not in decoded_top_keys:
                    reason = f"{name!r} is named in crit but absent from the record map"
                elif name in seen:
                    reason = f"{name!r} appears more than once in crit[]"
                seen.add(name)
                if reason is not None:
                    issues.append(_issue(["crit", ci], "CRIT_SHAPE_INVALID", reason))
                    continue
                if name not in IMPLEMENTED_EXTENSIONS:
                    issues.append(
                        _issue(
                            ["crit", ci],
                            "EXTENSION_UNSUPPORTED_CRITICAL",
                            f"crit entry {name!r} names an extension this verifier does not implement",
                        )
                    )
    if "sigs" in decoded:
        sigs = decoded["sigs"]
        if not isinstance(sigs, list):
            issues.append(_issue(["sigs"], "SCHEMA_TYPE_MISMATCH", "sigs must be an array"))
        elif len(sigs) < 1:
            issues.append(
                _issue(
                    ["sigs"], "SCHEMA_TYPE_MISMATCH", "sigs must be a non-empty array when present"
                )
            )
        else:
            for i, s in enumerate(sigs):
                # Each sigs[i] is a CLOSED CBOR map of shape
                # { "cose_sign1": chunked-bytes, ? "cose_key": chunked-bytes }.
                # Path 1 (in-signature kid) emits {"cose_sign1": ...}; Path 2
                # (CIP-30 wallet) emits {"cose_sign1": ..., "cose_key": ...}
                # carrying cbor<COSE_Key>.
                if not isinstance(s, dict):
                    issues.append(
                        _issue(
                            ["sigs", i],
                            "SIG_ENTRY_INVALID_SHAPE",
                            "each sigs entry must be a CBOR map { cose_sign1, cose_key? }",
                        )
                    )
                    continue
                # Required: "cose_sign1"
                if "cose_sign1" not in s:
                    issues.append(
                        _issue(
                            ["sigs", i],
                            "SIG_ENTRY_INVALID_SHAPE",
                            "sigs entry missing required 'cose_sign1' field",
                        )
                    )
                else:
                    sig_chunks = s["cose_sign1"]
                    if not _is_chunked_bytes_shape(sig_chunks):
                        issues.append(
                            _issue(
                                ["sigs", i, "cose_sign1"],
                                "SIG_ENTRY_INVALID_SHAPE",
                                "sigs[i].cose_sign1 must be a non-empty list of byte chunks (≤64B each)",
                            )
                        )
                    else:
                        _validate_chunk_lengths(sig_chunks, ["sigs", i, "cose_sign1"], issues)
                # Optional: "cose_key"
                if "cose_key" in s:
                    pubkey_chunks = s["cose_key"]
                    if not _is_chunked_bytes_shape(pubkey_chunks):
                        issues.append(
                            _issue(
                                ["sigs", i, "cose_key"],
                                "SIG_ENTRY_INVALID_SHAPE",
                                "sigs[i].cose_key must be a non-empty list of byte chunks (≤64B each)",
                            )
                        )
                    else:
                        _validate_chunk_lengths(pubkey_chunks, ["sigs", i, "cose_key"], issues)
                        # Decode the concatenated `cose_key` blob as
                        # `cbor<COSE_Key>` and apply two classes of structural
                        # check:
                        #
                        #   1. Private-material guard — reject any entry whose
                        #      decoded map carries a private-key material label
                        #      (label `-4` for OKP / EC2 per RFC 9052 §7.1, plus
                        #      future IANA-registered labels) with
                        #      `SIG_PRIVATE_KEY_LEAKED`.
                        #   2. Positive-shape guard — confirm the map is a
                        #      well-formed Ed25519 OKP public-key reference
                        #      (RFC 8152 §13.2): kty (label 1) = 1 (OKP), crv
                        #      (label -1) = 6 (Ed25519), and label -2 (Ed25519
                        #      public-key bytes) present as a 32-byte byte string.
                        #      Any failure → `MALFORMED_SIG_COSE_SIGN1`.
                        #
                        # The decode is cheap (a small CBOR map of a few dozen
                        # bytes) and is the last point where the validator can
                        # stop a private-key publication chain.
                        pubkey_joined = _join_chunks(pubkey_chunks)
                        try:
                            cose_key_decoded = cbor2.loads(pubkey_joined)
                        except Exception as e:
                            # Undecodable `cose_key` blob — surfaces as
                            # `MALFORMED_SIG_COSE_SIGN1`.
                            issues.append(
                                _issue(
                                    ["sigs", i, "cose_key"],
                                    "MALFORMED_SIG_COSE_SIGN1",
                                    f"sigs[{i}].cose_key failed to decode as cbor<COSE_Key>: {e}",
                                )
                            )
                            cose_key_decoded = None
                        if isinstance(cose_key_decoded, dict):
                            forbidden = [
                                k
                                for k in cose_key_decoded
                                if isinstance(k, int)
                                and not isinstance(k, bool)
                                and k in COSE_KEY_PRIVATE_MATERIAL_LABELS
                            ]
                            if forbidden:
                                issues.append(
                                    _issue(
                                        ["sigs", i, "cose_key"],
                                        "SIG_PRIVATE_KEY_LEAKED",
                                        "sigs[i].cose_key COSE_Key map carries private-key "
                                        f"material label(s) {sorted(forbidden)} "
                                        "(e.g. -4 = OKP/EC2 private scalar `d`, RFC 9052 §7.1); "
                                        "publishing a private key on the permanent ledger is forbidden",
                                    )
                                )
                            else:
                                # Positive-shape checks — only run when the
                                # private-material guard cleared, so the `-4`
                                # failure is not masked by shape noise.
                                kty = cose_key_decoded.get(1)
                                crv = cose_key_decoded.get(-1)
                                has_x = -2 in cose_key_decoded
                                x_val = cose_key_decoded.get(-2)
                                if kty != 1:
                                    issues.append(
                                        _issue(
                                            ["sigs", i, "cose_key"],
                                            "MALFORMED_SIG_COSE_SIGN1",
                                            f"sigs[{i}].cose_key COSE_Key kty (label 1) must be 1 (OKP); got {kty!r}",
                                        )
                                    )
                                elif crv != 6:
                                    issues.append(
                                        _issue(
                                            ["sigs", i, "cose_key"],
                                            "MALFORMED_SIG_COSE_SIGN1",
                                            f"sigs[{i}].cose_key COSE_Key crv (label -1) must be 6 (Ed25519); got {crv!r}",
                                        )
                                    )
                                elif not has_x:
                                    issues.append(
                                        _issue(
                                            ["sigs", i, "cose_key"],
                                            "MALFORMED_SIG_COSE_SIGN1",
                                            f"sigs[{i}].cose_key COSE_Key missing label -2 (Ed25519 public-key bytes)",
                                        )
                                    )
                                elif not isinstance(x_val, (bytes, bytearray)) or len(x_val) != 32:
                                    got = (
                                        f"{len(x_val)}-byte bstr"
                                        if isinstance(x_val, (bytes, bytearray))
                                        else type(x_val).__name__
                                    )
                                    issues.append(
                                        _issue(
                                            ["sigs", i, "cose_key"],
                                            "MALFORMED_SIG_COSE_SIGN1",
                                            f"sigs[{i}].cose_key COSE_Key label -2 must be a 32-byte byte string "
                                            f"(Ed25519 public key); got {got}",
                                        )
                                    )
                # Closed-schema check on sig-entry: any extra keys →
                # SCHEMA_UNKNOWN_FIELD. The sig-entry map does NOT participate in
                # the forward-compat extension-key namespace; the closed registry
                # is fixed at `{cose_sign1, cose_key}`.
                _check_unknown_keys(s, REGISTERED_SIG_ENTRY_KEYS, ["sigs", i], issues, "sig-entry")

    if issues:
        issues.sort(key=lambda i: ".".join(map(str, i["path"])))
        return {"valid": False, "issues": issues}

    # A single-entry `hashes` map is fully conformant; structural validators emit
    # no warning when only one entry is present. A single sound 256-bit digest
    # covers the archival threat model; the multi-hash pattern (sha2-256 +
    # blake2b-256) is OPTIONAL defence-in-depth, not required.

    # Domain-level: COSE_Sign1 structural check (no crypto verify)
    sig_issues: list[ValidationIssue] = []
    if isinstance(decoded.get("sigs"), list):
        for i, sig_entry in enumerate(decoded["sigs"]):
            # Skip entries that already failed schema-level shape checks above.
            if not isinstance(sig_entry, dict):
                continue
            sig_chunks = sig_entry.get("cose_sign1")
            if not _is_chunked_bytes_shape(sig_chunks):
                continue
            try:
                sig = _join_chunks(sig_chunks)
                cose = decode_cose_sign1(sig)
                payload = cose.get("payload")
                # Detached-only: payload field MUST be null. Any non-null payload,
                # including a zero-length byte string (`h''`), is forbidden.
                if payload is not None:
                    sig_issues.append(
                        _issue(
                            ["sigs", i],
                            "MALFORMED_SIG_COSE_SIGN1",
                            "COSE_Sign1 payload must be null (detached); attached form forbidden",
                        )
                    )
                    continue
                ph = cose.get("protected_header")
                alg = ph.get(1) if isinstance(ph, dict) else None
                if alg not in KNOWN_SIG_ALG_IDS:
                    # `SIGNATURE_UNSUPPORTED` is info-only: the content claim
                    # stands independently of which signature algorithms a
                    # verifier recognizes. Surfaced as a warning so consumers can
                    # react (e.g. fetch an updated alg table) without
                    # invalidating the record.
                    warnings.append(
                        _issue(
                            ["sigs", i],
                            "SIGNATURE_UNSUPPORTED",
                            f"alg {alg} not in KNOWN_SIG_ALG_IDS = {{-8}} (EdDSA)",
                        )
                    )
                # Path 1 / path 2 mutual exclusion at the wire level. If the
                # protected header carries a 32-byte `kid` (raw Ed25519 pubkey,
                # path 1) AND the parent sigs[i] map also carries an inline
                # `cose_key` (chunked cbor<COSE_Key>, path 2) → reject as
                # SIG_ENTRY_KID_COSE_KEY_CONFLICT. The check fires here, AFTER
                # COSE_Sign1 structural decode.
                kid = ph.get(4) if isinstance(ph, dict) else None
                if (
                    isinstance(kid, (bytes, bytearray))
                    and len(kid) == 32
                    and "cose_key" in sig_entry
                ):
                    sig_issues.append(
                        _issue(
                            ["sigs", i],
                            "SIG_ENTRY_KID_COSE_KEY_CONFLICT",
                            "sigs[i] carries both a 32-byte protected `kid` (path 1) "
                            "and an inline `cose_key` (path 2); paths are mutually exclusive",
                        )
                    )
            except Exception as e:
                sig_issues.append(_issue(["sigs", i], "MALFORMED_SIG_COSE_SIGN1", str(e)))

    # Signatures attach at the record level only; there is no per-item
    # `item.sig` verification loop. Multi-author content uses one PoE per author.

    if sig_issues:
        sig_issues.sort(key=lambda i: ".".join(map(str, i["path"])))
        return {"valid": False, "issues": sig_issues}

    result: ValidValidationResult = {"valid": True, "record": decoded}
    if warnings:
        result["warnings"] = warnings
    return result


# === Merkle leaves-list fetch+parse (verifier-layer helper) ==================


def parse_fetched_leaves_list(
    fetched_bytes: bytes,
    *,
    content_type: str | None = None,
) -> tuple[Any, list[ValidationIssue]]:
    """Parse a fetched leaves-list document, defaulting to CBOR.

    The on-storage byte-normative form of the leaves-list is canonical CBOR.
    Verifiers SHOULD parse CBOR; a verifier that encounters a JSON-encoded
    leaves-list MAY parse it as a fallback to support producers that have not
    migrated, but MUST emit `MERKLE_LEAVES_INFORMATIVE_FORM` (info-severity) to
    nudge producer migration.

    Returns `(decoded_leaves_list, issues_or_warnings)`. On success
    `decoded_leaves_list` is a `LeavesList` dataclass; on failure it is `None`
    and the second element carries the (single) error issue. The
    `MERKLE_LEAVES_INFORMATIVE_FORM` entry, when emitted, lives in the returned
    list at info-severity for the caller to merge into warnings.

    `content_type` is an optional hint (e.g. from an HTTP `Content-Type` header)
    used only to disambiguate when the byte sniff is inconclusive.
    """
    from .merkle_leaves_list import (
        MerkleLeavesListMalformed,
        SchemaMerkleLeavesFormatUnsupported,
        decode_leaves_list,
        from_json_projection,
    )

    informational: list[ValidationIssue] = []

    # Sniff: a CBOR canonical leaves-list starts with major-type-5 map header
    # (0xa0..0xbb). JSON starts with `{` (0x7b). The sniff order mirrors the
    # producer guidance: CBOR first, JSON only as fallback.
    looks_like_json = fetched_bytes[:1] == b"{" or (
        content_type is not None and "json" in content_type.lower()
    )

    if not looks_like_json:
        try:
            return decode_leaves_list(fetched_bytes), informational
        except SchemaMerkleLeavesFormatUnsupported as e:
            return None, [_issue([], "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED", str(e))]
        except (MerkleLeavesListMalformed, ValueError) as e:
            return None, [_issue([], "MALFORMED_CBOR", str(e))]

    # JSON fallback path — surface the informational warning so callers can
    # nudge producers to publish CBOR.
    informational.append(
        _issue(
            [],
            "MERKLE_LEAVES_INFORMATIVE_FORM",
            "fetched leaves-list is JSON; CBOR is the byte-normative wire form — "
            "producers SHOULD publish CBOR",
        )
    )
    try:
        return from_json_projection(fetched_bytes.decode("utf-8")), informational
    except SchemaMerkleLeavesFormatUnsupported as e:
        return None, informational + [_issue([], "SCHEMA_MERKLE_LEAVES_FORMAT_UNSUPPORTED", str(e))]
    except (MerkleLeavesListMalformed, UnicodeDecodeError) as e:
        return None, informational + [
            _issue([], "MALFORMED_CBOR", f"leaves-list JSON projection malformed: {e}")
        ]


# Verifier-layer code surfaced when a `sigs[i]` signer's identity cannot be
# resolved at verification time — neither a 32-byte protected `kid` (path 1) nor
# a successful directory lookup yields a public key. The structural validator
# does not resolve keys, so it is carried as an exported constant for verifier
# callers that import it.
SIGNER_KEY_UNRESOLVED: str = "SIGNER_KEY_UNRESOLVED"


def verify_merkle_leaf_count(
    on_chain_leaf_count: int,
    leaves_list_leaf_count: int,
    *,
    merkle_index: int = 0,
) -> ValidationIssue | None:
    """Cross-check the on-chain `merkle[i].leaf_count` against the off-chain
    leaves-list `leaf_count`. Emits `SCHEMA_MERKLE_LEAF_COUNT_MISMATCH`
    (verifier-layer) on disagreement.

    The dominant flow is verifier-time URI-fetch of the leaves-list; the
    structural validator can also call this helper when given inline leaves
    bytes (offline mode).
    """
    if on_chain_leaf_count == leaves_list_leaf_count:
        return None
    return _issue(
        ["merkle", merkle_index, "leaf_count"],
        "SCHEMA_MERKLE_LEAF_COUNT_MISMATCH",
        f"on-chain merkle[{merkle_index}].leaf_count "
        f"({on_chain_leaf_count}) does not match off-chain leaves-list "
        f"leaf_count ({leaves_list_leaf_count})",
    )
