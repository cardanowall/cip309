# CIP-309 v1 reference implementation — SHA-256 + BLAKE2b-256 dual-hash.
#
# The two registered v1 content-hash algorithms. A single 256-bit digest is
# sufficient for the archival threat model; the dual-hash pattern is optional
# defence-in-depth.

import hashlib


def sha2_256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def dual_hash(data: bytes) -> dict[str, bytes]:
    return {
        "sha2-256": sha2_256(data),
        "blake2b-256": blake2b_256(data),
    }
