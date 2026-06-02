# CIP-309 v1 reference implementation — seed → Ed25519 + X25519 + X-Wing keypairs.
#
# Key derivation stops at the seed: how the 32-byte seed is stored and protected
# (passphrase vault, hardware key, etc.) is an implementation concern outside
# this standard. Given the seed, each keypair is derived deterministically with
# HKDF-SHA-256 under a fixed per-key info string:
#   "cardano-poe-ed25519-v1"        (22 bytes) → Ed25519 secret scalar
#   "cardano-poe-x25519-v1"         (21 bytes) → X25519 secret scalar
#   "cardano-poe-mlkem768x25519-v1" (29 bytes) → X-Wing root seed (PQ-hybrid key)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .hkdf import hkdf_sha256
from .mlkem768x25519 import mlkem768x25519_keygen
from .x25519 import x25519_public_key

ED25519_INFO = b"cardano-poe-ed25519-v1"  # 22 bytes
X25519_INFO = b"cardano-poe-x25519-v1"  # 21 bytes
MLKEM768X25519_INFO = b"cardano-poe-mlkem768x25519-v1"  # 29 bytes


def derive_ed25519_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    secret = hkdf_sha256(ikm=seed, info=ED25519_INFO, length=32)
    priv = Ed25519PrivateKey.from_private_bytes(secret)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return secret, pub


def derive_x25519_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    secret = hkdf_sha256(ikm=seed, info=X25519_INFO, length=32)
    return secret, x25519_public_key(secret)


def derive_mlkem768x25519_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Derive the X-Wing (ML-KEM-768 + X25519) recipient keypair.

    Returns ``(secret_seed, public_key)``. The 32-byte HKDF output IS the X-Wing
    root seed: key-gen re-expands the ML-KEM coins and the X25519 scalar from it
    via SHAKE-256, so ``secret_seed`` equals this HKDF value. ``public_key`` is
    the 1216-byte on-record hybrid recipient key (``mlkem768x25519_pub``), giving
    every identity the ability to RECEIVE post-quantum sealed records.
    """
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    xwing_seed = hkdf_sha256(ikm=seed, info=MLKEM768X25519_INFO, length=32)
    return mlkem768x25519_keygen(xwing_seed)
