# Label 309 v1 reference implementation — X25519 keygen + ECDH.
# Reference: RFC 7748. pyca/cryptography rejects an all-zero shared secret
# (low-order points) per RFC 7748 §6.1 internally.

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Returns (secret_key_32_bytes, public_key_32_bytes)."""
    priv = X25519PrivateKey.generate()
    return (
        priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
    )


def x25519_public_key(secret_key: bytes) -> bytes:
    if len(secret_key) != 32:
        raise ValueError("secret_key must be 32 bytes")
    priv = X25519PrivateKey.from_private_bytes(secret_key)
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def x25519_shared_secret(secret_key: bytes, their_public_key: bytes) -> bytes:
    if len(secret_key) != 32 or len(their_public_key) != 32:
        raise ValueError("keys must be 32 bytes")
    priv = X25519PrivateKey.from_private_bytes(secret_key)
    pub = X25519PublicKey.from_public_bytes(their_public_key)
    # pyca/cryptography raises on low-order points / all-zero shared (RFC 7748 §6.1).
    return priv.exchange(pub)
