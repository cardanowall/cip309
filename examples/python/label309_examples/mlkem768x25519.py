# Label 309 v1 reference implementation — X-Wing hybrid KEM (ML-KEM-768 + X25519).
# Construction: draft-connolly-cfrg-xwing-kem-06 / IACR ePrint 2024/039.
#
# X-Wing combines a post-quantum KEM (ML-KEM-768) with a classical one (X25519):
# an attacker must break BOTH to recover the shared secret, so the hybrid is no
# weaker than either part. The 32-byte combined secret is fed straight into the
# sealed-PoE per-slot KEK derivation, exactly where the classical X25519 ECDH
# output goes — only the KEK info label differs.
#
# Byte-equivalent with the TypeScript reference (mlkem768x25519.ts) for the same
# inputs. This module rebuilds the X-Wing combiner over kyber-py's ML-KEM-768
# internal primitives so the byte layout is fully explicit; ML-KEM is always
# FIRST, X25519 LAST.

from __future__ import annotations

import hashlib
import secrets
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from kyber_py.ml_kem import ML_KEM_768

# Wire lengths (bytes). ML-KEM-768 sizes are fixed by FIPS 203; X25519 by
# RFC 7748; the seed/secret-key and combiner label by the X-Wing draft.
SEED_LENGTH: Final[int] = 32
PUBLIC_KEY_LENGTH: Final[int] = 1216  # ML-KEM ek (1184) ‖ X25519 pub (32)
ENC_LENGTH: Final[int] = 1120  # ML-KEM ct (1088) ‖ X25519 eph (32)
SHARED_SECRET_LENGTH: Final[int] = 32
ESEED_LENGTH: Final[int] = 64  # 32 ML-KEM message ‖ 32 X25519 ephemeral seed

_MLKEM_EK_LENGTH: Final[int] = 1184
_MLKEM_CT_LENGTH: Final[int] = 1088
_MLKEM_MESSAGE_LENGTH: Final[int] = 32

# Seed expansion: SHAKE256(seed, 96) splits into ML-KEM keygen coins d||z (the
# first 64 bytes) and the X25519 secret scalar (the last 32 bytes). The X25519
# scalar is stored RAW — X25519 clamps internally at multiply time, so we must
# NOT pre-clamp here or we would diverge from the standard's vectors.
_EXPANDED_SEED_LENGTH: Final[int] = 96

# The combiner's domain-separation label: ASCII rb"\.//^\". Concatenated LAST
# into the SHA3-256 preimage, it binds the derived secret to the X-Wing
# construction so the same component secrets cannot be replayed in another KEM.
_COMBINER_LABEL: Final[bytes] = bytes.fromhex("5c2e2f2f5e5c")


class XWingLengthError(ValueError):
    """A public key, ciphertext, seed, or eseed had the wrong byte length."""


def _expand_seed(seed: bytes) -> tuple[bytes, bytes, bytes]:
    """Expand the 32-byte root seed into (ml_kem_d, ml_kem_z, x25519_scalar)."""
    expanded = hashlib.shake_256(seed).digest(_EXPANDED_SEED_LENGTH)
    return expanded[0:32], expanded[32:64], expanded[64:96]


def _x25519_public_key(secret_scalar: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(secret_scalar)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _x25519_ecdh(secret_scalar: bytes, peer_public_key: bytes) -> bytes:
    # Unlike a bare X25519 KEM, X-Wing must NOT reject small-order peer points:
    # the combiner mixes ss_X with the PQ secret ss_M, and a degenerate
    # (all-zero) ss_X still yields a defined hybrid secret. The draft's security
    # argument and the interoperability vectors both depend on this raw,
    # non-rejecting behaviour.
    priv = X25519PrivateKey.from_private_bytes(secret_scalar)
    pub = X25519PublicKey.from_public_bytes(peer_public_key)
    return priv.exchange(pub)


def _combine(ss_mlkem: bytes, ss_x25519: bytes, ct_x25519: bytes, pk_x25519: bytes) -> bytes:
    """X-Wing shared-secret combiner: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)."""
    return hashlib.sha3_256(ss_mlkem + ss_x25519 + ct_x25519 + pk_x25519 + _COMBINER_LABEL).digest()


def mlkem768x25519_keygen(seed: bytes) -> tuple[bytes, bytes]:
    """Derive an X-Wing keypair from a 32-byte root seed.

    Returns ``(secret_seed, public_key)``: ``public_key`` is 1216 bytes
    (ML-KEM-768 encapsulation key ‖ X25519 public key) and ``secret_seed`` is
    the 32-byte root seed itself — the draft-06 secret key IS the seed; the
    secret material is re-expanded on demand during decapsulation.
    """
    if len(seed) != SEED_LENGTH:
        raise XWingLengthError(f"seed must be {SEED_LENGTH} bytes, got {len(seed)}")

    d, z, x_scalar = _expand_seed(seed)
    ek_mlkem, _dk_mlkem = ML_KEM_768._keygen_internal(d, z)
    pk_x25519 = _x25519_public_key(x_scalar)

    public_key = ek_mlkem + pk_x25519
    if len(public_key) != PUBLIC_KEY_LENGTH:
        raise XWingLengthError(
            f"derived public key is {len(public_key)} bytes, expected {PUBLIC_KEY_LENGTH}"
        )
    return seed, public_key


def mlkem768x25519_encapsulate(
    public_key: bytes, eseed: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encapsulate to an X-Wing public key.

    Returns ``(enc, shared_secret)``: ``enc`` is 1120 bytes (ML-KEM-768
    ciphertext ‖ X25519 ephemeral public key) and ``shared_secret`` is 32 bytes.
    ``eseed`` is the 64-byte encapsulation randomness (ML-KEM message ‖ X25519
    ephemeral scalar); supply it for byte-deterministic vectors, omit it in
    production so a fresh value is drawn.
    """
    if len(public_key) != PUBLIC_KEY_LENGTH:
        raise XWingLengthError(
            f"public key must be {PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}"
        )
    if eseed is None:
        eseed = secrets.token_bytes(ESEED_LENGTH)
    elif len(eseed) != ESEED_LENGTH:
        raise XWingLengthError(f"eseed must be {ESEED_LENGTH} bytes, got {len(eseed)}")

    ek_mlkem = public_key[:_MLKEM_EK_LENGTH]
    pk_x25519 = public_key[_MLKEM_EK_LENGTH:]
    mlkem_message = eseed[:_MLKEM_MESSAGE_LENGTH]
    x_ephemeral_scalar = eseed[_MLKEM_MESSAGE_LENGTH:]

    ss_mlkem, ct_mlkem = ML_KEM_768._encaps_internal(ek_mlkem, mlkem_message)
    ct_x25519 = _x25519_public_key(x_ephemeral_scalar)
    ss_x25519 = _x25519_ecdh(x_ephemeral_scalar, pk_x25519)

    enc = ct_mlkem + ct_x25519
    if len(enc) != ENC_LENGTH:
        raise XWingLengthError(f"enc is {len(enc)} bytes, expected {ENC_LENGTH}")

    shared_secret = _combine(ss_mlkem, ss_x25519, ct_x25519, pk_x25519)
    return enc, shared_secret


def mlkem768x25519_decapsulate(secret_seed: bytes, enc: bytes) -> bytes:
    """Decapsulate an X-Wing ciphertext, returning the 32-byte shared secret.

    Constant work: ML-KEM-768 implicit rejection means a corrupted ciphertext
    yields a pseudorandom (but deterministic) secret rather than an error, so
    this NEVER raises on bad ciphertext content — a wrong shared secret is the
    correct, indistinguishable failure mode (the per-slot ``wrap`` AEAD then
    rejects). It raises only on a structurally wrong-length ``secret_seed`` or
    ``enc`` (caller misuse).
    """
    if len(secret_seed) != SEED_LENGTH:
        raise XWingLengthError(f"secret seed must be {SEED_LENGTH} bytes, got {len(secret_seed)}")
    if len(enc) != ENC_LENGTH:
        raise XWingLengthError(f"enc must be {ENC_LENGTH} bytes, got {len(enc)}")

    d, z, x_scalar = _expand_seed(secret_seed)
    _ek_mlkem, dk_mlkem = ML_KEM_768._keygen_internal(d, z)
    pk_x25519 = _x25519_public_key(x_scalar)

    ct_mlkem = enc[:_MLKEM_CT_LENGTH]
    ct_x25519 = enc[_MLKEM_CT_LENGTH:]

    ss_mlkem = ML_KEM_768._decaps_internal(dk_mlkem, ct_mlkem)
    ss_x25519 = _x25519_ecdh(x_scalar, ct_x25519)

    return _combine(ss_mlkem, ss_x25519, ct_x25519, pk_x25519)


__all__ = [
    "ENC_LENGTH",
    "ESEED_LENGTH",
    "PUBLIC_KEY_LENGTH",
    "SEED_LENGTH",
    "SHARED_SECRET_LENGTH",
    "XWingLengthError",
    "mlkem768x25519_decapsulate",
    "mlkem768x25519_encapsulate",
    "mlkem768x25519_keygen",
]
