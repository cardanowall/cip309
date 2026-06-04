# Label 309 v1 reference implementation — Ed25519 sign / verify / keygen.
# Strict RFC 8032 verification (§5.1.7).
#
# Why PyNaCl (libsodium), not pyca/cryptography:
#   - pyca/cryptography's Ed25519PublicKey.verify uses the cofactored
#     verification equation, which accepts small-subgroup public keys — this is
#     NON-conformant with the strict RFC 8032 §5.1.7 verification rule Label 309
#     mandates.
#   - libsodium (and therefore PyNaCl) implements strict verification by
#     default: canonical R/S encoding, S < L, low-order public-key rejection.
#   - The TypeScript reference uses @noble/ed25519 with `{ zip215: false }`,
#     which is the same strict semantics. TS<->Python verdicts MUST agree on
#     every fixture, including the low-order-public-key differentiating vector.

import os

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Returns (secret_key_32_bytes, public_key_32_bytes)."""
    seed = os.urandom(32)  # RFC 8032 §5.1.5 step 1
    sk = SigningKey(seed)
    return (bytes(sk), bytes(sk.verify_key))


def sign_ed25519(message: bytes, secret_key: bytes) -> bytes:
    if len(secret_key) != 32:
        raise ValueError("secret_key must be 32 bytes (RFC 8032 §5.1.5)")
    # SignedMessage.signature is the 64-byte R || S per RFC 8032 §5.1.6.
    return SigningKey(secret_key).sign(message).signature


def verify_ed25519(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Strict RFC 8032 §5.1.7 verification (libsodium default).

    Returns False on any verification failure (bad sig, wrong key length,
    small-subgroup public key, non-canonical R/S encoding).
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except BadSignatureError:
        return False
