"""Passphrase-derived sealed-PoE wrap/unwrap — Python reference implementation.

Construction (passphrase path):
    CEK         <- Argon2id(passphrase_NFKC_ws, salt, m, t, p, hashLen=32)
    plaintext   <- XChaCha20-Poly1305_Decrypt(CEK, nonce=enc.nonce, aad=b'',
                                                ciphertext)

AAD on the passphrase path is the EMPTY byte string per the AAD-selection rule.
This is distinct from the sealed-recipient (`slots`) path, which uses
`nonce || slots_mac` as its AAD.

Cross-language parity: byte-identical with the TypeScript reference
(passphrase-kdf-unwrap.ts) when fed the same inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from .passphrase import normalize_passphrase


class PassphraseUnwrapError(Exception):
    """Decryption error with a stable discriminator."""

    code: str

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class PassphraseArgon2idEnvelope:
    scheme: int  # MUST be 1
    aead: str  # MUST be "xchacha20-poly1305"
    nonce: bytes  # 24 B for XChaCha20-Poly1305
    # {"alg": "argon2id", "salt": bytes, "params": {"m": int, "t": int, "p": int}}
    passphrase: dict[str, Any]


# Type alias kept for API-surface clarity ("this is the sealed envelope on the
# passphrase path") and for forward-extensibility under the algorithm-agility
# registry: any additive passphrase-KDF identifier becomes a new dataclass and
# the alias widens to a Union — call sites that consume the alias do not change.
PassphraseSealedEnvelope = PassphraseArgon2idEnvelope


@dataclass(frozen=True)
class PassphraseWrapOutput:
    envelope: PassphraseSealedEnvelope
    ciphertext: bytes


# ----- CEK derivation -----


def _derive_cek_argon2id(passphrase_bytes: bytes, salt: bytes, params: dict[str, int]) -> bytes:
    try:
        return hash_secret_raw(
            secret=passphrase_bytes,
            salt=salt,
            time_cost=params["t"],
            memory_cost=params["m"],
            parallelism=params["p"],
            hash_len=32,
            type=Type.ID,
        )
    except Exception as e:
        raise PassphraseUnwrapError("KDF_DERIVATION_FAILED", str(e)) from e


def _derive_cek(envelope: PassphraseSealedEnvelope, passphrase: str) -> bytes:
    normalised = normalize_passphrase(passphrase)
    passphrase_bytes = normalised.encode("utf-8")
    alg = envelope.passphrase.get("alg")
    if alg == "argon2id":
        return _derive_cek_argon2id(
            passphrase_bytes,
            envelope.passphrase["salt"],
            envelope.passphrase["params"],
        )
    raise PassphraseUnwrapError(
        "ENC_PASSPHRASE_ALG_UNSUPPORTED", f"unknown passphrase alg: {alg!r}"
    )


# ----- Public API: passphrase-path unwrap -----


def ecies_passphrase_unwrap(
    *,
    envelope: PassphraseSealedEnvelope,
    ciphertext: bytes,
    passphrase: str,
) -> bytes:
    """Decrypt a sealed-PoE ciphertext whose `enc` carries `passphrase`.

    The passphrase path uses the EMPTY byte string as AEAD AAD (distinct from
    the sealed-recipient path's `nonce || slots_mac` AAD).

    Failure modes are surfaced as `PassphraseUnwrapError` with one of:
      - UNSUPPORTED_ENVELOPE_SCHEME / UNSUPPORTED_AEAD_ALG / ENC_PASSPHRASE_ALG_UNSUPPORTED
      - INVALID_ENVELOPE_SHAPE  (e.g. nonce wrong length)
      - KDF_DERIVATION_FAILED   (KDF rejected params at runtime)
      - TAMPERED_CIPHERTEXT     (AEAD tag verify failed; covers wrong passphrase)
    """
    if envelope.scheme != 1:
        raise PassphraseUnwrapError("UNSUPPORTED_ENVELOPE_SCHEME", f"enc.scheme={envelope.scheme}")
    if envelope.aead != "xchacha20-poly1305":
        raise PassphraseUnwrapError("UNSUPPORTED_AEAD_ALG", envelope.aead)
    if len(envelope.nonce) != 24:
        raise PassphraseUnwrapError("INVALID_ENVELOPE_SHAPE", "nonce length")
    if not envelope.passphrase:
        raise PassphraseUnwrapError("INVALID_ENVELOPE_SHAPE", "envelope has no passphrase block")

    cek = _derive_cek(envelope, passphrase)

    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, b"", envelope.nonce, cek)
    except Exception as e:
        raise PassphraseUnwrapError("TAMPERED_CIPHERTEXT", str(e)) from e


# ----- Public API: passphrase-path wrap (companion to unwrap) -----


def ecies_passphrase_wrap(
    *,
    plaintext: bytes,
    passphrase: str,
    passphrase_block: dict[str, Any],
    nonce: bytes,
) -> PassphraseWrapOutput:
    """Encrypt plaintext under a passphrase-derived CEK, producing the on-wire
    `enc` envelope and the AEAD ciphertext. AAD is the empty byte string.

    `passphrase_block` is:
      {"alg": "argon2id", "salt": bytes, "params": {"m": int, "t": int, "p": int}}
    """
    if len(nonce) != 24:
        raise PassphraseUnwrapError("INVALID_ENVELOPE_SHAPE", "nonce MUST be 24 bytes")

    if passphrase_block["alg"] == "argon2id":
        envelope: PassphraseSealedEnvelope = PassphraseArgon2idEnvelope(
            scheme=1,
            aead="xchacha20-poly1305",
            nonce=nonce,
            passphrase=dict(passphrase_block),
        )
    else:
        raise PassphraseUnwrapError(
            "ENC_PASSPHRASE_ALG_UNSUPPORTED",
            f"unknown passphrase alg: {passphrase_block['alg']!r}",
        )

    cek = _derive_cek(envelope, passphrase)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, b"", nonce, cek)
    return PassphraseWrapOutput(envelope=envelope, ciphertext=ciphertext)


__all__ = [
    "PassphraseArgon2idEnvelope",
    "PassphraseSealedEnvelope",
    "PassphraseUnwrapError",
    "PassphraseWrapOutput",
    "ecies_passphrase_unwrap",
    "ecies_passphrase_wrap",
]
