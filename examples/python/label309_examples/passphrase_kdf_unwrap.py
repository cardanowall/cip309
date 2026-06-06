"""Passphrase-derived sealed-PoE wrap/unwrap — Python reference implementation.

Construction (passphrase path, scheme 1):
    CEK         <- Argon2id(normalize(passphrase), salt, m, t, p, hashLen=32)
    payload_key <- HKDF-SHA-256(ikm=CEK, salt=enc.nonce,
                                info=b"cardano-poe-payload-passphrase-v1", L=32)
    ad_content  <- canonicalCBOR({scheme, path:"passphrase", aead, nonce,
                                  passphrase:{alg, salt, params, normalization}})
    plaintext   <- XChaCha20-Poly1305_Decrypt(payload_key, nonce=enc.nonce,
                                               aad=ad_content, ciphertext)

The content is encrypted under a payload_key derived from the CEK, never under
the CEK directly. The content AAD binds the KDF parameters and the normalization
profile id; there is NO `kem` key on this path, and the normalization id is a
scheme-fixed AAD constant, never serialised on the wire.

Cross-language parity: byte-identical with the TypeScript reference
(passphrase-kdf-unwrap.ts) when fed the same inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import cbor2
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from .passphrase import normalize_passphrase

# Passphrase normalization profile identifier, pinned into the content AAD so the
# verifier proves the CEK was derived under exactly this profile; never on the
# wire.
PW_NORM_PROFILE = "cardano-poe-pw-norm-v1"
# HKDF info for the passphrase-path content payload_key.
INFO_PAYLOAD_PASSPHRASE_V1 = b"cardano-poe-payload-passphrase-v1"  # 33 ASCII bytes
# XChaCha20-Poly1305 single-shot bound (2^38 - 64 plaintext bytes; ciphertext + 16).
MAX_SEALED_PLAINTEXT = (1 << 38) - 64
_MAX_SEALED_CIPHERTEXT = MAX_SEALED_PLAINTEXT + 16

# Maximum raw passphrase length, in UTF-8 bytes, enforced BEFORE normalization and
# the Argon2id KDF. An oversized passphrase would otherwise drive unbounded NFKC /
# whitespace-collapse work and a large Argon2id input before any cost-bounded
# primitive runs; capping the raw input closes that pre-KDF DoS. The bound is byte
# length of the raw UTF-8 encoding, not code-point count, so a short string of
# wide multi-byte characters is still measured by its encoded size. 4096 bytes is
# far above any human-chosen passphrase. It is a verifier-enforced, deployment-
# pinned constant — not a wire field — and deployments MAY tighten it.
MAX_PASSPHRASE_INPUT_BYTES = 4096


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
    # Pre-KDF input cap: reject an oversized raw passphrase BEFORE normalization
    # or Argon2id, so it cannot drive unbounded pre-KDF work. Byte length of the
    # raw UTF-8 encoding, not code-point count.
    raw_passphrase_bytes = len(passphrase.encode("utf-8"))
    if raw_passphrase_bytes > MAX_PASSPHRASE_INPUT_BYTES:
        raise PassphraseUnwrapError(
            "KDF_DERIVATION_FAILED",
            f"passphrase length {raw_passphrase_bytes} bytes exceeds the maximum "
            f"{MAX_PASSPHRASE_INPUT_BYTES} bytes",
        )
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


def _passphrase_payload_key(cek: bytes, nonce: bytes) -> bytes:
    """Passphrase-path content key: HKDF-SHA-256(ikm=CEK, salt=nonce,
    info=payload-passphrase-v1)."""
    return HKDF(algorithm=SHA256(), length=32, salt=nonce, info=INFO_PAYLOAD_PASSPHRASE_V1).derive(
        cek
    )


def _ad_content_passphrase(nonce: bytes, passphrase_block: dict[str, Any]) -> bytes:
    """canonicalCBOR(AD_CONTENT_PASSPHRASE): the closed content-AEAD AAD for the
    passphrase path. It binds the passphrase KDF parameters into the content tag,
    so tampering with salt or any params value after encryption changes the AAD
    and the AEAD open fails. The normalization profile id is a scheme-fixed
    constant pinned into the AAD, never on the wire. There is NO `kem` key."""
    params = passphrase_block["params"]
    return cbor2.dumps(
        {
            "scheme": 1,
            "path": "passphrase",
            "aead": "xchacha20-poly1305",
            "nonce": nonce,
            "passphrase": {
                "alg": passphrase_block["alg"],
                "salt": passphrase_block["salt"],
                "params": {"m": params["m"], "t": params["t"], "p": params["p"]},
                "normalization": PW_NORM_PROFILE,
            },
        },
        canonical=True,
    )


# ----- Public API: passphrase-path unwrap -----


def ecies_passphrase_unwrap(
    *,
    envelope: PassphraseSealedEnvelope,
    ciphertext: bytes,
    passphrase: str,
) -> bytes:
    """Decrypt a sealed-PoE ciphertext whose `enc` carries `passphrase`.

    The content is opened under a payload_key derived from the Argon2id CEK, with
    a structured AAD that binds the KDF parameters and the normalization profile
    id (distinct from the sealed-recipient path's slots-bound AAD).

    Failure modes are surfaced as `PassphraseUnwrapError` with one of:
      - UNSUPPORTED_ENVELOPE_SCHEME / UNSUPPORTED_AEAD_ALG / ENC_PASSPHRASE_ALG_UNSUPPORTED
      - INVALID_ENVELOPE_SHAPE  (e.g. nonce wrong length)
      - KDF_DERIVATION_FAILED   (KDF rejected params at runtime)
      - PAYLOAD_TOO_LARGE       (ciphertext at/above the single-shot bound)
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
    if len(ciphertext) >= _MAX_SEALED_CIPHERTEXT:
        raise PassphraseUnwrapError(
            "PAYLOAD_TOO_LARGE",
            f"ciphertext length={len(ciphertext)} is at or above the single-shot bound",
        )

    cek = _derive_cek(envelope, passphrase)

    # Content is opened under a payload_key derived from the CEK, with the
    # structured passphrase-path AAD; the CEK never keys the content AEAD directly.
    payload_key = _passphrase_payload_key(cek, envelope.nonce)
    aad = _ad_content_passphrase(envelope.nonce, envelope.passphrase)
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, envelope.nonce, payload_key
        )
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
    `enc` envelope and the AEAD ciphertext. The content is encrypted under a
    payload_key derived from the CEK, with the structured passphrase-path AAD.

    `passphrase_block` is:
      {"alg": "argon2id", "salt": bytes, "params": {"m": int, "t": int, "p": int}}
    """
    if len(nonce) != 24:
        raise PassphraseUnwrapError("INVALID_ENVELOPE_SHAPE", "nonce MUST be 24 bytes")
    if len(plaintext) >= MAX_SEALED_PLAINTEXT:
        raise PassphraseUnwrapError(
            "PAYLOAD_TOO_LARGE",
            f"plaintext length={len(plaintext)} is at or above the single-shot bound",
        )

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
    payload_key = _passphrase_payload_key(cek, nonce)
    aad = _ad_content_passphrase(nonce, envelope.passphrase)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, payload_key)
    return PassphraseWrapOutput(envelope=envelope, ciphertext=ciphertext)


__all__ = [
    "MAX_PASSPHRASE_INPUT_BYTES",
    "PassphraseArgon2idEnvelope",
    "PassphraseSealedEnvelope",
    "PassphraseUnwrapError",
    "PassphraseWrapOutput",
    "ecies_passphrase_unwrap",
    "ecies_passphrase_wrap",
]
