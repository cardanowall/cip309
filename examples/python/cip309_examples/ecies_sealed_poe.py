"""Multi-recipient sealed-PoE — Python reference implementation.

Two KEM branches share ONE envelope shape, discriminated on the envelope-level
`kem` field:

  * kem="x25519"         — classical age-style ECIES. Per-slot {epk(32), wrap(48)}.
  * kem="mlkem768x25519" — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot the
                           1120-byte X-Wing enc carried as a chunked byte-string
                           array (`kem_ct`) + wrap(48). NO per-slot epk.

Construction summary (one or more recipients):
  - One file-key CEK (32 random bytes).
  - For each recipient i — classical (x25519):
      priv_eph_i  <- randomBytes(32)
      shared_i    <- X25519(priv_eph_i, pub_R_i)
      KEK_i       <- HKDF-SHA-256(ikm=shared_i, salt=pub_eph_i||pub_R_i,
                                   info=b"cardano-poe-kek-v1", L=32)
      wrap_i      <- ChaCha20-Poly1305(KEK_i, nonce=zeros(12),
                                       aad=b"cardano-poe-kek-v1", CEK)
      slot_i      = {epk: pub_eph_i, wrap: wrap_i}
  - For each recipient i — hybrid (mlkem768x25519):
      (enc_i, shared_i) <- X-Wing.Encapsulate(pub_R_i; eseed_i)  # enc=1120B, ss=32B
      KEK_i       <- HKDF-SHA-256(ikm=shared_i, salt=b"",
                                   info=b"cardano-poe-kek-mlkem768x25519-v1", L=32)
      wrap_i      <- ChaCha20-Poly1305(KEK_i, nonce=zeros(12),
                                       aad=b"cardano-poe-kek-mlkem768x25519-v1", CEK)
      slot_i      = {kem_ct: chunk64(enc_i), wrap: wrap_i}
  - CSPRNG-shuffle the slot array.
  - Bind the slot set to CEK:
      HMAC_KEY    <- HKDF-SHA-256(CEK, salt=b"", info=b"cardano-poe-slots-mac-v1", L=32)
      slots_mac   <- HMAC-SHA-256(HMAC_KEY, canonicalCBOR(slots))
  - Encrypt content under CEK:
      nonce       <- randomBytes(24)
      ad_content  <- nonce || slots_mac
      ciphertext  <- XChaCha20-Poly1305(CEK, nonce, ad=ad_content, plaintext)

Everything outside the per-slot KEM — the content AEAD, slots_mac, AAD layout,
and the CSPRNG shuffle — is byte-identical across the two KEMs.

Cross-language parity: byte-identical with the TypeScript reference
(ecies-sealed-poe.ts) when fed the same inputs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from .mlkem768x25519 import (
    ENC_LENGTH as MLKEM768X25519_ENC_LENGTH,
)
from .mlkem768x25519 import (
    ESEED_LENGTH as MLKEM768X25519_ESEED_LENGTH,
)
from .mlkem768x25519 import (
    PUBLIC_KEY_LENGTH as MLKEM768X25519_PUBLIC_KEY_LENGTH,
)
from .mlkem768x25519 import (
    SEED_LENGTH as MLKEM768X25519_SEED_LENGTH,
)
from .mlkem768x25519 import (
    mlkem768x25519_decapsulate,
    mlkem768x25519_encapsulate,
)

# ----- Constants -----
INFO_KEK_V1: bytes = b"cardano-poe-kek-v1"  # 18 ASCII bytes
# Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a KEK
# derived under one KEM can never collide with the other. Reused verbatim as the
# per-slot wrap AEAD AAD, exactly as the classical path reuses its own label.
INFO_KEK_MLKEM768X25519_V1: bytes = b"cardano-poe-kek-mlkem768x25519-v1"  # 33 bytes
INFO_SLOTS_MAC_V1: bytes = b"cardano-poe-slots-mac-v1"  # 24 ASCII bytes
ZERO_NONCE_12: bytes = b"\x00" * 12

# Cardano ledger CDDL caps every transaction_metadatum byte string at 64 bytes,
# so the 1120-byte X-Wing `enc` is carried as an array of <=64-byte chunks
# (`kem_ct`). Identical split rule to the chunked-COSE byte encoding.
_CHUNK_MAX_BYTES = 64


def chunk_kem_ct(value: bytes) -> list[bytes]:
    """Split a logical byte string into <=64-byte chunks (X-Wing enc → kem_ct)."""
    if len(value) == 0:
        raise ValueError("chunk_kem_ct: refusing to chunk an empty byte string")
    return [value[i : i + _CHUNK_MAX_BYTES] for i in range(0, len(value), _CHUNK_MAX_BYTES)]


def join_kem_ct(chunks: Sequence[bytes]) -> bytes:
    """Inverse of chunk_kem_ct: concatenate the chunked kem_ct back to flat enc."""
    return b"".join(chunks)


class SealedPoeDecryptError(Exception):
    """Decryption error with a stable discriminator."""

    code: str

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class SealedSlot:
    """Classical per-slot wire shape: {epk: bstr(32), wrap: bstr(48)}."""

    epk: bytes
    wrap: bytes


@dataclass(frozen=True)
class MlKem768X25519Slot:
    """Hybrid per-slot wire shape: {kem_ct: [bstr .size (1..64), ...], wrap: bstr(48)}.

    The 1120-byte X-Wing enc is carried as `kem_ct`; there is NO per-slot epk.
    The X25519 ephemeral lives inside the trailing 32 bytes of the reassembled
    kem_ct.
    """

    kem_ct: tuple[bytes, ...]
    wrap: bytes


@dataclass(frozen=True)
class SealedEnvelope:
    scheme: int  # MUST be 1
    aead: str
    kem: str  # KEM identifier governing every slot in `slots[]`
    nonce: bytes
    # Wire field name: `slots` — recipient pubkeys are NOT on-wire; the array
    # carries opaque wrapped-CEK slots that recipients trial-decrypt with their
    # own private keys. User-facing API parameters (`recipient_public_keys`,
    # `recipient_secret_key`) keep the "recipient" terminology because those
    # describe identities, not slots. The slot type is KEM-specific: SealedSlot
    # for x25519, MlKem768X25519Slot for mlkem768x25519.
    slots: tuple[SealedSlot, ...] | tuple[MlKem768X25519Slot, ...]
    slots_mac: bytes


@dataclass(frozen=True)
class SealedPoeOutput:
    envelope: SealedEnvelope
    ciphertext: bytes


def _hkdf32(ikm: bytes, info: bytes, salt: bytes = b"") -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _x25519_public(priv: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(priv)
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _x25519_shared(priv: bytes, pub: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(priv)
    pk = X25519PublicKey.from_public_bytes(pub)
    return sk.exchange(pk)


def _slots_to_cbor_input(
    slots: Sequence[SealedSlot] | Sequence[MlKem768X25519Slot], kem: str
) -> bytes:
    """Encode the slot set as canonical CBOR for slots_mac input. KEM-driven so
    the hybrid kem_ct is committed by the MAC exactly as it appears on the wire:

      * x25519:         each slot → {epk: bstr, wrap: bstr}
      * mlkem768x25519: each slot → {kem_ct: [bstr, ...], wrap: bstr}

    The HMAC-SHA-256 input is `canonical_cbor(slots)` — independent of whether
    the local variable at the call site is named `slots` or `recipients`.
    """
    if kem == "x25519":
        return cbor2.dumps(
            [{"epk": s.epk, "wrap": s.wrap} for s in slots],  # type: ignore[union-attr]
            canonical=True,
        )
    return cbor2.dumps(
        [{"kem_ct": list(s.kem_ct), "wrap": s.wrap} for s in slots],  # type: ignore[union-attr]
        canonical=True,
    )


def _shuffle_in_place(slots: list) -> list:
    """Fisher-Yates CSPRNG shuffle (security-critical — prevents ordering leak)."""
    out = list(slots)
    for i in range(len(out) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def ecies_sealed_poe_wrap(
    *,
    plaintext: bytes,
    recipient_public_keys: Sequence[bytes],
    # KEM branch selector. Defaults to "x25519" (the classical path). Recipient
    # public-key length is validated against the chosen KEM.
    kem: str = "x25519",
    # Test-only deterministic overrides — production callers MUST NOT pass these.
    cek: bytes | None = None,
    nonce: bytes | None = None,
    # X25519 ephemeral scalars (32 B each) — x25519 branch only.
    ephemeral_secrets: Sequence[bytes] | None = None,
    # X-Wing encapsulation randomness (64 B each) — hybrid branch only.
    eseeds: Sequence[bytes] | None = None,
    skip_shuffle: bool = False,
) -> SealedPoeOutput:
    if kem not in ("x25519", "mlkem768x25519"):
        raise ValueError(f"unsupported kem={kem!r}")
    n = len(recipient_public_keys)
    if n < 1:
        raise ValueError("recipient_public_keys must contain at least one entry")
    expected_pub_len = 32 if kem == "x25519" else MLKEM768X25519_PUBLIC_KEY_LENGTH
    for pub in recipient_public_keys:
        if len(pub) != expected_pub_len:
            raise ValueError(
                f"each recipient public key MUST be exactly {expected_pub_len} bytes for kem={kem!r}"
            )

    if kem == "x25519":
        if eseeds is not None:
            raise ValueError(
                "eseeds is an mlkem768x25519 override; do not pass it for kem='x25519'"
            )
        if ephemeral_secrets is not None and len(ephemeral_secrets) != n:
            raise ValueError("ephemeral_secrets length must match recipient_public_keys")
    else:
        if ephemeral_secrets is not None:
            raise ValueError(
                "ephemeral_secrets is an x25519 override; do not pass it for kem='mlkem768x25519'"
            )
        if eseeds is not None:
            if len(eseeds) != n:
                raise ValueError("eseeds length must match recipient_public_keys")
            for i, e in enumerate(eseeds):
                if len(e) != MLKEM768X25519_ESEED_LENGTH:
                    raise ValueError(f"eseeds[{i}] MUST be {MLKEM768X25519_ESEED_LENGTH} bytes")

    cek = cek if cek is not None else secrets.token_bytes(32)
    nonce = nonce if nonce is not None else secrets.token_bytes(24)
    if len(cek) != 32:
        raise ValueError("CEK MUST be 32 bytes")
    if len(nonce) != 24:
        raise ValueError("nonce MUST be 24 bytes (XChaCha20-Poly1305 nonce)")

    slots: list[SealedSlot] | list[MlKem768X25519Slot]
    if kem == "x25519":
        x_slots: list[SealedSlot] = []
        for i, pub_r in enumerate(recipient_public_keys):
            priv_eph = (
                ephemeral_secrets[i] if ephemeral_secrets is not None else secrets.token_bytes(32)
            )
            if len(priv_eph) != 32:
                raise ValueError(f"ephemeral_secrets[{i}] MUST be 32 bytes")
            epk = _x25519_public(priv_eph)
            shared = _x25519_shared(priv_eph, pub_r)
            kek = _hkdf32(shared, INFO_KEK_V1, salt=epk + pub_r)
            wrap = ChaCha20Poly1305(kek).encrypt(ZERO_NONCE_12, cek, INFO_KEK_V1)
            assert len(wrap) == 48
            x_slots.append(SealedSlot(epk=epk, wrap=wrap))
        if not skip_shuffle:
            x_slots = _shuffle_in_place(x_slots)
        slots = x_slots
    else:
        h_slots: list[MlKem768X25519Slot] = []
        for i, pub_r in enumerate(recipient_public_keys):
            eseed = eseeds[i] if eseeds is not None else None
            kem_ct, shared = mlkem768x25519_encapsulate(pub_r, eseed)
            assert len(kem_ct) == MLKEM768X25519_ENC_LENGTH
            # Empty salt: the X-Wing combiner already binds the transcript.
            kek = _hkdf32(shared, INFO_KEK_MLKEM768X25519_V1)
            wrap = ChaCha20Poly1305(kek).encrypt(ZERO_NONCE_12, cek, INFO_KEK_MLKEM768X25519_V1)
            assert len(wrap) == 48
            h_slots.append(MlKem768X25519Slot(kem_ct=tuple(chunk_kem_ct(kem_ct)), wrap=wrap))
        if not skip_shuffle:
            h_slots = _shuffle_in_place(h_slots)
        slots = h_slots

    # Slot-set MAC binds the slot set to this CEK (KEM-driven slot CBOR).
    hmac_key = _hkdf32(cek, INFO_SLOTS_MAC_V1)
    slots_cbor = _slots_to_cbor_input(slots, kem)
    slots_mac = hmac.new(hmac_key, slots_cbor, hashlib.sha256).digest()

    # Content layer. AAD = nonce || slots_mac (24 + 32 = 56 bytes). KEM-independent.
    aad_content = nonce + slots_mac
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad_content, nonce, cek)

    return SealedPoeOutput(
        envelope=SealedEnvelope(
            scheme=1,
            aead="xchacha20-poly1305",
            kem=kem,
            nonce=nonce,
            slots=cast("tuple[SealedSlot, ...] | tuple[MlKem768X25519Slot, ...]", tuple(slots)),
            slots_mac=slots_mac,
        ),
        ciphertext=ciphertext,
    )


def _try_open_x25519_slot(slot: SealedSlot, priv_r: bytes, pub_r_local: bytes) -> bytes | None:
    """Open one classical slot; return the candidate CEK or None on a non-match
    (low-order epk rejection / AEAD failure)."""
    if len(slot.epk) != 32 or len(slot.wrap) != 48:
        return None
    try:
        shared = _x25519_shared(priv_r, slot.epk)
    except Exception:
        return None  # low-order epk (RFC 7748 §6.1 contributory-check rejection)
    kek = _hkdf32(shared, INFO_KEK_V1, salt=slot.epk + pub_r_local)
    try:
        return ChaCha20Poly1305(kek).decrypt(ZERO_NONCE_12, slot.wrap, INFO_KEK_V1)
    except Exception:
        return None


def _try_open_mlkem768x25519_slot(slot: MlKem768X25519Slot, secret_seed: bytes) -> bytes | None:
    """Open one hybrid slot. X-Wing decapsulate NEVER raises on attacker wire
    data (ML-KEM implicit rejection yields a pseudorandom shared secret), so a
    wrong seed simply produces a KEK whose AEAD tag fails — returned as a
    non-match. `slot.kem_ct` MUST already have been length-checked."""
    if len(slot.wrap) != 48:
        return None
    shared = mlkem768x25519_decapsulate(secret_seed, join_kem_ct(slot.kem_ct))
    # Empty salt: the X-Wing combiner already binds the transcript.
    kek = _hkdf32(shared, INFO_KEK_MLKEM768X25519_V1)
    try:
        return ChaCha20Poly1305(kek).decrypt(ZERO_NONCE_12, slot.wrap, INFO_KEK_MLKEM768X25519_V1)
    except Exception:
        return None


def ecies_sealed_poe_unwrap(
    *,
    envelope: SealedEnvelope,
    ciphertext: bytes,
    recipient_secret_key: bytes,
) -> bytes:
    """Trial-decrypt. Raises SealedPoeDecryptError on any failure.

    For kem="x25519" `recipient_secret_key` is the 32-byte X25519 private key;
    for kem="mlkem768x25519" it is the 32-byte X-Wing secret seed. Both are 32
    bytes; which applies is selected from `envelope.kem`.
    """
    if envelope.scheme != 1:
        raise SealedPoeDecryptError("UNSUPPORTED_ENVELOPE_SCHEME", f"enc.scheme={envelope.scheme}")
    if envelope.aead != "xchacha20-poly1305":
        raise SealedPoeDecryptError("UNSUPPORTED_AEAD_ALG", envelope.aead)
    if envelope.kem not in ("x25519", "mlkem768x25519"):
        raise SealedPoeDecryptError("UNSUPPORTED_KEM_ALG", envelope.kem)
    if len(envelope.nonce) != 24:
        raise SealedPoeDecryptError("INVALID_ENVELOPE_SHAPE", "nonce length")
    if len(envelope.slots_mac) != 32:
        raise SealedPoeDecryptError("INVALID_ENVELOPE_SHAPE", "slots_mac length")
    if len(envelope.slots) < 1:
        raise SealedPoeDecryptError("ENC_SLOTS_EMPTY", str(len(envelope.slots)))
    # Both branches use a 32-byte recipient secret (X25519 private key / X-Wing seed).
    if len(recipient_secret_key) != MLKEM768X25519_SEED_LENGTH:
        raise SealedPoeDecryptError("INVALID_RECIPIENT_KEY", "recipient secret length")

    # Partitioning-oracle defence (hybrid): every kem_ct MUST reassemble to the
    # exact X-Wing enc length BEFORE any decapsulation.
    if envelope.kem == "mlkem768x25519":
        for slot in envelope.slots:
            if len(join_kem_ct(slot.kem_ct)) != MLKEM768X25519_ENC_LENGTH:  # type: ignore[union-attr]
                raise SealedPoeDecryptError("KEM_CT_LENGTH_MISMATCH", "kem_ct reassembled length")

    # Pre-compute slots_mac inputs once (constant across slots), KEM-driven.
    slots_cbor = _slots_to_cbor_input(envelope.slots, envelope.kem)
    # X25519 recipient public key, needed only by the classical salt.
    pub_r_local = _x25519_public(recipient_secret_key) if envelope.kem == "x25519" else b""

    # Distinguish "no slot ever opened under the recipient secret"
    # (WRONG_RECIPIENT_KEY) from "some slot opened but no opened slot's CEK
    # satisfies slots_mac" (TAMPERED_HEADER). A malicious sender can inject a
    # slot opening under the recipient secret with an attacker-controlled CEK;
    # early-exit on first AEAD success would let the forged slot shadow the real
    # one. We therefore continue scanning until an opened slot's CEK verifies
    # slots_mac or the slot list is exhausted.
    cek: bytes | None = None
    opened_any = False
    for slot in envelope.slots:
        if envelope.kem == "x25519":
            candidate_cek = _try_open_x25519_slot(slot, recipient_secret_key, pub_r_local)  # type: ignore[arg-type]
        else:
            candidate_cek = _try_open_mlkem768x25519_slot(slot, recipient_secret_key)  # type: ignore[arg-type]
        if candidate_cek is None:
            continue
        opened_any = True
        # Verify slots_mac under THIS candidate CEK. Only the slot whose CEK
        # matches the sender's HMAC_KEY produces the on-wire slots_mac.
        hmac_key = _hkdf32(candidate_cek, INFO_SLOTS_MAC_V1)
        slots_mac_calc = hmac.new(hmac_key, slots_cbor, hashlib.sha256).digest()
        if hmac.compare_digest(slots_mac_calc, envelope.slots_mac):
            cek = candidate_cek
            break
        # Otherwise this is a forged or tampered slot — keep scanning.

    if cek is None:
        if not opened_any:
            raise SealedPoeDecryptError(
                "WRONG_RECIPIENT_KEY", "no slot opened under recipient secret"
            )
        raise SealedPoeDecryptError("TAMPERED_HEADER", "opened slot(s) did not satisfy slots_mac")

    aad_content = envelope.nonce + envelope.slots_mac
    try:
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad_content, envelope.nonce, cek
        )
    except Exception as e:
        raise SealedPoeDecryptError("TAMPERED_CIPHERTEXT", str(e)) from e
    return plaintext


__all__ = [
    "INFO_KEK_MLKEM768X25519_V1",
    "INFO_KEK_V1",
    "INFO_SLOTS_MAC_V1",
    "MlKem768X25519Slot",
    "SealedEnvelope",
    "SealedPoeDecryptError",
    "SealedPoeOutput",
    "SealedSlot",
    "chunk_kem_ct",
    "ecies_sealed_poe_unwrap",
    "ecies_sealed_poe_wrap",
    "join_kem_ct",
]
