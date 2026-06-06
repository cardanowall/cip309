"""Multi-recipient sealed-PoE — Python reference implementation.

Two KEM branches share ONE envelope shape, discriminated on the envelope-level
`kem` field:

  * kem="x25519"         — classical age-style ECIES. Per-slot {epk(32), wrap(48)}.
  * kem="mlkem768x25519" — X-Wing hybrid (ML-KEM-768 + X25519). Per-slot the
                           1120-byte X-Wing enc carried as a chunked byte-string
                           array (`kem_ct`) + wrap(48). NO per-slot epk.

Construction summary (one or more recipients, scheme 1):
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
      salt_i      <- SHA-256(b"cardano-poe-xwing-kek-salt-v1" || enc_i || pub_R_i)
      KEK_i       <- HKDF-SHA-256(ikm=shared_i, salt=salt_i,
                                   info=b"cardano-poe-kek-mlkem768x25519-v1", L=32)
      wrap_i      <- ChaCha20-Poly1305(KEK_i, nonce=zeros(12),
                                       aad=b"cardano-poe-kek-mlkem768x25519-v1", CEK)
      slot_i      = {kem_ct: chunk64(enc_i), wrap: wrap_i}
  - CSPRNG-shuffle the slot array; reject duplicate per-slot KEM material.
  - Bind the slot set to CEK:
      slots_hash  <- SHA-256(b"cardano-poe-slots-transcript-v1" || canonicalCBOR(TRANSCRIPT))
                     where TRANSCRIPT is the closed map
                     {scheme, path:"slots", aead, kem, nonce, slots}.
      HMAC_KEY    <- HKDF-SHA-256(ikm=CEK, salt=b"", info=b"cardano-poe-slots-mac-v1", L=32)
      slots_mac   <- HMAC-SHA-256(HMAC_KEY, slots_hash)
  - Encrypt content under a key derived from CEK:
      nonce       <- randomBytes(24)
      payload_key <- HKDF-SHA-256(ikm=CEK, salt=nonce, info=b"cardano-poe-payload-v1", L=32)
      ad_content  <- canonicalCBOR({scheme, path:"slots", aead, kem, nonce,
                                    slots_hash, slots_mac})
      ciphertext  <- XChaCha20-Poly1305(payload_key, nonce, ad=ad_content, plaintext)

The content is encrypted under a payload_key derived from the CEK, never under
the CEK directly. The slots transcript hash binds the cross-KEM header fields to
the slot set; the content AAD re-binds the same header plus both slots_hash and
slots_mac.

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
    mlkem768x25519_keygen,
)

# ----- Constants -----
INFO_KEK_V1: bytes = b"cardano-poe-kek-v1"  # 18 ASCII bytes
# Hybrid (X-Wing) per-slot KEK label. Distinct from the classical label so a KEK
# derived under one KEM can never collide with the other. Reused verbatim as the
# per-slot wrap AEAD AAD, exactly as the classical path reuses its own label.
INFO_KEK_MLKEM768X25519_V1: bytes = b"cardano-poe-kek-mlkem768x25519-v1"  # 33 bytes
INFO_SLOTS_MAC_V1: bytes = b"cardano-poe-slots-mac-v1"  # 24 ASCII bytes
# SHA-256 prefix over the slots transcript; the resulting slots_hash is the
# constant-across-the-loop message the CEK-keyed HMAC signs.
SLOTS_TRANSCRIPT_PREFIX_V1: bytes = b"cardano-poe-slots-transcript-v1"  # 31 ASCII bytes
# HKDF info for the slots-path content payload_key (derived from the CEK; the
# content is never encrypted under the CEK directly).
INFO_PAYLOAD_V1: bytes = b"cardano-poe-payload-v1"  # 22 ASCII bytes
# SHA-256 prefix binding the reassembled hybrid kem_ct and the recipient X-Wing
# public key into the per-slot KEK salt, mirroring the classical salt's two
# bindings through a fixed-length digest because the hybrid inputs are oversized.
XWING_KEK_SALT_PREFIX_V1: bytes = b"cardano-poe-xwing-kek-salt-v1"  # 29 ASCII bytes
ZERO_NONCE_12: bytes = b"\x00" * 12

# XChaCha20-Poly1305 is a single-shot AEAD over the whole plaintext; its 32-bit
# internal block counter bounds one (key, nonce) invocation at 2^32 64-byte
# ChaCha20 blocks, the first of which is consumed by the Poly1305 one-time key.
# A payload at or above 2^38 - 64 plaintext bytes risks a counter-overflow
# keystream collision and MUST be rejected before the AEAD runs. The ciphertext
# carries a 16-byte tag, so the ciphertext bound is + 16.
MAX_SEALED_PLAINTEXT: int = (1 << 38) - 64
_MAX_SEALED_CIPHERTEXT: int = MAX_SEALED_PLAINTEXT + 16

# Verifier-side resource bounds enforced BEFORE any KEM/AEAD primitive runs, so a
# malformed envelope cannot drive unbounded per-slot work. Both are
# deployment-pinned reference constants (not wire fields); deployments MAY tighten
# them. They sit far above the ~16 KiB Cardano transaction-metadata ceiling that
# bounds honest records, so a conformant record never trips them.
#   * MAX_SLOTS — the maximum slot count; an envelope with more slots is rejected.
#   * MAX_DECODED_ENVELOPE_BYTES — a backstop on the decoded envelope's aggregate
#     byte size (nonce + slots_mac + per-slot wire fields).
MAX_SLOTS: int = 1024
MAX_DECODED_ENVELOPE_BYTES: int = 65536

# Component sizes the decoded-envelope backstop adds up.
_NONCE_LENGTH = 24
_SLOTS_MAC_LENGTH = 32
_X25519_PUBLIC_KEY_LENGTH = 32
_WRAP_LENGTH = 48

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
    """Decryption error with a stable discriminator.

    Codes: UNSUPPORTED_ENVELOPE_SCHEME / UNSUPPORTED_AEAD_ALG /
    UNSUPPORTED_KEM_ALG / INVALID_ENVELOPE_SHAPE / ENC_SLOTS_EMPTY /
    ENC_SLOTS_TOO_MANY / ENC_ENVELOPE_TOO_LARGE / KEM_CT_LENGTH_MISMATCH /
    ENC_SLOTS_DUPLICATE_KEM_MATERIAL / PAYLOAD_TOO_LARGE / INVALID_RECIPIENT_KEY
    / WRONG_RECIPIENT_KEY / TAMPERED_HEADER / TAMPERED_CIPHERTEXT.
    """

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


def _canonicalize_slots(
    slots: Sequence[SealedSlot] | Sequence[MlKem768X25519Slot], kem: str
) -> list:
    """Canonicalise the slot set — the value bound under the `slots` key of the
    transcript and the slots_mac. KEM-driven so the hybrid kem_ct is committed
    exactly as it appears on the wire:

      * x25519:         each slot → {epk: bstr, wrap: bstr}
      * mlkem768x25519: each slot → {kem_ct: [bstr, ...], wrap: bstr}

    The hybrid form re-chunks kem_ct into its canonical <=64-byte sequence so the
    transcript depends on the kem_ct BYTES, not on the chunk boundaries that
    arrived on the wire: a re-chunked record still verifies, any byte flip still
    changes the transcript.
    """
    if kem == "x25519":
        return [{"epk": s.epk, "wrap": s.wrap} for s in slots]  # type: ignore[union-attr]
    return [
        {"kem_ct": chunk_kem_ct(join_kem_ct(s.kem_ct)), "wrap": s.wrap}  # type: ignore[union-attr]
        for s in slots
    ]


def _slots_transcript(
    nonce: bytes, slots: Sequence[SealedSlot] | Sequence[MlKem768X25519Slot], kem: str
) -> bytes:
    """canonicalCBOR(TRANSCRIPT). TRANSCRIPT is the closed six-key map binding the
    cross-KEM header fields (scheme, path, aead, kem, nonce) to the canonicalised
    slot set, so a relay that flips any header field while leaving slot shapes
    valid yields a different slots_hash and the MAC fails. The keys are a set;
    canonical CBOR fixes their wire order."""
    return cbor2.dumps(
        {
            "scheme": 1,
            "path": "slots",
            "aead": "xchacha20-poly1305",
            "kem": kem,
            "nonce": nonce,
            "slots": _canonicalize_slots(slots, kem),
        },
        canonical=True,
    )


def _compute_slots_hash(
    nonce: bytes, slots: Sequence[SealedSlot] | Sequence[MlKem768X25519Slot], kem: str
) -> bytes:
    """slots_hash = SHA-256(prefix || canonicalCBOR(TRANSCRIPT)). Computed once
    per envelope and held constant across the trial-decrypt loop."""
    return hashlib.sha256(
        SLOTS_TRANSCRIPT_PREFIX_V1 + _slots_transcript(nonce, slots, kem)
    ).digest()


def _slots_mac_from_hash(cek: bytes, slots_hash: bytes) -> bytes:
    """slots_mac = HMAC-SHA-256(HKDF(CEK, b"", slots-mac-v1, 32), slots_hash)."""
    hmac_key = _hkdf32(cek, INFO_SLOTS_MAC_V1)
    return hmac.new(hmac_key, slots_hash, hashlib.sha256).digest()


def _ad_content_slots(nonce: bytes, kem: str, slots_hash: bytes, slots_mac: bytes) -> bytes:
    """canonicalCBOR(AD_CONTENT_SLOTS): the closed seven-key content-AEAD AAD for
    the slots path. It re-binds the slots-path header AND carries both slots_hash
    (binding to the exact transcript) and slots_mac (tying the content layer to
    the CEK-keyed MAC the recipient matched)."""
    return cbor2.dumps(
        {
            "scheme": 1,
            "path": "slots",
            "aead": "xchacha20-poly1305",
            "kem": kem,
            "nonce": nonce,
            "slots_hash": slots_hash,
            "slots_mac": slots_mac,
        },
        canonical=True,
    )


def _slots_payload_key(cek: bytes, nonce: bytes) -> bytes:
    """Slots-path content key: HKDF-SHA-256(ikm=CEK, salt=nonce, info=payload-v1)."""
    return _hkdf32(cek, INFO_PAYLOAD_V1, salt=nonce)


def _xwing_kek_salt(kem_ct: bytes, pub_r: bytes) -> bytes:
    """Hybrid (X-Wing) per-slot KEK salt:
    SHA-256(b"cardano-poe-xwing-kek-salt-v1" || kem_ct || pub_R). kem_ct is the
    reassembled 1120-byte X-Wing ciphertext (anchoring the KEK to a slot-unique
    value) and pub_R the 1216-byte recipient public key (binding to the specific
    recipient) — the same two bindings the classical epk||pub_R salt provides,
    through a fixed-length digest because the hybrid inputs are oversized."""
    return hashlib.sha256(XWING_KEK_SALT_PREFIX_V1 + kem_ct + pub_r).digest()


def _assert_unique_slot_kem_material(
    slots: Sequence[SealedSlot | MlKem768X25519Slot], kem: str
) -> None:
    """Reject duplicate per-slot KEM material — a repeated epk (x25519) or a
    repeated reassembled kem_ct (hybrid). The zero-nonce wrap is sound only when
    every slot's KEK is unique; the KEK is a deterministic function of the slot's
    KEM material, so two slots with identical material against the same recipient
    repeat the (KEK, nonce) pair. Enforced on both the producer side (before the
    wire) and the verifier side (before any decapsulation)."""
    seen: set[bytes] = set()
    field = "epk" if kem == "x25519" else "kem_ct"
    for i, s in enumerate(slots):
        material = s.epk if isinstance(s, SealedSlot) else join_kem_ct(s.kem_ct)
        if material in seen:
            raise SealedPoeDecryptError(
                "ENC_SLOTS_DUPLICATE_KEM_MATERIAL",
                f"slots[{i}].{field} duplicates an earlier slot",
            )
        seen.add(material)


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

    # Reject before any keystream is drawn: a payload at or above the single-shot
    # bound cannot be safely encrypted.
    if len(plaintext) >= MAX_SEALED_PLAINTEXT:
        raise SealedPoeDecryptError(
            "PAYLOAD_TOO_LARGE",
            f"plaintext length={len(plaintext)} is at or above the single-shot bound",
        )

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
        # Per-slot KEK uniqueness is the safety condition for the zero-nonce wrap.
        _assert_unique_slot_kem_material(x_slots, "x25519")
        if not skip_shuffle:
            x_slots = _shuffle_in_place(x_slots)
        slots = x_slots
    else:
        h_slots: list[MlKem768X25519Slot] = []
        for i, pub_r in enumerate(recipient_public_keys):
            eseed = eseeds[i] if eseeds is not None else None
            kem_ct, shared = mlkem768x25519_encapsulate(pub_r, eseed)
            assert len(kem_ct) == MLKEM768X25519_ENC_LENGTH
            # Salt binds the reassembled kem_ct and the recipient public key.
            kek = _hkdf32(shared, INFO_KEK_MLKEM768X25519_V1, salt=_xwing_kek_salt(kem_ct, pub_r))
            wrap = ChaCha20Poly1305(kek).encrypt(ZERO_NONCE_12, cek, INFO_KEK_MLKEM768X25519_V1)
            assert len(wrap) == 48
            h_slots.append(MlKem768X25519Slot(kem_ct=tuple(chunk_kem_ct(kem_ct)), wrap=wrap))
        _assert_unique_slot_kem_material(h_slots, "mlkem768x25519")
        if not skip_shuffle:
            h_slots = _shuffle_in_place(h_slots)
        slots = h_slots

    # Slot-set MAC binds the slots transcript hash (header fields + slot bytes)
    # to the CEK; the transcript is hashed once and signed with a CEK-keyed HMAC.
    # Computed AFTER the shuffle, binding the on-wire order.
    slots_hash = _compute_slots_hash(nonce, slots, kem)
    slots_mac = _slots_mac_from_hash(cek, slots_hash)

    # Content is encrypted under a payload_key derived from the CEK (never the
    # CEK directly), with a structured AAD that re-binds the slots-path header
    # plus both slots_hash and slots_mac.
    payload_key = _slots_payload_key(cek, nonce)
    aad_content = _ad_content_slots(nonce, kem, slots_hash, slots_mac)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad_content, nonce, payload_key
    )

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


# All-zero IKM for the dummy KEK an invalid-ECDH slot derives so it pays the same
# HKDF work as a live slot (see `_try_open_x25519_slot`).
_ZERO_IKM_32: bytes = b"\x00" * 32


def _try_open_x25519_slot(slot: SealedSlot, priv_r: bytes, pub_r_local: bytes) -> bytes | None:
    """Open one classical slot; return the candidate CEK or None on a non-match.

    Acceptance is `kem_ok AND open_ok`. `kem_ok` is the X25519 validity bit: a
    small-order epk drives the shared secret to all-zero, which RFC 7748 §6.1
    rejects. `cryptography` signals that all-zero case by raising, so a fully
    branchless ct-select over the shared secret is not expressible against this
    library API. The equivalent form is taken instead: on the all-zero rejection
    the slot derives a DUMMY KEK from `ikm=0^32` (same salt/info) so it performs
    the identical HKDF work, then returns a non-match WITHOUT attempting the AEAD
    — so an invalid-ECDH slot can never be accepted regardless of the wrap
    outcome (`kem_ok=false` ⟹ the AEAD is never reached), while the failed path
    still costs the same per-slot KEK derivation as a live one."""
    if len(slot.epk) != 32 or len(slot.wrap) != 48:
        return None
    salt = slot.epk + pub_r_local
    try:
        shared = _x25519_shared(priv_r, slot.epk)
    except Exception:
        # kem_ok = false (low-order epk; RFC 7748 §6.1 contributory-check
        # rejection). Derive the dummy KEK so the failed slot pays the same HKDF
        # cost a live slot would, then short-circuit to a non-match: the AEAD is
        # never attempted, so this slot can never be accepted.
        _hkdf32(_ZERO_IKM_32, INFO_KEK_V1, salt=salt)
        return None
    # kem_ok = true. Derive the real KEK and attempt the wrap AEAD.
    kek = _hkdf32(shared, INFO_KEK_V1, salt=salt)
    try:
        return ChaCha20Poly1305(kek).decrypt(ZERO_NONCE_12, slot.wrap, INFO_KEK_V1)
    except Exception:
        return None


def _try_open_mlkem768x25519_slot(
    slot: MlKem768X25519Slot, secret_seed: bytes, pub_r_local: bytes
) -> bytes | None:
    """Open one hybrid slot. X-Wing decapsulate NEVER raises on attacker wire
    data (ML-KEM implicit rejection yields a pseudorandom shared secret), so a
    wrong seed simply produces a KEK whose AEAD tag fails — returned as a
    non-match. `slot.kem_ct` MUST already have been length-checked. `pub_r_local`
    is the recipient's own 1216-byte X-Wing public key, recomputed from the held
    seed — the same value the producer bound into the KEK salt."""
    if len(slot.wrap) != 48:
        return None
    kem_ct = join_kem_ct(slot.kem_ct)
    shared = mlkem768x25519_decapsulate(secret_seed, kem_ct)
    # Salt binds the reassembled kem_ct and the recipient public key.
    kek = _hkdf32(shared, INFO_KEK_MLKEM768X25519_V1, salt=_xwing_kek_salt(kem_ct, pub_r_local))
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

    # Resource bound: reject an envelope with more than MAX_SLOTS slots before any
    # KEM/AEAD primitive runs, so a malformed record cannot drive unbounded
    # per-slot work.
    if len(envelope.slots) > MAX_SLOTS:
        raise SealedPoeDecryptError(
            "ENC_SLOTS_TOO_MANY",
            f"slots length={len(envelope.slots)} exceeds MAX_SLOTS={MAX_SLOTS}",
        )

    # Partitioning-oracle defence (hybrid): every kem_ct MUST reassemble to the
    # exact X-Wing enc length BEFORE any decapsulation.
    if envelope.kem == "mlkem768x25519":
        for slot in envelope.slots:
            if len(join_kem_ct(slot.kem_ct)) != MLKEM768X25519_ENC_LENGTH:  # type: ignore[union-attr]
                raise SealedPoeDecryptError("KEM_CT_LENGTH_MISMATCH", "kem_ct reassembled length")

    # Decoded-envelope byte backstop. Every per-slot field is fixed-length, so the
    # decoded envelope's aggregate size is determined here: nonce + slots_mac +
    # per-slot (epk|kem_ct + wrap). Reject before any KEM/AEAD primitive when it
    # exceeds the bound — the byte cap a parser that can see the decoded size
    # enforces, alongside the slot-count cap above.
    per_slot_bytes = (
        _X25519_PUBLIC_KEY_LENGTH + _WRAP_LENGTH
        if envelope.kem == "x25519"
        else MLKEM768X25519_ENC_LENGTH + _WRAP_LENGTH
    )
    decoded_envelope_bytes = (
        _NONCE_LENGTH + _SLOTS_MAC_LENGTH + len(envelope.slots) * per_slot_bytes
    )
    if decoded_envelope_bytes > MAX_DECODED_ENVELOPE_BYTES:
        raise SealedPoeDecryptError(
            "ENC_ENVELOPE_TOO_LARGE",
            f"decoded envelope size {decoded_envelope_bytes} exceeds "
            f"MAX_DECODED_ENVELOPE_BYTES={MAX_DECODED_ENVELOPE_BYTES}",
        )

    # Per-slot KEK uniqueness — rejected before any decapsulation so a duplicate
    # never enters the trial-decrypt loop.
    _assert_unique_slot_kem_material(envelope.slots, envelope.kem)

    # The slots transcript hash is constant across every trial-decrypt pass
    # (depends only on the envelope), so it is computed once here.
    slots_hash = _compute_slots_hash(envelope.nonce, envelope.slots, envelope.kem)
    # Recipient public key, recomputed from the held secret. The classical salt
    # is epk||pub_R; the hybrid salt binds the recipient's X-Wing public key.
    if envelope.kem == "x25519":
        pub_r_local = _x25519_public(recipient_secret_key)
    else:
        _seed, pub_r_local = mlkem768x25519_keygen(recipient_secret_key)

    # Trial-decrypt loop. Iterate ALL slots — no early break on a match — so the
    # acceptance follows the spec loop shape:
    #
    #   ok           = kem_ok AND open_ok AND mac_ok        ; mac folded in
    #   first        = ok AND NOT found                      ; first matching slot
    #   cek_conflict = cek_conflict OR (ok AND found AND NOT ct_eq(cand, selected))
    #   selected_CEK = first ? cand : selected
    #   found        = found OR ok
    #
    # Folding the slots_mac check into acceptance is load-bearing: a malicious
    # sender can inject a slot that opens under the recipient secret with an
    # attacker-chosen CEK; requiring the candidate CEK to also reproduce the
    # on-wire slots_mac over the constant slots_hash defeats slot substitution,
    # removal, and reorder. Multiple matching slots are PERMITTED (a producer may
    # seal the same CEK to one recipient in several slots to pad the count); the
    # FIRST match's CEK is selected. The narrow anomaly rejected is two matching
    # slots that recover DIFFERENT CEKs (constant-time compare) — a commitment
    # collision that fails the record closed (cek_conflict), distinct from the
    # within-record duplicate-KEM-material rejection above.
    cek: bytes | None = None
    opened_any = False  # a wrap AEAD opened under the recipient secret (no MAC yet)
    cek_conflict = False
    for slot in envelope.slots:
        if envelope.kem == "x25519":
            candidate_cek = _try_open_x25519_slot(slot, recipient_secret_key, pub_r_local)  # type: ignore[arg-type]
        else:
            candidate_cek = _try_open_mlkem768x25519_slot(slot, recipient_secret_key, pub_r_local)  # type: ignore[arg-type]
        if candidate_cek is None:
            continue
        opened_any = True
        # Verify slots_mac under THIS candidate CEK over the constant slots_hash.
        # Only a slot whose CEK matches the sender's HMAC_KEY produces the on-wire
        # slots_mac, so `ok` includes the MAC check.
        slots_mac_calc = _slots_mac_from_hash(candidate_cek, slots_hash)
        if not hmac.compare_digest(slots_mac_calc, envelope.slots_mac):
            continue  # a forged or tampered slot — keep scanning
        if cek is None:
            cek = candidate_cek  # first matching slot
        elif not hmac.compare_digest(candidate_cek, cek):
            # A later matching slot recovered a CEK that differs from the selected
            # one. Fail closed (defence-in-depth against a commitment collision).
            cek_conflict = True

    if cek_conflict:
        raise SealedPoeDecryptError(
            "TAMPERED_HEADER", "matching slots recovered conflicting CEKs"
        )
    if cek is None:
        if not opened_any:
            raise SealedPoeDecryptError(
                "WRONG_RECIPIENT_KEY", "no slot opened under recipient secret"
            )
        raise SealedPoeDecryptError("TAMPERED_HEADER", "opened slot(s) did not satisfy slots_mac")

    # Guard the single-shot bound before invoking the AEAD.
    if len(ciphertext) >= _MAX_SEALED_CIPHERTEXT:
        raise SealedPoeDecryptError(
            "PAYLOAD_TOO_LARGE",
            f"ciphertext length={len(ciphertext)} is at or above the single-shot bound",
        )

    # Content is opened under a payload_key derived from the recovered CEK, with
    # the structured slots-path AAD recomputed from the envelope.
    payload_key = _slots_payload_key(cek, envelope.nonce)
    aad_content = _ad_content_slots(envelope.nonce, envelope.kem, slots_hash, envelope.slots_mac)
    try:
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad_content, envelope.nonce, payload_key
        )
    except Exception as e:
        raise SealedPoeDecryptError("TAMPERED_CIPHERTEXT", str(e)) from e
    return plaintext


__all__ = [
    "INFO_KEK_MLKEM768X25519_V1",
    "INFO_KEK_V1",
    "INFO_PAYLOAD_V1",
    "INFO_SLOTS_MAC_V1",
    "MAX_DECODED_ENVELOPE_BYTES",
    "MAX_SEALED_PLAINTEXT",
    "MAX_SLOTS",
    "SLOTS_TRANSCRIPT_PREFIX_V1",
    "XWING_KEK_SALT_PREFIX_V1",
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
