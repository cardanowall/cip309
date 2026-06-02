# CIP-309 v1 reference implementation — off-host signing helper.
#
# Builds the Sig_structure for a record-level COSE_Sign1 (with the 25-byte
# domain-separator prefix) and assembles the COSE_Sign1 from a signature
# produced by an out-of-process signer, so the Ed25519 private key never has to
# enter this process. Includes the CIP-8 `hashed = true` companion for hardware
# co-signers with screen/buffer constraints.
#
# Use cases — the four supported off-host-signer integration shapes:
#   1. AWS KMS Sign — wrap the KMS API in a callable returning bytes; the
#      KMS-bound private key never leaves the HSM boundary.
#   2. Google Cloud HSM — same shape via GCP KMS asymmetric-sign.
#   3. YubiHSM — local hardware-backed signer addressable from a workstation.
#   4. Air-gapped offline signer — transport the Sig_structure bytes via QR /
#      USB / sneakernet to an offline workstation; transport the 64-byte
#      Ed25519 signature back.
#
# Privacy contract: this module never sees, stores, logs, or transmits any
# byte string containing the integrator's Ed25519 private signing key. The
# integrator's signer handles the seed; the module's input boundary is the
# 32-byte public key and the 64-byte Ed25519 signature — both PUBLIC data.

from __future__ import annotations

import hashlib
from typing import Protocol

from .cbor_canonical import encode_canonical_cbor
from .cose_sign1 import build_sig_structure, encode_cose_sign1
from .ed25519 import sign_ed25519
from .hash_dual import blake2b_256

CARDANO_POE_SIG_DOMAIN_PREFIX = b"cardano-poe-record-sig-v1"
assert len(CARDANO_POE_SIG_DOMAIN_PREFIX) == 25, "domain prefix must be 25 UTF-8 bytes"


class OffHostSigner(Protocol):
    """Integrator's signer abstraction. Both software (KMS / HSM) and hardware
    (YubiHSM / air-gapped) signers fit the same shape — accept a byte string,
    return a 64-byte Ed25519 signature.
    """

    def sign(self, message: bytes) -> bytes: ...


class MockHsmSigner:
    """Deterministic in-process signer driven by a hard-coded test seed. Useful
    for unit tests and example walkthroughs. In production, replace with a
    KMS-backed signer.
    """

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("MockHsmSigner: seed must be 32 bytes")
        self._seed = seed

    def sign(self, message: bytes) -> bytes:
        return sign_ed25519(message, self._seed)


def _path1_protected_header_bytes(signer_pubkey: bytes) -> bytes:
    """Canonical CBOR of `{1: -8, 4: <signer_pubkey>}` — always 38 bytes."""
    return encode_canonical_cbor({1: -8, 4: signer_pubkey})


def build_to_sign(record_body: dict[str, object]) -> bytes:
    """Return `utf8("cardano-poe-record-sig-v1") || canonical_cbor(record_body)`."""
    return CARDANO_POE_SIG_DOMAIN_PREFIX + encode_canonical_cbor(record_body)


def prepare_sig_structure(
    *,
    record_body: dict[str, object],
    signer_pubkey: bytes,
) -> tuple[bytes, bytes]:
    """Return `(sig_structure_bytes, protected_header_bytes)`."""
    if len(signer_pubkey) != 32:
        raise ValueError("signer_pubkey must be 32 bytes (Ed25519 raw public key)")
    protected_header_bytes = _path1_protected_header_bytes(signer_pubkey)
    to_sign = build_to_sign(record_body)
    sig_structure_bytes = build_sig_structure(
        context="Signature1",
        body_protected_bytes=protected_header_bytes,
        payload=to_sign,
    )
    return sig_structure_bytes, protected_header_bytes


def assemble_cose_sign1(*, signer_pubkey: bytes, signature: bytes) -> bytes:
    if len(signer_pubkey) != 32:
        raise ValueError("signer_pubkey must be 32 bytes")
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")
    return encode_cose_sign1(
        protected_header={1: -8, 4: signer_pubkey},
        unprotected_header={},
        payload=None,
        signature=signature,
    )


def _blake2b_224(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=28).digest()


def prepare_sig_structure_hashed(
    *,
    record_body: dict[str, object],
    signer_pubkey: bytes,
) -> tuple[bytes, bytes, bytes]:
    """CIP-8 `hashed = true` companion. Sig_structure[3] is Blake2b-224(to_sign).
    DISCOURAGED for software off-host signers; use only for hardware co-signers
    with screen / buffer constraints.

    Returns `(sig_structure_bytes, protected_header_bytes, to_sign_hash_bytes)`.
    """
    if len(signer_pubkey) != 32:
        raise ValueError("signer_pubkey must be 32 bytes")
    protected_header_bytes = _path1_protected_header_bytes(signer_pubkey)
    to_sign_hash = _blake2b_224(build_to_sign(record_body))
    sig_structure_bytes = build_sig_structure(
        context="Signature1",
        body_protected_bytes=protected_header_bytes,
        payload=to_sign_hash,
    )
    return sig_structure_bytes, protected_header_bytes, to_sign_hash


def assemble_cose_sign1_hashed(*, signer_pubkey: bytes, signature: bytes) -> bytes:
    if len(signer_pubkey) != 32:
        raise ValueError("signer_pubkey must be 32 bytes")
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")
    return encode_cose_sign1(
        protected_header={1: -8, 4: signer_pubkey},
        unprotected_header={"hashed": True},
        payload=None,
        signature=signature,
    )


def run_off_host_signing_demo() -> dict[str, bytes]:
    """End-to-end demo. Build a sample record body → ask the off-host signer
    for a signature over the Sig_structure → assemble the COSE_Sign1.

    In production the assembled bytes get spliced into `record.sigs[i]` and
    submitted on-chain via a Cardano transaction's label-309 metadata.

    The seed (0x11 repeated 32 times) and pubkey come from a fixed test vector
    so the demo output is reproducible.
    """
    seed = b"\x11" * 32
    signer_pubkey = bytes.fromhex(
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    )
    record_body: dict[str, object] = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": blake2b_256(b"demo content")}}],
    }

    signer = MockHsmSigner(seed)
    to_sign = build_to_sign(record_body)
    sig_structure_bytes, _ = prepare_sig_structure(
        record_body=record_body, signer_pubkey=signer_pubkey
    )
    signature = signer.sign(sig_structure_bytes)
    cose_sign1_bytes = assemble_cose_sign1(signer_pubkey=signer_pubkey, signature=signature)
    return {
        "cose_sign1_bytes": cose_sign1_bytes,
        "signer_pubkey": signer_pubkey,
        "to_sign": to_sign,
    }
