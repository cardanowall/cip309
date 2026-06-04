#!/usr/bin/env python3
"""Label 309 v1 reference implementation — end-to-end publish/verify demo.

Mirrors the TypeScript end-to-end example. It exercises the wire primitives in
the order a producer and a verifier use them, with no network and no SDK:

  1. Build a PoE record body and canonical-CBOR-encode it.
  2. Attach a record-level COSE_Sign1 signature (off-host signing helper).
  3. Decode the bytes back and run the structural validator.
  4. Verify the record-level signature cryptographically (strict Ed25519).
  5. Recompute the content hashes and confirm they match the record.
  6. Sealed-PoE: wrap a plaintext to a recipient X25519 key, then unwrap it.

A byte-parity assertion against a pinned canonical-CBOR vector shows that this
Python implementation produces the same bytes as the TypeScript twin.

Run:  uv run python end_to_end.py
  or: python -m end_to_end   (with the package installed / on sys.path)
"""

from __future__ import annotations

from label309_examples.cbor_canonical import (
    decode_canonical_cbor,
    encode_canonical_cbor,
)
from label309_examples.label309_validator import validate_poe_record
from label309_examples.cose_sign1 import build_sig_structure, decode_cose_sign1
from label309_examples.ecies_sealed_poe import (
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
)
from label309_examples.ed25519 import verify_ed25519
from label309_examples.hash_dual import blake2b_256, sha2_256
from label309_examples.off_host_sign import (
    CARDANO_POE_SIG_DOMAIN_PREFIX,
    MockHsmSigner,
    assemble_cose_sign1,
    prepare_sig_structure,
)
from label309_examples.seed_derive import (
    derive_ed25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)


def _chunk_bytes(data: bytes, n: int = 64) -> list[bytes]:
    return [data[i : i + n] for i in range(0, len(data), n)] or [b""]


def _section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def demo_minimal_record_byte_parity() -> None:
    """Build the minimal record and assert byte-parity with the pinned vector.

    The expected bytes are the same canonical-CBOR encoding the TypeScript
    reference produces for this record — proof the two implementations are a
    byte-for-byte twin for this deterministic operation.
    """
    _section("1. Minimal record — build + canonical-CBOR encode (byte-parity)")
    plaintext = b"minimal fixture content 2026-04-18"
    record = {
        "v": 1,
        "items": [
            {
                "hashes": {
                    "sha2-256": sha2_256(plaintext),
                    "blake2b-256": blake2b_256(plaintext),
                }
            }
        ],
    }
    cbor_bytes = encode_canonical_cbor(record)

    expected_hex = (
        "a2617601656974656d7381a166686173686573a268736861322d3235365820acbd2db1c365826ec7"
        "9328a30c46418396121ca457bcb28f6f4275ebff7635e86b626c616b6532622d32353658204933a7"
        "70ca4423edb274f3d660c2c8ae88e55331bb7eaf622c7a78d52128bae8"
    )
    expected = bytes.fromhex(expected_hex)
    print(f"encoded {len(cbor_bytes)}B canonical CBOR")
    print(f"hex: {cbor_bytes.hex()}")
    assert cbor_bytes == expected, "byte-parity FAILED against pinned vector"
    print("byte-parity with the pinned TypeScript twin vector: OK")

    # Round-trip the bytes through the validator.
    result = validate_poe_record(cbor_bytes)
    assert result["valid"], f"validator rejected a valid record: {result}"
    print("structural validation: valid")


def demo_signed_record() -> None:
    """Build a signed record, validate it, then verify the signature."""
    _section("2. Signed record — off-host COSE_Sign1, validate, verify signature")
    # Derive a signing identity deterministically from a 32-byte seed.
    seed = b"\x11" * 32
    signer_secret, signer_pub = derive_ed25519_keypair_from_seed(seed)
    print(f"signer pubkey: {signer_pub.hex()}")

    content = b"signed PoE content"
    record_body: dict[str, object] = {
        "v": 1,
        "items": [{"hashes": {"sha2-256": sha2_256(content)}}],
    }

    # Build the Sig_structure, sign it off-host, and assemble the COSE_Sign1.
    sig_structure_bytes, _protected = prepare_sig_structure(
        record_body=record_body, signer_pubkey=signer_pub
    )
    signer = MockHsmSigner(signer_secret)
    signature = signer.sign(sig_structure_bytes)
    cose_sign1 = assemble_cose_sign1(signer_pubkey=signer_pub, signature=signature)
    print(f"COSE_Sign1: {len(cose_sign1)}B (chunked into ≤64B byte strings on the wire)")

    full_record = dict(record_body)
    full_record["sigs"] = [{"cose_sign1": _chunk_bytes(cose_sign1)}]
    cbor_bytes = encode_canonical_cbor(full_record)

    # Decode + structural validation.
    decoded = decode_canonical_cbor(cbor_bytes)
    assert isinstance(decoded, dict)
    result = validate_poe_record(cbor_bytes)
    assert result["valid"], f"validator rejected the signed record: {result}"
    print("structural validation: valid")

    # Cryptographic signature verification (what a public verifier does).
    record_body_for_sig = {k: v for k, v in decoded.items() if k != "sigs"}
    to_sign = CARDANO_POE_SIG_DOMAIN_PREFIX + encode_canonical_cbor(record_body_for_sig)
    cose = decode_cose_sign1(b"".join(decoded["sigs"][0]["cose_sign1"]))
    sig_struct = build_sig_structure(
        context="Signature1",
        body_protected_bytes=cose["protected_bytes"],
        external_aad=b"",
        payload=to_sign,
    )
    ok = verify_ed25519(cose["signature"], sig_struct, signer_pub)
    assert ok, "signature verification FAILED"
    print("record-level Ed25519 signature: VALID")

    # Content-hash recomputation (the primary PoE claim).
    claimed = decoded["items"][0]["hashes"]["sha2-256"]
    assert sha2_256(content) == claimed, "content-hash mismatch"
    print("content-hash recomputation: matches")


def demo_sealed_poe_roundtrip() -> None:
    """Wrap a plaintext to one recipient, then unwrap it back."""
    _section("3. Sealed PoE — wrap to a recipient X25519 key, then unwrap")
    recipient_seed = b"\x22" * 32
    recipient_secret, recipient_pub = derive_x25519_keypair_from_seed(recipient_seed)
    print(f"recipient X25519 pubkey: {recipient_pub.hex()}")

    plaintext = b"a sealed message only the recipient can read"
    sealed = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        recipient_public_keys=[recipient_pub],
        kem="x25519",
    )
    env = sealed.envelope
    print(
        f"envelope: scheme={env.scheme} aead={env.aead} kem={env.kem} "
        f"slots={len(env.slots)} ciphertext={len(sealed.ciphertext)}B"
    )

    recovered = ecies_sealed_poe_unwrap(
        envelope=env,
        ciphertext=sealed.ciphertext,
        recipient_secret_key=recipient_secret,
    )
    assert recovered == plaintext, "sealed-PoE round-trip FAILED"
    print("sealed-PoE unwrap recovered the exact plaintext: OK")

    # A wrong recipient key must NOT recover the plaintext.
    wrong_secret, _ = derive_x25519_keypair_from_seed(b"\x99" * 32)
    try:
        ecies_sealed_poe_unwrap(
            envelope=env, ciphertext=sealed.ciphertext, recipient_secret_key=wrong_secret
        )
    except Exception as e:
        code = getattr(e, "code", type(e).__name__)
        print(f"wrong recipient key rejected as expected: {code}")
    else:  # pragma: no cover
        raise AssertionError("a wrong recipient key must not decrypt the sealed PoE")


def main() -> None:
    demo_minimal_record_byte_parity()
    demo_signed_record()
    demo_sealed_poe_roundtrip()
    _section("ALL END-TO-END CHECKS PASSED")


if __name__ == "__main__":
    main()
