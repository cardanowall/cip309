"""Label 309 sealed PoE — the multi-recipient encryption construction.

A sealed PoE publishes a public, timestamped commitment to a plaintext
digest while keeping the plaintext readable only by intended recipients:
the on-chain record carries the plaintext hashes plus an ``enc`` envelope
(the key-delivery material), and the ciphertext lives off-chain at a
content-addressed URI. This example tours the construction through the SDK
surface:

* wrap/unwrap under both registered KEMs — classical ``x25519`` and the
  post-quantum hybrid ``mlkem768x25519`` (X-Wing), the recommended default;
* the envelope shape: ``kem_ct`` is a single 1120-byte byte string, the
  content format is the segmented STREAM ``chacha20-poly1305-stream64k``;
* the hash-claim binding: the envelope's slot-set MAC commits to the item's
  ``hashes`` map, so an envelope spliced onto a different hash claim fails
  before any content work;
* trial-decrypt: recipient public keys are never on the wire — a recipient
  discovers their slot by attempting to open it;
* the decryption outcomes: a non-throwing result whose internal reason codes
  (WRONG_RECIPIENT_KEY / TAMPERED_HEADER / TAMPERED_CIPHERTEXT) are
  diagnostics for a trusted local caller — an untrusted caller MUST see one
  indistinguishable generic failure;
* the published age-style recipient encodings (``age1…`` / ``age1pqc…``).

Run: ``uv run python sealed_poe.py`` (exits non-zero on any failed check).
"""

from __future__ import annotations

import sys

from cardanowall import (
    ecies_sealed_poe_unwrap,
    ecies_sealed_poe_wrap,
    encode_age_x25519_recipient,
    encode_age_xwing_recipient,
)
from cardanowall.hash import blake2b_256, sha2_256
from cardanowall.seed_derive import (
    derive_mlkem768x25519_keypair_from_seed,
    derive_x25519_keypair_from_seed,
)

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    suffix = "" if ok or not detail else f" — {detail}"
    print(f"{'PASS' if ok else 'FAIL'}  {label}{suffix}")
    if not ok:
        failures += 1


def main() -> None:
    plaintext = b"sealed-poe example plaintext"
    # The item's hashes map MUST always commit to the PLAINTEXT, even when the
    # content ships encrypted — that commitment is what makes the time claim
    # meaningful, and it is the map the envelope is cryptographically bound to.
    hashes = {"sha2-256": sha2_256(plaintext), "blake2b-256": blake2b_256(plaintext)}

    # Three recipients with independent keys; seed-derived here so the example
    # is deterministic apart from the envelope's fresh CEK/nonce/ephemerals.
    seeds = [bytes([b]) * 32 for b in (1, 2, 3)]
    x25519_keys = [derive_x25519_keypair_from_seed(s) for s in seeds]
    x25519_pubs = [k["public_key"] for k in x25519_keys]

    # -- Classical x25519 path -------------------------------------------------
    classical = ecies_sealed_poe_wrap(
        plaintext=plaintext, hashes=hashes, recipient_public_keys=x25519_pubs, kem="x25519"
    )
    env = classical.envelope
    print(
        f"x25519 envelope     : scheme {env.scheme}, aead {env.aead}, {len(env.slots)} slot(s), "
        f"nonce {len(env.nonce)}B, slots_mac {len(env.slots_mac)}B"
    )
    check("aead is the segmented STREAM format", env.aead == "chacha20-poly1305-stream64k")
    check(
        "every classical slot is { epk: 32B, wrap: 48B }",
        all(
            s.epk is not None and len(s.epk) == 32 and len(s.wrap) == 48 and s.kem_ct is None
            for s in env.slots
        ),
    )
    # Every sealed chunk carries a 16-byte tag; this short payload is a single
    # final chunk, so ciphertext = plaintext + 16.
    check(
        "STREAM ciphertext = plaintext + 16-byte tag",
        len(classical.ciphertext) == len(plaintext) + 16,
    )

    # Recipient 2 unwraps with their private key. The slot order on the wire is
    # CSPRNG-shuffled at sealing time, so position reveals nothing; the
    # trial-decrypt loop visits every slot regardless of where the match sits.
    opened = ecies_sealed_poe_unwrap(
        envelope=classical.envelope,
        ciphertext=classical.ciphertext,
        hashes=hashes,
        recipient_secret_key=x25519_keys[1]["secret_key"],
    )
    check("recipient 2 unwraps", opened.matched)
    if opened.matched and opened.plaintext is not None:
        check("plaintext round-trips", opened.plaintext == plaintext)
        # The application-layer recheck: recompute the committed digests over
        # the recovered plaintext before acting on it.
        check("plaintext-hash recheck passes", sha2_256(opened.plaintext) == hashes["sha2-256"])

    # A non-recipient gets a clean no-match. The typed reason is an internal
    # diagnostic; an untrusted caller must receive one generic failure shape
    # regardless of WHY decryption failed.
    stranger = ecies_sealed_poe_unwrap(
        envelope=classical.envelope,
        ciphertext=classical.ciphertext,
        hashes=hashes,
        recipient_secret_key=derive_x25519_keypair_from_seed(bytes([99]) * 32)["secret_key"],
    )
    check(
        "non-recipient → WRONG_RECIPIENT_KEY",
        not stranger.matched and stranger.reason == "WRONG_RECIPIENT_KEY",
    )

    # The hash-claim binding: the slots transcript digests this item's `hashes`
    # map, so presenting the same envelope under a different hashes map fails
    # the slot-set MAC — before any ciphertext work.
    spliced = ecies_sealed_poe_unwrap(
        envelope=classical.envelope,
        ciphertext=classical.ciphertext,
        hashes={"sha2-256": sha2_256(b"a different claim")},
        recipient_secret_key=x25519_keys[1]["secret_key"],
    )
    check(
        "envelope spliced onto another hash claim → TAMPERED_HEADER",
        not spliced.matched and spliced.reason == "TAMPERED_HEADER",
    )

    # Ciphertext tamper: a flipped byte fails the chunk's Poly1305 tag.
    tampered = bytearray(classical.ciphertext)
    tampered[4] = (tampered[4] + 1) & 0xFF
    torn = ecies_sealed_poe_unwrap(
        envelope=classical.envelope,
        ciphertext=bytes(tampered),
        hashes=hashes,
        recipient_secret_key=x25519_keys[1]["secret_key"],
    )
    check(
        "tampered ciphertext → TAMPERED_CIPHERTEXT",
        not torn.matched and torn.reason == "TAMPERED_CIPHERTEXT",
    )

    # -- Hybrid mlkem768x25519 (X-Wing) path — the recommended default ---------
    # Secure against classical adversaries and harvest-now-decrypt-later
    # quantum adversaries, with X25519's classical security as the floor.
    hybrid_keys = derive_mlkem768x25519_keypair_from_seed(seeds[0])
    hybrid_pub = hybrid_keys["public_key"]
    check("X-Wing recipient public key is 1216 bytes", len(hybrid_pub) == 1216)
    hybrid = ecies_sealed_poe_wrap(
        plaintext=plaintext,
        hashes=hashes,
        recipient_public_keys=[hybrid_pub],
        kem="mlkem768x25519",
    )
    check(
        "hybrid slot carries kem_ct as a single 1120-byte byte string",
        hybrid.envelope.kem == "mlkem768x25519"
        and len(hybrid.envelope.slots) == 1
        and hybrid.envelope.slots[0].kem_ct is not None
        and len(hybrid.envelope.slots[0].kem_ct) == 1120
        and hybrid.envelope.slots[0].epk is None
        and len(hybrid.envelope.slots[0].wrap) == 48,
    )
    hybrid_opened = ecies_sealed_poe_unwrap(
        envelope=hybrid.envelope,
        ciphertext=hybrid.ciphertext,
        hashes=hashes,
        # The X-Wing decapsulation key is the 32-byte secret seed.
        recipient_secret_key=hybrid_keys["secret_seed"],
    )
    check(
        "hybrid unwrap round-trips",
        hybrid_opened.matched and hybrid_opened.plaintext == plaintext,
    )

    # -- Published recipient encodings ------------------------------------------
    # Out-of-band key distribution uses age-style Bech32 strings: ``age1…`` for
    # X25519 recipients, ``age1pqc…`` for X-Wing recipients (a Label 309
    # encoding — deliberately distinct from age's own ``age1pq``).
    age_classical = encode_age_x25519_recipient(x25519_pubs[0])
    age_hybrid = encode_age_xwing_recipient(hybrid_pub)
    print(f"x25519 recipient    : {age_classical}")
    print(f"X-Wing recipient    : {age_hybrid[:40]}… ({len(age_hybrid)} chars)")
    check("classical recipient encodes as age1…", age_classical.startswith("age1"))
    check("hybrid recipient encodes as age1pqc…", age_hybrid.startswith("age1pqc"))

    if failures:
        print(f"\n{failures} check(s) FAILED")
        sys.exit(1)
    print("\nALL sealed-PoE checks PASSED")


if __name__ == "__main__":
    main()
