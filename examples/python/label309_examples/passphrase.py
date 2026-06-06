# Label 309 reference implementation — passphrase normalization
# (the `cardano-poe-pw-norm-v1` profile).
#
# The sealed-PoE passphrase path (see ecies_passphrase_unwrap) derives the
# content-encryption key from a user passphrase via Argon2id. Before the KDF
# runs, the passphrase is normalized so the same human-typed secret produces the
# same bytes across platforms and input methods:
#   NFKC Unicode normalization -> collapse every maximal run of `White_Space`
#   codepoints to a single U+0020 -> trim leading/trailing space. Case is
#   preserved. The profile identifier is pinned into the content AAD (never on
#   the wire) so a verifier proves the CEK was derived under exactly this profile.

import unicodedata

# The Unicode `White_Space` property set — exactly these 25 codepoints. The
# profile collapses every maximal run of these to a single U+0020. This is
# spelled out explicitly rather than via the `\s` regex class, which matches a
# different set (e.g. it excludes U+0085 NEL) and would otherwise derive a
# different CEK from the same passphrase and break cross-implementation
# decryption.
_WHITE_SPACE: frozenset[str] = frozenset(
    chr(cp)
    for cp in (
        0x0009,
        0x000A,
        0x000B,
        0x000C,
        0x000D,
        0x0020,
        0x0085,
        0x00A0,
        0x1680,
        0x2000,
        0x2001,
        0x2002,
        0x2003,
        0x2004,
        0x2005,
        0x2006,
        0x2007,
        0x2008,
        0x2009,
        0x200A,
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    )
)


def normalize_passphrase(input_str: str) -> str:
    """NFKC + collapse `White_Space` runs to a single U+0020 + trim. Case is
    preserved (no ASCII case-fold). Producer and verifier MUST apply identical
    normalization or the derived CEK will not match."""
    nfkc = unicodedata.normalize("NFKC", input_str)
    out: list[str] = []
    in_run = False
    for ch in nfkc:
        if ch in _WHITE_SPACE:
            if not in_run:
                out.append(" ")
                in_run = True
        else:
            out.append(ch)
            in_run = False
    return "".join(out).strip(" ")
