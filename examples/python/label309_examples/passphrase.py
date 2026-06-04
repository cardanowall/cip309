# Label 309 v1 reference implementation — passphrase normalization.
#
# The sealed-PoE passphrase path (see ecies_passphrase_unwrap) derives the
# content-encryption key from a user passphrase via Argon2id. Before the KDF
# runs, the passphrase is normalized so the same human-typed secret produces
# the same bytes across platforms and input methods:
#   NFKC Unicode normalization -> collapse internal whitespace runs to a single
#   ASCII space -> trim leading/trailing whitespace. Case is preserved.

import re
import unicodedata

_WHITESPACE_RE = re.compile(r"\s+")


def normalize_passphrase(input_str: str) -> str:
    """NFKC + collapse-whitespace + trim. Case is preserved."""
    return _WHITESPACE_RE.sub(" ", unicodedata.normalize("NFKC", input_str)).strip()
