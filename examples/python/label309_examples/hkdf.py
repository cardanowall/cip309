# Label 309 v1 reference implementation — HKDF-SHA-256 wrapper.
# Reference: RFC 5869.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_sha256(
    *, ikm: bytes, salt: bytes | None = None, info: bytes | None = None, length: int
) -> bytes:
    if length > 255 * 32:
        raise ValueError(f"length {length} exceeds 255*HashLen=8160 for SHA-256")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or b"",  # RFC 5869 §2.2: empty/None → HashLen zero bytes
        info=info or b"",
    ).derive(ikm)
