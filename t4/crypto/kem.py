"""ML-KEM-768 key encapsulation (FIPS 203), wrapping ``pqcrypto==0.4.0``.

What it does: creates key pairs, encapsulates a fresh shared secret to a caller's
public key, and decapsulates it. The cryptography itself is done by the library.

Attacks defended against:
- Malformed keys or ciphertexts: type and exact length are checked first, and every
  failure surfaces as ``ValueError`` with a fixed message, so library internals and
  key bytes never reach an error string.
- Invalid public keys: ``pqcrypto`` 0.4.0 accepts any 1184 bytes, so the FIPS 203
  section 7.2 encapsulation-key check (every 12-bit coefficient below q) is applied
  before a key is used. This is input validation, not a cryptographic primitive.

Not covered: a tampered ciphertext does not raise. ML-KEM returns an unrelated
secret instead, so callers must confirm the secret (see ``proof``). We make no claim
about side channels inside the library.
"""

from __future__ import annotations

PUBLIC_KEY_SIZE = 1184
SECRET_KEY_SIZE = 2400
CIPHERTEXT_SIZE = 1088
SHARED_SECRET_SIZE = 32

_Q = 3329
_ENCODED_VECTOR_SIZE = 1152  # 3 polynomials of 384 bytes; the last 32 bytes are a seed


def _require(value: object, size: int, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != size:
        raise ValueError(f"invalid ML-KEM-768 {name}")
    return bytes(value)


def check_public_key(public_key: bytes) -> bytes:
    """Return the key if it passes the FIPS 203 encapsulation-key check.

    Raises ``ValueError`` for a wrong type, wrong length or out-of-range coefficient.
    """
    key = _require(public_key, PUBLIC_KEY_SIZE, "public key")
    for offset in range(0, _ENCODED_VECTOR_SIZE, 3):
        first, middle, last = key[offset], key[offset + 1], key[offset + 2]
        if (first | (middle & 0x0F) << 8) >= _Q or (middle >> 4 | last << 4) >= _Q:
            raise ValueError("invalid ML-KEM-768 public key")
    return key


def keygen() -> tuple[bytes, bytes]:
    """Return a new ``(public_key, secret_key)`` pair."""
    from pqcrypto.kem import ml_kem_768

    public_key, secret_key = ml_kem_768.generate_keypair()
    return bytes(public_key), bytes(secret_key)


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, shared_secret)`` for ``public_key``.

    Raises ``ValueError`` if the key is not a valid ML-KEM-768 public key.
    """
    key = check_public_key(public_key)
    from pqcrypto.kem import ml_kem_768

    try:
        ciphertext, shared_secret = ml_kem_768.encrypt(key)
    except Exception:
        raise ValueError("ML-KEM-768 encapsulation failed") from None
    return bytes(ciphertext), bytes(shared_secret)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Return the 32-byte shared secret. Raises ``ValueError`` on malformed input."""
    key = _require(secret_key, SECRET_KEY_SIZE, "secret key")
    data = _require(ciphertext, CIPHERTEXT_SIZE, "ciphertext")
    from pqcrypto.kem import ml_kem_768

    try:
        shared_secret = ml_kem_768.decrypt(key, data)
    except Exception:
        raise ValueError("ML-KEM-768 decapsulation failed") from None
    return bytes(shared_secret)
