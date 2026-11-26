"""ML-DSA-65 digital signatures (FIPS 204), wrapping ``pqcrypto==0.4.0``.

What it does: creates key pairs, signs messages and verifies signatures. Used for
audit-log checkpoints, device requests and revocation lists.

Attacks defended against:
- Forged or altered messages and signatures: ``verify`` returns ``False``.
- Crashes from hostile input: the library raises on wrong key lengths, over-long
  signatures and wrong types; ``verify`` checks these first and never raises, so a
  bad signature can only ever mean "no" (fail closed).
- Leaks through errors: signing failures raise ``ValueError`` with a fixed message.

Not covered: signatures say who held the key, not when a message was made. Callers
that need freshness or domain separation must put a type, sequence or nonce inside
the signed bytes. Signing is randomized, so signature bytes differ on every call.
"""

from __future__ import annotations

PUBLIC_KEY_SIZE = 1952
SECRET_KEY_SIZE = 4032
SIGNATURE_SIZE = 3309


def sig_keygen() -> tuple[bytes, bytes]:
    """Return a new ``(public_key, secret_key)`` pair."""
    from pqcrypto.sign import ml_dsa_65

    public_key, secret_key = ml_dsa_65.generate_keypair()
    return bytes(public_key), bytes(secret_key)


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Return the signature of ``message``. Raises ``ValueError`` on bad input."""
    if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError("invalid ML-DSA-65 secret key")
    if not isinstance(message, (bytes, bytearray)):
        raise ValueError("message must be bytes")
    from pqcrypto.sign import ml_dsa_65

    try:
        signature = ml_dsa_65.sign(bytes(secret_key), bytes(message))
    except Exception:
        raise ValueError("ML-DSA-65 signing failed") from None
    return bytes(signature)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` only for a valid signature. Never raises."""
    try:
        if not all(isinstance(v, (bytes, bytearray)) for v in (public_key, message, signature)):
            return False
        if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
            return False
        from pqcrypto.sign import ml_dsa_65

        return ml_dsa_65.verify(bytes(public_key), bytes(message), bytes(signature)) is True
    except Exception:
        return False
