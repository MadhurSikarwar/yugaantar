"""The ``protected_read`` proof: HMAC-SHA-256 (RFC 2104) from the standard library.

What it does: computes the lowercase hex HMAC of ``challenge + stored_body`` (that
order, no separator), keyed by the ML-KEM shared secret, as the adapter contract
requires. It shows the caller that the responder encapsulated to their key and holds
the body, without sending the body.

Attacks defended against:
- Timing attacks on comparison: ``verify_proof`` uses ``hmac.compare_digest``.
- Hostile input: ``verify_proof`` never raises; anything malformed is ``False``.

Not covered: the contract's format has no separator between challenge and body, so
the proof does not bind where one ends and the other begins. It is also not
encryption and says nothing about who the caller is.
"""

from __future__ import annotations

import hashlib
import hmac

SHARED_SECRET_SIZE = 32


def make_proof(shared_secret: bytes, challenge: bytes, stored_body: bytes) -> str:
    """Return the hex proof. Raises ``ValueError`` on wrong types or secret length."""
    if not isinstance(shared_secret, (bytes, bytearray)) or len(shared_secret) != SHARED_SECRET_SIZE:
        raise ValueError("invalid shared secret")
    if not isinstance(challenge, (bytes, bytearray)) or not isinstance(stored_body, (bytes, bytearray)):
        raise ValueError("challenge and body must be bytes")
    message = bytes(challenge) + bytes(stored_body)
    return hmac.new(bytes(shared_secret), message, hashlib.sha256).hexdigest()


def verify_proof(shared_secret: bytes, challenge: bytes, stored_body: bytes, proof: str) -> bool:
    """Return ``True`` only if ``proof`` matches exactly. Never raises."""
    try:
        if not isinstance(proof, str):
            return False
        expected = make_proof(shared_secret, challenge, stored_body)
        return hmac.compare_digest(expected.encode("ascii"), proof.encode("ascii"))
    except Exception:
        return False
