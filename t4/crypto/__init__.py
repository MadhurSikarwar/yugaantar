"""Thin wrappers around vetted post-quantum and standard-library cryptography.

Modules: ``kem`` (ML-KEM-768), ``sig`` (ML-DSA-65), ``proof`` (HMAC-SHA-256 proof
for ``protected_read``). Nothing is imported here on purpose: ``pqcrypto`` is only
loaded by the code paths that need it, which keeps process start-up fast.
No cryptographic primitive is implemented in this package.

``describe()`` reports what is actually in use (names, standards, sizes read from the
wrapper modules, library version read from the installed package), so tools such as the
web console never keep their own copy of these facts.
"""


def describe() -> list[dict]:
    """The primitives this package uses, with sizes from the code and versions from the install."""
    import hashlib
    import hmac
    from importlib import metadata

    from t4.crypto import kem, proof, sig

    try:
        pqcrypto = f"pqcrypto {metadata.version('pqcrypto')}"
    except metadata.PackageNotFoundError:
        pqcrypto = "pqcrypto (not installed)"
    digest = hashlib.sha256().digest_size
    return [
        {"name": "ML-KEM-768", "standard": "FIPS 203", "library": pqcrypto,
         "used_for": "Key encapsulation in the protected read",
         "sizes_bytes": {"public_key": kem.PUBLIC_KEY_SIZE, "secret_key": kem.SECRET_KEY_SIZE,
                         "ciphertext": kem.CIPHERTEXT_SIZE, "shared_secret": kem.SHARED_SECRET_SIZE}},
        {"name": "ML-DSA-65", "standard": "FIPS 204", "library": pqcrypto,
         "used_for": "Device requests, revocation lists and audit checkpoints",
         "sizes_bytes": {"public_key": sig.PUBLIC_KEY_SIZE, "secret_key": sig.SECRET_KEY_SIZE,
                         "signature": sig.SIGNATURE_SIZE}},
        {"name": "SHA-256", "standard": "FIPS 180-4", "library": f"Python {hashlib.__name__}",
         "used_for": "The audit log's hash chain", "sizes_bytes": {"digest": digest}},
        {"name": "HMAC-SHA256", "standard": "RFC 2104", "library": f"Python {hmac.__name__}",
         "used_for": "The protected-read proof and state and backup integrity tags",
         "sizes_bytes": {"key": proof.SHARED_SECRET_SIZE, "tag": digest}},
    ]
