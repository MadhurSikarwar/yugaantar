"""Thin wrappers around vetted post-quantum and standard-library cryptography.

Modules: ``kem`` (ML-KEM-768), ``sig`` (ML-DSA-65), ``proof`` (HMAC-SHA-256 proof
for ``protected_read``). Nothing is imported here on purpose: ``pqcrypto`` is only
loaded by the code paths that need it, which keeps process start-up fast.
No cryptographic primitive is implemented in this package.
"""
