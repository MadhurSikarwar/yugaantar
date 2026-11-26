"""Builds the real dependencies for one process (owner: c1).

What it does
    ``build_default_dependencies`` connects the service to the real state store
    and, lazily, to the modules owned by c2: ``t4.audit.log`` (the signed,
    hash-chained audit log) and ``t4.crypto.kem`` / ``t4.crypto.proof``.

The audit signer
    The log's ML-DSA key pair belongs to the audit log: ``load_or_create_signer``
    (c2) creates it on first use inside the audit directory and ``AuditLog``
    signs checkpoints with it. We call it while holding the state lock (lock
    order: state first, then audit), so two processes cannot create two keys.
    Honest limit (PRD 4.1): a key stored next to the log cannot protect against
    someone who can rewrite the whole directory; the operator pins the public key
    and the head hash elsewhere (``python -m t4.audit.cli head --out``).

Fail closed, never degrade silently
    If one of those modules is missing or unusable, a ``DependencyError`` is
    raised and the request fails. There is deliberately **no fallback** to a
    weaker or unsigned audit log: a silent downgrade is exactly what an attacker
    (or a broken deployment) would want.
"""
from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType

from t4.api import AuditSink, DependencyError, KemProvider, ProofProvider
from t4.service import Dependencies
from t4.store import FileStore, prepare_state_dir, resolve_state_dir

AUDIT_SUBDIR = "audit"


def _import(name: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ImportError:
        raise DependencyError(f"module unavailable: {name}") from None


def build_default_dependencies(state_dir: Path | None = None) -> Dependencies:
    directory = Path(state_dir) if state_dir is not None else resolve_state_dir()
    store = FileStore(directory)

    def audit_factory() -> AuditSink:
        # Called while the store lock is held (see t4.service), so creating the
        # audit directory and its signing key cannot race. ``store.directory`` is the
        # effective folder (a private subfolder when the configured one is shared);
        # preparing it again is idempotent.
        effective = prepare_state_dir(store.directory)
        module = _import("t4.audit.log")
        audit_dir = effective / AUDIT_SUBDIR
        try:
            signer = module.load_or_create_signer(audit_dir)
            return module.AuditLog(audit_dir, signer)
        except Exception:  # noqa: BLE001 - never leak details of a damaged log or key
            raise DependencyError("audit log unavailable") from None

    def kem_factory() -> KemProvider:
        return _import("t4.crypto.kem")  # the module itself provides ``encapsulate``

    def proof_factory() -> ProofProvider:
        return _import("t4.crypto.proof")  # the module itself provides ``make_proof``

    return Dependencies(
        store=store,
        audit_factory=audit_factory,
        kem_factory=kem_factory,
        proof_factory=proof_factory,
    )


__all__ = ["build_default_dependencies", "AUDIT_SUBDIR"]
