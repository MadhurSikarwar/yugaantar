"""Builds the real dependencies for one process (owner: c1).

What it does
    ``build_default_dependencies`` connects the service to the real state store
    and, lazily, to the modules owned by c2: ``t4.audit.log.AuditLog``,
    ``t4.crypto.kem``, ``t4.crypto.proof`` and ``t4.crypto.sig``.

Fail closed, never degrade silently
    If one of those modules is missing or unusable, a ``DependencyError`` is
    raised and the request fails. There is deliberately **no fallback** to a
    weaker audit log or an unsigned log: a silent downgrade is exactly what an
    attacker (or a broken deployment) would want. (If c2 reports that ML-DSA is
    unavailable, this is the one place to change, on purpose.)

The audit signing key
    Audit checkpoints are signed with ML-DSA. The key pair is created on first
    use and kept in ``audit-signing.json`` inside the state directory (mode
    0600), always while the state lock is held, so two processes cannot create
    two different keys. Honest limit (PRD 4.1): a key stored next to the log
    cannot protect against someone who can rewrite the whole directory; the
    operator pins the public key and the head hash elsewhere.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from types import ModuleType

from t4.api import AuditSink, DependencyError, KemProvider, ProofProvider, Signer
from t4.service import Dependencies
from t4.store import FileStore, atomic_write_bytes, prepare_state_dir, resolve_state_dir

SIGNING_KEY_FILE = "audit-signing.json"
AUDIT_SUBDIR = "audit"


class _FileSigner:
    """ML-DSA signer backed by a key pair stored in the state directory."""

    def __init__(self, public_key: bytes, secret_key: bytes, sign_function) -> None:
        self.public_key = public_key
        self._secret_key = secret_key
        self._sign = sign_function

    def sign(self, message: bytes) -> bytes:
        return self._sign(self._secret_key, message)


def _import(name: str) -> ModuleType:
    import importlib

    try:
        return importlib.import_module(name)
    except ImportError:
        raise DependencyError(f"module unavailable: {name}") from None


def load_audit_signer(state_dir: Path) -> Signer:
    """Load or create the audit signing key pair (call while holding the state lock)."""
    sig = _import("t4.crypto.sig")
    path = state_dir / SIGNING_KEY_FILE
    try:
        if not path.exists():
            public_key, secret_key = sig.sig_keygen()
            payload = json.dumps(
                {
                    "public_key": base64.b64encode(public_key).decode("ascii"),
                    "secret_key": base64.b64encode(secret_key).decode("ascii"),
                }
            ).encode("ascii")
            atomic_write_bytes(path, payload)
        data = json.loads(path.read_text(encoding="ascii"))
        public_key = base64.b64decode(data["public_key"], validate=True)
        secret_key = base64.b64decode(data["secret_key"], validate=True)
    except DependencyError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise DependencyError("audit signing key unavailable") from None
    return _FileSigner(public_key, secret_key, sig.sign)


def build_default_dependencies(state_dir: Path | None = None) -> Dependencies:
    directory = Path(state_dir) if state_dir is not None else resolve_state_dir()
    store = FileStore(directory)

    def audit_factory() -> AuditSink:
        # Called while the store lock is held (see t4.service), so creating the
        # key file and the audit directory cannot race.
        prepare_state_dir(directory)
        module = _import("t4.audit.log")
        signer = load_audit_signer(directory)
        try:
            return module.AuditLog(directory / AUDIT_SUBDIR, signer)
        except DependencyError:
            raise
        except Exception:  # noqa: BLE001 - never leak details of a damaged log
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


__all__ = ["build_default_dependencies", "load_audit_signer", "AUDIT_SUBDIR", "SIGNING_KEY_FILE"]
