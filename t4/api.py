"""Shared interfaces for every module (owner: c1; changes go through c1).

API VERSION: 1  (bump this number and tell all agents when anything changes)

This module holds only types: dataclasses, errors and ``typing.Protocol``
interfaces. No module implements anything here; each Protocol names the file
that provides the real implementation. Nothing in this file touches the
filesystem or imports ``pqcrypto``.

Why Protocols: c1, c2, c3 and c4 work on separate branches at the same time.
Each side codes against these shapes and uses a test double until the real
module arrives, so the final merge only has to connect things that already fit.

Attacks this layer helps defend against: none directly. Its job is to make the
*boundaries* explicit so that validation, authorization and logging cannot be
bypassed by a module that quietly changes a contract.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, runtime_checkable

API_VERSION = 1

# ---------------------------------------------------------------------------
# Errors. Every one of these is mapped to a generic failure by the adapter:
# no message ever reaches stdout, and stderr never carries request data.
# ---------------------------------------------------------------------------


class Track4Error(Exception):
    """Base class. ``category`` is a short fixed label, never request data."""

    category = "error"


class InputError(Track4Error):
    """The request is malformed (size, encoding, shape, types, Base64, ...)."""

    category = "invalid-input"


class IntegrityError(Track4Error):
    """Stored state failed its integrity check. Always fail closed."""

    category = "integrity"


class StoreBusyError(Track4Error):
    """The state lock could not be taken in time."""

    category = "busy"


class DependencyError(Track4Error):
    """A required module (audit log, crypto) is missing or unusable."""

    category = "dependency"


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """The outcome of one authorization check.

    ``reason`` is internal: it goes to the audit log and never to the caller.
    ``rule`` is a stable rule ID such as ``POL-REVOKED``.
    """

    allow: bool
    reason: str
    rule: str
    request_id: str
    epoch: int


# ---------------------------------------------------------------------------
# State store (c1: t4/store.py)
# ---------------------------------------------------------------------------


class Txn(Protocol):
    """A view of the state held under the exclusive lock.

    ``get`` returns a deep copy (or ``None``); ``put`` is buffered. ``commit``
    makes everything buffered durable (atomic replace + fsync) and may be called
    early; leaving the ``with`` block without an exception commits implicitly.
    """

    version: int

    def get(self, name: str) -> dict | None: ...

    def put(self, name: str, obj: dict) -> None: ...

    def commit(self) -> None: ...


class Store(Protocol):
    def locked(self) -> AbstractContextManager[Txn]:
        """Exclusive lock, integrity-checked load, atomic commit.

        Lock order across the whole project: **store lock first, then audit
        lock**. Never the other way round.
        """
        ...


# ---------------------------------------------------------------------------
# Audit log (c2: t4/audit/log.py)
# ---------------------------------------------------------------------------


class AuditSink(Protocol):
    """The part of the audit log that the request path needs."""

    def append(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        decision: str,
        rule: str,
        request_id: str,
        detail: Mapping[str, str | int | bool],
    ) -> dict:
        """Append one entry and flush it. Returns ``{"seq": int, "hash": str}``."""
        ...


class AuditLogApi(AuditSink, Protocol):
    """Full interface of ``t4.audit.log.AuditLog`` (PRD 5.1)."""

    def head(self) -> dict: ...  # {"seq", "hash", "sig"}

    def explain(self, request_id: str) -> list[dict]: ...

    def find(self, **match: str) -> list[dict]: ...

    def verify(self, pinned_head: dict | None = None) -> object: ...


@runtime_checkable
class Signer(Protocol):
    """Signs audit checkpoints (ML-DSA). ``public_key`` is for pinning."""

    public_key: bytes

    def sign(self, message: bytes) -> bytes: ...


# ---------------------------------------------------------------------------
# Crypto (c2: t4/crypto/kem.py and proof.py)
# ---------------------------------------------------------------------------

ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SHARED_SECRET_BYTES = 32


class KemProvider(Protocol):
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, shared_secret)``; raise ``ValueError`` on a bad key."""
        ...


class ProofProvider(Protocol):
    def make_proof(self, shared_secret: bytes, challenge: bytes, stored_body: bytes) -> str:
        """Lowercase hex HMAC-SHA256 keyed by ``shared_secret`` over ``challenge + body``."""
        ...


# ---------------------------------------------------------------------------
# Rotation and backup (c3: t4/rotation.py, t4/backup.py)
# Signatures proposed by c1; c3 may ask for changes through a request file.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecoveryReport:
    action: str  # "none" | "rolled_back" | "rolled_forward"
    rotation_id: str | None
    active_key_version: int


@dataclass(frozen=True)
class BackupInfo:
    path: Path
    created_epoch: int
    verified_by: str  # name of the verification key, never its value


@dataclass(frozen=True)
class RestoreReport:
    ok: bool
    reason: str  # fixed label, e.g. "verified", "bad-tag", "truncated"
    restored_epoch: int | None


class RotationApi(Protocol):
    def prepare(self, *, device_id: str, new_public_key: bytes, activation_time: float) -> str:
        """Journal ``PREPARED``; returns the rotation ID."""
        ...

    def commit(self, rotation_id: str) -> None:
        """Single atomic pointer swap to the new key version (the commit point)."""
        ...

    def recover(self) -> RecoveryReport:
        """Run on every load: roll back without a commit marker, forward with one."""
        ...


class BackupApi(Protocol):
    def create(self, destination: Path) -> BackupInfo: ...

    def restore(self, source: Path, *, verification_key: bytes) -> RestoreReport:
        """Verify before use; never remove a revocation newer than the backup."""
        ...


# ---------------------------------------------------------------------------
# Node layer (c3: t4/node/*). Signatures from PRD 5.1.
# ---------------------------------------------------------------------------


class NodeApi(Protocol):
    def sign_request(self, device_sk: bytes, fields: Mapping[str, object]) -> dict: ...

    def handle_request(self, node: object, signed: Mapping[str, object], now: float) -> Decision: ...

    def issue_list(self, authority: object, now: float) -> dict: ...

    def accept_list(self, node: object, signed_list: Mapping[str, object], now: float) -> bool:
        """False on a bad signature, an old ``seq`` or a stale ``issued_at``."""
        ...
