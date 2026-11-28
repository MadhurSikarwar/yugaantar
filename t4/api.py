"""Shared interfaces for every module.

API VERSION: 2  (bump this number and tell all agents when anything changes)

Change log
    2  RotationApi / BackupVaultApi / node interfaces describe the built modules;
       AuditLogApi gained ``alert``; ``StoreFullError`` added. ``tests/unit/test_api_contract.py``
       compares every interface below with the real module whenever it is present.
    1  first version

This module holds only types: dataclasses, errors and ``typing.Protocol``
interfaces. No module implements anything here; each Protocol names the file
that provides the real implementation. Nothing in this file touches the
filesystem or imports ``pqcrypto``.

Why Protocols: the modules were built independently.
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
from typing import Callable, Iterable, Mapping, Protocol, runtime_checkable

API_VERSION = 2

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


class StoreFullError(Track4Error):
    """The new state would be too large to load back, so it was not written.

    Refusing to write keeps the previous (loadable) state intact: the service
    degrades instead of bricking itself.
    """

    category = "store-full"


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
# State store (t4/store.py)
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
# Audit log (t4/audit/log.py)
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
        detail: Mapping[str, str | int | bool] | None = None,
    ) -> dict:
        """Append one entry and flush it. Returns ``{"seq": int, "hash": str}``."""
        ...


class AuditLogApi(AuditSink, Protocol):
    """Full interface of ``t4.audit.log.AuditLog``."""

    def alert(
        self,
        *,
        rule: str,
        explanation: str,
        actor: str = "",
        target: str = "",
        request_id: str = "",
        entries: Iterable[int] = (),
        request_ids: Iterable[str] = (),
        detail: Mapping[str, str | int | bool] | None = None,
    ) -> dict:
        """Record an alert with its triggering entry numbers and request IDs."""
        ...

    def head(self) -> dict: ...  # {"seq", "hash", "sig"}

    def explain(self, request_id: str) -> list[dict]: ...

    def find(self, **match: str) -> list[dict]: ...

    def verify(self, pinned_head: dict | None = None, pinned_public_key: bytes | None = None) -> object: ...


@runtime_checkable
class Signer(Protocol):
    """Signs audit checkpoints (ML-DSA). ``public_key`` is for pinning."""

    public_key: bytes

    def sign(self, message: bytes) -> bytes: ...


# ---------------------------------------------------------------------------
# Crypto (t4/crypto/kem.py and proof.py)
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
# Rotation, backup and the node layer (t4/rotation.py, t4/backup.py, t4/node/*)
# These describe the built modules. Rotation and the
# node functions are module-level functions; the module itself is the provider.
# ---------------------------------------------------------------------------

# A fault hook is called with the name of a step. Tests use it to raise or exit at
# exactly that step, which simulates a crash.
Fault = Callable[[str], None]


class RotationApi(Protocol):
    """``t4.rotation``: functions on a device store (journal PREPARED, COMMITTED, applied)."""

    def begin_rotation(
        self, store: Store, signer: Signer, activate_at: float, fault: Fault = ..., *, now: float | None = None
    ) -> int:
        """Create and commit the next key version locally; returns its version number."""
        ...

    def recover(self, store: Store) -> dict:
        """Finish or undo an interrupted rotation, then return the keyring."""
        ...

    def mark_published(self, store: Store, version: int, activate_at: float) -> None:
        """Record the authority's acceptance and adopt its activation time."""
        ...

    def signing_key(self, store: Store, now: float) -> tuple[int, bytes]:
        """The one key this device may sign with at ``now``: ``(version, secret_key)``."""
        ...

    def revoke_key(self, store: Store, version: int, at: float, vault: "BackupVaultApi | None" = None) -> None:
        """Add a version to the revoked set. There is no way to remove it."""
        ...


class RestoreReportApi(Protocol):
    """What ``t4.backup.RestoreReport`` exposes."""

    used_id: int
    damaged: tuple[str, ...]
    newest_expected_id: int

    @property
    def fell_back(self) -> bool: ...


class BackupVaultApi(Protocol):
    """``t4.backup.Vault``: authenticated backups; the verification key is kept apart from them.

    ``BackupError(message, damaged=())`` (defined in ``t4.backup``) is raised when no backup
    verifies or the vault itself is damaged. ``key_wrap`` / ``key_unwrap`` let the deployment layer
    keep the encryption key in an OS keystore; only the wrapped blob is written then.
    """

    @classmethod
    def create(cls, key_dir: str | Path, backup_dir: str | Path, subject: str, *,
               encrypt: bool = False, key_wrap: Callable[[bytes], bytes] | None = None,
               key_unwrap: Callable[[bytes], bytes] | None = None) -> "BackupVaultApi": ...

    def location(self) -> dict[str, str]: ...

    def record_removal(self, set_name: str, item: str, at: float) -> None: ...

    def backup(self, store: Store, record_name: str, now: float, fault: Fault = ...) -> int: ...

    def restore(self, target: str | Path, record_name: str, fault: Fault = ...) -> RestoreReportApi:
        """Restore into ``target``; safe to run again after a crash. Never drops a newer revocation."""
        ...


class NodeRequestApi(Protocol):
    """``t4.node.request``"""

    def sign_request(self, device_sk: bytes, fields: Mapping[str, object], *, signer: Signer | None = None) -> dict: ...

    def handle_request(self, node: object, signed: Mapping[str, object], now: float) -> Decision: ...

    def respond(self, node: object, signed: Mapping[str, object], now: float) -> dict: ...


class NodeAuthorityApi(Protocol):
    """``t4.node.authority``"""

    def issue_list(self, authority: object, now: float) -> dict: ...


class NodeFreshnessApi(Protocol):
    """``t4.node.freshness``"""

    def accept_list(self, node: object, signed_list: Mapping[str, object], now: float) -> bool:
        """False on a bad signature, an old ``seq`` or a stale ``issued_at``."""
        ...
