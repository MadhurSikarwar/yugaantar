"""Crash-safe rotation of a device's signing key.

Local journal: PREPARED, then COMMITTED, then applied.

* PREPARED: the new key pair is saved to the side. A crash here rolls back.
* COMMITTED: one atomic write of the commit marker. A crash after it rolls
  forward.
* Applied: one atomic write adds the key and moves the ``current`` pointer.

``recover`` runs on every load. Revoked key versions live in a separate set
that only grows. The new key signs nothing until the authority has accepted its
publication; from the activation time C the old key is no longer used (no grace
period).

``fault`` is called after each durable step so tests can stop the process there.

What it defends against: a crash leaving no usable key or two conflicting ones,
and a revoked key coming back.
"""
from __future__ import annotations

from typing import Callable

from t4.node.common import NodeError, Signer, b64e, check_int, check_time
from t4.node.state import FileStore, LockTimeout, file_lock

RECORD = "keyring"
Fault = Callable[[str], None]


def no_fault(step: str) -> None:
    return None


def new_keyring(device_id: str, owner: str, pk: bytes, sk: bytes) -> dict:
    return {"device_id": device_id, "owner": owner, "current": 1, "journal": None,
            "revoked_keys": {},
            "keys": {"1": {"pk": b64e(pk), "sk": b64e(sk), "activate_at": 0,
                           "published": True}}}


def _rotation_lock(store: FileStore, timeout: float = 15.0):
    return file_lock(store.directory / "rotation.lock", timeout)


def _update(store: FileStore, change: Callable[[dict], None]) -> dict:
    with store.locked() as txn:
        ring = txn.get(RECORD)
        if ring is None:
            raise NodeError("not a device directory")
        change(ring)
        txn.put(RECORD, ring)
    return ring


def _read(store: FileStore) -> dict:
    with store.locked() as txn:
        ring = txn.get(RECORD)
    if ring is None:
        raise NodeError("not a device directory")
    return ring


def _apply(ring: dict) -> None:
    journal = ring["journal"]
    ring["keys"][str(journal["version"])] = journal["key"]
    ring["current"] = journal["version"]
    ring["journal"] = None


def _recover_locked(store: FileStore) -> None:
    journal = _read(store)["journal"]
    if journal is None:
        return
    if journal["state"] == "COMMITTED":
        _update(store, _apply)
    else:
        _update(store, lambda ring: ring.update(journal=None))


def recover(store: FileStore) -> dict:
    """Finish or undo an interrupted rotation, then return the keyring."""
    ring = _read(store)
    if ring["journal"] is None:
        return ring
    try:
        # A live rotation holds this lock; a crashed one has released it.
        with _rotation_lock(store, timeout=0):
            _recover_locked(store)
    except LockTimeout:
        pass
    return _read(store)


def begin_rotation(store: FileStore, signer: Signer, activate_at: float,
                   fault: Fault = no_fault, *, now: float | None = None) -> int:
    """Create and commit the next key version locally. Not yet published."""
    check_time(activate_at)
    with _rotation_lock(store):
        _recover_locked(store)
        ring = _read(store)
        latest = ring["keys"][str(ring["current"])]
        if not latest["published"]:
            raise NodeError("a rotation is already waiting to be published")
        if activate_at <= latest["activate_at"] or (
                now is not None and latest["activate_at"] > now):
            raise NodeError("an earlier rotation has not activated yet")
        version = ring["current"] + 1
        pk, sk = signer.sig_keygen()
        key = {"pk": b64e(pk), "sk": b64e(sk), "activate_at": activate_at, "published": False}
        _update(store, lambda r: r.update(
            journal={"state": "PREPARED", "version": version, "key": key}))
        fault("prepared")
        _update(store, lambda r: r["journal"].update(state="COMMITTED"))
        fault("committed")
        _update(store, _apply)
        fault("applied")
    return version


def reschedule(store: FileStore, version: int, activate_at: float) -> None:
    """Move C for a key the authority has not accepted yet."""
    check_time(activate_at)

    def change(ring: dict) -> None:
        key = ring["keys"][str(version)]
        if key["published"]:
            raise NodeError("a published activation time cannot change")
        key["activate_at"] = activate_at

    _update(store, change)


def mark_published(store: FileStore, version: int, activate_at: float) -> None:
    """Record the authority's acceptance, adopting its activation time."""
    _update(store, lambda r: r["keys"][str(version)].update(
        published=True, activate_at=activate_at))


def revoke_key(store: FileStore, version: int, at: float, vault=None) -> None:
    """Add a version to the revoked set. There is no way to remove it."""
    check_int(version)
    check_time(at)
    if vault is not None:  # Vault first: an extra revocation is safe, a lost one is not.
        vault.record_removal("revoked_keys", str(version), at)
    _update(store, lambda r: r["revoked_keys"].setdefault(str(version), at))


def signing_key(store: FileStore, now: float) -> tuple[int, bytes]:
    """The one key this device may sign with at ``now``."""
    from t4.node.common import b64d

    ring = recover(store)
    usable = [int(v) for v, key in ring["keys"].items()
              if key["published"] and key["activate_at"] <= now]
    if not usable:
        raise NodeError("no active key")
    version = max(usable)
    if str(version) in ring["revoked_keys"]:
        raise NodeError("the active key is revoked")
    return version, b64d(ring["keys"][str(version)]["sk"])
