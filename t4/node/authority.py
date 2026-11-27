"""The authority: the only place that enrolls, rotates, revokes and grants.

It holds its own ML-DSA key in its own state directory and publishes signed,
numbered revocation lists that nodes use to decide requests.

Timing rule behind the freshness bound : a revocation takes effect at
``max(now, newest list date)``. So no list dated after the revocation time can
omit it. The same rule applies to rotation announcements.

What it defends against: re-enrolling a revoked device ID or a previously used
key, activating a new key before every serving node can know it, and changes
that leave no trace (each one goes into the hash-chained key-event log).

Trust: whoever can run the authority controls identities. These calls do not
authenticate the operator.
"""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import Any

from t4.node.common import (KeyLog, NodeError, Signer, b64d, b64e, canonical, check_int,
                            check_text, check_time, require_record, signed_envelope)
from t4.node.state import FileStore

LIST_TYPE = "revocation_list"
LIST_FIELDS = frozenset({"type", "seq", "issued_at", "devices", "revoked_devices",
                         "revoked_actors", "grants"})
RECORD = "authority"


def check_public_key(public_key: str, expected_size: int | None = None) -> None:
    """Reject keys that cannot be this signature scheme's keys.

    ``expected_size`` is the signer's real public-key size (the real ML-DSA-65 wrapper declares
    ``PUBLIC_KEY_SIZE``); a key of any other size can never verify a request, so enrolling it
    would only break that device. A signer that declares no size (a test double) keeps the
    generic bound.
    """
    size = len(b64d(public_key))
    if expected_size is not None:
        if size != expected_size:
            raise NodeError("invalid public key")
    elif not 0 < size <= 8192:
        raise NodeError("invalid public key")


def grant_key(actor: str, asset: str) -> str:
    return canonical([actor, asset]).decode("ascii")


class Authority:
    def __init__(self, directory: str | Path, signer: Signer, log: KeyLog) -> None:
        self.store = FileStore(directory)
        self.signer = signer
        self.log = log

    @classmethod
    def create(cls, directory: str | Path, signer: Signer, log: KeyLog, *,
               freshness: float = 60.0, skew: float = 2.0,
               vault: dict[str, str] | None = None) -> "Authority":
        """``freshness`` is T and ``skew`` is s. ``vault`` names the backup vault."""
        if check_time(freshness) <= 0:
            raise NodeError("T must be positive")
        check_time(skew)
        pk, sk = signer.sig_keygen()
        FileStore.create(directory, {RECORD: {
            "pk": b64e(pk), "sk": b64e(sk), "T": freshness, "s": skew, "vault": vault,
            "list_seq": 0, "last_issued_at": 0, "devices": {},
            "revoked_devices": {}, "revoked_actors": {}, "grants": {}}})
        return cls(directory, signer, log)

    def _record(self) -> dict:
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
        if record is None:
            raise NodeError("not an authority directory")
        return record

    @property
    def public_key(self) -> bytes:
        return b64d(self._record()["pk"])

    @property
    def bounds(self) -> tuple[float, float]:
        """(T, s)."""
        record = self._record()
        return record["T"], record["s"]

    def _event(self, action: str, target: str, rule: str, detail: dict, *,
               identity: object = None) -> None:
        """Log a key event. With ``identity`` the event is logged once per identity.

        ``identity`` is data that stably names the operation (for example device, key version and
        public key). The request id is derived from it, and a log that supports ``append_once``
        writes it only if no entry with that id exists, so retrying an operation that was
        interrupted after this entry but before its state was saved cannot log it twice. A log
        without ``append_once`` (a test double) just appends.
        """
        once = identity is not None
        request_id = (f"{action}-{hashlib.sha256(canonical(identity)).hexdigest()[:32]}"
                      if once else secrets.token_hex(16))
        write = getattr(self.log, "append_once", None) if once else None
        write = write if callable(write) else self.log.append
        write(actor="authority", action=action, target=target, decision="allow",
              rule=rule, request_id=request_id, detail=detail)

    def _try_reconcile(self) -> None:
        """Best effort: write queued key events; a log that still fails never blocks the caller."""
        try:
            if self._record().get("pending_events"):
                self.reconcile()
        except Exception:  # noqa: BLE001 - the events stay queued and visible via pending_events()
            pass

    def _revoke_in_vault(self, record: dict, set_name: str, item: str, at: float) -> None:
        if record["vault"]:
            from t4.backup import Vault

            Vault(**record["vault"]).record_removal(set_name, item, at)

    def _rotation_in_vault(self, record: dict, device: dict, entry: dict) -> None:
        if record["vault"]:
            from t4.backup import Vault

            try:
                Vault(**record["vault"]).record_rotation(device["keys"][0]["public_key"], entry)
            except OSError:
                raise NodeError("the rotation could not be recorded in the vault") from None

    # -- devices ---------------------------------------------------------

    def enroll(self, device_id: str, owner: str, public_key: str, now: float) -> None:
        check_text(device_id)
        check_text(owner)
        check_public_key(public_key, getattr(self.signer, "PUBLIC_KEY_SIZE", None))
        check_time(now)
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            if device_id in record["devices"] or device_id in record["revoked_devices"]:
                raise NodeError("device ID was already used")
            if owner in record["revoked_actors"]:
                raise NodeError("actor is revoked")
            if any(key["public_key"] == public_key
                   for device in record["devices"].values() for key in device["keys"]):
                raise NodeError("public key was already used")
            record["devices"][device_id] = {"owner": owner, "keys": [
                {"version": 1, "public_key": public_key, "activate_at": 0}]}
            # Log first: if the log fails, nothing is enrolled.
            self._event("enroll", device_id, "KEY-ENROLL", {"owner": owner, "version": 1},
                        identity=[device_id, owner, public_key])
            txn.put(RECORD, record)

    def publish_rotation(self, device_id: str, version: int, public_key: str,
                         activate_at: float, now: float) -> float:
        """Publish a new key. Returns the activation time C that is in force.

        Repeating a publication that already succeeded returns the stored C, so
        a device that crashed before hearing the answer can safely retry.
        """
        check_text(device_id)
        check_int(version)
        check_public_key(public_key, getattr(self.signer, "PUBLIC_KEY_SIZE", None))
        check_time(activate_at)
        check_time(now)
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            device = record["devices"].get(device_id)
            if device is None or device_id in record["revoked_devices"] \
                    or device["owner"] in record["revoked_actors"]:
                raise NodeError("device cannot rotate")
            for key in device["keys"]:
                if key["version"] == version and key["public_key"] == public_key:
                    return key["activate_at"]
            newest = device["keys"][-1]
            if version != newest["version"] + 1:
                raise NodeError("unexpected key version")
            if any(key["public_key"] == public_key
                   for other in record["devices"].values() for key in other["keys"]):
                raise NodeError("public key was already used")
            announced = max(now, record["last_issued_at"])
            if newest["activate_at"] > announced:
                raise NodeError("an earlier rotation has not activated yet")
            if not activate_at > announced + record["T"] + record["s"]:
                raise NodeError("activation time must be more than T + s ahead")
            entry = {"version": version, "public_key": public_key, "activate_at": activate_at}
            device["keys"].append(entry)
            # Vault first: if it cannot record the new key, nothing is published, because a
            # later restore would silently make the replaced key current again.
            self._rotation_in_vault(record, device, entry)
            detail = {"owner": device["owner"], "version": version,
                      "activate_at": repr(activate_at),
                      "key_sha256": hashlib.sha256(b64d(public_key)).hexdigest()}
            logged = self._logged_rotation(device_id, version, public_key)
            if logged is None or logged == repr(activate_at):
                # The one logical rotation event (exactly once, also across retries).
                self._event("rotate", device_id, "KEY-ROTATE", detail,
                            identity=[device_id, version, public_key])
            else:
                # An earlier attempt logged this rotation with a cutoff that was never committed
                # (interrupted after the audit entry, before the authority state was saved) and the
                # device has since rescheduled. Signed history is never edited: the committed
                # cutoff is recorded as an explicit, once-only reschedule entry that names the
                # cutoff it replaces, so audit evidence and committed state agree.
                self._event("rotate_reschedule", device_id, "KEY-ROTATE-RESCHEDULED",
                            {**detail, "replaces_activate_at": logged},
                            identity=[device_id, version, public_key, repr(activate_at)])
            txn.put(RECORD, record)
        return activate_at

    def _logged_rotation(self, device_id: str, version: int, public_key: str) -> str | None:
        """The ``activate_at`` the newest rotation entry for this key version records, if any.

        Looks at the once-only rotation entry and any later reschedule entries for the same key.
        A log without ``find`` (a test double) reports nothing.
        """
        find = getattr(self.log, "find", None)
        if not callable(find):
            return None
        request_id = f"rotate-{hashlib.sha256(canonical([device_id, version, public_key])).hexdigest()[:32]}"
        found = find(request_id=request_id)
        if not found:
            return None
        newest = found[-1]["detail"].get("activate_at")
        key_sha = hashlib.sha256(b64d(public_key)).hexdigest()
        for entry in find(action="rotate_reschedule", target=device_id):
            if entry["detail"].get("key_sha256") == key_sha and entry["detail"].get("version") == version:
                newest = entry["detail"].get("activate_at")
        return newest

    def revoke_device(self, device_id: str, now: float) -> float:
        """Returns the effective revocation time r."""
        return self._revoke("revoked_devices", device_id, now, "revoke_device",
                            "KEY-REVOKE-DEVICE")

    def revoke_actor(self, actor: str, now: float) -> float:
        return self._revoke("revoked_actors", actor, now, "revoke_actor", "KEY-REVOKE-ACTOR")

    def _revoke(self, set_name: str, item: str, now: float, action: str, rule: str) -> float:
        check_text(item)
        check_time(now)
        failure: Exception | None = None
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            at = record[set_name].get(item, max(now, record["last_issued_at"]))
            record[set_name][item] = at
            # The key event is queued in the same atomic write as the revocation, so the revocation
            # is in force at once and its record can never be lost: it is written below, or by the
            # next authority operation that can reach the log (``reconcile``).
            _queue_event(record, action, item, rule, {"effective_at": repr(at)}, [action, item, repr(at)])
            txn.put(RECORD, record)
            # Vault before the save: an extra removal there is safe, a missing one is not.
            # A revocation persists even if the vault or the log fails.
            try:
                self._revoke_in_vault(record, set_name, item, at)
            except Exception as error:
                failure = error
        try:
            self.reconcile()
        except Exception as error:
            failure = error
        if failure is not None:
            raise NodeError("revoked, but recording it in the vault or log failed; the log entry "
                            "is queued and will be written by the next authority operation") from failure
        return at

    def pending_events(self) -> int:
        """How many key events are in force but not yet in the log (degraded logging)."""
        return len(self._record().get("pending_events", []))

    def reconcile(self) -> int:
        """Write queued key events to the log, oldest first, each exactly once. Returns how many.

        Idempotent: each queued event carries the identity it was created with, and is written with
        ``append_once``, so a crash between the write and the queue update cannot log it twice.
        Raises if the log still cannot be written (the rest stays queued).
        """
        written = 0
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            queue = record.get("pending_events", [])
            try:
                while queue:
                    event = queue[0]
                    self._event(event["action"], event["target"], event["rule"], event["detail"],
                                identity=event["identity"])
                    queue.pop(0)
                    written += 1
            finally:
                if written:
                    record["pending_events"] = queue
                    txn.put(RECORD, record)
        return written

    # -- permission grants  ----------------------------------------

    def grant(self, actor: str, asset: str, now: float, *, approval_id: str = "",
              granted_by: str = "authority") -> None:
        """Give an actor read access. A grant without an approval ID is allowed
        here on purpose: spotting it is the detector's job."""
        check_text(actor)
        check_text(asset)
        check_text(granted_by)
        check_time(now)
        if approval_id:
            check_text(approval_id)
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            if actor in record["revoked_actors"]:
                raise NodeError("actor is revoked")
            key = grant_key(actor, asset)
            record["grants"][key] = {"actor": actor, "asset": asset, "approval_id": approval_id}
            # Each (actor, asset) pair has its own grant counter, saved with the state. The log entry
            # is written first, so a crash before the save leaves the counter unchanged and a retry
            # logs the same entry once, even if other grants were made in between. A later,
            # deliberate re-grant (after an ungrant) gets the next number and its own entry.
            counts = record.setdefault("grant_counts", {})
            number = int(counts.get(key, 0)) + 1
            counts[key] = number
            self._event("grant", asset, "PERM-GRANT", {
                "subject": actor, "approval_id": approval_id, "granted_by": granted_by},
                identity=["grant", actor, asset, approval_id, number])
            txn.put(RECORD, record)

    def ungrant(self, actor: str, asset: str, now: float, *, granted_by: str = "authority") -> None:
        check_text(actor)
        check_text(asset)
        check_time(now)
        failure: Exception | None = None
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            key = grant_key(actor, asset)
            record["grants"].pop(key, None)
            grant_op = record.get("grant_counts", {}).get(key, 0)  # which grant is being removed
            # Queued with the removal in one atomic write (see ``_revoke``).
            _queue_event(record, "ungrant", asset, "PERM-REMOVE", {"subject": actor, "granted_by": granted_by},
                         ["ungrant", actor, asset, grant_op])
            txn.put(RECORD, record)
            try:
                self._revoke_in_vault(record, "removed_grants", key, max(now, record["last_issued_at"]))
            except Exception as error:
                failure = error
        try:
            self.reconcile()
        except Exception as error:
            failure = error
        if failure is not None:
            raise NodeError("removed, but recording it in the vault or log failed; the log entry "
                            "is queued and will be written by the next authority operation") from failure

    # -- signed lists -----------------------------------------------------

    def issue_list(self, now: float) -> dict[str, Any]:
        """Sign the current state. The new number is stored before it is returned."""
        check_time(now)
        self._try_reconcile()
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "authority")
            # Time-based numbering keeps rising even after restoring an old backup.
            seq = max(record["list_seq"] + 1, int(now * 1000))
            issued_at = max(now, record["last_issued_at"])
            record["list_seq"], record["last_issued_at"] = seq, issued_at
            body = {"type": LIST_TYPE, "seq": seq, "issued_at": issued_at,
                    "devices": record["devices"],
                    "revoked_devices": sorted(record["revoked_devices"]),
                    "revoked_actors": sorted(record["revoked_actors"]),
                    "grants": [record["grants"][key] for key in sorted(record["grants"])]}
            txn.put(RECORD, record)
            sk = b64d(record["sk"])
        return signed_envelope(self.signer, sk, body)


def _queue_event(record: dict, action: str, target: str, rule: str, detail: dict, identity: list) -> None:
    """Remember a key event that is in force and must still be logged (see ``Authority.reconcile``)."""
    queue = record.setdefault("pending_events", [])
    if not any(event["identity"] == identity for event in queue):
        queue.append({"action": action, "target": target, "rule": rule, "detail": detail,
                      "identity": identity})


def issue_list(authority: Authority, now: float) -> dict[str, Any]:
    return authority.issue_list(now)
