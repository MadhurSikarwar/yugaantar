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

import secrets
from pathlib import Path
from typing import Any

from t4.node.common import (KeyLog, NodeError, Signer, b64d, b64e, canonical, check_int,
                            check_text, check_time, signed_envelope)
from t4.node.state import FileStore

LIST_TYPE = "revocation_list"
LIST_FIELDS = frozenset({"type", "seq", "issued_at", "devices", "revoked_devices",
                         "revoked_actors", "grants"})
RECORD = "authority"


def check_public_key(public_key: str) -> None:
    if not 0 < len(b64d(public_key)) <= 8192:
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
            record = txn.get(RECORD)
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

    def _event(self, action: str, target: str, rule: str, detail: dict) -> None:
        self.log.append(actor="authority", action=action, target=target, decision="allow",
                        rule=rule, request_id=secrets.token_hex(16), detail=detail)

    def _revoke_in_vault(self, record: dict, set_name: str, item: str, at: float) -> None:
        if record["vault"]:
            from t4.backup import Vault

            Vault(**record["vault"]).record_removal(set_name, item, at)

    # -- devices ---------------------------------------------------------

    def enroll(self, device_id: str, owner: str, public_key: str, now: float) -> None:
        check_text(device_id)
        check_text(owner)
        check_public_key(public_key)
        check_time(now)
        with self.store.locked() as txn:
            record = txn.get(RECORD)
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
            self._event("enroll", device_id, "KEY-ENROLL", {"owner": owner, "version": 1})
            txn.put(RECORD, record)

    def publish_rotation(self, device_id: str, version: int, public_key: str,
                         activate_at: float, now: float) -> float:
        """Publish a new key. Returns the activation time C that is in force.

        Repeating a publication that already succeeded returns the stored C, so
        a device that crashed before hearing the answer can safely retry.
        """
        check_text(device_id)
        check_int(version)
        check_public_key(public_key)
        check_time(activate_at)
        check_time(now)
        with self.store.locked() as txn:
            record = txn.get(RECORD)
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
            device["keys"].append({"version": version, "public_key": public_key,
                                   "activate_at": activate_at})
            self._event("rotate", device_id, "KEY-ROTATE",
                        {"owner": device["owner"], "version": version,
                         "activate_at": repr(activate_at)})
            txn.put(RECORD, record)
        return activate_at

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
            record = txn.get(RECORD)
            at = record[set_name].get(item, max(now, record["last_issued_at"]))
            record[set_name][item] = at
            txn.put(RECORD, record)
            # A revocation persists even if the vault or the log fails.
            for step in (lambda: self._revoke_in_vault(record, set_name, item, at),
                         lambda: self._event(action, item, rule, {"effective_at": repr(at)})):
                try:
                    step()
                except Exception as error:
                    failure = error
        if failure is not None:
            raise NodeError("revoked, but recording it in the vault or log failed") from failure
        return at

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
            record = txn.get(RECORD)
            if actor in record["revoked_actors"]:
                raise NodeError("actor is revoked")
            record["grants"][grant_key(actor, asset)] = {
                "actor": actor, "asset": asset, "approval_id": approval_id}
            self._event("grant", asset, "PERM-GRANT", {
                "subject": actor, "approval_id": approval_id, "granted_by": granted_by})
            txn.put(RECORD, record)

    def ungrant(self, actor: str, asset: str, now: float, *, granted_by: str = "authority") -> None:
        check_text(actor)
        check_text(asset)
        check_time(now)
        failure: Exception | None = None
        with self.store.locked() as txn:
            record = txn.get(RECORD)
            key = grant_key(actor, asset)
            record["grants"].pop(key, None)
            txn.put(RECORD, record)
            for step in (lambda: self._revoke_in_vault(
                             record, "removed_grants", key, max(now, record["last_issued_at"])),
                         lambda: self._event("ungrant", asset, "PERM-REMOVE",
                                             {"subject": actor, "granted_by": granted_by})):
                try:
                    step()
                except Exception as error:
                    failure = error
        if failure is not None:
            raise NodeError("removed, but recording it in the vault or log failed") from failure

    # -- signed lists -----------------------------------------------------

    def issue_list(self, now: float) -> dict[str, Any]:
        """Sign the current state. The new number is stored before it is returned."""
        check_time(now)
        with self.store.locked() as txn:
            record = txn.get(RECORD)
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


def issue_list(authority: Authority, now: float) -> dict[str, Any]:
    return authority.issue_list(now)
