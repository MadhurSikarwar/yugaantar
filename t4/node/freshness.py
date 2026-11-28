"""A node's state, signed-list acceptance and the freshness bound T.

A node accepts a list only if the signature matches the authority key it was
given at provisioning, the number is higher than the stored one, and the list is
younger than T and not dated more than s in the future. Age always counts from
the authority's ``issued_at``, never from delivery. With no list, or a list older
than T, the node denies every request.

What it defends against: forged lists, replayed older lists, a courier that
delays or withholds lists, an authority restored from an old backup (revocations
a node has seen are never forgotten), and a node clock set backwards.
Limits: node clocks and node state are trusted. Restoring an older copy of node
state can allow a recent request to be replayed within W.
"""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Mapping

from t4.node.authority import LIST_FIELDS, LIST_TYPE
from t4.node.common import (KeyLog, NodeError, Signer, b64d, b64e, canonical, check_int,
                            check_text, check_time, open_envelope, require_record)
from t4.node.state import FileStore

RECORD = "node"

ALERT_TEXT = {
    "NODE-LIST-BAD-SIGNATURE": "A revocation list was not signed by this node's authority.",
    "NODE-LIST-NOT-NEWER": "A revocation list with an old or repeated number was presented.",
    "NODE-LIST-MALFORMED": "A revocation list did not have the expected format.",
    "NODE-BAD-SIGNATURE": "A request signature did not match the enrolled device key.",
    "NODE-WRONG-NODE": "A request signed for a different node was presented here.",
    "NODE-DEVICE-REVOKED": "A revoked device tried to use this node.",
    "NODE-KEY-REVOKED": "A request was signed with a key version the authority revoked.",
    "NODE-ACTOR-REVOKED": "A revoked actor tried to use this node.",
    "NODE-OWNER-MISMATCH": "A device tried to act as an actor who does not own it.",
    "NODE-REPLAY": "A previously used signed request was presented again.",
    "NODE-NONCE-STORE-FULL": "The replay-nonce store is full; requests are refused until entries expire.",
    "NODE-CLOCK-ROLLBACK":"This node's clock is behind a time it has already seen.",
}


class Node:
    def __init__(self, directory: str | Path, signer: Signer, log: KeyLog) -> None:
        self.store = FileStore(directory)
        self.signer = signer
        self.log = log

    @classmethod
    def provision(cls, directory: str | Path, signer: Signer, log: KeyLog, *, node_id: str,
                  authority_pk: bytes, owners: Mapping[str, str], contents: Mapping[str, str],
                  freshness: float = 60.0, skew: float = 2.0, window: float = 30.0) -> "Node":
        """Install synthetic data and the authority's public key on a node."""
        check_text(node_id)
        if set(owners) != set(contents):
            raise NodeError("owners and contents must list the same assets")
        for asset, owner in owners.items():
            check_text(asset)
            check_text(owner)
            if not isinstance(contents[asset], str):
                raise NodeError("content must be text")
        if check_time(freshness) <= 0 or check_time(window) <= 0:
            raise NodeError("T and W must be positive")
        check_time(skew)
        FileStore.create(directory, {RECORD: {
            "node_id": node_id, "authority_pk": b64e(authority_pk),
            "T": freshness, "s": skew, "W": window,
            "owners": dict(owners), "contents": dict(contents),
            "list": None, "revoked_devices": [], "revoked_actors": [],
            "nonces": {}, "clock_high": 0}})
        return cls(directory, signer, log)

    def owners(self) -> tuple[str, dict[str, str]]:
        """(node ID, {asset: owner}) as provisioned. No file contents."""
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "node")
        return record["node_id"], record["owners"]

    def record_event(self, *, actor: str, action: str, target: str, decision: str,
                     rule: str, request_id: str, detail: Mapping[str, Any]) -> None:
        """Append one node event, followed by an alert entry if the rule calls for it."""
        entry = self.log.append(actor=actor, action=action, target=target, decision=decision,
                                rule=rule, request_id=request_id, detail=dict(detail))
        if rule in ALERT_TEXT:
            # ``actor`` is what the request CLAIMED. The alert also names the device that signed
            # it and whether that signature was checked, so an operator never mistakes the named
            # (possibly framed) actor for the sender.
            extra = {name: detail[name] for name in ("device_id", "signature_verified") if name in detail}
            self.log.alert(rule=rule, explanation=ALERT_TEXT[rule], actor=actor, target=target,
                           request_id=request_id, entries=[entry["seq"]],
                           request_ids=[request_id],
                           detail={"node_id": detail.get("node_id", ""), "claimed_actor": actor, **extra})

    def accept_list(self, signed_list: Any, now: float) -> bool:
        """True if the list was stored. Never raises on bad input."""
        try:
            return self._accept(signed_list, now)
        except Exception:
            return False

    def reconcile(self) -> int:
        """Write list-delivery events that were accepted while the log failed. Returns how many."""
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "node")
            written = self._flush(record)
            if written:
                txn.put(RECORD, record)
        return written

    def pending_events(self) -> int:
        """How many accepted-list events are in force but not yet logged (degraded logging)."""
        with self.store.locked() as txn:
            return len(require_record(txn.get(RECORD), "node").get("pending_events", []))

    def _flush(self, record: dict) -> int:
        """Log queued events oldest first, each once (fixed request IDs + ``append_once``)."""
        queue = record.get("pending_events", [])
        write = getattr(self.log, "append_once", None)
        written = 0
        try:
            while queue:
                event = queue[0]
                if callable(write):
                    write(**event)
                else:
                    self.log.append(**event)
                queue.pop(0)
                written += 1
        except Exception:  # noqa: BLE001 - the rest stays queued and visible
            pass
        if written:
            record["pending_events"] = queue
        return written

    def _accept(self, signed_list: Any, now: float) -> bool:
        check_time(now)
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "node")
            if self._flush(record):
                txn.put(RECORD, record)
            rule, seq = self._judge(record, signed_list, now)
            accepted = rule == "NODE-LIST-ACCEPTED"
            if accepted:
                body = signed_list["body"]
                record["list"] = body
                for name in ("revoked_devices", "revoked_actors"):
                    record[name] = sorted(set(record[name]) | set(body[name]))
                # Revoked key versions are remembered like revoked devices: never forgotten.
                record["revoked_keys"] = sorted(set(record.get("revoked_keys", [])) | {
                    f"{device_id}/{key['version']}" for device_id, device in body["devices"].items()
                    for key in device.get("keys", []) if isinstance(key, dict) and key.get("revoked") is True})
                txn.put(RECORD, record)
            event = {"actor": "courier", "action": "deliver_list", "target": record["node_id"],
                     "decision": "accept" if accepted else "reject", "rule": rule,
                     "request_id": secrets.token_hex(16),
                     "detail": {"node_id": record["node_id"], "list_seq": seq}}
            try:
                self.record_event(**event)
            except Exception:
                # A valid newer list only tightens or refreshes state that the authority signed, so
                # it is kept even if logging fails. Its record is queued in the same atomic write
                # and written (once) by the next delivery, the next signed request or ``reconcile``. Rejections change no
                # state and are not queued.
                if accepted:
                    record.setdefault("pending_events", []).append(event)
                    txn.put(RECORD, record)
        return accepted

    def _judge(self, record: dict, signed_list: Any, now: float) -> tuple[str, int]:
        try:
            body, signature = open_envelope(signed_list, LIST_TYPE, LIST_FIELDS)
            message = canonical(body)
        except (NodeError, ValueError, TypeError, RecursionError):
            return "NODE-LIST-MALFORMED", -1
        if self.signer.verify(b64d(record["authority_pk"]), message, signature) is not True:
            return "NODE-LIST-BAD-SIGNATURE", -1
        try:
            seq = check_int(body["seq"])
            issued_at = check_time(body["issued_at"])
        except NodeError:
            return "NODE-LIST-MALFORMED", -1
        if record["list"] is not None and seq <= record["list"]["seq"]:
            return "NODE-LIST-NOT-NEWER", seq
        if not now - issued_at < record["T"]:
            return "NODE-LIST-EXPIRED", seq
        if issued_at - now > record["s"]:
            return "NODE-LIST-FUTURE", seq
        return "NODE-LIST-ACCEPTED", seq


def accept_list(node: Node, signed_list: Mapping, now: float) -> bool:
    return node.accept_list(signed_list, now)
