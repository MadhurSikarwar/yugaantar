"""Authenticated gateway in front of the adapter, and signed reviewer decisions.

Why it exists
    The judged adapter decides permission for the ``actor`` it is told and cannot check who is
    calling: the contract carries no credential. The gateway is the front door a deployment puts
    in front of it. Every caller is enrolled with an ML-DSA-65 public key and a role, signs each
    request, and the gateway forwards only requests that pass every check. The adapter itself is
    not changed, so the judged contract stays exactly as it is.

Roles and what each may do
    user      read, protected_read, audit -- and only as the actor bound to its key
    admin     setup, revoke, audit
    reviewer  decide: approve or reject an alert ({"alert_id", "evidence", "verdict", "reason"}),
              where ``evidence`` is the SHA-256 of the alert record being judged. The gateway
              refuses an unknown alert (GW-UNKNOWN-ALERT) or changed evidence (GW-STALE-EVIDENCE),
              refuses the same verdict twice (GW-DUPLICATE-DECISION) and records a different later
              verdict as REV-CONFLICT, never as a silent change. A decision never grants access.

Checks, in this order (each failure has its own rule ID in the gateway's signed log; the caller
only ever receives ``{"error": "refused"}``):
    GW-MALFORMED, GW-UNKNOWN-CALLER, GW-BAD-SIGNATURE, GW-EXPIRED (outside the time window),
    GW-REPLAY (nonce already used), GW-NOT-PERMITTED (role may not use this op),
    GW-ACTOR-MISMATCH (a user acting as someone else), then the request is forwarded
    (GW-FORWARDED) or, for a reviewer, the decision is recorded (REV-DECISION).

Signed reviewer decisions
    A reviewer's approve or reject is signed over the alert ID, verdict, reason, caller, nonce and
    time. The gateway verifies it and writes every signed field and the signature into its log, so
    ``verify_decision`` can check it again later with only the reviewer's public key.

Limits, stated plainly
    The gateway's own folder holds its registry and nonces; whoever can write it can enroll a
    caller (the same trust boundary as the authority). Enrolling callers is not itself
    authenticated: run it on the operator's machine. Nonces are kept for the time window only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from t4.node.common import (KeyLog, NodeError, Signer, b64d, b64e, canonical, check_text, check_time,
                            open_envelope, require_record, signed_envelope)
from t4.node.state import FileStore

RECORD = "gateway"
REQUEST_TYPE = "gateway-request"
REQUEST_FIELDS = frozenset({"type", "caller", "op", "body", "nonce", "issued_at"})
DECISION_TYPE = "review-decision"
AUTHORITY_OPS = frozenset({"grant", "ungrant", "revoke_device", "revoke_actor", "revoke_key", "enroll",
                           "backup", "restore"})
ROLES = {
    "user": frozenset({"read", "protected_read", "audit"}),
    # Adapter administration and every authority command go through the same signed checks.
    "admin": frozenset({"setup", "revoke", "audit"}) | AUTHORITY_OPS,
    "reviewer": frozenset({"decide"}),
}
RATE_LIMIT = 60  # requests per caller per RATE_WINDOW seconds; above it: GW-RATE-LIMITED
RATE_WINDOW = 60.0
ACTOR_BOUND_OPS = frozenset({"read", "protected_read"})
VERDICTS = frozenset({"approve", "reject"})
MAX_NONCES = 50_000
MAX_REASON = 300
REFUSED = {"error": "refused"}


class Gateway:
    def __init__(self, directory: str | Path, signer: Signer, log: KeyLog) -> None:
        self.store = FileStore(directory)
        self.signer = signer
        self.log = log

    @classmethod
    def create(cls, directory: str | Path, signer: Signer, log: KeyLog, *,
               window: float = 30.0, skew: float = 2.0) -> "Gateway":
        if check_time(window) <= 0:
            raise NodeError("the time window must be positive")
        check_time(skew)
        FileStore.create(directory, {RECORD: {"callers": {}, "nonces": {}, "W": window, "s": skew}})
        return cls(directory, signer, log)

    # -- enrolment ------------------------------------------------------------

    def revoke_caller(self, caller: str) -> None:
        """Refuse every later request from this caller (logged; cannot be undone, enroll a new name)."""
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "gateway")
            entry = record["callers"].get(caller)
            if entry is None:
                raise NodeError("unknown caller")
            entry["revoked"] = True
            self.log.append(actor="gateway", action="revoke_caller", target=caller, decision="allow",
                            rule="GW-REVOKE-CALLER", request_id=f"revoke-{hashlib.sha256(caller.encode()).hexdigest()[:32]}",
                            detail={})
            txn.put(RECORD, record)

    def rotate_caller(self, caller: str, public_key: bytes) -> None:
        """Replace a caller's key: requests signed with the old key are refused from now on."""
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "gateway")
            entry = record["callers"].get(caller)
            if entry is None or entry.get("revoked"):
                raise NodeError("unknown or revoked caller")
            if any(other["public_key"] == b64e(public_key) for other in record["callers"].values()):
                raise NodeError("public key already used")
            entry["public_key"] = b64e(public_key)
            self.log.append(actor="gateway", action="rotate_caller", target=caller, decision="allow",
                            rule="GW-ROTATE-CALLER", request_id=f"rotate-{hashlib.sha256(public_key).hexdigest()[:32]}",
                            detail={})
            txn.put(RECORD, record)

    def enroll(self, caller: str, role: str, public_key: bytes, *, actor: str | None = None) -> None:
        """Register a caller's public key and role. A user is bound to exactly one actor."""
        check_text(caller)
        if role not in ROLES:
            raise NodeError("unknown role")
        if role == "user":
            check_text(actor)
        size = getattr(self.signer, "PUBLIC_KEY_SIZE", None)
        if not isinstance(public_key, bytes) or (size is not None and len(public_key) != size):
            raise NodeError("invalid public key")
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "gateway")
            if caller in record["callers"]:
                raise NodeError("caller already enrolled")
            if any(entry["public_key"] == b64e(public_key) for entry in record["callers"].values()):
                raise NodeError("public key already used")
            self.log.append(actor="gateway", action="enroll", target=caller, decision="allow",
                            rule="GW-ENROLL", request_id=f"enroll-{hashlib.sha256(public_key).hexdigest()[:32]}",
                            detail={"role": role, "actor": actor or ""})
            record["callers"][caller] = {"role": role, "actor": actor or "", "public_key": b64e(public_key)}
            txn.put(RECORD, record)

    # -- requests -------------------------------------------------------------

    def handle(self, signed: Any, now: float, forward: Callable[[dict], dict],
               alert_lookup: Callable[[str], str | None] | None = None) -> dict:
        """Check a signed request; forward it or record a decision. Never raises.

        ``alert_lookup(alert_id)`` returns the SHA-256 of that alert's current record, or ``None``
        when no such alert exists; without it reviewer decisions are refused.
        """
        try:
            check_time(now)
            with self.store.locked() as txn:
                record = require_record(txn.get(RECORD), "gateway")
                rule, body, signature = self._judge(record, signed, now)
                if rule == "GW-OK" and body["op"] == "decide":
                    rule = self._judge_decision(record, body["body"], alert_lookup)
                request_id = hashlib.sha256(canonical(signed if isinstance(signed, dict) else str(signed))).hexdigest()[:32]
                caller = body["caller"] if body else "unknown"
                op = body["op"] if body else "unknown"
                if rule != "GW-OK":
                    self.log.append(actor=str(caller)[:200], action=str(op)[:64], target="gateway", decision="deny",
                                    rule=rule, request_id=request_id, detail={})
                    txn.put(RECORD, record)
                    return dict(REFUSED)
                txn.put(RECORD, record)  # the nonce is spent before anything is forwarded
                if op == "decide":
                    return self._record_decision(record, body, signature, request_id, txn)
                self.log.append(actor=caller, action=op, target="adapter", decision="allow", rule="GW-FORWARDED",
                                request_id=request_id, detail={"actor": str(body["body"].get("actor", ""))[:200]})
            return forward({**body["body"], "op": op})
        except Exception:  # noqa: BLE001 - anything unexpected is a refusal
            return dict(REFUSED)

    def _judge(self, record: dict, signed: Any, now: float) -> tuple[str, dict | None, bytes]:
        try:
            body, signature = open_envelope(signed, REQUEST_TYPE, REQUEST_FIELDS)
            check_text(body["caller"])
            check_text(body["op"])
            check_text(body["nonce"])
            check_time(body["issued_at"])
            if not isinstance(body["body"], dict) or len(body["nonce"]) > 128:
                raise NodeError("malformed")
        except (NodeError, ValueError, TypeError, RecursionError):
            return "GW-MALFORMED", None, b""
        caller = record["callers"].get(body["caller"])
        if caller is None:
            return "GW-UNKNOWN-CALLER", body, signature
        if caller.get("revoked"):
            return "GW-CALLER-REVOKED", body, signature
        if self.signer.verify(b64d(caller["public_key"]), canonical(body), signature) is not True:
            return "GW-BAD-SIGNATURE", body, signature
        if not -record["s"] <= now - body["issued_at"] <= record["W"]:
            return "GW-EXPIRED", body, signature
        nonce = hashlib.sha256(canonical([body["caller"], body["nonce"]])).hexdigest()
        record["nonces"] = {key: until for key, until in record["nonces"].items() if until >= now}
        if nonce in record["nonces"]:
            return "GW-REPLAY", body, signature
        if len(record["nonces"]) >= MAX_NONCES:
            return "GW-BUSY", body, signature  # fail closed: forgetting a nonce would allow a replay
        record["nonces"][nonce] = body["issued_at"] + record["W"] + record["s"]
        # Rate limit per caller (verified callers only, so nobody can exhaust another's budget).
        recent = [t for t in record.setdefault("rates", {}).get(body["caller"], []) if now - t < RATE_WINDOW]
        if len(recent) >= RATE_LIMIT:
            record["rates"][body["caller"]] = recent
            return "GW-RATE-LIMITED", body, signature
        record["rates"][body["caller"]] = recent + [now]
        if body["op"] not in ROLES[caller["role"]]:
            return "GW-NOT-PERMITTED", body, signature
        if body["op"] in ACTOR_BOUND_OPS and body["body"].get("actor") != caller["actor"]:
            return "GW-ACTOR-MISMATCH", body, signature
        if body["op"] == "decide" and not _valid_decision(body["body"]):
            return "GW-MALFORMED", body, signature
        return "GW-OK", body, signature

    @staticmethod
    def _judge_decision(record: dict, decision: dict, alert_lookup) -> str:
        current = alert_lookup(decision["alert_id"]) if alert_lookup is not None else None
        if current is None:
            return "GW-UNKNOWN-ALERT"
        if decision["evidence"] != current:
            return "GW-STALE-EVIDENCE"
        earlier = record.setdefault("reviews", {}).get(decision["alert_id"])
        if earlier and decision["verdict"] in earlier["verdicts"]:
            return "GW-DUPLICATE-DECISION"
        return "GW-OK"

    def _record_decision(self, record: dict, body: dict, signature: bytes, request_id: str, txn) -> dict:
        decision = body["body"]
        reviews = record.setdefault("reviews", {})
        earlier = reviews.get(decision["alert_id"])
        rule = "REV-CONFLICT" if earlier else "REV-DECISION"
        self.log.append(actor=body["caller"], action="review", target=decision["alert_id"],
                        decision=decision["verdict"], rule=rule, request_id=request_id,
                        detail={"reason": decision["reason"], "evidence": decision["evidence"], "nonce": body["nonce"],
                                "issued_at": json.dumps(body["issued_at"]), "signature": signature.hex()})
        entry = reviews.setdefault(decision["alert_id"], {"verdicts": [], "reviewers": []})
        entry["verdicts"].append(decision["verdict"])
        entry["reviewers"].append(body["caller"])
        txn.put(RECORD, record)
        status = "conflict" if len(set(entry["verdicts"])) > 1 else decision["verdict"]
        return {"recorded": True, "alert_id": decision["alert_id"], "verdict": decision["verdict"], "status": status}

    def review_status(self) -> dict[str, dict]:
        """Durable review status per alert: approve, reject or conflict, with the reviewers."""
        with self.store.locked() as txn:
            record = require_record(txn.get(RECORD), "gateway")
        return {alert: {"status": "conflict" if len(set(r["verdicts"])) > 1 else r["verdicts"][0],
                        "reviewers": list(r["reviewers"])} for alert, r in record.get("reviews", {}).items()}


def _valid_decision(decision: Mapping[str, Any]) -> bool:
    try:
        check_text(decision["alert_id"])
        reason, evidence = decision["reason"], decision["evidence"]
        return (decision["verdict"] in VERDICTS and isinstance(reason, str) and len(reason) <= MAX_REASON
                and isinstance(evidence, str) and len(evidence) == 64
                and set(decision) == {"alert_id", "evidence", "verdict", "reason"})
    except (KeyError, NodeError):
        return False


def sign_request(signer: Signer, secret_key: bytes, *, caller: str, op: str, body: Mapping[str, Any],
                 nonce: str, issued_at: float) -> dict:
    """What a client sends: its request, signed with its own ML-DSA-65 key."""
    return signed_envelope(signer, secret_key, {"type": REQUEST_TYPE, "caller": caller, "op": op,
                                                "body": dict(body), "nonce": nonce, "issued_at": issued_at})


def verify_decision(signer: Signer, public_key: bytes, entry: Mapping[str, Any]) -> bool:
    """Re-check a recorded REV-DECISION entry against the reviewer's public key. Never raises."""
    try:
        detail = entry["detail"]
        body = {"type": REQUEST_TYPE, "caller": entry["actor"], "op": "decide",
                "body": {"alert_id": entry["target"], "evidence": detail["evidence"], "verdict": entry["decision"],
                         "reason": detail["reason"]},
                "nonce": detail["nonce"], "issued_at": json.loads(detail["issued_at"])}
        return signer.verify(public_key, canonical(body), bytes.fromhex(detail["signature"])) is True
    except Exception:  # noqa: BLE001
        return False
