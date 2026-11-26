"""Signed device requests and the node's decision.

This is where the prototype verifies identity (M-N1, M-N2). Checks run in a
fixed order and each failure has its own rule ID, written to the node's log.
The caller only ever sees ``{"decision": "deny"}``.

Order: format, fresh list, known device and key, signature, node binding, device
and actor not revoked, actor is the device's owner, key version active now,
time window, unused nonce, then permission.

What it defends against: forged requests, replay, forwarding a request to
another node, one enrolled device acting as someone else, revoked devices, old
keys after the cutoff, and stale nodes. Any unexpected error denies.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Any, Mapping

from t4.node.common import (Decision, NodeError, Signer, b64d, canonical, check_int,
                            check_text, check_time, load_signer, open_envelope,
                            signed_envelope)
from t4.node.freshness import RECORD, Node

REQUEST_TYPE = "request"
REQUEST_FIELDS = frozenset({"type", "node_id", "device_id", "key_version", "actor",
                            "action", "asset", "nonce", "issued_at"})
TEXT_FIELDS = ("node_id", "device_id", "actor", "action", "asset", "nonce")
MAX_NONCE = 128
MAX_NONCES = 50_000  # replay nonces kept inside the window; at the cap further requests are refused


def sign_request(device_sk: bytes, fields: Mapping, *, signer: Signer | None = None) -> dict:
    body = {**fields, "type": REQUEST_TYPE}
    if set(body) != REQUEST_FIELDS:
        raise NodeError("request fields are incomplete or unexpected")
    return signed_envelope(signer or load_signer(), device_sk, body)


def active_version(keys: list[dict], now: float) -> dict | None:
    """The one key in force at ``now``: no grace period for the previous one."""
    usable = [key for key in keys if key["activate_at"] <= now]
    return max(usable, key=lambda key: key["version"]) if usable else None


def _parse(signed: Any) -> tuple[dict, bytes, bytes]:
    body, signature = open_envelope(signed, REQUEST_TYPE, REQUEST_FIELDS)
    for name in TEXT_FIELDS:
        check_text(body[name])
    if len(body["nonce"]) > MAX_NONCE:
        raise NodeError("nonce is too long")
    check_int(body["key_version"])
    check_time(body["issued_at"])
    return body, signature, canonical(body)


def _evaluate_rule(node: Node, record: dict, body: dict, signature: bytes, message: bytes,
                   now: float) -> tuple[str, bool]:
    """Return (rule ID, whether the signature was verified)."""
    current = record["list"]
    if current is None or now - current["issued_at"] > record["T"]:
        return "NODE-STALE-LIST", False
    if now < record["clock_high"] - record["s"]:
        return "NODE-CLOCK-ROLLBACK", False
    device = current["devices"].get(body["device_id"])
    if device is None:
        return "NODE-UNKNOWN-DEVICE", False
    claimed = next((key for key in device["keys"] if key["version"] == body["key_version"]), None)
    if claimed is None:
        return "NODE-KEY-INACTIVE", False
    if node.signer.verify(b64d(claimed["public_key"]), message, signature) is not True:
        return "NODE-BAD-SIGNATURE", False
    if body["node_id"] != record["node_id"]:
        return "NODE-WRONG-NODE", True
    if body["device_id"] in record["revoked_devices"]:
        return "NODE-DEVICE-REVOKED", True
    if body["actor"] in record["revoked_actors"] or device["owner"] in record["revoked_actors"]:
        return "NODE-ACTOR-REVOKED", True
    if body["actor"] != device["owner"]:
        return "NODE-OWNER-MISMATCH", True
    if active_version(device["keys"], now) != claimed:
        return "NODE-KEY-INACTIVE", True
    if not -record["s"] <= now - body["issued_at"] <= record["W"]:
        return "NODE-EXPIRED", True
    nonce = hashlib.sha256(canonical([body["device_id"], body["nonce"]])).hexdigest()
    if nonce in record["nonces"]:
        return "NODE-REPLAY", True
    # Used up even if permission is refused below.
    record["nonces"] = {k: v for k, v in record["nonces"].items() if v >= now}
    if len(record["nonces"]) >= MAX_NONCES:
        # Fail closed: forgetting a nonce would allow a replay, and the state must stay loadable.
        return "NODE-NONCE-STORE-FULL", True
    record["nonces"][nonce] = body["issued_at"] + record["W"] + record["s"]
    if body["action"] != "read" or body["asset"] not in record["owners"]:
        return "NODE-NOT-PERMITTED", True
    if record["owners"][body["asset"]] == body["actor"]:
        return "NODE-ALLOW-OWNER", True
    if any(grant["actor"] == body["actor"] and grant["asset"] == body["asset"]
           for grant in current["grants"]):
        return "NODE-ALLOW-GRANT", True
    return "NODE-NOT-PERMITTED", True


def _decide(node: Node, signed: Any, now: float) -> tuple[Decision, str | None]:
    request_id = secrets.token_hex(16)
    body: dict | None = None
    content: str | None = None
    rule, epoch = "NODE-INTERNAL-ERROR", 0
    try:
        check_time(now)
        with node.store.locked() as txn:
            record = txn.get(RECORD)
            verified = False
            try:
                body, signature, message = _parse(signed)
            except (NodeError, ValueError, TypeError, RecursionError):
                rule = "NODE-MALFORMED-REQUEST"
            else:
                rule, verified = _evaluate_rule(node, record, body, signature, message, now)
            epoch = record["list"]["seq"] if record["list"] else 0
            allow = rule.startswith("NODE-ALLOW-")
            record["clock_high"] = max(record["clock_high"], now)
            txn.put(RECORD, record)
            detail = {"node_id": record["node_id"], "list_seq": epoch,
                      "signature_verified": verified,
                      "device_id": body["device_id"] if body else ""}
            # Logged under the store lock. If this raises, nothing is released.
            node.record_event(actor=body["actor"] if body else "unknown",
                              action=body["action"] if body else "unknown",
                              target=body["asset"] if body else "unknown",
                              decision="allow" if allow else "deny", rule=rule,
                              request_id=request_id, detail=detail)
            if allow:
                content = record["contents"][body["asset"]]
    except Exception:
        return Decision(False, "node could not complete the check", "NODE-INTERNAL-ERROR",
                        request_id, epoch), None
    return Decision(content is not None, rule, rule, request_id, epoch), content


def handle_request(node: Node, signed: Mapping, now: float) -> Decision:
    return _decide(node, signed, now)[0]


def respond(node: Node, signed: Mapping, now: float) -> dict:
    """What the caller receives: the body when allowed, otherwise only a deny."""
    decision, content = _decide(node, signed, now)
    if decision.allow:
        return {"decision": "allow", "body": content}
    return {"decision": "deny"}
