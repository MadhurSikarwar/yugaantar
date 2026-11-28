"""The authenticated gateway (item: caller authentication) and signed reviewer decisions."""
from __future__ import annotations

import pytest

from t4.audit.log import AuditLog
from t4.gateway import Gateway, sign_request, verify_decision
from t4.node.common import NodeError, load_signer, open_log

NOW = 1_000_000.0


@pytest.fixture()
def world(tmp_path):
    signer = load_signer()
    gateway = Gateway.create(tmp_path / "gw", signer, open_log(tmp_path / "gw-log"))
    keys = {}
    for caller, role, actor in (("maya-app", "user", "maya"), ("ops", "admin", None), ("ana", "reviewer", None)):
        pk, sk = signer.sig_keygen()
        keys[caller] = (pk, sk)
        gateway.enroll(caller, role, pk, actor=actor)
    forwarded = []

    def forward(request):
        forwarded.append(request)
        return {"forwarded": request["op"]}

    def send(caller, op, body, *, nonce="n1", at=NOW, key=None):
        signed = sign_request(signer, key or keys[caller][1], caller=caller, op=op, body=body, nonce=nonce, issued_at=at)
        return gateway.handle(signed, NOW, forward), signed

    return {"gateway": gateway, "send": send, "forwarded": forwarded, "keys": keys, "signer": signer,
            "log": tmp_path / "gw-log"}


def rules(world):
    return [e["rule"] for e in AuditLog(world["log"], None).entries()]


def test_a_user_reads_only_as_its_own_actor(world):
    reply, _ = world["send"]("maya-app", "read", {"actor": "maya", "asset": "plan", "request_id": "r1"})
    assert reply == {"forwarded": "read"}
    reply, _ = world["send"]("maya-app", "read", {"actor": "noor", "asset": "plan", "request_id": "r2"}, nonce="n2")
    assert reply == {"error": "refused"} and rules(world)[-1] == "GW-ACTOR-MISMATCH"
    assert len(world["forwarded"]) == 1


def test_forged_replayed_late_and_unknown_requests_are_refused(world):
    _, signed = world["send"]("maya-app", "read", {"actor": "maya", "asset": "plan", "request_id": "r1"})
    assert world["gateway"].handle(signed, NOW, lambda r: {"ok": True}) == {"error": "refused"}
    assert rules(world)[-1] == "GW-REPLAY"
    other_sk = world["keys"]["ops"][1]
    world["send"]("maya-app", "read", {"actor": "maya", "asset": "plan", "request_id": "r3"}, nonce="n3", key=other_sk)
    assert rules(world)[-1] == "GW-BAD-SIGNATURE"
    world["send"]("maya-app", "read", {"actor": "maya", "asset": "plan", "request_id": "r4"}, nonce="n4", at=NOW - 120)
    assert rules(world)[-1] == "GW-EXPIRED"
    signed["body"]["caller"] = "nobody"
    assert world["gateway"].handle(signed, NOW, lambda r: {}) == {"error": "refused"}
    assert rules(world)[-1] == "GW-UNKNOWN-CALLER"
    assert world["gateway"].handle({"junk": 1}, NOW, lambda r: {}) == {"error": "refused"}
    assert rules(world)[-1] == "GW-MALFORMED"


def test_roles_limit_operations(world):
    world["send"]("maya-app", "revoke", {"actor": "noor"})
    assert rules(world)[-1] == "GW-NOT-PERMITTED"
    reply, _ = world["send"]("ops", "revoke", {"actor": "noor"}, nonce="n9")
    assert reply == {"forwarded": "revoke"}


def test_a_reviewer_decision_is_signed_recorded_and_checkable_later(world):
    reply, _ = world["send"]("ana", "decide", {"alert_id": "authority-4", "verdict": "reject", "reason": "no approval"})
    assert reply == {"recorded": True, "alert_id": "authority-4", "verdict": "reject"}
    entry = [e for e in AuditLog(world["log"], None).entries() if e["rule"] == "REV-DECISION"][0]
    pk = world["keys"]["ana"][0]
    assert verify_decision(world["signer"], pk, entry)
    altered = {**entry, "decision": "approve"}
    assert not verify_decision(world["signer"], pk, altered)
    assert not verify_decision(world["signer"], world["keys"]["ops"][0], entry)
    world["send"]("ana", "decide", {"alert_id": "a", "verdict": "maybe", "reason": ""}, nonce="n5")
    assert rules(world)[-1] == "GW-MALFORMED"


def test_enrolment_refuses_duplicates_and_unbound_users(world):
    pk, _ = world["signer"].sig_keygen()
    with pytest.raises(NodeError):
        world["gateway"].enroll("maya-app", "user", pk, actor="maya")
    with pytest.raises(NodeError):
        world["gateway"].enroll("someone", "user", pk)
    with pytest.raises(NodeError):
        world["gateway"].enroll("x", "superuser", pk)
