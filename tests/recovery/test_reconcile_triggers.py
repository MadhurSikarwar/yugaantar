"""Queued audit entries are written by the next operation that can reach the log (retest finding R-01).

The README and the authority's error text promise that an event queued during a log failure is written
by the next request or authority operation, not only by a list delivery or an explicit ``reconcile``.
Each test queues one event, restores the log, runs one ordinary operation and checks the event was
written exactly once and before the new operation's own entry. Synthetic data, temporary folders.
"""
from __future__ import annotations

import pytest

from t4.audit.log import AuditLog
from t4.audit.verify import verify_log
from t4.node.authority import Authority
from t4.node.common import NodeError, load_signer, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond

from .test_assessment_fixes import NOW, S, T, FlakyLog


def _actions(path):
    return [e["action"] for e in AuditLog(path, None).entries()]


@pytest.fixture
def world(tmp_path):
    sig = load_signer()
    alog = FlakyLog(open_log(tmp_path / "alog"))
    auth = Authority.create(tmp_path / "authority", sig, alog, freshness=T, skew=S)
    nlog = FlakyLog(open_log(tmp_path / "nlog"))
    node = Node.provision(tmp_path / "node", sig, nlog, node_id="n", authority_pk=auth.public_key,
                          owners={"a": "maya", "b": "ravi"}, contents={"a": "A", "b": "B"},
                          freshness=T, skew=S)
    maya = Device.create(tmp_path / "maya", sig, "maya-phone", "maya")
    ravi = Device.create(tmp_path / "ravi", sig, "ravi-phone", "ravi")
    maya.enroll(auth, NOW)
    ravi.enroll(auth, NOW)
    node.accept_list(auth.issue_list(NOW), NOW)
    return {"tmp": tmp_path, "sig": sig, "auth": auth, "alog": alog, "node": node, "nlog": nlog,
            "maya": maya, "ravi": ravi}


def test_a_node_request_writes_a_queued_list_delivery_first(world):
    auth, node, nlog = world["auth"], world["node"], world["nlog"]
    auth.revoke_device("maya-phone", NOW + 1)
    nlog.broken = True
    assert node.accept_list(auth.issue_list(NOW + 2), NOW + 2) is True
    assert node.pending_events() == 1
    nlog.broken = False
    # A peer's ordinary read, no reconcile() and no new list.
    assert respond(node, world["ravi"].make_request("n", "b", NOW + 3), NOW + 3)["decision"] == "allow"
    assert node.pending_events() == 0
    actions = _actions(world["tmp"] / "nlog")
    assert actions.count("deliver_list") == 2  # the first list and the queued one, once each
    assert actions[-2:] == ["deliver_list", "read"]  # queued entry is written before the new one
    assert verify_log(world["tmp"] / "nlog").ok
    # The revocation stayed in force throughout.
    assert respond(node, world["maya"].make_request("n", "a", NOW + 4), NOW + 4)["decision"] == "deny"


def test_a_node_request_while_the_log_still_fails_keeps_the_queue(world):
    auth, node, nlog = world["auth"], world["node"], world["nlog"]
    nlog.broken = True
    assert node.accept_list(auth.issue_list(NOW + 2), NOW + 2) is True
    # The request itself cannot be logged, so it is refused (fail closed), and nothing is lost.
    assert respond(node, world["ravi"].make_request("n", "b", NOW + 3), NOW + 3)["decision"] == "deny"
    assert node.pending_events() == 1
    nlog.broken = False
    assert node.reconcile() == 1 and node.pending_events() == 0


@pytest.mark.parametrize("operation", ["grant", "enroll", "publish_rotation"])
def test_an_authority_operation_writes_a_queued_revocation_first(world, operation):
    auth, alog = world["auth"], world["alog"]
    alog.broken = True
    with pytest.raises(NodeError, match="queued"):
        auth.revoke_actor("eve", NOW + 1)
    assert auth.pending_events() == 1
    alog.broken = False
    if operation == "grant":
        auth.grant("ravi", "a", NOW + 2, approval_id="chg-1", granted_by="user-admin")
        new = "grant"
    elif operation == "enroll":
        extra = Device.create(world["tmp"] / "tab", world["sig"], "ravi-tablet", "ravi")
        extra.enroll(auth, NOW + 2)
        new = "enroll"
    else:
        world["ravi"].rotate(auth, NOW + 2, activate_at=NOW + 2 + T + S + 5)
        new = "rotate"
    assert auth.pending_events() == 0
    actions = _actions(world["tmp"] / "alog")
    assert actions.count("revoke_actor") == 1
    assert actions.index("revoke_actor") < len(actions) - 1 and actions[-1] == new
    assert verify_log(world["tmp"] / "alog").ok
