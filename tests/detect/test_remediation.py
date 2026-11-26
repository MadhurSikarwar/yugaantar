"""Regression tests for the detector fixes made after the independent security review.

Each test states the invariant it protects. They use the real engine, rules and export code
with synthetic data only; none touches a state directory.
"""
from datetime import datetime, timedelta, timezone

import pytest

from t4.detect import engine, export as exp, ingest
from t4.detect.ingest import Approval, Event, iso_z

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(eid, when=1, received=None, **kw):
    t = BASE + timedelta(seconds=when)
    r = BASE + timedelta(seconds=when if received is None else received)
    values = dict(event_id=eid, event_time_utc=iso_z(t), received_time_utc=iso_z(r), source_clock_offset_ms=0,
                  actor="alice", source_service="client", target_service="catalog", action="read",
                  role_before="viewer", role_after="viewer", outcome="allow", approval_id="", session_id="s",
                  correlation_id="c", receipt_index=0, event_time=t, received_time=r)
    values.update(kw)
    return Event(**values)


def approval(**kw):
    values = dict(approval_id="approved", approved_by="user-admin", subject="alice", operation="grant_role",
                  role="report-reader", scope=("reports-east",), valid_from=BASE,
                  valid_until=BASE + timedelta(seconds=60), effective_at=None)
    values.update(kw)
    return Approval(**values)


def test_approval_scope_is_enforced_for_a_change_aimed_at_another_service():
    wrong = event("wrong", target_service="reports-west", action="grant", role_after="report-reader",
                  approval_id="approved")
    assert engine.analyze([wrong], {"approved": approval()}).predicted()["wrong"] == "unexpected_role_change"
    right = event("right", target_service="reports-east", action="grant", role_after="report-reader",
                  approval_id="approved")
    assert engine.analyze([right], {"approved": approval()}).predicted()["right"] == "approved_change"


def test_scope_does_not_narrow_a_change_recorded_against_the_identity_service():
    """Our own logs record a grant against the identity service with the asset in the role name."""
    grant = event("g", target_service="identity", action="role_change", role_after="report-reader",
                  approval_id="approved")
    assert engine.analyze([grant], {"approved": approval()}).predicted()["g"] == "approved_change"


def test_review_alert_is_not_emitted_before_the_role_change_it_cites_was_received():
    use = event("use", when=2, received=3, role_before="operator", role_after="operator", receipt_index=0)
    change = event("change", when=1, received=30, action="grant", role_after="operator", receipt_index=1)
    alert = next(a for a in engine.analyze([use, change], {}).alerts if a.rule == "DET-REVIEW-AFTER-ROLE-CHANGE")
    assert alert.emitted_at >= change.received_time_utc


def test_movement_alert_time_is_still_the_event_that_reached_the_threshold():
    """The timestamp rule above must not delay movement alerts to the last event of the chain."""
    one = event("m1", when=1, target_service="svc-a", outcome="deny", receipt_index=0)
    two = event("m2", when=2, target_service="svc-b", outcome="deny", receipt_index=1)
    three = event("m3", when=9, target_service="svc-c", outcome="deny", receipt_index=2)
    alert = next(a for a in engine.analyze([one, two, three], {}).alerts if a.rule == "DET-LATERAL-MOVEMENT")
    assert alert.emitted_at == two.received_time_utc


def test_an_unauthorized_revoke_cannot_explain_away_multi_service_probing():
    intruder = approval(approval_id="bad", operation="revoke_role", approved_by="intruder", effective_at=BASE)
    grant = approval(approval_id="grant", scope=("reports-east", "reports-west"))
    events = [event("e1", target_service="reports-east", outcome="deny"),
              event("e2", when=2, target_service="reports-west", outcome="deny", receipt_index=1)]
    result = engine.analyze(events, {"bad": intruder, "grant": grant})
    assert any(a.rule == "DET-LATERAL-MOVEMENT" for a in result.alerts), result.predicted()


def test_an_authorized_revoke_still_explains_denials_after_it():
    revoke = approval(approval_id="rev", operation="revoke_role", effective_at=BASE)
    grant = approval(approval_id="grant", scope=("reports-east", "reports-west"))
    events = [event("e1", when=5, target_service="reports-east", outcome="deny"),
              event("e2", when=6, target_service="reports-west", outcome="deny", receipt_index=1)]
    result = engine.analyze(events, {"rev": revoke, "grant": grant})
    assert set(result.predicted().values()) == {"routine_denial"} and not result.alerts


def test_lone_surrogates_in_identifiers_do_not_crash_alert_generation():
    odd = "\ud800-event"
    change = event(odd, action="grant", role_before="viewer", role_after="admin")
    result = engine.analyze([change], {})
    assert any(a.rule == "DET-UNAPPROVED-ROLE-CHANGE" for a in result.alerts)


def test_a_clock_offset_that_cannot_be_applied_is_rejected_as_malformed_input():
    header = ",".join(ingest.COLUMNS)
    row = ["e1", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", str(10**15), "a", "s", "t", "read",
           "r", "r", "allow", "", "sess", "c"]
    with pytest.raises(ValueError, match="out of range"):
        ingest.parse_events(header + "\n" + ",".join(row) + "\n")


def _node_entry(seq, rule, decision="deny", actor="bob", verified=True, device="dev-a", asset="a"):
    return {"seq": seq, "ts": f"2026-01-01T00:00:{seq:02d}.000Z", "actor": actor, "action": "read", "target": asset,
            "decision": decision, "rule": rule, "request_id": f"r{seq}",
            "detail": {"node_id": "n", "signature_verified": verified, "device_id": device}}


def _key_entry(seq, action, decision, subject="bob", asset="a"):
    return {"seq": seq, "ts": f"2026-01-01T00:00:{seq:02d}.000Z", "actor": "authority", "action": action,
            "target": asset, "decision": decision, "rule": "PERM", "request_id": f"k{seq}",
            "detail": {"subject": subject, "approval_id": ""}}


@pytest.mark.parametrize("rule", ["NODE-OWNER-MISMATCH", "NODE-DEVICE-REVOKED", "NODE-ACTOR-REVOKED"])
def test_a_denial_before_the_owner_check_is_not_attributed_to_the_named_actor(rule):
    """The signature proves the device, not that the claimed actor owns it: a rogue enrolled
    device can name any victim, and the victim must not be framed for probing."""
    rows, _ = exp.convert({"n": [_node_entry(1, rule)]}, [])
    assert rows[0]["actor"] == exp.UNVERIFIED_ACTOR


def test_a_denial_after_the_owner_check_is_still_attributed():
    rows, _ = exp.convert({"n": [_node_entry(1, "NODE-NOT-PERMITTED")]}, [])
    assert rows[0]["actor"] == "bob"


def test_unproven_requests_share_one_session_so_a_new_device_id_cannot_split_a_chain():
    entries = [_node_entry(1, "NODE-BAD-SIGNATURE", verified=False, device="d1", asset="a"),
               _node_entry(2, "NODE-BAD-SIGNATURE", verified=False, device="d2", asset="b")]
    rows, _ = exp.convert({"n": entries}, [])
    assert {r["session_id"] for r in rows} == {exp.UNVERIFIED_SESSION}


def test_a_failed_ungrant_does_not_drop_the_active_grant():
    keys = [_key_entry(1, "grant", "allow"), _key_entry(2, "ungrant", "deny")]
    node = [_node_entry(3, "NODE-ALLOW-GRANT", decision="allow")]
    rows, _ = exp.convert({"n": node}, keys)
    read = next(r for r in rows if r["action"] == "read")
    assert read["role_before"] == "read:a"
    rows, _ = exp.convert({"n": node}, [_key_entry(1, "grant", "allow"), _key_entry(2, "ungrant", "allow")])
    assert next(r for r in rows if r["action"] == "read")["role_before"] == "user"


def test_the_baseline_uses_the_same_shortened_names_as_the_exported_rows():
    """An owner reading their own 4,096-character asset must not look like an unexpected edge."""
    asset = "f" * 4096
    baseline = exp.baseline_from_owners({"n": {asset: "alice"}})
    rows, _ = exp.convert({"n": [_node_entry(1, "NODE-ALLOW-OWNER", decision="allow", actor="alice", asset=asset)]}, [])
    assert rows[0]["target_service"] in baseline["alice"]
