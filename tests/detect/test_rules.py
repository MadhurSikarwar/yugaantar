"""Edge cases for each rule, on small synthetic fixtures."""

from dataclasses import replace

from t4.detect import engine
from t4.detect.config import DEFAULT_CONFIG

from .helpers import approvals, events, grant, revoke, row


def labels(evs, aps=None, cfg=DEFAULT_CONFIG):
    result = engine.analyze(evs, aps or {}, cfg)
    return result.predicted(), result.alerts


# --- role changes -----------------------------------------------------

def _change(at=120, approval_id="chg-1", actor="user-a", role_after="report-reader"):
    return row("e1", at, actor=actor, source="admin-console", target="identity", action="role_change",
               role="viewer", role_after=role_after, outcome="success", approval_id=approval_id)


def test_matching_approval_is_approved_not_alerted():
    pred, alerts = labels(events(_change()), approvals(grant()))
    assert pred == {"e1": "approved_change"}
    assert alerts == []


def test_approval_end_is_exclusive():
    pred, alerts = labels(events(_change(at=420)), approvals(grant(end=420)))
    assert pred["e1"] == "unexpected_role_change"
    assert "end exclusive" in alerts[0].explanation


def test_change_before_window_is_unexpected():
    pred, _ = labels(events(_change(at=59)), approvals(grant(start=60)))
    assert pred["e1"] == "unexpected_role_change"


def test_approval_for_another_subject_is_unexpected():
    pred, alerts = labels(events(_change()), approvals(grant(subject="user-b")))
    assert pred["e1"] == "unexpected_role_change"
    assert alerts[0].rule == "DET-UNAPPROVED-ROLE-CHANGE"


def test_wrong_role_is_unexpected():
    pred, _ = labels(events(_change(role_after="operator")), approvals(grant()))
    assert pred["e1"] == "unexpected_role_change"


def test_unauthorized_approver_is_unexpected():
    pred, _ = labels(events(_change()), approvals(grant(approver="user-mallory")))
    assert pred["e1"] == "unexpected_role_change"


def test_unknown_approval_id_is_unexpected():
    pred, alerts = labels(events(_change(approval_id="chg-404")), approvals(grant()))
    assert pred["e1"] == "unexpected_role_change"
    assert "does not exist" in alerts[0].explanation


def test_revoked_approval_no_longer_covers_change():
    pred, _ = labels(events(_change(at=300)), approvals(grant(), revoke(at=200)))
    assert pred["e1"] == "unexpected_role_change"


def test_denied_role_change_is_not_a_change():
    ev = _change(approval_id="")
    ev["outcome"] = "deny"
    pred, alerts = labels(events(ev))
    assert pred["e1"] == "isolated_denial"
    assert alerts == []


def test_approval_action_by_unauthorized_operator_alerts():
    ev = row("e1", 60, actor="user-mallory", source="admin-console", target="identity",
             action="approve_role_change", role="operator", outcome="success", approval_id="chg-1")
    pred, alerts = labels(events(ev), approvals(grant()))
    assert pred["e1"] == "unexpected_role_change"
    assert alerts[0].rule == "DET-UNAUTHORIZED-APPROVAL"


def test_every_use_of_the_unapproved_role_is_review_until_the_role_changes():
    evs = events(
        _change(approval_id=""),
        row("e2", 121, role="report-reader", target="catalog"),
        row("e3", 122, role="report-reader", target="catalog"),
        row("e4", 123, actor="user-a", source="admin-console", target="identity", action="role_change",
            role="report-reader", role_after="viewer", outcome="success"),
        row("e5", 124, role="report-reader", target="catalog"),  # after the role changed again
    )
    pred, alerts = labels(evs)
    assert pred["e2"] == pred["e3"] == "review_after_role_change"
    assert pred["e5"] != "review_after_role_change"
    assert [a.rule for a in alerts][:3] == ["DET-UNAPPROVED-ROLE-CHANGE", "DET-REVIEW-AFTER-ROLE-CHANGE",
                                            "DET-REVIEW-AFTER-ROLE-CHANGE"]


def test_review_followups_can_be_limited_to_the_next_action():
    evs = events(
        _change(approval_id=""),
        row("e2", 121, role="report-reader", target="catalog"),
        row("e3", 122, role="report-reader", target="catalog"),
    )
    pred, alerts = labels(evs, cfg=replace(DEFAULT_CONFIG, review_followups=1))
    assert pred["e2"] == "review_after_role_change"
    assert pred["e3"] == "routine"
    assert [a.rule for a in alerts] == ["DET-UNAPPROVED-ROLE-CHANGE", "DET-REVIEW-AFTER-ROLE-CHANGE"]


def test_denial_after_approval_ended_is_routine_denial():
    # grant() covers reports for user-a until 420; a denied reports read afterwards is the system working
    evs = events(row("e1", 500, role="viewer", target="reports", outcome="deny"),
                 row("e2", 501, role="viewer", target="reports-node-a", outcome="deny"))
    pred, alerts = labels(evs, approvals(grant(scope=("reports", "reports-node-a"))))
    assert pred == {"e1": "routine_denial", "e2": "routine_denial"}
    assert alerts == []


def test_denial_outside_the_ended_scope_is_still_judged():
    evs = events(row("e1", 500, role="viewer", target="billing", outcome="deny"),
                 row("e2", 501, role="viewer", target="archive", outcome="deny"))
    pred, alerts = labels(evs, approvals(grant(scope=("reports",))))
    assert pred == {"e1": "lateral_movement_candidate", "e2": "lateral_movement_candidate"}
    assert [a.rule for a in alerts] == ["DET-LATERAL-MOVEMENT"]


def test_review_requires_same_session():
    evs = events(_change(approval_id=""), row("e2", 121, role="report-reader", session="sess-other"))
    pred, _ = labels(evs)
    assert pred["e2"] == "routine"


# --- lateral movement -------------------------------------------------

def _edge(event_id, at, target, outcome="deny", session="sess-w", actor="svc-w", correlation=None):
    return row(event_id, at, actor=actor, source="reports", target=target, role="service-reader",
               outcome=outcome, session=session, correlation=correlation or f"flow-{event_id}")


def test_two_services_within_window_is_movement():
    pred, alerts = labels(events(_edge("e1", 0, "billing"), _edge("e2", 30, "archive")))
    assert pred == {"e1": "lateral_movement_candidate", "e2": "lateral_movement_candidate"}
    assert alerts[0].rule == "DET-LATERAL-MOVEMENT" and alerts[0].event_ids == ("e1", "e2")


def test_gap_above_window_splits_chain():
    pred, alerts = labels(events(_edge("e1", 0, "billing"), _edge("e2", 61, "archive")))
    assert pred == {"e1": "isolated_denial", "e2": "isolated_denial"}
    assert alerts == []


def test_slow_steps_of_one_flow_are_still_movement():
    """Steps more than W apart stay in one chain when they carry the same correlation ID."""
    pred, alerts = labels(events(_edge("e1", 0, "billing", correlation="flow-x"),
                                 _edge("e2", 140, "archive", correlation="flow-x")))
    assert pred == {"e1": "lateral_movement_candidate", "e2": "lateral_movement_candidate"}
    assert alerts[0].rule == "DET-LATERAL-MOVEMENT"


def test_a_flow_gap_above_the_flow_window_splits_the_chain():
    pred, _ = labels(events(_edge("e1", 0, "billing", correlation="flow-x"),
                            _edge("e2", 601, "archive", correlation="flow-x")))
    assert set(pred.values()) == {"isolated_denial"}


def test_the_flow_window_can_be_turned_off():
    cfg = replace(DEFAULT_CONFIG, movement_flow_window_s=0)
    pred, _ = labels(events(_edge("e1", 0, "billing", correlation="flow-x"),
                            _edge("e2", 140, "archive", correlation="flow-x")), cfg=cfg)
    assert set(pred.values()) == {"isolated_denial"}


def test_same_service_twice_is_not_movement():
    pred, _ = labels(events(_edge("e1", 0, "billing"), _edge("e2", 5, "billing")))
    assert set(pred.values()) == {"isolated_denial"}


def test_different_sessions_are_not_chained():
    pred, _ = labels(events(_edge("e1", 0, "billing", session="s1"), _edge("e2", 5, "archive", session="s2")))
    assert set(pred.values()) == {"isolated_denial"}


def test_successful_movement_is_reported_as_access():
    pred, alerts = labels(events(_edge("e1", 0, "billing", outcome="allow"), _edge("e2", 5, "archive")))
    assert set(pred.values()) == {"lateral_movement_candidate"}
    assert "successful access in e1" in alerts[0].explanation


def test_denials_after_revocation_do_not_count_as_movement():
    aps = approvals(grant(scope=("reports-node-a", "reports-node-b")), revoke(at=420))
    evs = events(
        row("e1", 422, target="reports-node-a", outcome="deny", approval_id="chg-2"),
        row("e2", 423, target="reports-node-b", outcome="deny", approval_id="chg-2"),
    )
    pred, alerts = labels(evs, aps)
    assert pred == {"e1": "routine_denial", "e2": "routine_denial"}
    assert alerts == []


def test_denial_outside_revoked_scope_is_not_routine():
    aps = approvals(grant(scope=("reports",)), revoke(at=420))
    pred, _ = labels(events(row("e1", 422, target="billing", outcome="deny")), aps)
    assert pred["e1"] == "isolated_denial"


def test_lone_allowed_unexpected_edge_is_low_alert():
    pred, alerts = labels(events(row("e1", 0, target="billing", outcome="allow")))
    assert pred["e1"] == "routine"
    assert [(a.rule, a.severity) for a in alerts] == [("DET-UNEXPECTED-EDGE", "low")]


def test_approval_scope_applies_only_while_valid():
    aps = approvals(grant(start=60, end=420))
    inside = row("e1", 100, target="reports", role="report-reader")
    after = row("e2", 421, target="reports", role="report-reader", outcome="allow")
    pred, alerts = labels(events(inside, after), aps)
    assert pred["e1"] == "routine"
    assert pred["e2"] == "routine" and alerts[0].rule == "DET-UNEXPECTED-EDGE"


def test_thresholds_come_from_config():
    cfg = replace(DEFAULT_CONFIG, movement_min_services=3)
    pred, _ = labels(events(_edge("e1", 0, "billing"), _edge("e2", 5, "archive")), cfg=cfg)
    assert set(pred.values()) == {"isolated_denial"}


def test_config_defaults_are_documented_values():
    assert DEFAULT_CONFIG.movement_min_services == 2
    assert DEFAULT_CONFIG.movement_window_s == 60.0
    assert DEFAULT_CONFIG.authorized_approvers == frozenset({"user-admin"})


# --- clock and order --------------------------------------------------

def test_delayed_delivery_label():
    pred, alerts = labels(events(row("e1", 0, delay=5)))
    assert pred["e1"] == "routine_delayed_delivery" and alerts == []


def test_clock_offset_label_and_correction():
    evs = events(row("e1", 0, offset_ms=-3000, delay=0.2))
    pred, _ = labels(evs)
    assert pred["e1"] == "routine_clock_offset"
    assert evs[0].event_time_utc == "2026-01-15T08:59:57.000Z"
    assert round(evs[0].delivery_delay_ms) == 200


def test_close_events_are_order_uncertain():
    result = engine.analyze(events(row("e1", 0), row("e2", 0.15)), {})
    assert result.order_uncertain == {"e1", "e2"}


def test_offset_outside_supported_range_is_uncertain():
    result = engine.analyze(events(row("e1", 0, offset_ms=9000), row("e2", 100)), {})
    assert "e1" in result.order_uncertain and "e2" not in result.order_uncertain


def test_uncertain_alert_is_flagged():
    _, alerts = labels(events(_edge("e1", 0, "billing"), _edge("e2", 0.05, "archive")))
    assert alerts[0].order_uncertain is True


def test_movement_found_regardless_of_receipt_order():
    late_first = _edge("e1", 0, "billing")
    late_first["received_time_utc"] = row("x", 40)["received_time_utc"]
    pred, alerts = labels(events(_edge("e2", 10, "archive"), late_first))
    assert set(pred.values()) == {"lateral_movement_candidate"}
    assert alerts[0].event_ids == ("e1", "e2")  # timeline order, not receipt order


# --- hostile text ----------------------------------------------------------

def test_hostile_identifiers_stay_opaque():
    actor = 'evil\n{"event_id":"evt-x","actor":"user-admin"} '
    pred, alerts = labels(events(_edge("e1", 0, "billing", actor=actor), _edge("e2", 1, "archive", actor=actor)))
    assert alerts[0].identity == actor
    assert set(pred) == {"e1", "e2"}
