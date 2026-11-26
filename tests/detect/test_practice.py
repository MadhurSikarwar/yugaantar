"""The detector against the 22 public practice events (copied from the toolkit)."""

from t4.detect import engine, metrics
from t4.detect.ingest import iso_z, load_approvals, load_events, load_labels

from .helpers import PRACTICE


def _run():
    events = load_events(PRACTICE / "events.csv")
    result = engine.analyze(events, load_approvals(PRACTICE / "approvals.json"))
    return events, result


def test_all_22_practice_rows_match_labels():
    events, result = _run()
    truth = load_labels(PRACTICE / "labels.csv")
    assert len(events) == 22
    assert result.predicted() == truth


def test_every_label_is_emitted():
    _, result = _run()
    assert set(result.predicted().values()) == set(engine.LABELS)


def test_alerts_name_identity_services_events_and_rule():
    _, result = _run()
    by_rule = {a.rule: a for a in result.alerts}
    assert set(by_rule) == {"DET-UNAPPROVED-ROLE-CHANGE", "DET-REVIEW-AFTER-ROLE-CHANGE", "DET-LATERAL-MOVEMENT"}
    move = by_rule["DET-LATERAL-MOVEMENT"]
    assert move.identity == "svc-report-worker"
    assert move.event_ids == ("evt-010", "evt-011", "evt-012")
    assert move.services == ("billing", "archive", "identity")
    assert "no successful access" in move.explanation
    # Triggered when the second distinct service arrives (evt-011).
    assert move.emitted_at == "2026-01-15T09:04:02.100Z"
    change = by_rule["DET-UNAPPROVED-ROLE-CHANGE"]
    assert change.identity == "user-blair" and change.event_ids == ("evt-008",)
    review = by_rule["DET-REVIEW-AFTER-ROLE-CHANGE"]
    assert review.event_ids == ("evt-008", "evt-009")
    assert not any(a.order_uncertain for a in result.alerts)


def test_approved_change_and_isolated_denial_raise_no_alert():
    _, result = _run()
    cited = {e for a in result.alerts for e in a.event_ids}
    assert not cited & {"evt-003", "evt-004", "evt-016", "evt-017", "evt-018", "evt-020"}


def test_clock_offset_correction_matches_examples():
    events, _ = _run()
    e15 = next(e for e in events if e.event_id == "evt-015")
    assert iso_z(e15.corrected_time) == "2026-01-15T09:06:01.000Z"
    assert round(e15.delivery_delay_ms) == 200
    assert e15.event_time_utc == "2026-01-15T09:06:03.000Z"  # raw evidence kept


def test_receipt_order_is_preserved():
    events, _ = _run()
    ids = [e.event_id for e in events]
    assert ids.index("evt-014") < ids.index("evt-013")


def test_metrics_on_practice_set():
    events, result = _run()
    truth = load_labels(PRACTICE / "labels.csv")
    report = metrics.evaluate(events, result.predicted(), truth, result.alerts)
    assert report["classification"]["accuracy"] == 1.0
    tta = report["time_to_alert"]
    assert tta["incidents"] == 2 and tta["detected"] == 2
    # evt-008 alert at 09:03:05.2 (0.2 s); movement alert at 09:04:02.1 vs start 09:04:00 (2.1 s).
    assert sorted(round(d, 3) for d in tta["delays_s"]) == [0.2, 2.1]
    assert report["false_alerts"]["false_alerts"] == 0
    assert report["false_alerts"]["benign_events"] == 17


def test_deterministic_alert_ids():
    _, first = _run()
    _, second = _run()
    assert [a.alert_id for a in first.alerts] == [a.alert_id for a in second.alerts]
