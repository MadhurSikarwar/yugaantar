"""When a lateral-movement alert is due, given late delivery (retest finding F-02).

The alert may only claim the time at which the events received so far form a chain on their own.
A connecting event that arrives late delays the alert and is part of its initial evidence.
"""

from __future__ import annotations

from t4.detect.engine import analyze
from t4.detect.ingest import parse_utc

from .helpers import events, row, ts


def edge(event_id, at, delay, target):
    return row(event_id, at, delay=delay, target=target, outcome="deny")


def movement(rows):
    result = analyze(events(*rows), {})
    found = [a for a in result.alerts if a.rule == "DET-LATERAL-MOVEMENT"]
    return result, found


def test_a_late_bridge_delays_the_alert_and_is_initial_evidence():
    # first and last are 100 s apart; only the bridge (51 s, arriving at 110 s) connects them.
    rows = [edge("first", 1, 0.2, "billing"), edge("last", 101, 0.2, "archive"),
            edge("bridge", 51, 59, "billing")]
    _, alerts = movement(rows)
    assert len(alerts) == 1
    alert = alerts[0]
    assert parse_utc(alert.emitted_at) == parse_utc(ts(110))
    assert set(alert.initial_event_ids) == {"first", "bridge", "last"}
    assert set(alert.event_ids) == {"first", "bridge", "last"}


def test_the_claimed_initial_evidence_alone_raises_the_alert():
    rows = [edge("first", 1, 0.2, "billing"), edge("last", 101, 0.2, "archive"),
            edge("bridge", 51, 59, "billing")]
    _, alerts = movement(rows)
    initial = set(alerts[0].initial_event_ids)
    _, again = movement([r for r in rows if r["event_id"] in initial])
    assert len(again) == 1
    assert parse_utc(again[0].emitted_at) <= parse_utc(alerts[0].emitted_at)


def test_in_order_delivery_still_alerts_at_the_second_service():
    rows = [edge("a", 1, 0.2, "billing"), edge("b", 30, 0.2, "archive"), edge("c", 60, 0.2, "identity")]
    _, alerts = movement(rows)
    alert = alerts[0]
    assert parse_utc(alert.emitted_at) == parse_utc(ts(30.2))
    assert set(alert.initial_event_ids) == {"a", "b"}
    assert parse_utc(alert.evidence_complete_at) == parse_utc(ts(60.2))


def test_a_late_event_that_is_not_needed_stays_later_evidence():
    # a and b already form a chain at 30.2 s; c arrives 50 s late and only extends it.
    rows = [edge("a", 1, 0.2, "billing"), edge("b", 30, 0.2, "archive"), edge("c", 40, 50, "identity")]
    _, alerts = movement(rows)
    alert = alerts[0]
    assert parse_utc(alert.emitted_at) == parse_utc(ts(30.2))
    assert "c" not in alert.initial_event_ids
    assert parse_utc(alert.evidence_complete_at) == parse_utc(ts(90))
