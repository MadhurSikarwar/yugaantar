"""Re-delivered events, severity after access was taken away, and rules loaded from a file."""
import json

import pytest

from t4.detect.cli import main
from t4.detect.config import DEFAULT_CONFIG
from t4.detect.engine import analyze
from t4.detect.ingest import COLUMNS, events_to_csv, parse_events
from t4.detect.policy_file import apply_policy_file

from .helpers import approvals, events, grant, revoke, row, ts


def test_an_exact_redelivery_is_ignored_even_with_a_later_receipt_time():
    again = {**row("e1", 0), "received_time_utc": ts(30)}
    ignored = []
    parsed = parse_events(events_to_csv([row("e1", 0), row("e2", 1), again]), redelivered=ignored)
    assert [e.event_id for e in parsed] == ["e1", "e2"] and ignored == ["e1"]
    assert [e.receipt_index for e in parsed] == [0, 1]


@pytest.mark.parametrize("change", [{"outcome": "deny"}, {"actor": "other"}, {"target": "billing"},
                                    {"session": "s9"}, {"offset_ms": 5}])
def test_a_conflicting_copy_is_alerted_and_hides_nothing_else(change):
    """The file also holds a real two-service probe: it must still be found."""
    probe = [row("p1", 10, actor="svc", target="billing", outcome="deny", session="p"),
             row("p2", 15, actor="svc", target="archive", outcome="deny", session="p")]
    parsed = parse_events(events_to_csv([row("e1", 0), row("e1", 0, **change), *probe]))
    alerts = {a.rule: a for a in analyze(parsed, {}).alerts}
    assert set(alerts) == {"DET-CONFLICTING-DUPLICATE", "DET-LATERAL-MOVEMENT"}
    conflict = alerts["DET-CONFLICTING-DUPLICATE"]
    assert conflict.severity == "high" and conflict.event_ids == ("e1",)
    assert conflict.identity == "user-a" and conflict.services and "->" in conflict.explanation


def test_many_copies_make_one_alert_and_identical_ones_are_counted_once():
    rows = [row("e1", 0)] + [row("e1", 0, session=f"s{i % 20}") for i in range(200)]
    parsed = parse_events(events_to_csv(rows))
    assert parsed[0].conflict_count == 20 and len(parsed[0].conflicting) == 5
    assert [a.rule for a in analyze(parsed, {}).alerts] == ["DET-CONFLICTING-DUPLICATE"]


def _csv(columns, rows):
    return "\n".join([",".join(columns)] + [",".join(str(r.get(c, "x")) for c in columns) for r in rows]) + "\n"


@pytest.mark.parametrize("name", ["reordered", "extra-column", "plus-zero", "lower-z", "byte-order-mark"])
def test_reasonable_csv_variations_give_the_same_result(name):
    rows = [row("p1", 10, target="billing", outcome="deny"), row("p2", 15, target="archive", outcome="deny")]
    normal = events_to_csv(rows)
    text = {"reordered": _csv(COLUMNS[::-1], rows), "extra-column": _csv((*COLUMNS, "note"), rows),
            "plus-zero": normal.replace("Z,", "+00:00,"), "lower-z": normal.replace("Z,", "z,"),
            "byte-order-mark": "\ufeff" + normal}[name]
    same = [(a.rule, a.identity, a.event_ids, a.emitted_at) for a in analyze(parse_events(text), {}).alerts]
    assert same == [(a.rule, a.identity, a.event_ids, a.emitted_at)
                    for a in analyze(parse_events(normal), {}).alerts] and same


def test_one_time_spelled_two_ways_is_a_redelivery_not_a_conflict():
    again = {**row("e1", 0), "event_time_utc": row("e1", 0)["event_time_utc"].replace("Z", "+00:00")}
    parsed = parse_events(events_to_csv([row("e1", 0), again]))
    assert len(parsed) == 1 and not parsed[0].conflicting


@pytest.mark.parametrize("text,message", [
    ("", "empty file"), (_csv(COLUMNS[:-1], []), "missing the columns"),
    (_csv((*COLUMNS, "actor"), []), "repeats a column"),
    (events_to_csv([row("e1", 0)]).replace("Z,", "+05:30,"), "UTC"),
])
def test_csv_that_cannot_be_read_exactly_is_still_refused(text, message):
    with pytest.raises(ValueError, match=message):
        parse_events(text)


def test_an_unconfigured_role_gets_its_own_alert():
    alerts = analyze(events(row("a1", 0, role="analyst")), {}).alerts
    assert [(a.rule, a.severity) for a in alerts] == [("DET-ROLE-NOT-CONFIGURED", "low")]
    assert "--policy" in alerts[0].explanation
    known = analyze(events(row("a1", 0, role="viewer", target="billing")), {}).alerts
    assert [a.rule for a in known] == ["DET-UNEXPECTED-EDGE"]


def test_an_unconfigured_role_does_not_hide_a_movement_chain():
    alerts = analyze(events(row("a1", 0, role="analyst", target="billing"),
                            row("a2", 5, role="analyst", target="archive")), {}).alerts
    assert [a.rule for a in alerts] == ["DET-LATERAL-MOVEMENT"]


def test_an_unknown_approver_stays_unapproved_and_the_alert_says_how_to_name_them():
    aps = approvals(grant(approver="user-lead", start=0, end=900))
    change = row("c1", 10, target="identity", action="change_role", role="viewer",
                 role_after="report-reader", approval_id="chg-1")
    alerts = analyze(events(change), aps).alerts
    assert [a.rule for a in alerts] == ["DET-UNAPPROVED-ROLE-CHANGE"]
    assert "--approver" in alerts[0].explanation


def severities(evs, aps):
    return [(a.rule, a.severity) for a in analyze(evs, aps).alerts]


def test_successful_access_after_revocation_is_high():
    aps = approvals(grant(scope=("reports",)), revoke(at=420))
    evs = events(row("e1", 430, target="reports", role="report-reader"))
    assert severities(evs, aps) == [("DET-UNEXPECTED-EDGE", "high")]


def test_successful_access_after_the_approval_ended_is_medium():
    aps = approvals(grant(start=0, end=300, scope=("reports",)))
    evs = events(row("e1", 301, target="reports", role="report-reader"))
    assert severities(evs, aps) == [("DET-UNEXPECTED-EDGE", "medium")]


def test_an_unrelated_edge_stays_low_even_with_a_revocation_on_file():
    aps = approvals(grant(scope=("reports",)), revoke(at=420))
    evs = events(row("e1", 430, target="billing", role="report-reader"))
    assert severities(evs, aps) == [("DET-UNEXPECTED-EDGE", "low")]


def test_policy_file_replaces_the_service_rules(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"role_scope": {"viewer": ["products"]}}), encoding="utf-8")
    cfg = apply_policy_file(policy, DEFAULT_CONFIG)
    evs = events(row("e1", 0, target="products"))
    assert analyze(evs, {}, cfg).alerts == [] and analyze(evs, {}).alerts != []
    assert cfg.authorized_approvers == DEFAULT_CONFIG.authorized_approvers
    (tmp_path / "events.csv").write_text(events_to_csv([row("e1", 0, target="products"), row("e1", 0, target="products")]), encoding="utf-8")
    (tmp_path / "approvals.json").write_text('{"changes": []}', encoding="utf-8")
    assert main(["detect", "--dir", str(tmp_path), "--policy", str(policy)]) == 0
    out = capsys.readouterr()
    assert "0 alerts" in out.out and "re-delivered" in out.err


@pytest.mark.parametrize("bad", [
    "[]", "{", '{"role_rank": {"viewer": 1}}', '{"role_scope": {}}', '{"role_scope": {"viewer": "catalog"}}',
    '{"role_scope": {"viewer": [1]}}', '{"role_scope": {"viewer": ["a"]}, "authorized_approvers": ["x"]}',
    '{"role_scope": {"viewer": ["a"]}, "role_rank": {"viewer": "1"}}',
])
def test_bad_policy_files_are_refused(tmp_path, bad):
    policy = tmp_path / "policy.json"
    policy.write_text(bad, encoding="utf-8")
    with pytest.raises(ValueError):
        apply_policy_file(policy, DEFAULT_CONFIG)
