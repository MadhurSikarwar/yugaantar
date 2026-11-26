"""Re-delivered events, severity after access was taken away, and rules loaded from a file."""
import json

import pytest

from t4.detect.cli import main
from t4.detect.config import DEFAULT_CONFIG
from t4.detect.engine import analyze
from t4.detect.ingest import events_to_csv, parse_events
from t4.detect.policy_file import apply_policy_file

from .helpers import approvals, events, grant, revoke, row, ts


def test_an_exact_redelivery_is_ignored_even_with_a_later_receipt_time():
    again = {**row("e1", 0), "received_time_utc": ts(30)}
    ignored = []
    parsed = parse_events(events_to_csv([row("e1", 0), row("e2", 1), again]), redelivered=ignored)
    assert [e.event_id for e in parsed] == ["e1", "e2"] and ignored == ["e1"]
    assert [e.receipt_index for e in parsed] == [0, 1]


@pytest.mark.parametrize("change", [{"outcome": "deny"}, {"actor": "other"}, {"target": "billing"}])
def test_two_different_records_with_one_id_are_still_refused(change):
    with pytest.raises(ValueError, match="different content"):
        parse_events(events_to_csv([row("e1", 0), row("e1", 0, **change)]))


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
