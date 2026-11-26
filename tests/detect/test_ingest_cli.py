"""Strict input parsing, metrics edge cases and the CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from t4.detect import metrics
from t4.detect.ingest import COLUMNS, events_to_csv, parse_approvals, parse_events, parse_utc

from .helpers import PRACTICE, row

ROOT = Path(__file__).resolve().parents[2]


def test_wrong_header_rejected():
    with pytest.raises(ValueError, match="header"):
        parse_events("a,b,c\n1,2,3\n")


def test_empty_file_rejected():
    with pytest.raises(ValueError):
        parse_events("")


def test_short_row_rejected():
    text = ",".join(COLUMNS) + "\nevt-1,x\n"
    with pytest.raises(ValueError, match="columns"):
        parse_events(text)


def test_reused_event_id_keeps_the_first_record_and_notes_the_other():
    parsed = parse_events(events_to_csv([row("e1", 0), row("e1", 1), row("e2", 2)]))
    assert [e.event_id for e in parsed] == ["e1", "e2"]
    assert parsed[0].conflict_count == 1 and len(parsed[0].conflicting) == 1


@pytest.mark.parametrize("value", ["2026-01-15T09:00:00", "2026-01-15T09:00:00+05:30", "yesterday", ""])
def test_non_utc_times_rejected(value):
    with pytest.raises(ValueError):
        parse_utc(value)


def test_bad_offset_rejected():
    bad = row("e1", 0)
    bad["source_clock_offset_ms"] = "2s"
    with pytest.raises(ValueError, match="offset"):
        parse_events(events_to_csv([bad]))


def test_csv_quoting_round_trips_hostile_text():
    hostile = row("e1", 0, actor='a,"b"\nc')
    assert parse_events(events_to_csv([hostile]))[0].actor == 'a,"b"\nc'


def test_approvals_validation():
    with pytest.raises(ValueError):
        parse_approvals({"changes": [{"approval_id": "x"}]})
    with pytest.raises(ValueError, match="duplicate"):
        good = {"approval_id": "x", "approved_by": "a", "subject": "s", "operation": "grant_role", "role": "r"}
        parse_approvals({"changes": [good, good]})
    with pytest.raises(ValueError):
        parse_approvals([])


def test_metrics_reject_missing_predictions():
    with pytest.raises(ValueError):
        metrics.classification_report({}, {"e1": "routine"})


def test_metrics_counts_false_alert():
    from t4.detect.engine import Alert
    alert = Alert("A", "R", "low", "x", ("s",), ("e1",), "2026-01-15T09:00:00.000Z", "", False)
    report = metrics.false_alerts({"e1": "routine", "e2": "routine"}, [alert])
    assert report["false_alerts"] == 1 and report["per_1000_benign"] == 500.0


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "t4.detect.cli", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)


def test_cli_evaluate_json():
    proc = _cli("evaluate", "--dir", str(PRACTICE), "--json")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["classification"]["correct"] == 22


def test_cli_detect_lists_alerts():
    proc = _cli("detect", "--dir", str(PRACTICE))
    assert proc.returncode == 0
    assert "DET-LATERAL-MOVEMENT" in proc.stdout


def test_cli_bad_input_is_generic_error(tmp_path):
    (tmp_path / "events.csv").write_text("not,a,valid,file\n", encoding="utf-8")
    (tmp_path / "approvals.json").write_text("{}", encoding="utf-8")
    proc = _cli("detect", "--dir", str(tmp_path))
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr and proc.stdout == ""


def test_cli_missing_file_is_generic_error(tmp_path):
    proc = _cli("detect", "--dir", str(tmp_path))
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
