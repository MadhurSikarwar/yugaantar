"""The log generator: reproducible, practice-compatible and internally consistent."""

import csv
import importlib.util
import io
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gen_logs", ROOT / "tools" / "gen_logs.py")
gen = importlib.util.module_from_spec(SPEC)
sys.modules["gen_logs"] = gen
SPEC.loader.exec_module(gen)


def rows(content):
    return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def corrected(row):
    return when(row["event_time_utc"]) - timedelta(milliseconds=int(row["source_clock_offset_ms"]))


@pytest.fixture(scope="module")
def data():
    files = gen.generate(7, 12000)
    events = rows(files["events.csv"])
    labels = {row["event_id"]: row["label"] for row in rows(files["labels.csv"])}
    changes = {c["approval_id"]: c for c in json.loads(files["approvals.json"])["changes"]}
    manifest = json.loads(files["manifest.json"])
    return files, events, labels, changes, manifest


def test_same_seed_same_bytes():
    assert gen.generate(5, 2000) == gen.generate(5, 2000)
    assert gen.generate(5, 2000)["events.csv"] != gen.generate(6, 2000)["events.csv"]
    assert gen.HELD_OUT_SEED != gen.DEFAULT_SEED


def test_size_and_all_nine_labels(data):
    _, events, labels, _, manifest = data
    assert len(events) >= 12000 and len(labels) == len(events) == manifest["events"]
    assert set(labels.values()) == set(gen.LABELS)
    assert Counter(labels.values()) == Counter({k: v for k, v in manifest["label_counts"].items()})
    attacks = sum(manifest["label_counts"][name] for name in
                  ("unexpected_role_change", "review_after_role_change", "lateral_movement_candidate"))
    assert 0.01 < attacks / len(events) < 0.2


def test_receipt_order_and_unique_ids(data):
    _, events, labels, _, _ = data
    assert len({row["event_id"] for row in events}) == len(events)
    received = [row["received_time_utc"] for row in events]
    assert received == sorted(received)
    assert {row["event_id"] for row in events} == set(labels)


def test_offsets_and_delays_stay_in_the_supported_range(data):
    _, events, _, _, _ = data
    for row in events:
        assert abs(int(row["source_clock_offset_ms"])) <= gen.MAX_OFFSET_MS
        delay = when(row["received_time_utc"]) - corrected(row)
        assert timedelta(0) < delay <= timedelta(milliseconds=gen.MAX_DELAY_MS)


def test_ids_follow_corrected_event_time(data):
    ordered = sorted(data[1], key=lambda row: row["event_id"])
    times = [corrected(row) for row in ordered]
    assert times == sorted(times)


def covered(row, changes):
    approval = changes.get(row["approval_id"])
    return bool(
        approval
        and approval["operation"] == "grant_role"
        and approval["subject"] == row["actor"]
        and approval["role"] == row["role_after"]
        and approval["approved_by"] in gen.CONTEXT["authorized_approvers"]
        and when(approval["valid_from_utc"]) <= corrected(row) < when(approval["valid_until_utc"])
    )


def test_role_change_labels_match_the_approvals(data):
    _, events, labels, changes, _ = data
    seen = Counter()
    for row in events:
        if row["action"] == "role_change":
            expected = "approved_change" if covered(row, changes) else "unexpected_role_change"
            assert labels[row["event_id"]] == expected, row
            seen[expected] += 1
    assert seen["approved_change"] > 100 and seen["unexpected_role_change"] > 30


def test_every_mismatch_variant_and_pace_appears(data):
    incidents = data[4]["incidents"].values()
    variants = {i.get("variant") for i in incidents if i["kind"] == "unapproved_change"}
    assert variants == {"no_approval", "expired", "at_end", "early", "wrong_subject", "wrong_role",
                        "unauthorized_approver", "skew_hides_expiry"}
    assert {i.get("pace") for i in incidents if i["kind"] == "lateral_movement"} == {"fast", "slow"}


def test_incidents_match_their_events(data):
    _, events, labels, _, manifest = data
    by_id = {row["event_id"]: row for row in events}
    for incident in manifest["incidents"].values():
        members = [by_id[event_id] for event_id in incident["events"]]
        assert {row["actor"] for row in members} == {incident["actor"]}
        assert len({row["session_id"] for row in members}) == 1
        assert when(incident["first_event_time_utc"]) == corrected(members[0])
        if incident["kind"] == "lateral_movement":
            assert len({row["target_service"] for row in members}) >= 2
            assert {labels[row["event_id"]] for row in members} == {"lateral_movement_candidate"}


def test_lateral_events_never_use_a_normal_edge(data):
    _, events, labels, _, _ = data
    edges = gen.CONTEXT["baseline_edges"]
    normal = {tuple(edge) for name in ("users", gen.WORKER) for edge in edges[name]}
    suspicious = [row for row in events if labels[row["event_id"]] == "lateral_movement_candidate"]
    assert suspicious
    assert not [row for row in suspicious if (row["source_service"], row["target_service"]) in normal]


def test_delayed_events_really_arrive_late(data):
    _, events, labels, _, _ = data
    position = {row["event_id"]: index for index, row in enumerate(events)}
    sessions = defaultdict(list)
    for row in events:
        sessions[row["session_id"]].append(row)
    late = [row for row in events if labels[row["event_id"]] == "routine_delayed_delivery"]
    assert late
    for row in late:
        assert any(corrected(other) > corrected(row) and position[other["event_id"]] < position[row["event_id"]]
                   for other in sessions[row["session_id"]])


def test_denial_and_offset_labels(data):
    _, events, labels, _, _ = data
    isolated = defaultdict(set)
    for row in events:
        label = labels[row["event_id"]]
        if label in ("isolated_denial", "routine_denial"):
            assert row["outcome"] == "deny"
        if label == "isolated_denial":
            isolated[row["session_id"]].add(row["target_service"])
        if label == "routine_clock_offset":
            assert int(row["source_clock_offset_ms"]) != 0
    assert all(len(targets) == 1 for targets in isolated.values())


def test_columns_match_the_toolkit_practice_files(data):
    practice = ROOT.parent / "Track-4-Toolkit" / "practice"
    if not practice.is_dir():
        pytest.skip("toolkit not cloned next to the repository")
    files, events, _, _, _ = data
    for name in ("events.csv", "labels.csv"):
        header = (practice / name).read_text(encoding="utf-8").splitlines()[0]
        assert files[name].decode().splitlines()[0] == header
    theirs = json.loads((practice / "approvals.json").read_text(encoding="utf-8"))["changes"]
    ours = json.loads(files["approvals.json"])["changes"]
    for operation in ("grant_role", "revoke_role"):
        expected = next(set(c) for c in theirs if c["operation"] == operation)
        assert next(set(c) for c in ours if c["operation"] == operation) == expected
    practice_labels = {row["label"] for row in csv.DictReader((practice / "labels.csv").open(encoding="utf-8"))}
    assert practice_labels == set(gen.LABELS)


def test_command_line(tmp_path, capsys):
    assert gen.main(["--out", str(tmp_path), "--seed", "3", "--events", "500"]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "approvals.json", "context.json", "events.csv", "labels.csv", "manifest.json"]
    assert json.loads(capsys.readouterr().out)["events"] >= 500
