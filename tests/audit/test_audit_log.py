"""Audit log behaviour: writing, searching, hostile text, repair and concurrency."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from t4.audit.log import (
    GENESIS_HASH,
    LOG_NAME,
    RULE_PARTIAL_REPAIRED,
    AuditIntegrityError,
    AuditLog,
    load_or_create_signer,
    load_signer,
)

ROOT = Path(__file__).resolve().parents[2]


def add(log, request_id="r1", actor="maya", decision="allow", **detail):
    return log.append(
        actor=actor, action="read", target="brief", decision=decision,
        rule="POL-OWNER-ALLOWED", request_id=request_id, detail=detail,
    )


@pytest.fixture
def folder(tmp_path):
    return tmp_path / "audit"


@pytest.fixture
def log(folder):
    return AuditLog(folder, load_or_create_signer(folder), checkpoint_every=4)


def test_append_returns_sequence_and_hash(log):
    first, second = add(log), add(log, "r2")
    assert (first["seq"], second["seq"]) == (1, 2)
    assert first["hash"] != second["hash"] and len(second["hash"]) == 64


def test_entries_have_all_fields_and_a_utc_time(log):
    add(log, generation=3)
    (entry,) = log.entries()
    assert set(entry) == {"seq", "ts", "actor", "action", "target", "decision", "rule", "request_id", "detail", "hash"}
    assert entry["ts"].endswith("Z") and entry["detail"] == {"generation": 3}


def test_survives_reopening(folder, log):
    add(log)
    reopened = AuditLog(folder, load_signer(folder), checkpoint_every=4)
    assert add(reopened, "r2")["seq"] == 2
    assert reopened.verify().ok


@pytest.mark.parametrize(
    "hostile",
    [
        "evil\nsecond line",
        "evil\r\ncarriage",
        "line separator paragraph\u0085next",
        "nul\x00byte",
        "lone\ud800surrogate",
        '"},{"seq":99,"actor":"admin","decision":"allow"}\n{"seq":2',
        "\x1b[2Jterminal",
    ],
)
def test_hostile_text_stays_one_record(folder, log, hostile):
    log.append(actor=hostile, action="read", target=hostile, decision="deny",
               rule="POL-UNKNOWN", request_id=hostile, detail={"note": hostile})
    add(log, "after")
    raw = (folder / LOG_NAME).read_bytes()
    assert raw.count(b"\n") == 2 and all(byte < 128 for byte in raw)
    first, second = log.entries()
    assert first["actor"] == hostile and first["request_id"] == hostile and second["actor"] == "maya"
    assert log.verify().ok
    assert log.explain(hostile) == [first]


@pytest.mark.parametrize("bad", [{"x": 1.5}, {"x": None}, {"x": ["a"]}, {1: "x"}])
def test_detail_types_are_restricted(log, bad):
    with pytest.raises(ValueError):
        log.append(actor="a", action="read", target="t", decision="deny", rule="r", request_id="q", detail=bad)


def test_fields_must_be_strings(log):
    with pytest.raises(ValueError):
        log.append(actor=5, action="read", target="t", decision="deny", rule="r", request_id="q")


def test_explain_returns_records_and_related_alerts(log):
    add(log, "r1")
    add(log, "r2")
    add(log, "r1", decision="deny")
    log.alert(rule="AUD-DUPLICATE-REQUEST-ID", explanation="reused", entries=[1, 3], request_ids=["r1"])
    found = log.explain("r1")
    assert [entry["seq"] for entry in found] == [1, 3, 4]
    assert log.explain("missing") == []


def test_find_by_detail_and_field(log):
    add(log, "p1", challenge_sha256="ab" * 32, generation=2)
    add(log, "p2", challenge_sha256="cd" * 32, generation=2)
    assert [e["request_id"] for e in log.find(challenge_sha256="ab" * 32)] == ["p1"]
    assert len(log.find(rule="POL-OWNER-ALLOWED", generation="2")) == 2
    assert log.find(rule="nothing") == []
    assert log.find(absent="x") == []


def test_alerts_carry_rule_explanation_and_triggers(log):
    add(log)
    log.alert(rule="GRD-THRESHOLD", explanation="five denied requests", actor="eve",
              entries=[1], request_ids=["r1"], detail={"count": 5})
    (alert,) = log.alerts()
    assert alert["rule"] == "GRD-THRESHOLD" and alert["detail"]["count"] == 5
    assert json.loads(alert["detail"]["entries"]) == [1]
    assert json.loads(alert["detail"]["request_ids"]) == ["r1"]


def test_empty_log(log):
    assert log.entries() == []
    head = log.head()
    assert head["seq"] == 0 and head["hash"] == GENESIS_HASH and head["sig"]
    assert log.verify().ok


def test_unsigned_log_works_and_says_so(tmp_path):
    log = AuditLog(tmp_path, None)
    add(log)
    assert log.head()["sig"] is None
    report = log.verify()
    assert report.ok and any("removed tail" in warning for warning in report.warnings)


def test_signer_is_stable_and_never_printed(folder):
    first, second = load_or_create_signer(folder), load_or_create_signer(folder)
    assert first.public_key == second.public_key and first.secret_key == second.secret_key
    assert first.secret_key.hex()[:32] not in repr(first) and "hidden" in repr(first)


def test_wrong_signer_is_rejected(tmp_path):
    AuditLog(tmp_path / "a", load_or_create_signer(tmp_path / "a"))
    with pytest.raises(AuditIntegrityError):
        AuditLog(tmp_path / "a", load_or_create_signer(tmp_path / "b"))


def test_interrupted_write_is_repaired_with_an_alert(folder, log):
    add(log)
    with (folder / LOG_NAME).open("ab") as handle:
        handle.write(b'{"action":"read","actor":"ma')
    assert not log.verify().ok
    assert [e["seq"] for e in log.entries()] == [1]  # reading ignores the fragment
    assert add(log, "r2")["seq"] == 3
    entries = log.entries()
    assert entries[1]["rule"] == RULE_PARTIAL_REPAIRED and entries[1]["decision"] == "alert"
    assert log.verify().ok


def test_interrupted_first_write_is_repaired(folder, log):
    (folder / LOG_NAME).write_bytes(b'{"act')
    assert add(log)["seq"] == 2
    assert log.verify().ok


def test_interrupted_checkpoint_is_repaired(folder, log):
    for number in range(4):
        add(log, f"r{number}")
    with (folder / "checkpoints.jsonl").open("ab") as handle:
        handle.write(b'{"hash":"ab')
    for number in range(4, 8):
        add(log, f"r{number}")
    report = log.verify()
    assert report.ok and report.covered_seq == 8


def test_append_refuses_a_damaged_newest_entry(folder, log):
    add(log)
    add(log, "r2")
    path = folder / LOG_NAME
    path.write_bytes(path.read_bytes().replace(b'"r2"', b'"r9"'))
    with pytest.raises(AuditIntegrityError):
        add(log, "r3")


def test_append_refuses_a_truncated_log(folder, log):
    for number in range(4):  # a checkpoint is written at entry 4
        add(log, f"r{number}")
    path = folder / LOG_NAME
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:2]))
    with pytest.raises(AuditIntegrityError):
        add(log, "r9")
    with pytest.raises(AuditIntegrityError):
        log.entries()


def test_fragment_is_kept_when_earlier_records_are_damaged(folder, log):
    add(log)
    add(log, "r2")
    path = folder / LOG_NAME
    path.write_bytes(path.read_bytes().replace(b'"r2"', b'"r9"') + b'{"frag')
    before = path.read_bytes()
    with pytest.raises(AuditIntegrityError):
        add(log, "r3")
    assert path.read_bytes() == before


def test_odd_request_id_lists_do_not_break_explain(log):
    log.append(actor="", action="alert", target="", decision="alert", rule="X",
               request_id="", detail={"request_ids": "not json"})
    log.append(actor="", action="alert", target="", decision="alert", rule="X",
               request_id="", detail={"request_ids": "5"})
    assert log.explain("5") == []


def test_search_refuses_an_edited_middle_entry(folder, log):
    for number in range(3):
        add(log, f"r{number}")
    path = folder / LOG_NAME
    path.write_bytes(path.read_bytes().replace(b'"r1"', b'"r7"'))
    with pytest.raises(AuditIntegrityError):
        log.explain("r0")


def test_long_entries_span_read_blocks(log):
    for number in range(5):
        add(log, f"r{number}", actor="x" * 20000)
    assert log.verify().ok and len(log.entries()) == 5


def test_concurrent_processes_keep_one_chain(folder, log):
    code = (
        "import sys\n"
        "from t4.audit.log import AuditLog, load_signer\n"
        "log = AuditLog(sys.argv[1], load_signer(sys.argv[1]), checkpoint_every=4)\n"
        "for i in range(15):\n"
        "    log.append(actor=sys.argv[2], action='read', target='t', decision='allow',\n"
        "               rule='r', request_id=f'{sys.argv[2]}-{i}')\n"
    )
    workers = [
        subprocess.Popen([sys.executable, "-B", "-c", code, str(folder), f"w{n}"], cwd=ROOT)
        for n in range(8)
    ]
    assert [worker.wait(timeout=60) for worker in workers] == [0] * 8
    entries = log.entries()
    assert [e["seq"] for e in entries] == list(range(1, 121))
    assert len({e["request_id"] for e in entries}) == 120
    assert log.verify().ok
