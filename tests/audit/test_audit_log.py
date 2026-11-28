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
from t4.audit.verify import verify_log

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


def _tamper_request_id(folder, old: str, new: str) -> None:
    """Change one entry's content, in place, WITHOUT recomputing its stored hash --
    the simplest possible non-tail tamper: no signing key, no rehashing."""
    path = folder / LOG_NAME
    data = path.read_bytes().replace(f'"{old}"'.encode(), f'"{new}"'.encode())
    path.write_bytes(data)


def _once(log, request_id="op-1", rule="KEY-ROTATE", **detail):
    return log.append_once(actor="authority", action="rotate", target="phone", decision="allow",
                           rule=rule, request_id=request_id, detail=detail)


def test_append_once_logs_the_same_operation_a_single_time(folder, log):
    first = _once(log, key_sha256="aa")
    again = _once(log, key_sha256="aa")
    assert again == first  # the existing entry is returned, nothing is appended
    assert [e["request_id"] for e in log.entries()] == ["op-1"]


def test_append_once_distinguishes_operations_and_rules(folder, log):
    _once(log, "op-1")
    _once(log, "op-2")                       # another operation: logged
    _once(log, "op-1", rule="KEY-ENROLL")    # same id, different rule: logged
    assert [(e["request_id"], e["rule"]) for e in log.entries()] == [
        ("op-1", "KEY-ROTATE"), ("op-2", "KEY-ROTATE"), ("op-1", "KEY-ENROLL")]
    assert log.verify().ok


def test_append_once_is_not_fooled_by_the_id_appearing_elsewhere_in_an_entry(folder, log):
    """Only the request_id field counts: the same text in another field does not suppress an entry."""
    log.append(actor="op-1", action="x", target="op-1", decision="allow", rule="KEY-ROTATE",
               request_id="other", detail={"note": "op-1"})
    _once(log, "op-1")
    assert [e["request_id"] for e in log.entries()] == ["other", "op-1"]


def test_append_once_under_concurrency_writes_one_entry(folder, log):
    import threading

    errors = []

    def worker():
        try:
            _once(AuditLog(folder, load_signer(folder), checkpoint_every=4))
        except Exception as error:  # noqa: BLE001 - reported below
            errors.append(error)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert [e["request_id"] for e in log.entries()] == ["op-1"]
    assert log.verify().ok


def test_append_once_never_rewrites_existing_history(folder, log):
    for number in range(3):
        add(log, f"r{number}")
    before = log.entries()
    _once(log)
    assert log.entries()[:3] == before


def test_append_catches_a_tamper_before_any_checkpoint_exists(folder, log):
    """A non-tail tamper is caught on the very next append even with zero checkpoints
    written yet (the window reaches genesis when the log is still this short)."""
    for number in range(3):  # checkpoint_every=4: only entry 1 is signed so far
        add(log, f"r{number}")
    _tamper_request_id(folder, "r1", "zz1")
    with pytest.raises(AuditIntegrityError):
        add(log, "r9")


def test_append_catches_a_tamper_since_the_second_newest_checkpoint(folder, log):
    """A non-tail tamper within roughly the last two checkpoint intervals is caught on
    the very next append -- this is the fix for the audit finding: previously only the
    newest 1-2 entries were ever re-checked by a live append."""
    for number in range(9):  # checkpoints at seq 4 and 8 (checkpoint_every=4)
        add(log, f"r{number}")
    _tamper_request_id(folder, "r4", "zz4")  # seq 5: just after the first checkpoint
    with pytest.raises(AuditIntegrityError):
        add(log, "r9")


def test_append_catches_an_old_tamper_while_the_log_is_small(folder, log):
    """Below FULL_CHECK_EVERY_APPEND_BYTES every append re-hashes the whole chain, so an edit
    to an entry far older than the recent window is refused on the next append."""
    for number in range(13):  # checkpoints at seq 4, 8 and 12; the recent window anchors at 8
        add(log, f"r{number}")
    _tamper_request_id(folder, "r0", "zz0")  # seq 1: well before the recent window
    with pytest.raises(AuditIntegrityError):
        add(log, "r13")


def test_append_does_not_catch_an_older_tamper_on_a_large_log_but_verify_does(folder, log, monkeypatch):
    """Honest limit, not a bug: once the log is larger than the full-check size caps, a live
    append only re-checks the recent window, so an older edit is invisible to it. The size caps
    are set to zero here to model a large log without writing megabytes; a full chain walk
    (verify()/verify-log, explain, find, head()) still catches it."""
    import t4.audit.log as audit_log

    monkeypatch.setattr(audit_log, "FULL_CHECK_EVERY_APPEND_BYTES", 0)
    monkeypatch.setattr(audit_log, "FULL_CHECK_AT_CHECKPOINT_BYTES", 0)
    for number in range(13):
        add(log, f"r{number}")
    _tamper_request_id(folder, "r0", "zz0")  # seq 1: well before the recent window
    add(log, "r13")  # does NOT raise: outside the live window and over the size caps
    assert not log.verify().ok
    with pytest.raises(AuditIntegrityError):
        log.entries()


def test_head_refuses_to_sign_over_edited_history_even_on_a_large_log(folder, log, monkeypatch):
    """head() signs a checkpoint, which vouches for the whole chain: it re-checks all of it
    regardless of the size caps, so it can never sign on top of an edited old entry."""
    import t4.audit.log as audit_log

    monkeypatch.setattr(audit_log, "FULL_CHECK_EVERY_APPEND_BYTES", 0)
    monkeypatch.setattr(audit_log, "FULL_CHECK_AT_CHECKPOINT_BYTES", 0)
    for number in range(13):
        add(log, f"r{number}")
    _tamper_request_id(folder, "r0", "zz0")
    before = (folder / "checkpoints.jsonl").read_bytes()
    with pytest.raises(AuditIntegrityError):
        log.head()
    assert (folder / "checkpoints.jsonl").read_bytes() == before  # nothing was signed


def test_whole_chain_check_runs_once_per_checkpoint_interval_when_the_log_is_mid_sized(folder, monkeypatch):
    """Between the two caps, a log that checkpoints rarely re-checks everything only on the
    append that completes a checkpoint interval."""
    import t4.audit.log as audit_log

    monkeypatch.setattr(audit_log, "FULL_CHECK_EVERY_APPEND_BYTES", 0)
    mid = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=8)
    for number in range(30):  # window = 2 * 8 + 2 = 18 lines, so seq 1 is far outside it
        add(mid, f"r{number}")
    _tamper_request_id(folder, "r0", "zz0")  # seq 1
    add(mid, "a")  # becomes seq 31: 31 is not the last of an interval -> recent window only
    with pytest.raises(AuditIntegrityError):
        add(mid, "b")  # would be seq 32, which completes the interval: whole chain re-checked


def test_key_files_are_written_through_exclusive_unique_temp_files(folder):
    """A planted file or symlink at a guessable temp name cannot capture a signing key, and
    a failed write leaves no temp file behind."""
    import t4.audit.log as audit_log

    folder.mkdir(parents=True)
    (folder / "audit.key.tmp").write_bytes(b"planted")
    for pid_name in (f"audit.key.{__import__('os').getpid()}.tmp",):
        (folder / pid_name).write_bytes(b"planted")
    audit_log._write_atomically(folder / "audit.key", b"K" * 8)
    assert (folder / "audit.key").read_bytes() == b"K" * 8
    assert (folder / "audit.key.tmp").read_bytes() == b"planted"  # untouched, never reused
    leftovers = [p.name for p in folder.iterdir() if p.name.startswith(".audit.key.")]
    assert leftovers == []


def test_verify_reports_a_busy_log_instead_of_reading_it_unlocked(folder, log, monkeypatch):
    """A lock timeout means a writer is active: verification must say so, not read torn data
    and present it as a verdict. An unopenable lock file (read-only copy) still falls back."""
    import t4.audit.verify as audit_verify
    from t4.audit.log import AuditError

    add(log)

    def busy(directory, *a, **k):
        raise AuditError("audit log is busy")

    monkeypatch.setattr(audit_verify, "locked", busy)
    report = audit_verify.verify_log(folder)
    assert not report.ok and any("busy" in error for error in report.errors)

    def readonly(directory, *a, **k):
        raise PermissionError("read-only")

    monkeypatch.setattr(audit_verify, "locked", readonly)
    report = audit_verify.verify_log(folder)
    assert report.ok and any("without the audit lock" in w for w in report.warnings)


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


def _clock(times):
    values = iter(times)
    return lambda: next(values)


def _checkpoint_seqs(folder):
    return [json.loads(line)["seq"] for line in (folder / "checkpoints.jsonl").read_text().splitlines()]


def test_the_first_entry_is_signed_so_a_small_log_is_never_unsigned(folder):
    log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=16)
    add(log, "r0")
    assert _checkpoint_seqs(folder) == [1]
    assert verify_log(folder).covered_seq == 1


def test_a_checkpoint_is_signed_when_the_newest_is_older_than_the_timer(folder):
    stamps = [f"2026-11-28T10:00:{s:02d}.000Z" for s in (0, 0, 10, 20, 31, 31)]  # entry and checkpoint times
    log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=16, checkpoint_seconds=30,
                   clock=_clock(stamps))
    for number in range(4):
        add(log, f"r{number}")
    # entry 1 (signed at :00), entries 2 and 3 within 30 s, entry 4 at :31 is signed by the timer
    assert _checkpoint_seqs(folder) == [1, 4]


def test_the_timer_can_be_turned_off(folder):
    stamps = [f"2026-11-28T10:0{m}:00.000Z" for m in (0, 0, 1, 2, 3)]
    log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=16, checkpoint_seconds=None,
                   clock=_clock(stamps))
    for number in range(4):
        add(log, f"r{number}")
    assert _checkpoint_seqs(folder) == [1]
