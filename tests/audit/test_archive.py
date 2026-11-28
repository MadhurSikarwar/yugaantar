"""Archiving a finished segment: the live log continues the same chain from a signed anchor."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from t4.audit.archive import archive
from t4.audit.log import (CHECKPOINT_NAME, LOG_NAME, SEGMENT_NAME, AuditError, AuditIntegrityError,
                          AuditLog, load_or_create_signer)
from t4.audit.verify import verify_log


def _log(folder):
    return AuditLog(folder, load_or_create_signer(folder))


def _add(log, n, start=0):
    for i in range(start, start + n):
        log.append(actor="u", action="read", target="x", decision="allow", rule="R", request_id=f"r{i}")


def test_archive_moves_the_segment_and_the_chain_continues(tmp_path):
    live, store = tmp_path / "log", tmp_path / "archive"
    _add(_log(live), 40)
    result = archive(live, store)
    assert result["segment"] == 1 and result["seq"] == 40
    assert (live / LOG_NAME).read_bytes() == b"" and (live / SEGMENT_NAME).exists()
    segment = store / "segment-000001"
    pin = json.loads((segment / "pin.json").read_text())
    assert verify_log(segment, pin, bytes.fromhex(pin["public_key"])).ok  # the archive checks on its own
    log = _log(live)
    assert log.last_seq() == 40
    _add(log, 5, start=40)
    entries = log.entries()
    assert [e["seq"] for e in entries] == [41, 42, 43, 44, 45]
    report = verify_log(live)
    assert report.ok and report.entries == 5 and report.covered_seq >= 41
    # A second archive continues the numbering.
    assert archive(live, store)["segment"] == 2 and _log(live).last_seq() == 45


def test_a_forged_anchor_is_refused_everywhere(tmp_path):
    live = tmp_path / "log"
    _add(_log(live), 20)
    archive(live, tmp_path / "archive")
    anchor = json.loads((live / SEGMENT_NAME).read_text())
    anchor["seq"] = 3  # try to make history start later than it really did
    (live / SEGMENT_NAME).write_text(json.dumps(anchor))
    with pytest.raises(AuditIntegrityError):
        _add(_log(live), 1, start=99)
    assert not verify_log(live).ok


def test_an_interrupted_archive_is_finished_by_running_it_again(tmp_path):
    live, store = tmp_path / "log", tmp_path / "archive"
    _add(_log(live), 10)
    archive(live, store)
    (live / SEGMENT_NAME).unlink()  # the crash: log emptied, anchor not yet written
    assert archive(live, store)["completed_earlier_run"] is True
    _add(_log(live), 1, start=10)
    assert _log(live).last_seq() == 11 and verify_log(live).ok


def test_archive_refuses_an_empty_log_and_a_folder_inside_the_log(tmp_path):
    live = tmp_path / "log"
    _add(_log(live), 3)
    with pytest.raises(AuditError):
        archive(live, live / "inside")
    archive(live, tmp_path / "archive")
    with pytest.raises(AuditError):
        archive(live, tmp_path / "archive")


def test_the_adapter_keeps_working_after_its_log_is_archived(tmp_path):
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    env = {"TRACK4_STATE_DIR": str(tmp_path / "state")}
    import os

    env = {**os.environ, **env}

    def call(request):
        done = subprocess.run([sys.executable, "-B", str(root / "track4_service.py")], input=json.dumps(request).encode(),
                              capture_output=True, env=env, cwd=root, timeout=60)
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout)

    call({"op": "setup", "owners": {"a": "maya"}, "contents": {"a": "body"}, "disabled": [], "key_material": "k"})
    assert call({"op": "read", "actor": "maya", "asset": "a", "request_id": "r1"})["decision"] == "allow"
    archive(tmp_path / "state" / "audit", tmp_path / "archive")
    assert call({"op": "revoke", "actor": "maya"}) == {}
    assert call({"op": "read", "actor": "maya", "asset": "a", "request_id": "r2"}) == {"decision": "deny"}
    from t4.consistency import check

    assert check(tmp_path / "state")["problems"] == []
    assert verify_log(tmp_path / "state" / "audit").ok
