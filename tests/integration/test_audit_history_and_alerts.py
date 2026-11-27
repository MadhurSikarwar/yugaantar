"""Lost or damaged audit history: the service refuses, and says so in a separate signed log.

Drives the real adapter, one process per request. The first test group is the important one:
ordinary use, including interrupted writes, must never trip the check.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SETUP = {"op": "setup", "owners": {"a": "maya", "b": "ravi"}, "contents": {"a": "A", "b": "B"},
         "disabled": [], "key_material": "k"}
PUBLIC_KEY = __import__("base64").b64encode(b"\0" * 1184).decode()


def call(state, request):
    env = {**os.environ, "TRACK4_STATE_DIR": str(state)}
    p = subprocess.run([sys.executable, str(ROOT / "track4_service.py")], cwd=ROOT, env=env,
                       input=json.dumps(request).encode(), capture_output=True, timeout=30)
    return p.returncode, (json.loads(p.stdout) if p.stdout else None), p.stderr.decode().strip()


def read(state, rid, actor="maya", asset="a"):
    return call(state, {"op": "read", "actor": actor, "asset": asset, "request_id": rid})


def entries(folder):
    path = folder / "audit.jsonl"
    return [json.loads(l) for l in path.read_bytes().splitlines()] if path.exists() else []


def alerts(state):
    return [e for e in entries(state / "alerts") if e["rule"] == "AUD-LOG-INTEGRITY-FAILURE"]


@pytest.fixture
def state(tmp_path):
    directory = tmp_path / "state"
    assert call(directory, SETUP)[1] == {"ready": True}
    return directory


def test_ordinary_use_never_trips_the_check(state):
    pr = {"op": "protected_read", "actor": "maya", "asset": "a", "challenge": "c", "public_key": PUBLIC_KEY}
    for i in range(3):
        for request in (pr, {"op": "revoke", "actor": f"x{i}"}, pr, {**pr, "actor": "zed"}):
            assert call(state, request)[0] == 0
        assert read(state, f"r{i}")[1] == {"decision": "allow", "body": "A"}
        assert read(state, f"r{i}")[1]["decision"] == "allow"  # duplicate id: an extra alert entry
        for _ in range(5):
            assert read(state, f"d{i}", actor="eve")[1] == {"decision": "deny"}
        assert call(state, {"op": "read"})[0] == 1  # malformed
    assert call(state, SETUP)[1] == {"ready": True}  # second generation, same log
    assert read(state, "after")[1]["decision"] == "allow"
    assert not (state / "alerts").exists()


def test_an_interrupted_append_does_not_trip_the_check(state):
    read(state, "r1")
    with open(state / "audit" / "audit.jsonl", "ab") as handle:
        handle.write(b'{"half":')
    assert read(state, "r2")[1]["decision"] == "allow"
    assert not (state / "alerts").exists()


@pytest.mark.parametrize("what", ["files", "folder"])
def test_deleted_history_is_refused_and_alerted(state, what):
    for i in range(20):
        read(state, f"r{i}")
    if what == "folder":
        shutil.rmtree(state / "audit")
    else:
        (state / "audit" / "audit.jsonl").unlink()
        (state / "audit" / "checkpoints.jsonl").unlink(missing_ok=True)
    for i in range(25):  # refusals must not let a new log grow back past the saved number
        code, reply, err = read(state, f"after{i}")
        assert (code, reply, err) == (1, None, "Request failed (integrity).")
    for request in ({"op": "protected_read", "actor": "maya", "asset": "a", "challenge": "c",
                     "public_key": PUBLIC_KEY}, {"op": "read"}):
        assert call(state, request)[0] == 1
    assert entries(state / "audit") == []
    assert len(alerts(state)) == 1


def test_revoke_still_works_and_does_not_extend_a_shortened_log(state):
    read(state, "r1")
    (state / "audit" / "audit.jsonl").unlink()
    (state / "audit" / "checkpoints.jsonl").unlink(missing_ok=True)
    # In force, but the reply says the audit entry is still pending (the log lost history).
    assert call(state, {"op": "revoke", "actor": "maya"})[:2] == (0, {"audit": "pending"})
    assert entries(state / "audit") == [] and alerts(state)
    code, reply, _ = read(state, "r2")
    assert reply is None or reply == {"decision": "deny"}


def test_edited_entry_is_alerted_once_and_the_alert_log_verifies(state):
    read(state, "r1")
    path = state / "audit" / "audit.jsonl"
    path.write_bytes(path.read_bytes().replace(b'"actor":"maya"', b'"actor":"mayb"', 1))
    for i in range(4):
        assert read(state, f"x{i}")[:2] == (1, None)
    assert len(alerts(state)) == 1
    p = subprocess.run([sys.executable, "-m", "t4.audit.cli", "--dir", str(state / "alerts"), "verify-log"],
                       cwd=ROOT, capture_output=True)
    assert p.returncode == 0


def test_setup_after_lost_history_works_and_leaves_an_alert(state):
    read(state, "r1")
    shutil.rmtree(state / "audit")
    assert call(state, SETUP)[1] == {"ready": True}
    assert alerts(state)
    assert read(state, "r2")[1]["decision"] == "allow"


def test_consistency_command_reports_lost_history(state):
    for i in range(5):
        read(state, f"r{i}")
    lines = (state / "audit" / "audit.jsonl").read_bytes().splitlines(keepends=True)
    (state / "audit" / "audit.jsonl").write_bytes(b"".join(lines[:2]))
    (state / "audit" / "checkpoints.jsonl").unlink(missing_ok=True)
    p = subprocess.run([sys.executable, "-m", "t4.consistency", "--state-dir", str(state)],
                       cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 1 and "audit history was lost" in p.stdout


@pytest.mark.parametrize("key", ["", "AAAA", "!!!not base64", PUBLIC_KEY[:-4], PUBLIC_KEY + "\n", "\u00e9" * 20])
def test_a_bad_public_key_does_not_change_who_is_allowed(state, key):
    """Not allowed: the ordinary deny. Allowed: a clean error, nothing released."""
    base = {"op": "protected_read", "asset": "a", "challenge": "c", "public_key": key}
    assert call(state, {**base, "actor": "eve"})[:2] == (0, {"decision": "deny"})
    assert call(state, {**base, "actor": "maya"}) == (1, None, "Request failed (invalid-input).")
    call(state, {"op": "revoke", "actor": "maya"})
    assert call(state, {**base, "actor": "maya"})[:2] == (0, {"decision": "deny"})
    rules = [e["rule"] for e in entries(state / "audit")]
    assert "CRY-KEY-REJECTED" in rules and "POL-NOT-OWNER" in rules and "POL-REVOKED" in rules
