"""Every tamper case, plus the operator commands."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from t4.audit.log import (
    CHECKPOINT_NAME,
    GENESIS_HASH,
    LOG_NAME,
    PUBLIC_KEY_NAME,
    AuditLog,
    canonical,
    entry_hash,
    load_or_create_signer,
)
from t4.audit.verify import verify_log

ROOT = Path(__file__).resolve().parents[2]


def build(folder, count=10, every=4):
    log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=every)
    for number in range(1, count + 1):
        log.append(actor="maya", action="read", target="brief", decision="allow",
                   rule="POL-OWNER-ALLOWED", request_id=f"r{number}",
                   detail={"challenge_sha256": f"{number:064x}"})
    return log


def lines_of(folder):
    return (folder / LOG_NAME).read_bytes().splitlines(keepends=True)


def write_lines(folder, lines):
    (folder / LOG_NAME).write_bytes(b"".join(lines))


def rebuild(folder, change):
    """What an attacker with write access can do: edit and recompute the whole chain."""
    previous, out = GENESIS_HASH, []
    for line in lines_of(folder):
        entry = json.loads(line)
        change(entry)
        entry["hash"] = entry_hash(entry, previous)
        previous = entry["hash"]
        out.append(canonical(entry) + b"\n")
    write_lines(folder, out)


@pytest.fixture
def folder(tmp_path):
    target = tmp_path / "audit"
    build(target)
    return target


def test_clean_log_verifies(folder):
    report = verify_log(folder)
    assert report.ok and report.entries == 10 and report.checkpoints == 2 and report.covered_seq == 8
    assert report.first_bad_seq is None
    assert any("2 newest entries" in warning for warning in report.warnings)


def test_edited_entry_is_pinpointed(folder):
    lines = lines_of(folder)
    lines[4] = lines[4].replace(b'"maya"', b'"mallory"')
    write_lines(folder, lines)
    report = verify_log(folder)
    assert not report.ok and report.first_bad_seq == 5


def test_whitespace_or_duplicate_key_edit_is_detected(folder):
    for replacement in (b'{ "action"', b'{"actor":"mallory","action"'):
        lines = lines_of(folder)
        original = list(lines)
        lines[2] = lines[2].replace(b'{"action"', replacement, 1)
        write_lines(folder, lines)
        assert verify_log(folder).first_bad_seq == 3
        write_lines(folder, original)


@pytest.mark.parametrize("index", [0, 4, 8])
def test_deleted_line_is_pinpointed(folder, index):
    lines = lines_of(folder)
    del lines[index]
    write_lines(folder, lines)
    assert verify_log(folder).first_bad_seq == index + 1


def test_reordered_lines_are_pinpointed(folder):
    lines = lines_of(folder)
    lines[2], lines[3] = lines[3], lines[2]
    write_lines(folder, lines)
    assert verify_log(folder).first_bad_seq == 3


def test_inserted_copy_is_pinpointed(folder):
    lines = lines_of(folder)
    lines.insert(6, lines[5])
    write_lines(folder, lines)
    assert verify_log(folder).first_bad_seq == 7


def test_tail_cut_below_a_checkpoint_is_detected(folder):
    write_lines(folder, lines_of(folder)[:6])
    report = verify_log(folder)
    assert not report.ok and report.first_bad_seq == 7
    assert any("tail removed" in error for error in report.errors)


def test_tail_cut_after_the_last_checkpoint_needs_a_pin(folder):
    pin = AuditLog(folder, None).entries()[-1]
    write_lines(folder, lines_of(folder)[:9])
    assert verify_log(folder).ok  # documented limit
    report = verify_log(folder, {"seq": pin["seq"], "hash": pin["hash"]})
    assert not report.ok and report.first_bad_seq == 10


def test_rebuilt_chain_is_caught_by_checkpoints(folder):
    rebuild(folder, lambda entry: entry.update(actor="mallory") if entry["seq"] == 2 else None)
    report = verify_log(folder)
    assert not report.ok and report.first_bad_seq == 4


def test_rebuilt_log_and_checkpoints_are_caught_only_by_a_pin(folder, tmp_path):
    original = AuditLog(folder, load_or_create_signer(folder))
    pin = original.head()
    public_key = (folder / PUBLIC_KEY_NAME).read_bytes()
    forged = tmp_path / "forged"
    build(forged)  # a fresh history with the attacker's own key
    for name in (LOG_NAME, CHECKPOINT_NAME, PUBLIC_KEY_NAME):
        shutil.copyfile(forged / name, folder / name)
    assert verify_log(folder).ok  # documented limit
    report = verify_log(folder, pin, public_key)
    assert not report.ok
    assert any("pinned key" in error for error in report.errors)
    assert any("signature is invalid" in error for error in report.errors)


def test_rolled_back_directory_is_caught_by_a_pin(tmp_path):
    folder = tmp_path / "audit"
    log = build(folder, count=4)
    snapshot = tmp_path / "snapshot"
    shutil.copytree(folder, snapshot)
    for number in range(5, 9):
        log.append(actor="maya", action="read", target="brief", decision="deny",
                   rule="POL-REVOKED", request_id=f"r{number}")
    pin = log.head()
    shutil.rmtree(folder)
    shutil.copytree(snapshot, folder)
    assert verify_log(folder).ok
    assert verify_log(folder, pin).first_bad_seq == 5


def test_forged_checkpoint_is_rejected(folder):
    path = folder / CHECKPOINT_NAME
    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    records[0]["hash"] = "0" * 64
    path.write_bytes(b"".join(canonical(record) + b"\n" for record in records))
    report = verify_log(folder)
    assert not report.ok and any("signature is invalid" in error for error in report.errors)


@pytest.mark.parametrize("garbage", [b"not json\n", b"[]\n", b'{"seq":"1"}\n', b"\xff\xfe\n", b"[" * 100000 + b"\n"])
def test_garbage_never_crashes_verification(folder, garbage):
    for name in (LOG_NAME, CHECKPOINT_NAME):
        path = folder / name
        original = path.read_bytes()
        path.write_bytes(garbage)
        assert not verify_log(folder).ok
        path.write_bytes(original)


@pytest.mark.parametrize("pin", [{}, {"seq": "1", "hash": "x"}, {"seq": -1, "hash": "x"}, {"seq": 1}, []])
def test_malformed_pin_is_reported(folder, pin):
    report = verify_log(folder, pin)
    assert not report.ok and any("pinned head" in error for error in report.errors)


def test_missing_directory_fails(tmp_path):
    assert not verify_log(tmp_path / "nowhere").ok


def run(folder, *args):
    command = [sys.executable, "-B", "-m", "t4.audit.cli", "--dir", str(folder), *args]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_cli_head_pin_and_verify(folder, tmp_path):
    pin = tmp_path / "pin.json"
    assert run(folder, "head", "--out", str(pin)).returncode == 0
    saved = json.loads(pin.read_text())
    assert saved["seq"] == 10 and saved["public_key"] and saved["sig"]
    good = run(folder, "verify-log", "--pin", str(pin))
    assert good.returncode == 0 and json.loads(good.stdout)["key_pinned"] is True
    write_lines(folder, lines_of(folder)[:9])
    bad = run(folder, "verify-log", "--pin", str(pin))
    assert bad.returncode == 1 and json.loads(bad.stdout)["first_bad_seq"] == 10


def test_cli_explain_by_id_and_challenge(folder):
    by_id = run(folder, "explain", "r3")
    by_challenge = run(folder, "explain", "--challenge", f"{3:064x}".upper())
    assert by_id.returncode == by_challenge.returncode == 0
    assert by_id.stdout == by_challenge.stdout and json.loads(by_id.stdout)["request_id"] == "r3"
    assert run(folder, "explain").returncode == 2


def test_cli_alerts_escape_terminal_control_text(folder):
    log = AuditLog(folder, load_or_create_signer(folder))
    log.alert(rule="X", explanation="\x1b[2J spoof", actor="\x1b]0;title\x07")
    result = run(folder, "alerts")
    assert result.returncode == 0 and result.stdout.count("\n") == 1
    assert "\x1b" not in result.stdout and " " not in result.stdout


def test_cli_reports_damage_and_never_prints_the_key(folder):
    # An ML-DSA secret key starts with the public seed (also in the public key), so
    # check bytes 32 to 64, the secret seed that follows it.
    secret = (folder / "audit.key").read_bytes()[32:64].hex()
    outputs = [run(folder, "head"), run(folder, "verify-log")]
    write_lines(folder, [b"junk\n"])
    damaged = run(folder, "alerts")
    assert damaged.returncode == 1 and "Traceback" not in damaged.stderr
    for result in (*outputs, damaged):
        assert secret not in result.stdout + result.stderr
