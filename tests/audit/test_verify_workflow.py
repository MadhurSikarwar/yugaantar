"""Layered audit verification: live checks, full-history verification and trusted pins.

Synthetic, signed logs in temporary folders only. Each test states what a person running these
tools can rely on, and what they cannot.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

import t4.audit.log as audit_log
import t4.audit.verify as audit_verify
from t4.audit.log import (
    CHECKPOINT_NAME,
    LOG_NAME,
    AuditIntegrityError,
    AuditLog,
    canonical,
    load_signer,
)
from t4.audit.verify import verify_log
from tests.audit.synthetic import build_log

ROOT = Path(__file__).resolve().parents[2]
BIG = 800  # entries; with pad this is comfortably over FULL_CHECK_EVERY_APPEND_BYTES (256 KiB)


@pytest.fixture
def folder(tmp_path):
    return tmp_path / "audit"


@pytest.fixture
def big(folder):
    """A signed log over the 256 KiB live-check size, checkpointing every 16 entries."""
    seq, head = build_log(folder, BIG, pad=300)
    assert (folder / LOG_NAME).stat().st_size > audit_log.FULL_CHECK_EVERY_APPEND_BYTES
    return folder, seq, head


def live(folder, checkpoint_every=16):
    return AuditLog(folder, load_signer(folder), checkpoint_every=checkpoint_every)


def edit_entry(folder, index, **changes):
    """Edit one entry in place WITHOUT fixing its hash: the simplest tamper, no key needed."""
    path = folder / LOG_NAME
    lines = path.read_bytes().split(b"\n")
    item = json.loads(lines[index - 1])
    item.update(changes)
    lines[index - 1] = canonical(item)
    path.write_bytes(b"\n".join(lines))


def append_one(log, name="live"):
    return log.append(actor="a", action="read", target="t", decision="allow", rule="R", request_id=name)


# ---- layer 1: live verification -------------------------------------------------------------


def test_live_append_catches_a_recent_edit_on_a_large_log(big):
    folder, seq, _ = big
    edit_entry(folder, seq - 3, actor="mallory")
    with pytest.raises(AuditIntegrityError):
        append_one(live(folder))


def test_live_append_does_not_look_at_old_history_on_a_large_log_by_design(big):
    """Documented trade-off: past the size caps the service re-checks only the recent window."""
    folder, seq, _ = big
    assert (seq + 1) % 16 != 0  # not the append that completes a checkpoint interval
    edit_entry(folder, 5, actor="mallory")
    append_one(live(folder))  # accepted: that entry is outside the live window


def test_live_append_does_check_everything_at_a_checkpoint_boundary_on_a_mid_sized_log(folder):
    seq, _ = build_log(folder, 15 + 16 * 40, pad=300)  # next append completes an interval
    assert (folder / LOG_NAME).stat().st_size > audit_log.FULL_CHECK_EVERY_APPEND_BYTES
    edit_entry(folder, 5, actor="mallory")
    with pytest.raises(AuditIntegrityError):
        append_one(live(folder))


# ---- layer 2: full-history verification -----------------------------------------------------


def test_full_verification_detects_an_old_edit_the_live_service_missed(big):
    folder, _, _ = big
    edit_entry(folder, 5, actor="mallory")
    append_one(live(folder))  # the live path accepted it (see above)
    report = verify_log(folder)
    assert not report.ok and report.first_bad_seq == 5


def test_full_verification_of_a_clean_large_log_passes_with_every_checkpoint_valid(big):
    folder, seq, head = big
    report = verify_log(folder)
    assert report.ok and report.entries == seq and report.checkpoints == seq // 16
    assert report.covered_seq == (seq // 16) * 16 and report.head_hash == head


def test_a_missing_historical_entry_is_pinpointed(big):
    folder, _, _ = big
    path = folder / LOG_NAME
    lines = path.read_bytes().split(b"\n")
    del lines[99]  # entry 100
    path.write_bytes(b"\n".join(lines))
    assert verify_log(folder).first_bad_seq == 100


def test_a_sequence_inconsistency_is_pinpointed(big):
    folder, _, _ = big
    edit_entry(folder, 300, seq=999)
    assert verify_log(folder).first_bad_seq == 300


def test_a_truncated_log_is_detected_against_the_checkpoints(big):
    folder, seq, _ = big
    path = folder / LOG_NAME
    lines = path.read_bytes().split(b"\n")
    path.write_bytes(b"\n".join(lines[: seq - 100]) + b"\n")
    report = verify_log(folder)
    assert not report.ok and any("tail removed" in e for e in report.errors)


def test_an_invalid_checkpoint_signature_is_detected(big):
    folder, _, _ = big
    path = folder / CHECKPOINT_NAME
    rows = path.read_bytes().splitlines()
    record = json.loads(rows[10])
    record["sig"] = "00" * (len(record["sig"]) // 2)
    rows[10] = canonical(record)
    path.write_bytes(b"\n".join(rows) + b"\n")
    report = verify_log(folder)
    assert not report.ok and any("checkpoint 11" in e and "signature is invalid" in e for e in report.errors)


def test_verification_is_read_only_and_repeatable(big):
    folder, _, _ = big
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.name != "audit.lock"}
    first, second = verify_log(folder), verify_log(folder)
    after = {p.name: p.read_bytes() for p in folder.iterdir() if p.name != "audit.lock"}
    assert before == after and first == second


def test_verification_streams_it_does_not_read_the_log_into_memory(big, monkeypatch):
    folder, _, _ = big
    calls = []
    real = audit_verify.read_bytes
    monkeypatch.setattr(audit_verify, "read_bytes",
                        lambda path: (calls.append(Path(path).name), real(path))[1])
    assert verify_log(folder).ok
    # Neither the log nor the checkpoint file (about as large as the log: each signature is 6.6 KB
    # of hex) is read whole; only the small public key is.
    assert set(calls) == {"audit.pub"}


def test_an_append_during_verification_does_not_confuse_it(big, monkeypatch):
    """The snapshot fixes how much of the log is checked; later appends are simply not part of it."""
    folder, seq, _ = big
    real = audit_verify._snapshot

    def snapshot_then_append(path, warnings):
        taken = real(path, warnings)
        for number in range(5):
            append_one(live(folder), f"during-{number}")
        return taken

    monkeypatch.setattr(audit_verify, "_snapshot", snapshot_then_append)
    report = verify_log(folder)
    assert report.ok and report.entries == seq
    monkeypatch.undo()
    assert verify_log(folder).entries >= seq + 5


# ---- layer 3: trusted pins ------------------------------------------------------------------


def run(folder, *args):
    return subprocess.run([sys.executable, "-m", "t4.audit.cli", "--dir", str(folder), *args],
                          capture_output=True, text=True, cwd=ROOT)


def test_a_pin_survives_a_valid_extension_and_a_stale_pin_still_verifies(folder, tmp_path):
    build_log(folder, 40)
    pin = tmp_path / "pins" / "pin.json"
    pin.parent.mkdir()
    assert run(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    saved = json.loads(pin.read_text())
    seq, head = build_log(folder, 40, start_seq=saved["seq"], previous=saved["hash"])
    report = verify_log(folder, saved, bytes.fromhex(saved["public_key"]))
    assert report.ok and report.head_pinned and report.covered_seq >= saved["seq"]  # stale but valid


def test_a_pin_that_does_not_match_fails_verification(folder, tmp_path):
    build_log(folder, 40)
    pin = tmp_path / "pin.json"
    assert run(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    saved = json.loads(pin.read_text())
    saved["hash"] = "ab" * 32
    assert not verify_log(folder, saved, bytes.fromhex(saved["public_key"])).ok
    saved = json.loads(pin.read_text())
    assert not verify_log(folder, saved, b"\x00" * 1952).ok  # wrong key


def test_pin_init_refuses_a_path_inside_the_audit_directory(folder):
    build_log(folder, 20)
    result = run(folder, "pin", "init", "--pin", str(folder / "pin.json"))
    assert result.returncode == 2 and not (folder / "pin.json").exists()


def test_pin_init_never_replaces_an_existing_pin(folder, tmp_path):
    build_log(folder, 20)
    pin = tmp_path / "pin.json"
    pin.write_text("trusted-bytes")
    assert run(folder, "pin", "init", "--pin", str(pin)).returncode == 2
    assert pin.read_text() == "trusted-bytes"


def test_head_out_refuses_to_overwrite_a_pin(folder, tmp_path):
    build_log(folder, 20)
    pin = tmp_path / "pin.json"
    pin.write_text("trusted-bytes")
    assert run(folder, "head", "--out", str(pin)).returncode == 2
    assert pin.read_text() == "trusted-bytes"


def test_pin_init_refuses_to_pin_a_log_that_does_not_verify(folder, tmp_path):
    build_log(folder, 40)
    edit_entry(folder, 7, actor="mallory")
    pin = tmp_path / "pin.json"
    result = run(folder, "pin", "init", "--pin", str(pin))
    assert result.returncode == 1 and not pin.exists()


def test_pin_advance_moves_the_pin_only_after_the_whole_log_verifies(folder, tmp_path):
    build_log(folder, 40)
    pin = tmp_path / "pin.json"
    assert run(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    first = json.loads(pin.read_text())
    build_log(folder, 40, start_seq=first["seq"], previous=first["hash"])
    assert run(folder, "pin", "advance", "--pin", str(pin)).returncode == 0
    second = json.loads(pin.read_text())
    assert second["seq"] > first["seq"] and second["public_key"] == first["public_key"]
    assert run(folder, "verify-log", "--pin", str(pin)).returncode == 0


def test_pin_advance_on_a_rewritten_history_leaves_the_pin_untouched(folder, tmp_path):
    build_log(folder, 40)
    pin = tmp_path / "pin.json"
    assert run(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    before = pin.read_bytes()
    edit_entry(folder, 3, actor="mallory")  # history under the pin was edited
    result = run(folder, "pin", "advance", "--pin", str(pin))
    assert result.returncode == 1 and pin.read_bytes() == before
    assert run(folder, "verify-log", "--pin", str(pin)).returncode == 1  # and a scheduled check fails


def test_a_rolled_back_log_cannot_move_the_pin_backwards(folder, tmp_path):
    build_log(folder, 40)
    pin = tmp_path / "pin.json"
    assert run(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    before = pin.read_bytes()
    path = folder / LOG_NAME
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[:20]))  # rolled back
    (folder / CHECKPOINT_NAME).write_bytes(
        b"".join((folder / CHECKPOINT_NAME).read_bytes().splitlines(keepends=True)[:1]))
    result = run(folder, "pin", "advance", "--pin", str(pin))
    assert result.returncode == 1 and pin.read_bytes() == before


# ---- layer 4: failure handling ----------------------------------------------------------------


def test_head_refuses_to_sign_a_log_whose_history_was_edited(big):
    folder, _, _ = big
    edit_entry(folder, 5, actor="mallory")
    before = (folder / CHECKPOINT_NAME).read_bytes()
    with pytest.raises(AuditIntegrityError):
        live(folder).head()
    assert (folder / CHECKPOINT_NAME).read_bytes() == before  # nothing was signed over it


def test_the_cli_returns_a_nonzero_status_and_does_not_alter_the_evidence(big):
    folder, _, _ = big
    edit_entry(folder, 5, actor="mallory")
    snapshot = {p.name: p.read_bytes() for p in folder.iterdir() if p.name != "audit.lock"}
    result = run(folder, "verify-log")
    assert result.returncode == 1 and json.loads(result.stdout)["first_bad_seq"] == 5
    assert snapshot == {p.name: p.read_bytes() for p in folder.iterdir() if p.name != "audit.lock"}
