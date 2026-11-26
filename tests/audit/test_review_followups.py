"""Regression tests for the second independent review: read-only logs and repeated head() calls."""
import pytest

import t4.audit.log as audit_log
from t4.audit.log import AuditIntegrityError, AuditLog, LOG_NAME, load_or_create_signer
from tests.audit.synthetic import build_log


def _add(log, name):
    return log.append(actor="a", action="read", target="t", decision="allow", rule="R",
                      request_id=name, detail={})


def test_reading_works_when_the_directory_cannot_be_locked_for_writing(tmp_path, monkeypatch):
    """A read-only copy (mount, chmod 0555) must still be readable: only a busy lock is an error."""
    folder = tmp_path / "audit"
    log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=4)
    for i in range(6):
        _add(log, f"r{i}")

    def refuse(*_args, **_kwargs):
        raise PermissionError("read-only")

    monkeypatch.setattr(audit_log, "locked", refuse)
    reader = AuditLog(folder, None)
    assert [e["request_id"] for e in reader.iter_entries()] == [f"r{i}" for i in range(6)]
    assert len(reader.entries()) == 6


def test_a_busy_lock_is_still_an_error_not_an_unlocked_read(tmp_path, monkeypatch):
    folder = tmp_path / "audit"
    log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=4)
    _add(log, "r0")

    def busy(*_args, **_kwargs):
        raise audit_log.AuditError("audit log is busy")

    monkeypatch.setattr(audit_log, "locked", busy)
    with pytest.raises(audit_log.AuditError):
        list(AuditLog(folder, None).iter_entries())


def _big_log(folder):
    # Larger than the every-append whole-chain limit, so only the recent window is re-checked live.
    seq, head = build_log(folder, 896, pad=300)  # 896 = 56 * 16: a checkpoint sits on the last entry
    assert (folder / LOG_NAME).stat().st_size > audit_log.FULL_CHECK_EVERY_APPEND_BYTES
    return AuditLog(folder, load_or_create_signer(folder), checkpoint_every=16)


def _tamper_last_entry(folder):
    path = folder / LOG_NAME
    lines = path.read_bytes().split(b"\n")
    assert lines[-1] == b""
    assert b'"actor":"actor-0"' in lines[-2]
    lines[-2] = lines[-2].replace(b'"actor":"actor-0"', b'"actor":"MALLORY"')
    path.write_bytes(b"\n".join(lines))


def test_calling_head_twice_does_not_blind_the_live_check_on_the_newest_entry(tmp_path):
    folder = tmp_path / "audit"
    log = _big_log(folder)
    log.head()
    log.head()  # a second signed checkpoint at the same sequence number
    _tamper_last_entry(folder)
    with pytest.raises(AuditIntegrityError):
        _add(log, "after-tamper")


def test_repeated_head_calls_do_not_pile_up_duplicate_checkpoints(tmp_path):
    folder = tmp_path / "audit"
    log = _big_log(folder)
    first = log.head()
    lines_before = (folder / audit_log.CHECKPOINT_NAME).read_bytes().count(b"\n")
    again = log.head()
    assert (folder / audit_log.CHECKPOINT_NAME).read_bytes().count(b"\n") == lines_before
    assert (first["seq"], first["hash"]) == (again["seq"], again["hash"]) and again["sig"]


def test_a_log_that_already_holds_duplicate_checkpoints_still_appends(tmp_path):
    """Logs written before the fix can hold several checkpoints at one sequence number."""
    folder = tmp_path / "audit"
    log = _big_log(folder)
    cp = folder / audit_log.CHECKPOINT_NAME
    last = cp.read_bytes().rstrip(b"\n").split(b"\n")[-1]
    with cp.open("ab") as handle:
        handle.write((last + b"\n") * 3)
    _add(log, "still-works")
    assert log.entries()[-1]["request_id"] == "still-works"


# ---- pins ------------------------------------------------------------------------------------------
import json  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _cli(folder, *args):
    return subprocess.run([sys.executable, "-m", "t4.audit.cli", "--dir", str(folder), *args],
                          capture_output=True, text=True, cwd=ROOT)


@pytest.mark.parametrize("bad", [None, "", 5])
def test_a_pin_without_a_public_key_is_refused_not_silently_unpinned(tmp_path, bad):
    folder = tmp_path / "audit"
    build_log(folder, 40)
    pin = tmp_path / "pin.json"
    assert _cli(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    data = json.loads(pin.read_text())
    data["public_key"] = bad
    pin.write_text(json.dumps(data))
    assert _cli(folder, "verify-log", "--pin", str(pin)).returncode == 2
    assert _cli(folder, "pin", "advance", "--pin", str(pin)).returncode == 2


def test_pin_init_on_an_unsigned_log_writes_no_unusable_pin(tmp_path):
    folder = tmp_path / "audit"
    folder.mkdir()
    AuditLog(folder, None).append(actor="a", action="read", target="t", decision="allow", rule="R",
                                  request_id="r", detail={})
    pin = tmp_path / "pin.json"
    result = _cli(folder, "pin", "init", "--pin", str(pin))
    assert result.returncode == 2 and not pin.exists()


def test_pin_advance_rejects_a_log_rewritten_while_it_runs(tmp_path, monkeypatch):
    """The old pin is checked again after the new head is signed."""
    from t4.audit import cli as audit_cli
    folder = tmp_path / "audit"
    build_log(folder, 40)
    pin = tmp_path / "pin.json"
    assert _cli(folder, "pin", "init", "--pin", str(pin)).returncode == 0
    before = pin.read_bytes()
    real_head = AuditLog.head

    def rewrite_then_head(self):  # a rewrite lands between the first check and the new head
        path = folder / LOG_NAME
        data = path.read_bytes().replace(b'"actor":"actor-3"', b'"actor":"MALLORY"', 1)
        path.write_bytes(data)
        return real_head(self)

    monkeypatch.setattr(AuditLog, "head", rewrite_then_head)
    code = audit_cli.main(["--dir", str(folder), "pin", "advance", "--pin", str(pin)])
    assert code != 0 and pin.read_bytes() == before


def test_many_legacy_duplicate_checkpoints_at_the_tail_do_not_stop_appends(tmp_path):
    """A log written before head() stopped repeating itself can end in a long run of equal checkpoints."""
    folder = tmp_path / "audit"
    log = _big_log(folder)
    cp = folder / audit_log.CHECKPOINT_NAME
    nl = bytes([10])
    last = cp.read_bytes().rstrip(nl).split(nl)[-1]
    with cp.open("ab") as handle:
        handle.write((last + nl) * 200)
    _add(log, "still-works-after-200-duplicates")
    assert log.entries()[-1]["request_id"] == "still-works-after-200-duplicates"
