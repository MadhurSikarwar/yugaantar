"""The storage report: thresholds, exit codes, and what it must never touch."""
import json
import subprocess
import sys
from pathlib import Path

from t4.storage_status import report

ROOT = Path(__file__).resolve().parents[2]


def make(folder: Path, state=100, log=200, checkpoints=50):
    (folder / "audit").mkdir(parents=True)
    (folder / "state.json").write_bytes(b"s" * state)
    (folder / "audit" / "audit.jsonl").write_bytes(b"l" * log)
    (folder / "audit" / "checkpoints.jsonl").write_bytes(b"c" * checkpoints)
    return folder


def cli(folder, *args):
    return subprocess.run([sys.executable, "-m", "t4.storage_status", "--state-dir", str(folder), *args],
                          capture_output=True, text=True, cwd=ROOT)


def test_reports_the_sizes_it_finds(tmp_path):
    result = report(make(tmp_path / "s"))
    assert (result["state_file_bytes"], result["audit_log_bytes"], result["audit_checkpoints_bytes"],
            result["audit_total_bytes"]) == (100, 200, 50, 250)
    assert result["status"] == "ok" and result["warnings"] == []


def test_low_free_space_warns_then_goes_critical(tmp_path):
    folder = make(tmp_path / "s")
    free_mb = report(folder)["volume_free_bytes"] / (1024 * 1024)
    assert report(folder, warn_free_mb=free_mb + 1)["status"] == "warning"
    assert report(folder, warn_free_mb=free_mb + 10, critical_free_mb=free_mb + 1)["status"] == "critical"


def test_a_large_audit_log_and_a_full_state_file_each_warn(tmp_path):
    folder = make(tmp_path / "s", state=2 * 1024 * 1024, log=3 * 1024 * 1024)
    result = report(folder, warn_audit_mb=1, warn_state_mb=1, warn_free_mb=0, critical_free_mb=0)
    assert result["status"] == "warning" and len(result["warnings"]) == 2
    assert any("audit log" in w for w in result["warnings"]) and any("state file" in w for w in result["warnings"])


def test_exit_status_follows_the_report(tmp_path):
    folder = make(tmp_path / "s")
    assert cli(folder, "--warn-free-mb", "0", "--critical-free-mb", "0").returncode == 0
    assert cli(folder, "--warn-audit-mb", "0.0000001", "--warn-free-mb", "0", "--critical-free-mb", "0").returncode == 1
    assert cli(folder, "--critical-free-mb", "999999999").returncode == 2


def test_it_never_prints_file_contents_and_says_it_reserves_nothing(tmp_path):
    folder = make(tmp_path / "s")
    (folder / "state.key").write_bytes(b"SECRET-KEY-MATERIAL")
    result = cli(folder)
    assert "SECRET-KEY-MATERIAL" not in result.stdout + result.stderr
    assert "no space is reserved" in json.loads(result.stdout)["note"]


def test_a_missing_state_directory_is_reported_not_crashed_on(tmp_path):
    result = cli(tmp_path / "nowhere")
    assert result.returncode in (0, 1, 2) and "Traceback" not in result.stderr
