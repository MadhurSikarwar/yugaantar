"""The red-team suite must pass a correct service and catch planted defects."""

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("selfattack", ROOT / "tools" / "selfattack.py")
attack = importlib.util.module_from_spec(SPEC)
sys.modules["selfattack"] = attack
SPEC.loader.exec_module(attack)


@pytest.fixture
def double(tmp_path, monkeypatch):
    """A copy of the test double in its own directory, with the real t4 packages."""
    shutil.copyfile(ROOT / "tests" / "redteam" / "double_service.py", tmp_path / "track4_service.py")
    # Only the packages the double uses, so teammates' modules in a merged tree do
    # not change what these tests exercise.
    for package in ("crypto", "audit"):
        shutil.copytree(ROOT / "t4" / package, tmp_path / "t4" / package,
                        ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setenv("DOUBLE_REPO", str(tmp_path))
    monkeypatch.delenv("DOUBLE_FLAW", raising=False)
    return tmp_path / "track4_service.py"


def failures(entry, items):
    return [r for r in attack.Suite(entry).execute(items) if r.status == "FAIL"]


def test_correct_service_has_no_failures(double):
    results = attack.Suite(double).execute(list(attack.Suite.ITEMS))
    assert [r for r in results if r.status == "FAIL"] == []
    assert sum(r.status == "PASS" for r in results) > 150
    assert {r.item for r in results if r.status == "SKIP"} == {6, 9, 10}


def test_ignored_revocation_is_critical(double, monkeypatch):
    monkeypatch.setenv("DOUBLE_FLAW", "ignore-revoke")
    found = failures(double, [7])
    assert any(r.severity == "critical" and "revoked" in r.name for r in found)
    assert any("disabled" in r.name for r in found)


def test_content_leak_in_a_denial_is_critical(double, monkeypatch):
    monkeypatch.setenv("DOUBLE_FLAW", "leak")
    found = failures(double, [12, 13])
    assert any(r.severity == "critical" and "protected content" in r.name for r in found)
    assert any("denial" in r.name for r in found)


def test_state_keyed_by_raw_identifiers_is_reported(double, monkeypatch):
    monkeypatch.setenv("DOUBLE_FLAW", "raw-index")
    names = {r.name for r in failures(double, [2])}
    assert {"flood: long identifiers in reads cost little state",
            "flood: long identifiers in revocations cost little state",
            "flood: raw identifiers are not kept in state"} <= names


def test_unsafe_code_is_reported(double):
    source = double.parent / "t4" / "unsafe.py"
    source.write_text("import pickle\nimport os\nos.system('x')\neval('1')\n", encoding="utf-8")
    (found,) = failures(double, [14])
    assert "pickle" in found.detail and "eval" in found.detail


def test_a_service_that_always_allows_fails_badly(tmp_path):
    entry = tmp_path / "track4_service.py"
    entry.write_text(
        "import json,sys\nr=sys.stdin.read()\n"
        "print(json.dumps({'ready':True,'decision':'allow','body':'x'}))\n", encoding="utf-8")
    found = failures(entry, [1, 7, 11])
    assert sum(r.severity == "critical" for r in found) > 10


def test_report_lists_failures_without_secrets(double, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DOUBLE_FLAW", "leak")
    report = tmp_path / "report.md"
    assert attack.main(["--entry", str(double), "--items", "12", "--report", str(report)]) == 1
    text = report.read_text(encoding="utf-8")
    assert "## Failures" in text and "[critical]" in text
    assert "body-" not in text + capsys.readouterr().out and "marker-" not in text


@pytest.mark.parametrize("arguments", [["--entry", "https://example.invalid/x.py"], ["--items", "99"]])
def test_bad_arguments(arguments, double):
    assert attack.main(["--entry", str(double), *arguments]) == 2
