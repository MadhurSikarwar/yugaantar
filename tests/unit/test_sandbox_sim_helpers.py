"""Small regression tests for scripts/sandbox_sim.py (found by a WSL run: a venv python symlink was resolved away)."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sandbox_sim.py"
spec = importlib.util.spec_from_file_location("sandbox_sim", SCRIPT)
sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sim)  # type: ignore[union-attr]


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_a_symlinked_interpreter_path_is_not_resolved(tmp_path):
    real = tmp_path / "base" / "python3.12"
    real.parent.mkdir()
    real.write_text("#!/bin/sh\n")
    link = tmp_path / "venv" / "bin" / "python"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    assert sim.normalize_python(str(link)) == str(link)  # still the venv path, not the base interpreter


def test_a_bare_command_name_is_left_alone():
    assert sim.normalize_python("python3") == "python3"


def test_a_relative_path_becomes_absolute_without_following_links():
    result = sim.normalize_python(os.path.join("some", "dir", "python"))
    assert os.path.isabs(result) and result.endswith(os.path.join("some", "dir", "python"))


def test_preflight_rejects_an_interpreter_without_pqcrypto(tmp_path):
    fake = tmp_path / "fakepython.cmd" if sys.platform == "win32" else tmp_path / "fakepython"
    if sys.platform == "win32":
        fake.write_text("@echo off\r\necho import error 1>&2\r\nexit /b 1\r\n")
    else:
        fake.write_text("#!/bin/sh\necho 'import error' >&2\nexit 1\n")
        fake.chmod(0o755)
    with pytest.raises(SystemExit) as raised:
        sim.preflight(str(fake))
    assert "cannot import pqcrypto" in str(raised.value)
