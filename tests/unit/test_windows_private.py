"""Windows folder privacy: junctions are refused at runtime; the operator tool removes inherited access."""
from __future__ import annotations

import os
import subprocess

import pytest

from t4.api import IntegrityError
from t4.store import prepare_state_dir
from tools.windows_private import make_private

windows = pytest.mark.skipif(os.name != "nt", reason="Windows access rules")


def _acl(path) -> str:
    """The access entries only (the path is cut off: it may itself contain the word "Users")."""
    out = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    return out.replace(str(path), "").split("Successfully processed")[0]


def _principals(path) -> set[str]:
    return {line.strip().split(":")[0].lower() for line in _acl(path).splitlines() if ":" in line}


@windows
def test_the_tool_leaves_only_the_current_user_and_system(tmp_path):
    folder = tmp_path / "state"
    folder.mkdir()
    (folder / "state.key").write_text("x")
    assert "(I)" in _acl(folder)  # inherited from the parent before
    make_private(folder)
    assert "(I)" not in _acl(folder)  # nothing inherited from the shared parent any more
    (folder / "later.txt").write_text("y")  # new files inherit the private rules
    for path in (folder, folder / "state.key", folder / "later.txt"):
        names = _principals(path)
        user = "\\".join((os.environ["USERDOMAIN"], os.environ["USERNAME"])).lower()
        expected = {"nt authority\\system", user}
        assert names == expected
    assert (folder / "state.key").read_text() == "x"  # and the owner can still read it


@windows
def test_a_junction_is_refused_as_a_state_folder(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "state"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    with pytest.raises(IntegrityError):
        prepare_state_dir(link)


def test_the_tool_is_a_no_op_off_windows(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("checks the POSIX path")
    make_private(tmp_path)  # does nothing, raises nothing
