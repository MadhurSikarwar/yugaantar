#!/usr/bin/env python3
"""Windows: make a state, node, authority or backup folder private to the current user.

    python tools/windows_private.py <folder> [<folder> ...]

Why this is a separate tool
    On Linux and macOS the service makes its folders 0700 itself. Windows has no mode bits: a
    folder inherits the access rules of its parent, so a state folder under a shared parent can
    be readable by other users. Changing access rules on Windows needs ``icacls`` (a process) or
    ``ctypes``, and the project's own static check forbids both in runtime code (``t4/``). So the
    runtime only refuses linked folders (symlinks and junctions), and this operator tool does the
    tightening once, after a folder is created. ``tools/bridge.py`` runs it on its workspace.

What it does
    Removes the inherited rules and grants full control to the current user and to the SYSTEM
    account only (SYSTEM is what Windows itself and its virus scanner run as). Files and folders
    created inside afterwards inherit that. Existing files are covered too (``/T``).

What it does not do
    An administrator can still take ownership of any folder; like 0700 on POSIX, this protects
    against other ordinary users. On Linux and macOS it does nothing and says so.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SYSTEM_SID = "*S-1-5-18"


def current_principal() -> str:
    user = os.environ.get("USERNAME", "").strip()
    if not user:
        raise OSError("the current Windows user is unknown")
    domain = os.environ.get("USERDOMAIN", "").strip()
    return f"{domain}\\{user}" if domain else user


SYSTEM_NAME = "nt authority\\system"


def _run(command: list[str]) -> str:
    try:
        done = subprocess.run(command, check=True, capture_output=True, timeout=60, text=True, errors="replace")
    except (subprocess.SubprocessError, FileNotFoundError) as error:
        raise OSError("the folder's access rules could not be changed") from error
    return done.stdout


def principals(path: Path) -> set[str]:
    """Every principal that has an access entry on ``path`` (lower case), as icacls lists them."""
    names = set()
    for line in _run(["icacls", str(path)]).splitlines():
        line = line.replace(str(path), "", 1).strip()
        if not line or line.startswith("Successfully processed"):
            continue
        match = re.match(r"(.+?):\(", line)
        if match:
            names.add(match.group(1).strip().lower())
    return names


def make_private(directory: Path) -> None:
    """Allow ONLY the current user and SYSTEM on a folder and everything in it, verified. Raises OSError.

    1. Take ownership (another owner could change the rules back).
    2. Drop inherited rules and grant the user and SYSTEM full control, inherited by children.
    3. Remove every other principal's explicit entries (``/grant:r`` alone leaves, for example,
       an explicit BUILTIN\\Users read entry in place).
    4. Reset everything inside to inherit from the folder, then check the folder and every file
       and subfolder: any other principal, or any problem, raises (fail closed).
    """
    if os.name != "nt":
        return
    path = Path(directory)
    if not path.is_dir() or path.is_symlink() or getattr(os.path, "isjunction", lambda p: False)(path):
        raise OSError("not a real folder")
    for child in path.rglob("*"):
        if child.is_symlink() or getattr(os.path, "isjunction", lambda p: False)(child):
            raise OSError("a linked folder or file inside: refusing")
    me = current_principal()
    allowed = {me.lower(), SYSTEM_NAME}
    _run(["icacls", str(path), "/setowner", me, "/T", "/C", "/Q"])
    _run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{me}:(OI)(CI)F", f"{SYSTEM_SID}:(OI)(CI)F", "/Q"])
    for name in principals(path) - allowed:
        _run(["icacls", str(path), "/remove", name, "/Q"])
    if any(path.iterdir()):
        _run(["icacls", str(path / "*"), "/reset", "/T", "/Q"])
    for item in (path, *path.rglob("*")):
        extra = principals(item) - allowed
        if extra:
            raise OSError(f"access for {sorted(extra)} remains on {item.name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Make folders private to the current Windows user.")
    parser.add_argument("folders", nargs="+")
    args = parser.parse_args(argv)
    if os.name != "nt":
        print("not Windows: the service already makes its folders 0700 itself; nothing to do")
        return 0
    failed = 0
    for folder in args.folders:
        try:
            make_private(Path(folder))
            print(f"private: {folder}")
        except OSError as error:
            failed += 1
            print(f"FAILED: {folder}: {error}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
