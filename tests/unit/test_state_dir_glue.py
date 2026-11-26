"""The POSIX glue of the state-directory policy, exercised through a simulated POSIX layer.

c1 develops on Windows, where ``os.getuid``, ``fchmod`` and ``O_NOFOLLOW`` do not exist.
These tests replace the ``os`` calls used by ``t4.store._claim_posix`` with a small fake
file table so the exact call sequence (open without following symlinks, fstat, fchmod only
on our own private-able folders, never on shared ones) is checked on every OS. They do
NOT replace running the real-folder tests on Linux (``test_state_dir_policy.py``).
"""
from __future__ import annotations

import errno
import stat
import types
from pathlib import Path

import pytest

from t4 import store as store_module
from t4.api import IntegrityError
from t4.store import PRIVATE_SUBDIR_PREFIX, locate_state_dir, prepare_state_dir

DIR = stat.S_IFDIR


class FakePosix:
    """Delegates to the real ``os`` except for the handful of POSIX-only calls."""

    O_DIRECTORY = 0x10000
    O_NOFOLLOW = 0x20000

    def __init__(self, real_os, table: dict[Path, tuple[int, int] | None], uid: int = 1000) -> None:
        self._real = real_os
        self.table = table  # path -> (owner uid, full st_mode) ; None means "a symlink"
        self.uid = uid
        self.chmods: list[tuple[Path, int]] = []
        self._fds: dict[int, Path] = {}
        self._next = 100

    def __getattr__(self, name):
        return getattr(self._real, name)

    def getuid(self) -> int:
        return self.uid

    def open(self, path, flags):
        key = Path(path)
        if key not in self.table:
            raise FileNotFoundError(errno.ENOENT, "missing")
        if self.table[key] is None:
            raise OSError(errno.ELOOP, "symlink")  # what O_NOFOLLOW does
        self._next += 1
        self._fds[self._next] = key
        return self._next

    def fstat(self, fd):
        uid, mode = self.table[self._fds[fd]]
        return types.SimpleNamespace(st_mode=mode, st_uid=uid)

    def lstat(self, path):
        entry = self.table.get(Path(path))
        if entry is None:
            raise FileNotFoundError(errno.ENOENT, "missing")
        return types.SimpleNamespace(st_mode=entry[1], st_uid=entry[0])

    def fchmod(self, fd, mode):
        key = self._fds[fd]
        uid, current = self.table[key]
        self.chmods.append((key, mode))
        self.table[key] = (uid, (current & ~0o7777) | mode)

    def close(self, fd):
        self._fds.pop(fd, None)


@pytest.fixture
def posix(monkeypatch):
    def install(table, uid=1000):
        fake = FakePosix(store_module.os, table, uid)
        monkeypatch.setattr(store_module, "os", fake)
        monkeypatch.setattr(store_module, "_IS_WINDOWS", False)
        return fake

    return install


def child_of(base: Path, uid: int) -> Path:
    return base / f"{PRIVATE_SUBDIR_PREFIX}{uid}"


def test_our_loose_folder_is_tightened_through_the_open_descriptor(tmp_path, posix):
    base = tmp_path / "state"
    fake = posix({base: (1000, DIR | 0o755)})
    assert prepare_state_dir(base) == base
    assert fake.chmods == [(base, 0o700)]


def test_our_private_folder_is_used_without_any_chmod(tmp_path, posix):
    base = tmp_path / "state"
    fake = posix({base: (1000, DIR | 0o700)})
    assert prepare_state_dir(base) == base and fake.chmods == []


def test_a_shared_sticky_folder_gets_a_subfolder_and_is_never_chmodded(tmp_path, posix):
    base = tmp_path / "tmp"
    base.mkdir()
    child = child_of(base, 1000)
    fake = posix({base: (0, DIR | 0o1777), child: (1000, DIR | 0o700)})
    assert prepare_state_dir(base) == child
    assert child.is_dir()  # really created by the policy
    assert fake.chmods == []  # the shared folder was left alone


def test_root_never_chmods_the_shared_tmp_it_owns(tmp_path, posix):
    base = tmp_path / "tmp"
    base.mkdir()
    child = child_of(base, 0)
    fake = posix({base: (0, DIR | 0o1777), child: (0, DIR | 0o700)}, uid=0)
    assert prepare_state_dir(base) == child
    assert fake.chmods == []


def test_someone_elses_folder_is_never_chmodded(tmp_path, posix):
    base = tmp_path / "theirs"
    base.mkdir()
    child = child_of(base, 1000)
    fake = posix({base: (1001, DIR | 0o755), child: (1000, DIR | 0o700)})
    assert prepare_state_dir(base) == child
    assert fake.chmods == []


def test_a_loose_subfolder_of_ours_is_tightened(tmp_path, posix):
    base = tmp_path / "tmp"
    base.mkdir()
    child = child_of(base, 1000)
    child.mkdir()
    fake = posix({base: (0, DIR | 0o1777), child: (1000, DIR | 0o755)})
    assert prepare_state_dir(base) == child
    assert fake.chmods == [(child, 0o700)]


@pytest.mark.parametrize(
    "child_entry",
    [None, (1001, DIR | 0o700), (1000, DIR | 0o1777), (0, DIR | 0o1777)],
    ids=["symlink", "owned-by-someone-else", "ours-but-shared", "root-shared"],
)
def test_an_unsafe_subfolder_is_refused(tmp_path, posix, child_entry):
    base = tmp_path / "tmp"
    base.mkdir()
    child_of(base, 1000).mkdir()
    posix({base: (0, DIR | 0o1777), child_of(base, 1000): child_entry})
    with pytest.raises(IntegrityError):
        prepare_state_dir(base)


def test_a_symlinked_base_is_refused(tmp_path, posix):
    base = tmp_path / "link"
    posix({base: None})
    with pytest.raises(IntegrityError):
        prepare_state_dir(base)


def test_a_failing_fchmod_fails_closed(tmp_path, posix, monkeypatch):
    base = tmp_path / "state"
    fake = posix({base: (1000, DIR | 0o755)})

    def broken(fd, mode):
        raise OSError(errno.EPERM, "denied")

    monkeypatch.setattr(fake, "fchmod", broken)
    with pytest.raises(IntegrityError):
        prepare_state_dir(base)


def test_an_unwritable_shared_folder_fails_closed(tmp_path, posix, monkeypatch):
    base = tmp_path / "tmp"
    base.mkdir()
    posix({base: (0, DIR | 0o1777)})

    original = Path.mkdir

    def mkdir(self, *args, **kwargs):
        if self.name.startswith(PRIVATE_SUBDIR_PREFIX):
            raise PermissionError(errno.EACCES, "read-only")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    with pytest.raises(IntegrityError):
        prepare_state_dir(base)


def test_the_folder_is_opened_without_following_symlinks(tmp_path, posix, monkeypatch):
    base = tmp_path / "state"
    fake = posix({base: (1000, DIR | 0o700)})
    seen = []
    real_open = fake.open
    monkeypatch.setattr(fake, "open", lambda path, flags: (seen.append(flags), real_open(path, flags))[1])
    prepare_state_dir(base)
    assert seen and seen[0] & fake.O_NOFOLLOW and seen[0] & fake.O_DIRECTORY


def test_locate_reports_the_subfolder_without_creating_anything(tmp_path, posix):
    base = tmp_path / "tmp"
    base.mkdir()
    posix({base: (0, DIR | 0o1777)})
    assert locate_state_dir(base) == child_of(base, 1000)
    assert list(base.iterdir()) == []


def test_locate_returns_the_folder_itself_when_it_is_ours_or_missing(tmp_path, posix):
    base = tmp_path / "state"
    posix({base: (1000, DIR | 0o755)})
    assert locate_state_dir(base) == base
    assert locate_state_dir(tmp_path / "missing") == tmp_path / "missing"
