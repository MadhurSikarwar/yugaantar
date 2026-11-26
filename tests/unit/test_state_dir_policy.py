"""State directory policy (`setup` must work on Linux in a 0755 folder).

The decision table is a pure function, so it is tested on every OS. The POSIX tests apply
the policy to real folders; they are skipped on Windows and must run on Linux.
"""
from __future__ import annotations

import os
import stat
import sys

import pytest

from t4 import store as store_module
from t4.api import IntegrityError
from t4.store import (
    PRIVATE_SUBDIR_PREFIX,
    DirAction,
    FileStore,
    classify_directory,
    locate_state_dir,
    prepare_state_dir,
    resolve_state_dir,
)

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions and ownership")
ME, ROOT, OTHER = 1000, 0, 1001


def classify(mode, owner=ME, me=ME, real=True, sub=True):
    return classify_directory(is_real_dir=real, owner_uid=owner, my_uid=me, mode=mode, allow_subfolder=sub)


# --- the decision table (runs everywhere) -----------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "owner", "me", "expected"),
    [
        (0o700, ME, ME, DirAction.USE),
        (0o755, ME, ME, DirAction.TIGHTEN),  # mkdir with the default umask
        (0o750, ME, ME, DirAction.TIGHTEN),
        (0o705, ME, ME, DirAction.TIGHTEN),
        (0o775, ME, ME, DirAction.TIGHTEN),  # group-writable but not world-writable: ours and loose
        (0o777, ME, ME, DirAction.SUBFOLDER),  # world-writable folders are shared: never chmod them
        (0o1777, ROOT, ME, DirAction.SUBFOLDER),  # /tmp as seen by a normal user
        (0o1777, ROOT, ROOT, DirAction.SUBFOLDER),  # /tmp as seen by root: still must not be chmodded
        (0o1700, ME, ME, DirAction.SUBFOLDER),  # a sticky bit marks a shared folder
        (0o755, ROOT, ME, DirAction.SUBFOLDER),  # someone else's folder: never touch it
        (0o700, OTHER, ME, DirAction.SUBFOLDER),
    ],
)
def test_decision_table(mode, owner, me, expected):
    assert classify(mode, owner, me) is expected


@pytest.mark.parametrize("mode", [0o700, 0o755, 0o777, 0o1777])
def test_a_symlink_or_file_is_always_refused(mode):
    assert classify(mode, real=False) is DirAction.REFUSE


@pytest.mark.parametrize(
    ("mode", "owner", "expected"),
    [
        (0o700, ME, DirAction.USE),
        (0o755, ME, DirAction.TIGHTEN),
        (0o700, OTHER, DirAction.REFUSE),  # a subfolder owned by someone else was planted: refuse
        (0o777, ME, DirAction.REFUSE),
        (0o1777, ROOT, DirAction.REFUSE),
    ],
)
def test_the_subfolder_itself_must_be_ours_and_private(mode, owner, expected):
    assert classify(mode, owner, sub=False) is expected


def test_the_policy_never_asks_to_chmod_anything_not_ours():
    for owner in (ROOT, OTHER):
        for mode in (0o700, 0o755, 0o777, 0o1777):
            assert classify(mode, owner) is not DirAction.TIGHTEN


def test_the_policy_never_asks_to_chmod_a_shared_folder_even_if_ours():
    for mode in (0o777, 0o1777, 0o1755, 0o1700):
        assert classify(mode, ME, ME) is DirAction.SUBFOLDER


def test_resolve_state_dir_prefers_the_environment_and_falls_back_to_the_temp_folder():
    assert resolve_state_dir({"TRACK4_STATE_DIR": "/x/y"}).name == "y"
    assert resolve_state_dir({}).name == "track4-state"


# --- real folders (POSIX) ---------------------------------------------------------------------------------


def mode_of(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@POSIX_ONLY
def test_an_existing_0755_folder_of_ours_is_tightened_and_used(tmp_path):
    folder = tmp_path / "state"
    folder.mkdir()
    os.chmod(folder, 0o755)
    assert prepare_state_dir(folder) == folder
    assert mode_of(folder) == 0o700


@POSIX_ONLY
def test_setup_and_reads_work_in_an_existing_0755_folder(tmp_path):
    from t4.validate_in import ReadRequest, SetupRequest
    from tests.unit.doubles import make_service

    folder = tmp_path / "state"
    folder.mkdir()
    os.chmod(folder, 0o755)
    service, *_ = make_service(folder)
    assert service.setup(SetupRequest(owners={"a": "maya"}, contents={"a": "body"}, disabled=())) == {"ready": True}
    assert (folder / "state.json").is_file() and mode_of(folder) == 0o700
    assert service.read(ReadRequest(actor="maya", asset="a", request_id="r")) == {"decision": "allow", "body": "body"}


@POSIX_ONLY
def test_the_fallback_folder_in_the_temp_directory_works_when_it_already_exists_as_0755(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    fallback = resolve_state_dir({})
    fallback.mkdir()
    os.chmod(fallback, 0o755)
    store = FileStore(fallback)
    with store.locked() as txn:
        txn.put("doc", {"ok": True})
    assert store.directory == fallback and mode_of(fallback) == 0o700


@POSIX_ONLY
def test_a_shared_sticky_folder_gets_a_private_subfolder_and_is_never_chmodded(tmp_path):
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)  # like /tmp
    effective = prepare_state_dir(shared)
    assert effective == shared / f"{PRIVATE_SUBDIR_PREFIX}{os.getuid()}"
    assert mode_of(shared) == 0o1777  # untouched
    assert mode_of(effective) == 0o700


@POSIX_ONLY
def test_the_store_works_through_a_shared_folder_and_exists_looks_in_the_right_place(tmp_path):
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    store = FileStore(shared)
    assert store.exists() is False
    assert not (shared / f"{PRIVATE_SUBDIR_PREFIX}{os.getuid()}").exists()  # exists() created nothing
    with store.locked() as txn:
        txn.put("doc", {"ok": True})
    assert store.directory == shared / f"{PRIVATE_SUBDIR_PREFIX}{os.getuid()}"
    assert store.exists() is True
    assert FileStore(shared).exists() is True  # a new process finds the same state
    with FileStore(shared).locked() as txn:
        assert txn.get("doc") == {"ok": True}
    assert not (shared / "state.json").exists()  # nothing was written into the shared folder itself


@POSIX_ONLY
def test_a_world_writable_folder_without_a_sticky_bit_also_gets_a_subfolder(tmp_path):
    shared = tmp_path / "open"
    shared.mkdir()
    os.chmod(shared, 0o777)
    assert prepare_state_dir(shared).name.startswith(PRIVATE_SUBDIR_PREFIX)
    assert mode_of(shared) == 0o777


@POSIX_ONLY
def test_an_existing_loose_subfolder_of_ours_is_tightened(tmp_path):
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    child = shared / f"{PRIVATE_SUBDIR_PREFIX}{os.getuid()}"
    child.mkdir()
    os.chmod(child, 0o755)
    assert prepare_state_dir(shared) == child and mode_of(child) == 0o700


@POSIX_ONLY
def test_a_symlinked_subfolder_is_refused(tmp_path):
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (shared / f"{PRIVATE_SUBDIR_PREFIX}{os.getuid()}").symlink_to(elsewhere)
    with pytest.raises(IntegrityError):
        prepare_state_dir(shared)


@POSIX_ONLY
def test_a_symlinked_state_folder_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(IntegrityError):
        prepare_state_dir(link)


@POSIX_ONLY
def test_a_file_where_the_folder_should_be_is_refused(tmp_path):
    path = tmp_path / "file"
    path.write_text("x")
    with pytest.raises(IntegrityError):
        prepare_state_dir(path)


@POSIX_ONLY
def test_locate_changes_nothing(tmp_path):
    missing = tmp_path / "missing"
    assert locate_state_dir(missing) == missing and not missing.exists()
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    assert locate_state_dir(shared).name.startswith(PRIVATE_SUBDIR_PREFIX)
    assert list(shared.iterdir()) == [] and mode_of(shared) == 0o1777


@POSIX_ONLY
def test_the_returned_folder_is_stable_so_repeated_calls_agree(tmp_path):
    shared = tmp_path / "tmp"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    first = prepare_state_dir(shared)
    assert prepare_state_dir(shared) == first and prepare_state_dir(first) == first


def test_the_windows_branch_only_checks_for_a_real_directory(tmp_path, monkeypatch):
    """The Windows branch (also exercised here by forcing it on any OS)."""
    monkeypatch.setattr(store_module, "_IS_WINDOWS", True)
    folder = tmp_path / "w"
    assert prepare_state_dir(folder) == folder
    file_path = tmp_path / "f"
    file_path.write_text("x")
    with pytest.raises(IntegrityError):
        prepare_state_dir(file_path)
