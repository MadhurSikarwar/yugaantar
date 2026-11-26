"""State store: durability, atomicity, tamper detection, locking."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from t4 import store as store_module
from t4.api import IntegrityError, StoreBusyError
from t4.store import FileStore, prepare_state_dir, resolve_state_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


def test_empty_state_then_put_and_get(state_dir):
    store = FileStore(state_dir)
    with store.locked() as txn:
        assert txn.get("assets") is None
        assert txn.version == 0
        txn.put("assets", {"a": {"owner": "u", "body": "b"}})
    with store.locked() as txn:
        assert txn.get("assets") == {"a": {"owner": "u", "body": "b"}}
        assert txn.version == 1


def test_get_returns_a_copy(state_dir):
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"list": [1]})
        txn.get("doc")["list"].append(2)
        assert txn.get("doc") == {"list": [1]}


def test_no_commit_when_the_block_raises(state_dir):
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"n": 1})
    with pytest.raises(RuntimeError):
        with store.locked() as txn:
            txn.put("doc", {"n": 2})
            raise RuntimeError("boom")
    with store.locked() as txn:
        assert txn.get("doc") == {"n": 1}


def test_explicit_early_commit_survives_a_later_error(state_dir):
    store = FileStore(state_dir)
    with pytest.raises(RuntimeError):
        with store.locked() as txn:
            txn.put("doc", {"n": 1})
            txn.commit()
            txn.put("doc", {"n": 2})
            raise RuntimeError("boom")
    with store.locked() as txn:
        assert txn.get("doc") == {"n": 1}


def test_reading_without_changes_does_not_rewrite_the_file(state_dir):
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"n": 1})
    before = store.state_path.read_bytes()
    with store.locked() as txn:
        txn.get("doc")
    assert store.state_path.read_bytes() == before


@pytest.mark.parametrize("name", ["", "A", "1x", "a-b", "a b", "x" * 33, "../x", "a\n"])
def test_invalid_document_names(state_dir, name):
    store = FileStore(state_dir)
    with pytest.raises(ValueError):
        with store.locked() as txn:
            txn.put(name, {})


def test_documents_must_be_dicts(state_dir):
    store = FileStore(state_dir)
    with pytest.raises(TypeError):
        with store.locked() as txn:
            txn.put("doc", [1, 2])  # type: ignore[arg-type]


# --- tamper detection (PRD section 8, item 4) ----------------------------------


def _seed(state_dir) -> FileStore:
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"revoked": []})
    return store


def test_flipping_one_byte_fails_closed(state_dir):
    store = _seed(state_dir)
    raw = bytearray(store.state_path.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    store.state_path.write_bytes(bytes(raw))
    with pytest.raises(IntegrityError):
        with store.locked():
            pass


def test_editing_a_value_without_the_key_is_detected(state_dir):
    store = _seed(state_dir)
    body = json.loads(store.state_path.read_text())
    body["docs"]["doc"]["revoked"] = ["nobody"]
    store.state_path.write_text(json.dumps(body))
    with pytest.raises(IntegrityError):
        with store.locked():
            pass


def test_bumping_the_version_without_the_key_is_detected(state_dir):
    store = _seed(state_dir)
    body = json.loads(store.state_path.read_text())
    body["version"] += 1
    store.state_path.write_text(json.dumps(body))
    with pytest.raises(IntegrityError):
        with store.locked():
            pass


@pytest.mark.parametrize("cut", [0, 1, 10, -5])
def test_truncated_state_fails_closed(state_dir, cut):
    store = _seed(state_dir)
    raw = store.state_path.read_bytes()
    store.state_path.write_bytes(raw[:cut] if cut >= 0 else raw[:cut])
    with pytest.raises(IntegrityError):
        with store.locked():
            pass


@pytest.mark.parametrize("junk", [b"", b"not json", b"[]", b"null", b'{"v":1}', b'{"v":1,"version":"x","docs":{},"tag":"a"}'])
def test_garbage_state_fails_closed(state_dir, junk):
    store = _seed(state_dir)
    store.state_path.write_bytes(junk)
    with pytest.raises(IntegrityError):
        with store.locked():
            pass


def test_deleting_the_key_never_resets_trust(state_dir):
    store = _seed(state_dir)
    store.key_path.unlink()
    with pytest.raises(IntegrityError):
        with store.locked():
            pass
    assert not store.key_path.exists(), "a missing key must not be silently regenerated"


@pytest.mark.parametrize("bad_key", ["", "zz", "00" * 31, "00" * 33])
def test_damaged_key_fails_closed(state_dir, bad_key):
    store = _seed(state_dir)
    store.key_path.write_text(bad_key)
    with pytest.raises(IntegrityError):
        with store.locked():
            pass


def test_state_signed_with_another_key_is_rejected(state_dir, tmp_path):
    victim = _seed(state_dir)
    other_dir = tmp_path / "other"
    other_dir.mkdir(mode=0o700)
    attacker = _seed(other_dir)
    victim.state_path.write_bytes(attacker.state_path.read_bytes())
    with pytest.raises(IntegrityError):
        with victim.locked():
            pass


def test_full_rollback_is_not_detected_documented_limit(state_dir):
    """Honest limit (PRD 4.1): restoring an older copy of the whole directory passes.

    The pinned audit head is what exposes the lost log entries. This test exists so
    that nobody can claim otherwise without changing it.
    """
    store = _seed(state_dir)
    old = store.state_path.read_bytes()
    with store.locked() as txn:
        txn.put("doc", {"revoked": ["maya"]})
    store.state_path.write_bytes(old)  # attacker restores the old copy
    with store.locked() as txn:
        assert txn.get("doc") == {"revoked": []}  # accepted: the revocation is silently gone


def test_a_missing_state_with_an_existing_key_is_a_fresh_start(state_dir):
    """A crash between creating the key and the first commit must not brick the service."""
    store = FileStore(state_dir)
    with store.locked():
        pass  # creates the key, commits nothing
    assert store.key_path.exists() and not store.state_path.exists()
    with store.locked() as txn:
        txn.put("doc", {"ok": True})
    assert store.state_path.exists()


# --- atomic writes ------------------------------------------------------------------


def test_failed_replace_leaves_old_state_and_no_temp_files(state_dir, monkeypatch):
    store = _seed(state_dir)
    before = store.state_path.read_bytes()

    def broken_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(store_module.os, "replace", broken_replace)
    with pytest.raises(OSError):
        with store.locked() as txn:
            txn.put("doc", {"revoked": ["maya"]})
    monkeypatch.undo()

    assert store.state_path.read_bytes() == before
    assert [p.name for p in state_dir.iterdir() if p.name.endswith(".tmp")] == []
    with store.locked() as txn:
        assert txn.get("doc") == {"revoked": []}


def test_stale_temp_files_from_a_crash_are_swept_but_recent_ones_are_kept(state_dir):
    store = _seed(state_dir)
    stale = state_dir / ".state.json.999.dead.tmp"
    recent = state_dir / ".state.json.998.live.tmp"
    unrelated = state_dir / "notes.tmp"  # not ours: must never be touched
    for path in (stale, recent, unrelated):
        path.write_bytes(b"x")
    long_ago = __import__("time").time() - 3600
    os.utime(stale, (long_ago, long_ago))
    with store.locked():
        pass
    assert not stale.exists()
    assert recent.exists() and unrelated.exists()


def test_state_file_is_canonical_json_with_ascii_only(state_dir):
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"text": "é \U0001f600\x00"})
    raw = store.state_path.read_bytes()
    raw.decode("ascii")  # must not raise
    with store.locked() as txn:
        assert txn.get("doc")["text"] == "é \U0001f600\x00"


# --- locking ---------------------------------------------------------------------------


WORKER = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, sys.argv[1])
    from pathlib import Path
    from t4.store import FileStore
    store = FileStore(Path(sys.argv[2]), lock_timeout=30)
    for _ in range(int(sys.argv[3])):
        with store.locked() as txn:
            doc = txn.get("counter") or {"n": 0}
            doc["n"] += 1
            txn.put("counter", doc)
    """
)


def test_parallel_processes_never_lose_an_update(state_dir):
    workers, increments = 6, 15
    procs = [
        subprocess.Popen([sys.executable, "-c", WORKER, str(REPO_ROOT), str(state_dir), str(increments)])
        for _ in range(workers)
    ]
    assert [p.wait(timeout=120) for p in procs] == [0] * workers
    with FileStore(state_dir).locked() as txn:
        assert txn.get("counter") == {"n": workers * increments}
        assert txn.version == workers * increments


def test_lock_timeout_is_reported_as_busy(state_dir):
    holder = FileStore(state_dir)
    waiter = FileStore(state_dir, lock_timeout=0.2)
    with holder.locked():
        # a second *process* is needed: locks held by the same process can be re-entered on some platforms
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]);"
            "from pathlib import Path; from t4.store import FileStore; from t4.api import StoreBusyError\n"
            "try:\n"
            "    with FileStore(Path(sys.argv[2]), lock_timeout=0.2).locked(): pass\n"
            "except StoreBusyError:\n"
            "    sys.exit(7)\n"
        )
        result = subprocess.run([sys.executable, "-c", code, str(REPO_ROOT), str(state_dir)], timeout=60)
    assert result.returncode == 7
    del waiter


# --- state directory ----------------------------------------------------------------------


def test_resolve_state_dir_uses_the_environment():
    assert resolve_state_dir({"TRACK4_STATE_DIR": "/x/y"}).name == "y"
    assert resolve_state_dir({}).name == "track4-state"


def test_prepare_creates_missing_directories(tmp_path):
    target = tmp_path / "a" / "b"
    assert prepare_state_dir(target).is_dir()


def test_prepare_rejects_a_file(tmp_path):
    path = tmp_path / "file"
    path.write_text("x")
    with pytest.raises(IntegrityError):
        prepare_state_dir(path)


@POSIX_ONLY
def test_prepare_rejects_group_or_world_access(tmp_path):
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o777)
    with pytest.raises(IntegrityError):
        prepare_state_dir(open_dir)


@POSIX_ONLY
def test_prepare_rejects_symlinks(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(IntegrityError):
        prepare_state_dir(link)


@POSIX_ONLY
def test_key_and_state_files_are_private(state_dir):
    store = _seed(state_dir)
    assert oct(store.key_path.stat().st_mode & 0o777) == "0o600"
    assert oct(store.state_path.stat().st_mode & 0o777) == "0o600"


def test_busy_error_type_is_exported():
    assert issubclass(StoreBusyError, Exception)
