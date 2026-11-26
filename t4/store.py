"""Durable, locked, integrity-checked state (owner: c1; PRD 4.1, M-A6).

What it does
    Every request runs in a brand-new process, so everything that must survive
    lives in one file under the state directory. This module gives the rest of
    the code a tiny transaction API:

        with store.locked() as txn:
            data = txn.get("assets")
            txn.put("assets", {...})
        # leaving the block commits atomically

How it is built (and which attack each part answers)
    * One state file, one version counter, one tag. The file holds every
      document plus a monotonically increasing ``version`` and an HMAC-SHA256
      tag over both. Because everything is in a single file, a crash cannot
      leave documents from two different versions side by side, and swapping a
      single file cannot mix old and new documents (red-team item 4).
    * Atomic replace: write a temp file in the same directory, flush, fsync,
      ``os.replace``, then fsync the directory (POSIX). A crash leaves either
      the old or the new state, never a torn one.
    * Exclusive lock (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows)
      so 20 parallel processes cannot lose a revocation or corrupt the file.
    * Integrity: the tag is verified on every load. Any mismatch, parse error or
      missing key raises ``IntegrityError`` and the caller fails closed.
    * The key lives in ``state.key`` (mode 0600), created only when no state
      file exists, so deleting the key can never make a tampered state valid.
    * The state directory must be a real directory owned by us with no group or
      world access (POSIX). A pre-planted directory or symlink in a shared temp
      directory is rejected.

Honest limits (also stated in the threat model)
    * The key sits next to the data. Someone who can rewrite the whole state
      directory can forge a valid state. The tag catches corruption and naive
      tampering, not that attacker.
    * A **full rollback** (restoring an older copy of the whole directory)
      passes every check here. It cannot be detected from this directory alone;
      the pinned audit head (PRD 4.1) is what exposes lost log entries.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Iterator

from t4.api import IntegrityError, StoreBusyError, StoreFullError

STATE_FILE = "state.json"
KEY_FILE = "state.key"
LOCK_FILE = "state.lock"
FORMAT_VERSION = 1
MAX_STATE_BYTES = 64 * 1024 * 1024  # a larger file is refused when LOADING
MAX_WRITE_BYTES = 48 * 1024 * 1024  # a larger state is refused when WRITING (headroom below the load limit)
DEFAULT_LOCK_TIMEOUT = 5.0  # seconds; the validator allows 8 s per operation
STALE_TEMP_SECONDS = 60

_DOC_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")  # used with fullmatch: `$` would accept a trailing newline
_IS_WINDOWS = sys.platform == "win32"


# ---------------------------------------------------------------------------
# State directory
# ---------------------------------------------------------------------------


def resolve_state_dir(env: dict[str, str] | None = None) -> Path:
    """``TRACK4_STATE_DIR`` if set, else a private folder in the OS temp dir."""
    env = os.environ if env is None else env
    raw = env.get("TRACK4_STATE_DIR")
    if raw:
        base = Path(raw)
    else:
        import tempfile  # imported lazily: it costs startup time and is rarely needed

        base = Path(tempfile.gettempdir()) / "track4-state"
    return base.absolute()


def prepare_state_dir(path: Path) -> Path:
    """Create the directory if needed and refuse an unsafe one.

    On POSIX the directory must not be a symlink, must be owned by the current
    user and must not be accessible to group or others. Without that, anyone
    on a shared ``/tmp`` could pre-create the directory and read or replace our
    state.
    """
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(path)
    except OSError:
        raise IntegrityError("state directory unavailable") from None
    if not stat.S_ISDIR(info.st_mode):
        raise IntegrityError("state path is not a real directory")
    if not _IS_WINDOWS:
        if info.st_uid != os.getuid() or (info.st_mode & 0o077):
            raise IntegrityError("state directory is not private")
    return path


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _tag(key: bytes, version: int, docs: dict) -> str:
    message = _canonical({"v": FORMAT_VERSION, "version": version, "docs": docs})
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _fsync_dir(directory: Path) -> None:
    if _IS_WINDOWS:
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` so a crash leaves either the old or the new file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class _FileLock:
    """Cross-process exclusive lock on ``state.lock`` with a timeout."""

    def __init__(self, path: Path, timeout: float) -> None:
        self._path = path
        self._timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> "_FileLock":
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        deadline = time.monotonic() + self._timeout
        try:
            if _IS_WINDOWS and os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")  # msvcrt.locking needs a byte to lock
            while True:
                if self._try_lock(fd):
                    break
                if time.monotonic() >= deadline:
                    raise StoreBusyError("state lock timeout")
                time.sleep(0.01)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    @staticmethod
    def _try_lock(fd: int) -> bool:
        try:
            if _IS_WINDOWS:
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def __exit__(self, *exc: object) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if _IS_WINDOWS:
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                with contextlib.suppress(OSError):
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------


class _Txn:
    """Buffered view of the documents while the lock is held."""

    def __init__(self, store: "FileStore", key: bytes, version: int, docs: dict) -> None:
        self._store = store
        self._key = key
        self.version = version
        self._docs = docs
        self._dirty = False

    def get(self, name: str) -> dict | None:
        _check_name(name)
        value = self._docs.get(name)
        return None if value is None else copy.deepcopy(value)

    def put(self, name: str, obj: dict) -> None:
        _check_name(name)
        if not isinstance(obj, dict):
            raise TypeError("documents must be dicts")
        self._docs[name] = copy.deepcopy(obj)
        self._dirty = True

    def commit(self) -> None:
        """Persist everything buffered so far (idempotent when nothing changed)."""
        if not self._dirty:
            return
        new_version = self.version + 1
        body = {
            "v": FORMAT_VERSION,
            "version": new_version,
            "docs": self._docs,
            "tag": _tag(self._key, new_version, self._docs),
        }
        encoded = _canonical(body)
        if len(encoded) > MAX_WRITE_BYTES:
            # Never write a state we could not load back: that would brick the
            # service (even `revoke` would fail). Keep the old, loadable state.
            raise StoreFullError("state would exceed the size limit")
        atomic_write_bytes(self._store.state_path, encoded)
        self.version = new_version
        self._dirty = False


def _check_name(name: str) -> None:
    if not isinstance(name, str) or not _DOC_NAME.fullmatch(name):
        raise ValueError("invalid document name")


class FileStore:
    """Implements ``t4.api.Store`` on one directory."""

    def __init__(self, directory: Path, *, lock_timeout: float = DEFAULT_LOCK_TIMEOUT) -> None:
        self.directory = Path(directory)
        self._lock_timeout = lock_timeout

    @property
    def state_path(self) -> Path:
        return self.directory / STATE_FILE

    @property
    def key_path(self) -> Path:
        return self.directory / KEY_FILE

    def exists(self) -> bool:
        """True once a state file exists (used to decide whether alerts can be stored)."""
        return self.state_path.is_file()

    @contextlib.contextmanager
    def locked(self) -> Iterator[_Txn]:
        prepare_state_dir(self.directory)
        with _FileLock(self.directory / LOCK_FILE, self._lock_timeout):
            key, version, docs = self._load()
            txn = _Txn(self, key, version, docs)
            yield txn
            txn.commit()

    # -- loading ----------------------------------------------------------

    def _sweep_stale_temp_files(self) -> None:
        """Delete temp files left behind by a crash (kill -9 between write and rename).

        Called while holding the lock, so no live writer in this directory owns a
        recent one; the 60 second grace period protects other modules that may
        also stage files here under the same lock.
        """
        cutoff = time.time() - STALE_TEMP_SECONDS
        try:
            for path in self.directory.iterdir():
                if path.name.startswith(".") and path.name.endswith(".tmp") and path.is_file():
                    if path.stat().st_mtime < cutoff:
                        with contextlib.suppress(OSError):
                            path.unlink()
        except OSError:
            return

    def _load(self) -> tuple[bytes, int, dict]:
        self._sweep_stale_temp_files()
        state_exists = self.state_path.exists()
        key = self._load_key(create=not state_exists)
        if not state_exists:
            return key, 0, {}
        try:
            size = self.state_path.stat().st_size
            if size > MAX_STATE_BYTES:
                raise IntegrityError("state file too large")
            raw = self.state_path.read_bytes()
            body = json.loads(raw.decode("utf-8"))
            version, docs, tag = body["version"], body["docs"], body["tag"]
            valid_shape = (
                body.get("v") == FORMAT_VERSION
                and isinstance(version, int)
                and not isinstance(version, bool)
                and version >= 0
                and isinstance(docs, dict)
                and isinstance(tag, str)
            )
        except IntegrityError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            raise IntegrityError("state unreadable") from None
        if not valid_shape or not hmac.compare_digest(tag, _tag(key, version, docs)):
            raise IntegrityError("state integrity check failed")
        return key, version, docs

    def _load_key(self, *, create: bool) -> bytes:
        """Read the integrity key.

        ``create`` is True only when no state file exists. Then nothing depends on
        the key, so a missing, empty or truncated key (a crash during the very
        first ``setup``) is simply replaced. When a state file exists the key is
        what authenticates it: a damaged or missing key fails closed and is never
        regenerated.
        """
        try:
            key = bytes.fromhex(self.key_path.read_text(encoding="ascii").strip())
            problem = None if len(key) == 32 else "unreadable"
        except FileNotFoundError:
            problem = "missing"
        except (OSError, ValueError):
            problem = "unreadable"
        if problem is None:
            return key
        if not create:
            raise IntegrityError(f"state key {problem}")
        return self._create_key()

    def _create_key(self) -> bytes:
        """Write a fresh key atomically, so a crash can never leave a partial key behind."""
        key = os.urandom(32)
        try:
            atomic_write_bytes(self.key_path, key.hex().encode("ascii"))
        except OSError:
            raise IntegrityError("state key could not be written") from None
        return key
