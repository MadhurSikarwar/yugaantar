"""Locked, atomic, integrity-checked state for the authority, devices and nodes.

It follows the ``Store``/``Txn`` interface. All records live in one
file, so a commit is a single atomic replace.

What it defends against: half-written state after a crash, two processes
updating at once, accidental corruption and naive edits (the file fails closed).
What it does not defend against: someone who can read the state key and write
the directory, or who restores an older copy of the whole directory.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from t4.node.common import NodeError, canonical

KEY_NAME = "state.key"
STATE_NAME = "state.json"
LOCK_NAME = "state.lock"
LOCK_TIMEOUT = 15.0


class IntegrityError(NodeError):
    """State is missing, damaged or altered. Callers must fail closed."""


class LockTimeout(NodeError):
    """Another process holds the lock."""


def _try_lock(fd: int) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def file_lock(path: Path, timeout: float = LOCK_TIMEOUT) -> Iterator[None]:
    """Exclusive lock. The OS releases it if the process dies. Not reentrant."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise LockTimeout("timed out waiting for a lock")
            time.sleep(0.005)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes) -> None:
    """Temp file in the same directory, fsync, replace, fsync the directory."""
    temp = path.with_name(f"{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(50):
            try:
                os.replace(temp, path)
                break
            except PermissionError:  # Windows: another program briefly has it open.
                if attempt == 49:
                    raise
                time.sleep(0.01)
    finally:
        if temp.exists():
            temp.unlink()
    if os.name != "nt":
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _tag(key: bytes, version: int, records: dict) -> str:
    message = b"t4-node-state-v1\0" + canonical({"version": version, "records": records})
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class _Txn:
    def __init__(self, records: dict) -> None:
        self._records = records
        self.dirty = False

    def get(self, name: str) -> dict | None:
        value = self._records.get(name)
        return None if value is None else json.loads(canonical(value))

    def put(self, name: str, obj: dict) -> None:
        self._records[name] = json.loads(canonical(obj))
        self.dirty = True


class FileStore:
    """One directory of state."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    @classmethod
    def create(cls, directory: str | Path, records: dict) -> "FileStore":
        store = cls(directory)
        store.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with file_lock(store.directory / LOCK_NAME):
            if (store.directory / STATE_NAME).exists() or (store.directory / KEY_NAME).exists():
                raise NodeError("state already exists in this directory")
            key = secrets.token_bytes(32)
            atomic_write(store.directory / KEY_NAME, key)
            store._write(key, 1, records)
        return store

    @contextmanager
    def replacing(self) -> Iterator[tuple[dict | None, Callable]]:
        """Lock the directory to overwrite it. Used only by verified restore.

        Yields the current records (None if lost or damaged) and a function
        ``write(records, on_key_ready)``.
        """
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with file_lock(self.directory / LOCK_NAME):
            try:
                current = self._load(self._read_key())[1]
            except IntegrityError:
                current = None

            def write(records: dict, on_key_ready: Callable = lambda: None) -> None:
                try:
                    key = self._read_key()
                except IntegrityError:
                    key = secrets.token_bytes(32)
                    atomic_write(self.directory / KEY_NAME, key)
                on_key_ready()
                self._write(key, 1, records)

            yield current, write

    def _read_key(self) -> bytes:
        try:
            key = (self.directory / KEY_NAME).read_bytes()
        except OSError:
            raise IntegrityError("state key is missing") from None
        if len(key) != 32:
            raise IntegrityError("state key is damaged")
        return key

    def _write(self, key: bytes, version: int, records: dict) -> None:
        document = {"version": version, "records": records, "tag": _tag(key, version, records)}
        atomic_write(self.directory / STATE_NAME, canonical(document))

    def _load(self, key: bytes) -> tuple[int, dict]:
        try:
            document = json.loads((self.directory / STATE_NAME).read_bytes())
            version, records, tag = document["version"], document["records"], document["tag"]
            valid = hmac.compare_digest(tag.encode("ascii"), _tag(key, version, records).encode("ascii"))
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            raise IntegrityError("state file is missing or unreadable") from None
        if not valid:
            raise IntegrityError("state integrity check failed")
        return version, records

    @contextmanager
    def locked(self) -> Iterator[_Txn]:
        """Exclusive access. Changes commit only if the block ends normally."""
        if not self.directory.is_dir():
            raise IntegrityError("state directory is missing")
        with file_lock(self.directory / LOCK_NAME):
            key = self._read_key()
            version, records = self._load(key)
            txn = _Txn(records)
            yield txn
            if txn.dirty:
                self._write(key, version + 1, records)
