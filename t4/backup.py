"""Authenticated key backups and safe restore.

A vault has two places that must be separate from each other and from the
directory being restored:

* ``key_dir``: the HMAC-SHA-256 verification key and a ledger of removals
  (revoked devices, actors and keys, and removed grants);
* ``backup_dir``: numbered backup files.

Restore checks backups from newest to oldest, reports each damaged one, and uses
the newest that verifies. It then re-applies every removal in the ledger and in
the current state, if readable, so a restore never brings back access that was
taken away after the backup.

What it defends against: damaged, edited, truncated or swapped backups, and
rollback of revocations through restore.

Limits, stated plainly: backups are authenticated but NOT encrypted (no vetted
cipher is available to us), so they contain private keys in readable form and
need the same protection as the live directory. Changes other than removals made
after the chosen backup (enrollments, rotations, grants) are lost. Losing
``key_dir`` makes restore impossible. Someone who controls ``key_dir`` can forge
backups.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from t4.node.common import NodeError, canonical, check_text, check_time
from t4.node.state import FileStore, atomic_write, file_lock

BACKUP_NAME = re.compile(r"backup-(\d{8,})\.json")  # 8 digits are the minimum, not a ceiling
REMOVAL_SETS = ("revoked_devices", "revoked_actors", "revoked_keys", "removed_grants")
Fault = Callable[[str], None]


def no_fault(step: str) -> None:
    return None


class BackupError(NodeError):
    """No backup could be safely used, or the vault itself is damaged."""

    def __init__(self, message: str, damaged: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.damaged = damaged


@dataclass(frozen=True)
class RestoreReport:
    used_id: int
    damaged: tuple[str, ...]
    newest_expected_id: int

    @property
    def fell_back(self) -> bool:
        return self.used_id != self.newest_expected_id


def _seal(key: bytes, label: bytes, body: dict) -> bytes:
    tag = hmac.new(key, label + canonical(body), hashlib.sha256).hexdigest()
    return canonical({"body": body, "tag": tag})


def _unseal(key: bytes, label: bytes, data: bytes) -> dict:
    try:
        document = json.loads(data)
        body = document["body"]
        expected = hmac.new(key, label + canonical(body), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(document["tag"].encode("ascii"), expected.encode("ascii"))
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise BackupError("unreadable") from None
    if not valid:
        raise BackupError("authentication failed")
    return body


BACKUP_LABEL = b"t4-backup-v1\0"
LEDGER_LABEL = b"t4-vault-ledger-v1\0"


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


class Vault:
    def __init__(self, key_dir: str | Path, backup_dir: str | Path) -> None:
        self.key_dir = Path(key_dir).resolve()
        self.backup_dir = Path(backup_dir).resolve()
        if _inside(self.key_dir, self.backup_dir) or _inside(self.backup_dir, self.key_dir):
            raise BackupError("the verification key must be kept apart from the backups")

    def location(self) -> dict[str, str]:
        return {"key_dir": str(self.key_dir), "backup_dir": str(self.backup_dir)}

    @classmethod
    def create(cls, key_dir: str | Path, backup_dir: str | Path, subject: str) -> "Vault":
        """``subject`` names what is protected, for example ``authority``."""
        check_text(subject)
        vault = cls(key_dir, backup_dir)
        vault.key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        vault.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (vault.key_dir / "vault.key").exists():
            raise BackupError("vault already exists")
        key = secrets.token_bytes(32)
        atomic_write(vault.key_dir / "vault.key", key)
        atomic_write(vault.key_dir / "ledger.json", _seal(key, LEDGER_LABEL, {
            "subject": subject, "last_backup_id": 0,
            "removals": {name: {} for name in REMOVAL_SETS}}))
        return vault

    @contextmanager
    def _ledger(self) -> Iterator[tuple[bytes, dict]]:
        """Yields (key, ledger). A damaged ledger stops everything."""
        if not self.key_dir.is_dir():
            raise BackupError("vault key directory is missing")
        with file_lock(self.key_dir / "vault.lock"):
            try:
                key = (self.key_dir / "vault.key").read_bytes()
                data = (self.key_dir / "ledger.json").read_bytes()
            except OSError:
                raise BackupError("vault key or ledger is missing") from None
            if len(key) != 32:
                raise BackupError("vault key is damaged")
            yield key, _unseal(key, LEDGER_LABEL, data)

    def _save_ledger(self, key: bytes, ledger: dict) -> None:
        atomic_write(self.key_dir / "ledger.json", _seal(key, LEDGER_LABEL, ledger))

    def record_removal(self, set_name: str, item: str, at: float) -> None:
        if set_name not in REMOVAL_SETS:
            raise BackupError("unknown removal set")
        with self._ledger() as (key, ledger):
            previous = ledger["removals"][set_name].get(item)
            # Grants can be removed more than once; keep the latest time.
            ledger["removals"][set_name][item] = at if previous is None else max(previous, at)
            self._save_ledger(key, ledger)

    def backup(self, store: FileStore, record_name: str, now: float,
               fault: Fault = no_fault) -> int:
        check_time(now)
        with store.locked() as txn:  # Lock order: store, then vault.
            record = txn.get(record_name)
            if record is None:
                raise BackupError("nothing to back up")
            with self._ledger() as (key, ledger):
                existing = [int(m.group(1)) for p in self.backup_dir.iterdir()
                            if (m := BACKUP_NAME.fullmatch(p.name))]
                backup_id = max([ledger["last_backup_id"], *existing]) + 1
                body = {"id": backup_id, "subject": ledger["subject"], "created_at": now,
                        "record_name": record_name, "record": record}
                atomic_write(self.backup_dir / f"backup-{backup_id:08d}.json",
                             _seal(key, BACKUP_LABEL, body))
                fault("backup-written")
                ledger["last_backup_id"] = backup_id
                self._save_ledger(key, ledger)
                fault("ledger-updated")
        return backup_id

    def _newest_good(self, key: bytes, subject: str, record_name: str) \
            -> tuple[dict, list[str]]:
        damaged: list[str] = []
        # Newest first by NUMBER: names of different widths do not sort correctly as text.
        names = sorted((p for p in self.backup_dir.iterdir() if BACKUP_NAME.fullmatch(p.name)),
                       key=lambda p: int(BACKUP_NAME.fullmatch(p.name).group(1)), reverse=True)
        for path in names:
            try:
                body = _unseal(key, BACKUP_LABEL, path.read_bytes())
                if body["id"] != int(BACKUP_NAME.fullmatch(path.name).group(1)):
                    raise BackupError("file name does not match its number")
                if body["subject"] != subject or body["record_name"] != record_name:
                    raise BackupError("backup belongs to something else")
            except (OSError, BackupError, KeyError, TypeError) as error:
                reason = str(error) if isinstance(error, BackupError) else "unreadable"
                damaged.append(f"{path.name}: {reason}")
                continue
            return body, damaged
        raise BackupError("no backup passed verification", tuple(damaged))

    def restore(self, target: str | Path, record_name: str,
                fault: Fault = no_fault) -> RestoreReport:
        """Restore into ``target``. Safe to run again after a crash."""
        target = Path(target).resolve()
        for directory in (self.key_dir, self.backup_dir):
            if _inside(directory, target) or _inside(target, directory):
                raise BackupError("vault and restore target must be separate")
        # Lock order is store, then vault, the same as revocation and backup.
        with FileStore(target).replacing() as (records, write), self._ledger() as (key, ledger):
            current = (records or {}).get(record_name)
            body, damaged = self._newest_good(key, ledger["subject"], record_name)
            fault("verified")
            record = body["record"]
            _apply_removals(record, ledger["removals"], body["created_at"], current)
            expected = max(ledger["last_backup_id"], body["id"])
            if expected > body["id"] and not any(
                    line.startswith(f"backup-{expected:08d}") for line in damaged):
                damaged.append(f"backup-{expected:08d}.json: missing")
            fault("merged")
            write({record_name: record}, lambda: fault("key-ready"))
            fault("state-written")
        return RestoreReport(body["id"], tuple(damaged), expected)


def _apply_removals(record: dict, removals: dict, backup_time: float,
                    current: dict | None) -> None:
    for name in ("revoked_devices", "revoked_actors", "revoked_keys"):
        if name not in record:
            continue
        merged = dict(removals[name])
        merged.update((current or {}).get(name, {}))
        for item, at in merged.items():
            record[name].setdefault(item, at)
    if "grants" in record:
        for grant, at in removals["removed_grants"].items():
            if at >= backup_time:
                record["grants"].pop(grant, None)
        # A readable current state is evidence too. Grants only ever leave by being removed, so
        # one that is in the backup but not in the current state was removed after the backup,
        # even when no vault ledger recorded it (an authority created without a vault).
        # Restoring must not give that access back. Grants added after the backup stay lost
        # (documented); only removals are merged here, as for revocations.
        if current is not None and isinstance(current.get("grants"), dict):
            for grant in [g for g in record["grants"] if g not in current["grants"]]:
                del record["grants"][grant]
    if "journal" in record:
        record["journal"] = None
    if current is not None:
        # Never move list numbering or list dates backwards.
        for name in ("list_seq", "last_issued_at"):
            if name in record:
                record[name] = max(record[name], current[name])
