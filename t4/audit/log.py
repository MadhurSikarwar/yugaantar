"""Append-only, hash-chained audit log with signed checkpoints (PRD M-C1 to M-C5).

What it does: writes one canonical JSON object per line to ``audit.jsonl``. Each
entry's hash covers its content and the previous entry's hash. Every
``checkpoint_every`` entries, and whenever ``head()`` is called, the current
``(seq, hash)`` is signed with ML-DSA into ``checkpoints.jsonl``.

Attacks defended against:
- Log injection: caller text is only ever a JSON string value, escaped to ASCII, so
  newlines, ``U+2028`` or text shaped like an entry cannot start a second record or
  change the recorded actor.
- Editing, deleting or reordering entries: the hash chain and sequence numbers break.
- Cutting off the tail: appending and verifying compare the log with the newest
  signed checkpoint (and verification also with a head the operator pinned).
- Concurrent writers: an exclusive file lock; callers that also hold the state-store
  lock must take that one first (PRD lock order: store, then audit).
- Interrupted writes: only an incomplete last line is removed, and an alert says so.
- Damaged logs: appending and searching fail closed with ``AuditIntegrityError``.
- Editing an entry written within roughly the last two checkpoint intervals: every
  live ``append()`` (and ``head()``) now re-derives and cross-checks the whole chain
  back through the *second-newest* signed checkpoint, not just the newest entry or
  two, so this is caught on the very next request, not only by an operator-run
  ``verify-log``. Anchoring one checkpoint further back than the newest matters: it
  means the newest checkpoint's own entry is re-derived from what is actually on disk
  and compared against what the checkpoint claims, rather than that one entry's hash
  being trusted outright -- which otherwise misses a tamper of exactly that entry
  whenever it is the newest (the common case for a node log, where a checkpoint sits
  on every single entry). The window this re-checks is bounded (``2 *
  checkpoint_every``) and does not grow with the size of the log (see
  ``_head_of_complete_log``).

Not covered:
- Editing an entry older than that window. The second-newest checkpoint's own recorded
  hash is trusted as a fixed anchor on every live append rather than re-derived from
  the whole log each time (that would be an unbounded cost per append and would not
  scale to this project's own documented unbounded log growth), so an older tamper
  leaves the live append path's own check satisfied. This is caught only by a full
  chain walk: ``entries()``, ``verify()``/``verify-log``, ``explain`` or ``find`` --
  i.e. an operator-run check against a pin kept outside the directory. The live
  service does not run one of these on its own; it must be run by the operator (a cron
  job, a step in CI, or a pre-judging check), the same way the pinned head itself must
  be kept outside the directory to be worth anything.
- Whoever can write this directory can read the signing key and rebuild everything
  consistently with it. Only a head and public key pinned *outside* the directory
  reveal that, and only up to the pinned entry. Restoring an older copy of the whole
  directory also passes without such a pin.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Iterator, Mapping, Protocol

if TYPE_CHECKING:  # pragma: no cover
    from t4.audit.verify import VerifyReport

LOG_NAME = "audit.jsonl"
CHECKPOINT_NAME = "checkpoints.jsonl"
PUBLIC_KEY_NAME = "audit.pub"
SECRET_KEY_NAME = "audit.key"
LOCK_NAME = "audit.lock"

CHECKPOINT_TYPE = "audit-checkpoint"
GENESIS_HASH = hashlib.sha256(b"t4-audit-genesis-v1").hexdigest()
DEFAULT_CHECKPOINT_EVERY = 16
ALERT_DECISION = "alert"
RULE_PARTIAL_REPAIRED = "AUD-PARTIAL-RECORD-REPAIRED"

TEXT_FIELDS = ("actor", "action", "target", "decision", "rule", "request_id")
ENTRY_FIELDS = frozenset(TEXT_FIELDS) | {"seq", "ts", "detail", "hash"}

_LOCK_TIMEOUT_S = 6.0

# How much of the history a live append re-hashes (see ``AuditLog._head_of_complete_log``).
# Re-hashing everything on every append is O(log size) per request, which does not scale to
# a log an attacker can make large, so the cost is tiered and bounded by file size:
#   * log at most this size: the WHOLE chain is re-checked on every append;
#   * larger, at most FULL_CHECK_AT_CHECKPOINT_BYTES: the whole chain is re-checked once per
#     checkpoint interval (only for logs that checkpoint rarely, i.e. checkpoint_every >= 8);
#   * otherwise only the recent window is re-checked, and ``head()``/``verify-log`` remain
#     the way to check older history. ``head()`` always re-checks the whole chain.
FULL_CHECK_EVERY_APPEND_BYTES = 256 * 1024
FULL_CHECK_AT_CHECKPOINT_BYTES = 8 * 1024 * 1024
MIN_PERIODIC_CHECKPOINT_EVERY = 8
_O_BINARY = getattr(os, "O_BINARY", 0)


class AuditError(Exception):
    """The audit log could not be used. Callers must fail closed."""


class AuditIntegrityError(AuditError):
    """The stored log or its keys are inconsistent."""


class Signer(Protocol):
    """Anything that can sign checkpoints."""

    public_key: bytes

    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True, repr=False)
class MLDSASigner:
    """ML-DSA-65 signer. ``repr`` is suppressed so the secret key cannot be printed."""

    public_key: bytes
    secret_key: bytes

    def sign(self, message: bytes) -> bytes:
        from t4.crypto import sig

        return sig.sign(self.secret_key, message)

    def __repr__(self) -> str:
        return "MLDSASigner(<keys hidden>)"


def canonical(value: object) -> bytes:
    """The one serialization used for hashing, signing and storage."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def entry_hash(entry: Mapping[str, object], previous_hash: str) -> str:
    """SHA-256 over the canonical entry (without ``hash``) followed by the previous hash."""
    body = {key: value for key, value in entry.items() if key != "hash"}
    return hashlib.sha256(canonical(body) + bytes.fromhex(previous_hash)).hexdigest()


def checkpoint_message(seq: int, head_hash: str, ts: str) -> bytes:
    """The exact bytes a checkpoint signature covers."""
    return canonical({"type": CHECKPOINT_TYPE, "seq": seq, "hash": head_hash, "ts": ts})


def parse_line(line: bytes) -> dict:
    """Decode one stored entry, rejecting anything not written in canonical form."""
    try:
        entry = json.loads(line.decode("ascii"))
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise ValueError("unexpected fields")
        if type(entry["seq"]) is not int or not isinstance(entry["detail"], dict):
            raise ValueError("unexpected types")
        if not all(isinstance(entry[name], str) for name in (*TEXT_FIELDS, "ts", "hash")):
            raise ValueError("unexpected types")
        if canonical(entry) != line:
            raise ValueError("not canonical")
    except (ValueError, UnicodeError, RecursionError):
        raise AuditIntegrityError("malformed audit record") from None
    return entry


def split_records(data: bytes) -> tuple[list[bytes], bytes]:
    """Split file content into complete lines and the unterminated remainder."""
    parts = data.split(b"\n")
    return parts[:-1], parts[-1]


def read_bytes(path: Path) -> bytes:
    """File content, or empty bytes if the file does not exist."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def _tail(path: Path, count: int) -> tuple[list[bytes], bytes]:
    """The last ``count`` complete lines and the unterminated remainder, read from the end."""
    try:
        handle = path.open("rb")
    except FileNotFoundError:
        return [], b""
    with handle:
        position = handle.seek(0, os.SEEK_END)
        data = b""
        while position > 0 and data.count(b"\n") <= count:
            step = min(8192, position)
            position -= step
            handle.seek(position)
            data = handle.read(step) + data
    lines, partial = split_records(data)
    if position > 0:
        lines = lines[1:]  # the first line may be cut off by the block boundary
    return lines[-count:], partial


def _fsync_directory(directory: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _append_durably(path: Path, data: bytes) -> None:
    is_new = not path.exists()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_BINARY, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if is_new:
        _fsync_directory(path.parent)


def _truncate_durably(path: Path, size: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | _O_BINARY)
    try:
        os.ftruncate(descriptor, size)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_atomically(path: Path, data: bytes) -> None:
    # A fresh, unpredictable name created exclusively (O_EXCL): a pre-planted file or symlink
    # at a guessable name cannot redirect where a signing key is written.
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(6).hex()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        for attempt in range(50):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:  # Windows: another program briefly has it open.
                if attempt == 49:
                    raise
                time.sleep(0.01)
    except BaseException:
        try:
            os.unlink(temporary)  # never leave a (partial) key file behind
        except OSError:
            pass
        raise
    _fsync_directory(path.parent)


def _try_lock(descriptor: int) -> bool:
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def locked(directory: Path, timeout: float = _LOCK_TIMEOUT_S) -> Iterator[None]:
    """Hold the directory's exclusive audit lock. Not re-entrant."""
    descriptor = os.open(directory / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while not _try_lock(descriptor):
            if time.monotonic() > deadline:
                raise AuditError("audit log is busy")
            time.sleep(0.002)
        try:
            yield
        finally:
            _unlock(descriptor)
    finally:
        os.close(descriptor)


def load_signer(directory: Path | str) -> MLDSASigner | None:
    """Load the signing key pair stored in ``directory``, or ``None`` if there is none."""
    from t4.crypto import sig

    folder = Path(directory)
    secret_key = read_bytes(folder / SECRET_KEY_NAME)
    public_key = read_bytes(folder / PUBLIC_KEY_NAME)
    if not secret_key:
        return None
    if len(secret_key) != sig.SECRET_KEY_SIZE or len(public_key) != sig.PUBLIC_KEY_SIZE:
        raise AuditIntegrityError("audit signing key files are damaged")
    return MLDSASigner(public_key, secret_key)


def load_or_create_signer(directory: Path | str) -> MLDSASigner:
    """Return the directory's signer, generating and storing a key pair on first use."""
    from t4.crypto import sig

    folder = Path(directory)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    with locked(folder):
        existing = load_signer(folder)
        if existing is not None:
            return existing
        if (folder / CHECKPOINT_NAME).exists():
            raise AuditIntegrityError("signed checkpoints exist but the signing key is missing")
        public_key, secret_key = sig.sig_keygen()
        # Public key first: the secret key file is what marks the pair as complete.
        _write_atomically(folder / PUBLIC_KEY_NAME, public_key)
        _write_atomically(folder / SECRET_KEY_NAME, secret_key)
    return MLDSASigner(public_key, secret_key)


def _listed_ids(entry: dict) -> list:
    """The request IDs an alert refers to, or nothing if the value is not a list."""
    try:
        listed = json.loads(entry["detail"]["request_ids"])
    except (KeyError, TypeError, ValueError, RecursionError):
        return []
    return listed if isinstance(listed, list) else []


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """One log directory. Safe to open from many processes at once."""

    def __init__(
        self,
        dir: Path | str,
        signer: Signer | None,
        *,
        checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        if checkpoint_every < 1:
            raise ValueError("checkpoint_every must be at least 1")
        self.directory = Path(dir)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.signer = signer
        self.checkpoint_every = checkpoint_every
        self._clock = clock
        self.log_path = self.directory / LOG_NAME
        self.checkpoint_path = self.directory / CHECKPOINT_NAME
        if signer is not None:
            public_path = self.directory / PUBLIC_KEY_NAME
            with locked(self.directory):
                stored = read_bytes(public_path)
                if not stored:
                    _write_atomically(public_path, signer.public_key)
                elif stored != signer.public_key:
                    raise AuditIntegrityError("signer does not match the log's public key")

    # ---- writing -----------------------------------------------------------------

    def append(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        decision: str,
        rule: str,
        request_id: str,
        detail: Mapping[str, str | int | bool] | None = None,
    ) -> dict:
        """Durably add one entry and return ``{"seq", "hash"}``.

        Raises ``ValueError`` for wrong argument types and ``AuditError`` if the log
        cannot be extended safely.
        """
        fields, extra = self._checked_entry(
            actor, action, target, decision, rule, request_id, detail)
        try:
            with locked(self.directory):
                seq, head_hash = self._recover_and_head()
                return self._write_entry(seq, head_hash, fields, extra)
        except OSError:
            raise AuditError("audit log could not be written") from None

    def append_once(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        decision: str,
        rule: str,
        request_id: str,
        detail: Mapping[str, str | int | bool] | None = None,
    ) -> dict:
        """Append unless an entry with this ``request_id`` and ``rule`` is already in the log.

        Returns ``{"seq", "hash"}`` of the new entry, or of the existing one. The search and the
        append happen under ONE hold of the audit lock, so two writers cannot both decide the
        entry is missing. This is what lets a retried operation (for example a key rotation
        interrupted after its audit entry was written but before its state was saved) log its
        event exactly once: the caller passes a request_id derived from the operation's stable
        identity instead of a random one. Existing history is never changed.
        """
        fields, extra = self._checked_entry(
            actor, action, target, decision, rule, request_id, detail)
        try:
            with locked(self.directory):
                seq, head_hash = self._recover_and_head()
                existing = self._find_once(request_id, rule)
                if existing is not None:
                    return existing
                return self._write_entry(seq, head_hash, fields, extra)
        except OSError:
            raise AuditError("audit log could not be written") from None

    @staticmethod
    def _checked_entry(actor, action, target, decision, rule, request_id, detail):
        fields = {
            "actor": actor,
            "action": action,
            "target": target,
            "decision": decision,
            "rule": rule,
            "request_id": request_id,
        }
        if not all(isinstance(value, str) for value in fields.values()):
            raise ValueError("audit fields must be strings")
        extra = dict(detail or {})
        for key, value in extra.items():
            if not isinstance(key, str) or not isinstance(value, (str, int, bool)):
                raise ValueError("audit detail must map strings to str, int or bool")
        return fields, extra

    def _find_once(self, request_id: str, rule: str) -> dict | None:
        """Stream the log for an entry with this request_id and rule (lock must be held)."""
        needle = b'"request_id":' + canonical(request_id)
        try:
            handle = self.log_path.open("rb")
        except FileNotFoundError:
            return None
        with handle:
            for raw in handle:
                if not raw.endswith(b"\n") or needle not in raw:
                    continue  # an unterminated tail was repaired before this point
                entry = parse_line(raw[:-1])
                if entry["request_id"] == request_id and entry["rule"] == rule:
                    return {"seq": entry["seq"], "hash": entry["hash"]}
        return None

    def alert(
        self,
        *,
        rule: str,
        explanation: str,
        actor: str = "",
        target: str = "",
        request_id: str = "",
        entries: Iterable[int] = (),
        request_ids: Iterable[str] = (),
        detail: Mapping[str, str | int | bool] | None = None,
    ) -> dict:
        """Record an alert with its rule, plain explanation and triggering records (M-A12).

        ``entries`` (sequence numbers) and ``request_ids`` are stored as JSON lists
        inside strings, so any identifier text survives unchanged.
        """
        extra = dict(detail or {})
        extra["explanation"] = explanation
        extra["entries"] = json.dumps([int(number) for number in entries])
        extra["request_ids"] = json.dumps(list(request_ids))
        return self.append(
            actor=actor,
            action="alert",
            target=target,
            decision=ALERT_DECISION,
            rule=rule,
            request_id=request_id,
            detail=extra,
        )

    def head(self) -> dict:
        """Return ``{"seq", "hash", "sig"}`` and store the signature as a checkpoint.

        ``sig`` is hex, or ``None`` for an unsigned log. ``ts`` is included because
        the signature covers it.
        """
        try:
            with locked(self.directory):
                # Signing a checkpoint vouches for the chain up to here, so check ALL of it
                # first: never sign on top of history that has been edited.
                seq, head_hash = self._recover_and_head(full=True)
                if self.signer is None:
                    return {"seq": seq, "hash": head_hash, "ts": self._clock(), "sig": None}
                _older, newest = self._checkpoint_pair()
                if newest is not None and newest["seq"] == seq and newest["hash"] == head_hash:
                    return newest  # already signed at exactly this head: no duplicate record
                return self._write_checkpoint(seq, head_hash)
        except OSError:
            raise AuditError("audit log could not be read or signed") from None

    # ---- reading -----------------------------------------------------------------

    def iter_entries(self):
        """Yield every entry in order, checking the hash chain as it goes, one entry in memory.

        The lock is held only to take a snapshot (log size and newest checkpoint). The log is
        append-only, so reading exactly that many bytes afterwards is a consistent view even if a
        writer keeps appending; later entries are not part of this pass. An incomplete last line is
        ignored. The newest checkpoint is compared with the entry it names once the pass reaches
        it. A broken chain raises ``AuditIntegrityError`` at the first bad entry, so a caller that
        builds a result list gets no partial answer from a damaged log.
        """
        def snapshot():
            try:
                size = self.log_path.stat().st_size
            except FileNotFoundError:
                size = 0
            return size, self._newest_checkpoint()

        try:
            try:
                with locked(self.directory):
                    size, newest = snapshot()
            except AuditError:
                raise  # busy: never fall back to an unlocked read
            except OSError:
                # The directory cannot be locked for writing (a read-only mount or copy). The log
                # is append-only and only complete lines are used, so an unlocked read is still a
                # consistent view; every check below runs exactly as before.
                size, newest = snapshot()
            handle = self.log_path.open("rb") if size else None
        except (OSError, FileNotFoundError):
            raise AuditError("audit log could not be read") from None
        previous, count, consumed = GENESIS_HASH, 0, 0
        if handle is not None:
            with handle:
                while consumed < size:
                    raw = handle.readline()
                    if not raw:
                        break
                    consumed += len(raw)
                    if consumed > size:
                        raw = raw[: len(raw) - (consumed - size)]
                        consumed = size
                    if not raw.endswith(b"\n"):
                        break  # an incomplete last line is ignored
                    entry = parse_line(raw[:-1])
                    count += 1
                    if entry["seq"] != count or entry["hash"] != entry_hash(entry, previous):
                        raise AuditIntegrityError(f"audit chain is broken at entry {count}")
                    previous = entry["hash"]
                    if newest is not None and count == newest["seq"] and previous != newest["hash"]:
                        raise AuditIntegrityError("audit log differs from a signed checkpoint")
                    yield entry
        if newest is not None and newest["seq"] > count:
            raise AuditIntegrityError("audit log is shorter than a signed checkpoint")

    def entries(self) -> list[dict]:
        """All entries, after checking the hash chain. Ignores an incomplete last line.

        Builds a list, so memory grows with the log; prefer ``iter_entries``, ``find``,
        ``explain`` or ``alerts`` (all streaming) for a large log.
        """
        return list(self.iter_entries())

    def explain(self, request_id: str) -> list[dict]:
        """Every entry for ``request_id``, including alerts that list it, oldest first."""
        found = []
        for entry in self.iter_entries():
            if entry["request_id"] == request_id:
                found.append(entry)
            elif entry["decision"] == ALERT_DECISION and request_id in _listed_ids(entry):
                found.append(entry)
        return found

    def find(self, **match: str) -> list[dict]:
        """Entries whose fields (or ``detail`` keys) all equal the given values."""
        found = []
        for entry in self.iter_entries():
            for key, wanted in match.items():
                holder = entry if key in ENTRY_FIELDS and key != "detail" else entry["detail"]
                if key not in holder or str(holder[key]) != str(wanted):
                    break
            else:
                found.append(entry)
        return found

    def alerts(self) -> list[dict]:
        """Every alert entry, oldest first."""
        return [entry for entry in self.iter_entries() if entry["decision"] == ALERT_DECISION]

    def verify(
        self, pinned_head: dict | None = None, pinned_public_key: bytes | None = None
    ) -> "VerifyReport":
        """Full check of chain, checkpoints and any pinned values."""
        from t4.audit.verify import verify_log

        return verify_log(self.directory, pinned_head, pinned_public_key)

    # ---- internal (all called with the lock held) ---------------------------------

    @staticmethod
    def _parse_checkpoint_record(line: bytes) -> dict:
        try:
            record = json.loads(line.decode("ascii"))
            if type(record["seq"]) is not int or not isinstance(record["hash"], str):
                raise ValueError("bad checkpoint")
        except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
            raise AuditIntegrityError("malformed checkpoint record") from None
        return record

    def _newest_checkpoint(self) -> dict | None:
        lines, _partial = _tail(self.checkpoint_path, 1)
        return self._parse_checkpoint_record(lines[-1]) if lines else None

    def _checkpoint_pair(self) -> tuple[dict | None, dict | None]:
        """(second-newest, newest) checkpoint records; either or both may be ``None``.

        Used by ``_head_of_complete_log`` so a live append re-derives and cross-checks
        the newest checkpoint's own entry too, instead of trusting its recorded hash
        without ever recomputing it (that blind trust was the gap this pair closes).
        """
        lines, _partial = _tail(self.checkpoint_path, 64)
        records = [self._parse_checkpoint_record(line) for line in lines]
        if not records:
            return None, None
        newest = records[-1]
        # Skip repeats at the same sequence number (older versions let ``head()`` sign the same
        # head again and again): the anchor must be a *different*, earlier entry, or the newest
        # entry would be trusted without being re-hashed.
        older = next((r for r in reversed(records[:-1]) if r["seq"] < newest["seq"]), None)
        return older, newest

    @staticmethod
    def _compare_with_checkpoint(checkpoint: dict, count: int, entries: list[dict]) -> None:
        seq = checkpoint["seq"]
        if seq > count:
            raise AuditIntegrityError("audit log is shorter than a signed checkpoint")
        expected = GENESIS_HASH if seq == 0 else entries[seq - 1]["hash"]
        if checkpoint["hash"] != expected:
            raise AuditIntegrityError("audit log differs from a signed checkpoint")

    def _recover_and_head(self, full: bool = False) -> tuple[int, str]:
        """Repair interrupted writes, check the newest records and return the head.

        ``full`` re-checks the whole chain regardless of size (used by ``head()``).
        """
        for path in (self.checkpoint_path, self.log_path):
            _lines, partial = _tail(path, 1)
            if partial:
                # Check the complete records first: if they are damaged, keep the
                # fragment as evidence and fail instead of repairing.
                head = self._head_of_complete_log() if path == self.log_path else None
                _truncate_durably(path, path.stat().st_size - len(partial))
                if head is not None:
                    seq, head_hash = head
                    self._write_entry(
                        seq,
                        head_hash,
                        {
                            "actor": "",
                            "action": "repair",
                            "target": LOG_NAME,
                            "decision": ALERT_DECISION,
                            "rule": RULE_PARTIAL_REPAIRED,
                            "request_id": "",
                        },
                        {
                            "explanation": "removed an incomplete last record left by an interrupted write",
                            "removed_bytes": len(partial),
                            "removed_sha256": hashlib.sha256(partial).hexdigest(),
                        },
                    )
        seq, head_hash = self._head_of_complete_log()
        if full or self._wants_whole_chain(seq):
            return self._walk_whole_log()
        return seq, head_hash

    def _wants_whole_chain(self, seq: int) -> bool:
        """Whether this append re-checks the whole chain (the cost tiers above)."""
        try:
            size = self.log_path.stat().st_size
        except FileNotFoundError:
            return False
        if size <= FULL_CHECK_EVERY_APPEND_BYTES:
            return True
        return (
            self.checkpoint_every >= MIN_PERIODIC_CHECKPOINT_EVERY
            and (seq + 1) % self.checkpoint_every == 0
            and size <= FULL_CHECK_AT_CHECKPOINT_BYTES
        )

    def _walk_whole_log(self) -> tuple[int, str]:
        """Re-hash every entry from genesis, streaming (no whole-file copy in memory).

        Checks sequence numbers, every entry's hash against its content and predecessor, and
        the newest signed checkpoint against the entry it names. Signatures are not checked
        here (``verify-log`` does that); this detects edits to entries without the signing key.
        """
        newest = self._newest_checkpoint()
        previous, seq = GENESIS_HASH, 0
        try:
            handle = self.log_path.open("rb")
        except FileNotFoundError:
            handle = None
        if handle is not None:
            with handle:
                for raw in handle:
                    if not raw.endswith(b"\n"):
                        break  # an unterminated last record is repaired before this point
                    entry = parse_line(raw[:-1])
                    if entry["seq"] != seq + 1 or entry["hash"] != entry_hash(entry, previous):
                        raise AuditIntegrityError(f"audit chain is broken at entry {seq + 1}")
                    previous, seq = entry["hash"], entry["seq"]
                    if newest is not None and seq == newest["seq"] and previous != newest["hash"]:
                        raise AuditIntegrityError("audit log differs from a signed checkpoint")
        if newest is not None and newest["seq"] > seq:
            raise AuditIntegrityError("audit log is shorter than a signed checkpoint")
        return seq, previous

    def _head_of_complete_log(self) -> tuple[int, str]:
        """Verify and return the head, re-deriving every entry's hash back through the
        *second-newest* signed checkpoint (or genesis, if fewer than two exist yet) on
        every call.

        Bounded, not a full scan: the gap from the second-newest checkpoint to the tail
        is at most ``2 * checkpoint_every`` entries by construction (a checkpoint is
        written every ``checkpoint_every`` appends; ``head()`` can only add extra
        checkpoints, never skip a scheduled one), so the window read and re-hashed here
        never grows with the size of the whole log.

        Anchoring one checkpoint further back than the newest one matters: it means the
        newest checkpoint's *own* entry gets walked and its hash re-derived from the
        actual bytes on disk too, and cross-checked against what the checkpoint claims
        (below), instead of the newest checkpoint's recorded hash being trusted outright
        without ever being recomputed -- which would miss a tamper of exactly that one
        entry whenever it happens to be the newest (the common case for a node log,
        where ``checkpoint_every == 1`` and a checkpoint sits on every single entry).

        What this catches that a 1-2 line tail check would not: an edit to any entry
        written within roughly the last two checkpoint intervals is now detected on the
        very next append, not only an edit to the newest entry or two.

        What this still does NOT catch: an edit to an entry older than that window. That
        tamper leaves this window's own chain self-consistent, because the second-newest
        checkpoint's recorded hash is itself trusted as a fixed anchor here, not
        re-derived from the whole log on every append (which would be an unbounded,
        O(log size) cost per append and does not scale to this project's own documented
        unbounded log growth). Catching an older tamper still needs a full chain walk:
        ``entries()``, ``verify()``/``verify-log``, ``explain`` or ``find`` -- i.e. an
        operator-run check against a pin kept outside the directory, not something the
        live service does by itself on every request. See docs/threat-model.md.
        """
        older, newest = self._checkpoint_pair()
        anchor_seq = older["seq"] if older is not None else 0
        anchor_hash = older["hash"] if older is not None else GENESIS_HASH
        window = 2 * self.checkpoint_every + 2  # 2 intervals of margin
        lines, _partial = _tail(self.log_path, window)
        if not lines:
            if newest is not None:
                raise AuditIntegrityError("audit log is shorter than a signed checkpoint")
            return 0, GENESIS_HASH
        parsed = [parse_line(line) for line in lines]
        # The log's own tail (not the anchor) decides whether it's shorter than a
        # checkpoint that claims a higher seq -- check this before anything else, since
        # a truncated/rolled-back log must fail closed even if the window below ends up
        # empty after filtering (nothing left to re-walk is not the same as "verified").
        if newest is not None and newest["seq"] > parsed[-1]["seq"]:
            raise AuditIntegrityError("audit log is shorter than a signed checkpoint")
        if parsed[0]["seq"] > anchor_seq + 1:
            # The window was not wide enough to reach the older anchor (or genesis).
            # Should not happen with this instance's own checkpoint_every; fail closed
            # rather than silently trusting an unverified gap if it ever does (for
            # example checkpoint_every was lowered after the checkpoint was written).
            raise AuditIntegrityError("cannot verify the log back to its last checkpoint")
        parsed = [entry for entry in parsed if entry["seq"] >= anchor_seq + 1]
        previous, seq = anchor_hash, anchor_seq
        for entry in parsed:
            if entry["seq"] != seq + 1 or entry["hash"] != entry_hash(entry, previous):
                raise AuditIntegrityError(f"audit chain is broken at entry {seq + 1}")
            previous, seq = entry["hash"], entry["seq"]
            if newest is not None and seq == newest["seq"] and previous != newest["hash"]:
                # The newest checkpoint's own entry, re-derived from what is actually on
                # disk, does not match what the checkpoint claims.
                raise AuditIntegrityError("audit log differs from a signed checkpoint")
        return seq, previous

    def _write_entry(self, seq: int, head_hash: str, fields: dict, detail: dict) -> dict:
        entry = {**fields, "seq": seq + 1, "ts": self._clock(), "detail": detail}
        entry["hash"] = entry_hash(entry, head_hash)
        _append_durably(self.log_path, canonical(entry) + b"\n")
        if self.signer is not None and entry["seq"] % self.checkpoint_every == 0:
            self._write_checkpoint(entry["seq"], entry["hash"])
        return {"seq": entry["seq"], "hash": entry["hash"]}

    def _write_checkpoint(self, seq: int, head_hash: str) -> dict:
        assert self.signer is not None
        ts = self._clock()
        signature = self.signer.sign(checkpoint_message(seq, head_hash, ts)).hex()
        record = {"seq": seq, "hash": head_hash, "ts": ts, "sig": signature}
        _append_durably(self.checkpoint_path, canonical(record) + b"\n")
        return record
