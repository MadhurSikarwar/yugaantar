"""Independent check of an audit log directory (PRD M-C3, M-C5, goal 5).

What it does: re-reads every entry, recomputes the hash chain, checks sequence numbers, verifies
each signed checkpoint, and compares the log with a head and a public key that the operator saved
elsewhere. It never changes any file except the lock file.

How it reads (memory and consistency): the log is streamed one entry at a time, so memory does not
grow with the size of the log (only the small checkpoint list and the few hashes that checkpoints
or a pin name are kept). The audit lock is held only long enough to take a snapshot: the checkpoint
and key files are read and the log's size is recorded. The log is append-only, so reading up to
that recorded size afterwards is a consistent view even while a service keeps appending; entries
written after the snapshot are simply not part of this verification. Holding the lock for the
whole pass instead would stall every request for as long as a large log takes to check.

Attacks defended against: editing, inserting, deleting and reordering entries; cut tails (against
a checkpoint or pinned head); forged or altered checkpoints; a replaced public key (against a
pinned key). It reports the first bad entry.

Not covered: without pinned values an attacker with write access to the directory can rebuild a
consistent log. Changes confined to entries after the newest checkpoint or pin can be cut off
unnoticed; the report says how many are uncovered. Verification is something an operator runs: it
detects tampering when it is run, not at the moment it happens.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from t4.audit.log import (
    CHECKPOINT_NAME,
    GENESIS_HASH,
    LOG_NAME,
    PUBLIC_KEY_NAME,
    AuditError,
    AuditIntegrityError,
    checkpoint_message,
    entry_hash,
    locked,
    parse_line,
    read_bytes,
    split_records,
)


@dataclass(frozen=True)
class VerifyReport:
    """Result of a verification. ``ok`` is true only when ``errors`` is empty."""

    ok: bool
    entries: int
    checkpoints: int
    covered_seq: int  # newest entry protected by a valid checkpoint or pinned head
    head_hash: str  # hash of the last entry that passed the chain check
    first_bad_seq: int | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    key_pinned: bool
    head_pinned: bool

    def as_dict(self) -> dict:
        return asdict(self)


def verify_log(
    directory: Path | str,
    pinned_head: dict | None = None,
    pinned_public_key: bytes | None = None,
) -> VerifyReport:
    """Verify the log in ``directory``. Never raises for damaged input."""
    folder = Path(directory)
    errors: list[str] = []
    warnings: list[str] = []
    bad: list[int] = []

    def fail(message: str, seq: int | None = None) -> None:
        errors.append(message)
        if seq is not None:
            bad.append(seq)

    checkpoint_data = stored_key = b""
    log_size = 0
    if not folder.is_dir():
        fail("no audit log directory")
    else:
        try:
            checkpoint_data, stored_key, log_size = _snapshot(folder, warnings)
        except OSError:
            fail("audit files could not be read")
        except AuditError:
            fail("audit log is busy: verification needs a consistent read, try again")

    # ---- public key ----------------------------------------------------------
    key = pinned_public_key if pinned_public_key is not None else stored_key
    if pinned_public_key is not None and stored_key and stored_key != pinned_public_key:
        fail("stored public key differs from the pinned key")
    if pinned_public_key is None:
        warnings.append("public key not pinned: it was read from the log directory")

    # ---- checkpoints and the pinned head: signatures first, hash comparison after the stream
    checkpoint_lines, checkpoint_partial = split_records(checkpoint_data)
    if checkpoint_partial:
        warnings.append("incomplete trailing checkpoint ignored")
    to_compare: list[tuple[str, int, str, bool]] = []  # (source, seq, hash, is_checkpoint)
    for number, line in enumerate(checkpoint_lines, start=1):
        try:
            record = json.loads(line.decode("ascii"))
            seq, head_hash, ts = record["seq"], record["hash"], record["ts"]
            signature = bytes.fromhex(record["sig"])
            if type(seq) is not int or seq < 0 or not isinstance(head_hash, str) or not isinstance(ts, str):
                raise ValueError("bad types")
            message = checkpoint_message(seq, head_hash, ts)
        except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
            fail(f"checkpoint {number}: malformed record")
            continue
        if not _signature_ok(key, message, signature):
            fail(f"checkpoint {number}: signature is invalid")
            continue
        to_compare.append((f"checkpoint {number}", seq, head_hash, True))

    if pinned_head is not None:
        try:
            seq, head_hash = pinned_head["seq"], pinned_head["hash"]
            if type(seq) is not int or seq < 0 or not isinstance(head_hash, str):
                raise ValueError("bad types")
            signature_hex = pinned_head.get("sig")
            if signature_hex is not None:
                message = checkpoint_message(seq, head_hash, pinned_head["ts"])
                if not _signature_ok(key, message, bytes.fromhex(signature_hex)):
                    fail("pinned head: signature is invalid for this public key")
        except (ValueError, KeyError, TypeError, AttributeError):
            fail("pinned head is malformed")
        else:
            to_compare.append(("pinned head", seq, head_hash, False))

    # ---- entry chain, streamed ----------------------------------------------
    wanted = {seq for _, seq, _, _ in to_compare if seq > 0}
    seen: dict[int, str] = {}  # hash of the entry at each wanted seq (only those are kept)
    previous = GENESIS_HASH
    good = 0  # entries that passed, contiguously from the start
    chain_intact = True
    complete_lines = 0
    partial = False
    consumed = 0
    broke = False
    if log_size:
        try:
            handle = (folder / LOG_NAME).open("rb")
        except OSError:
            fail("audit files could not be read")
            handle = None
        if handle is not None:
            with handle:
                while consumed < log_size:
                    raw = handle.readline()
                    if not raw:
                        break
                    consumed += len(raw)
                    if consumed > log_size:  # written after the snapshot: not part of this check
                        raw = raw[: len(raw) - (consumed - log_size)]
                        consumed = log_size
                    if not raw.endswith(b"\n"):
                        partial = True
                        break
                    complete_lines += 1
                    if broke:
                        continue  # only counting the rest, for the incomplete-record position
                    number = complete_lines
                    try:
                        entry = parse_line(raw[:-1])
                    except AuditIntegrityError:
                        fail(f"entry {number}: malformed or edited record", number)
                        broke = True
                        continue
                    if entry["seq"] != number:
                        fail(f"entry {number}: sequence number is {entry['seq']} (deleted, inserted or reordered)", number)
                        broke = True
                        continue
                    if entry["hash"] != entry_hash(entry, previous):
                        fail(f"entry {number}: hash does not match its content and predecessor", number)
                        broke = True
                        continue
                    previous = entry["hash"]
                    good = number
                    if number in wanted:
                        seen[number] = previous
            if consumed < log_size and not partial:
                warnings.append("the log became shorter while it was being verified")
    if partial:
        fail(f"entry {complete_lines + 1}: incomplete trailing record", complete_lines + 1)
    chain_intact = not broke

    def compare(source: str, seq: int, head_hash: str) -> bool:
        if seq == 0:
            if head_hash != GENESIS_HASH:
                fail(f"{source}: wrong starting hash", 1)
                return False
            return True
        if seq > good:
            if chain_intact:
                fail(f"{source}: log ends at entry {good} but entry {seq} was recorded (tail removed)", good + 1)
            return False
        if seen.get(seq) != head_hash:
            fail(f"{source}: entry {seq} differs from the recorded hash (history rewritten at or before it)", seq)
            return False
        return True

    covered = 0
    valid_checkpoints = 0
    for source, seq, head_hash, is_checkpoint in to_compare:
        if compare(source, seq, head_hash):
            covered = max(covered, seq)
            if is_checkpoint:
                valid_checkpoints += 1

    if not checkpoint_lines and pinned_head is None:
        warnings.append("no signed checkpoint or pinned head: a removed tail cannot be detected")
    elif good > covered:
        warnings.append(f"{good - covered} newest entries are not covered by a checkpoint or pin")

    return VerifyReport(
        ok=not errors,
        entries=good,
        checkpoints=valid_checkpoints,
        covered_seq=covered,
        head_hash=previous,
        first_bad_seq=min(bad) if bad else None,
        errors=tuple(errors),
        warnings=tuple(warnings),
        key_pinned=pinned_public_key is not None,
        head_pinned=pinned_head is not None,
    )


def _snapshot(folder: Path, warnings: list[str]) -> tuple[bytes, bytes, int]:
    """Read the small files and record the log's size, under the lock when it can be taken.

    Returns ``(checkpoints, public key, log size in bytes)``. The log is append-only, so reading
    exactly that many bytes later is a consistent view of the log as it was at this moment.
    """

    def take() -> tuple[bytes, bytes, int]:
        try:
            size = (folder / LOG_NAME).stat().st_size
        except FileNotFoundError:
            size = 0
        return (read_bytes(folder / CHECKPOINT_NAME), read_bytes(folder / PUBLIC_KEY_NAME), size)

    try:
        with locked(folder):
            return take()
    except OSError:
        # The lock file cannot be opened (for example a read-only copy): nothing is writing
        # to it either, so an unlocked read is consistent.
        warnings.append("checked without the audit lock")
        return take()
    # A lock TIMEOUT (AuditError) is deliberately not caught here: a writer is active, and an
    # unlocked snapshot could be taken mid-append, so it must not be reported as a verdict.


def _signature_ok(public_key: bytes, message: bytes, signature: bytes) -> bool:
    from t4.crypto import sig

    return sig.verify(public_key, message, signature)
