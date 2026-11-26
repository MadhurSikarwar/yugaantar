"""Independent check of an audit log directory.

What it does: re-reads every entry, recomputes the hash chain, checks sequence
numbers, verifies each signed checkpoint, and compares the log with a head and a
public key that the operator saved elsewhere. It never changes any file except the
lock file.

Attacks defended against: editing, inserting, deleting and reordering entries; cut
tails (against a checkpoint or pinned head); forged or altered checkpoints; a
replaced public key (against a pinned key). It reports the first bad entry.

Not covered: without pinned values an attacker with write access to the directory
can rebuild a consistent log. Changes confined to entries after the newest
checkpoint or pin can be cut off unnoticed; the report says how many are uncovered.
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

    log_data = checkpoint_data = stored_key = b""
    if not folder.is_dir():
        fail("no audit log directory")
    else:
        try:
            log_data, checkpoint_data, stored_key = _read_files(folder, warnings)
        except OSError:
            fail("audit files could not be read")

    # ---- entry chain ---------------------------------------------------------
    lines, partial = split_records(log_data)
    hashes: list[str] = []  # hashes of the entries that passed, in order
    previous = GENESIS_HASH
    for number, line in enumerate(lines, start=1):
        try:
            entry = parse_line(line)
        except AuditIntegrityError:
            fail(f"entry {number}: malformed or edited record", number)
            break
        if entry["seq"] != number:
            fail(f"entry {number}: sequence number is {entry['seq']} (deleted, inserted or reordered)", number)
            break
        if entry["hash"] != entry_hash(entry, previous):
            fail(f"entry {number}: hash does not match its content and predecessor", number)
            break
        previous = entry["hash"]
        hashes.append(previous)
    if partial:
        fail(f"entry {len(lines) + 1}: incomplete trailing record", len(lines) + 1)
    chain_intact = len(hashes) == len(lines)

    def compare(source: str, seq: int, head_hash: str) -> bool:
        if seq == 0:
            if head_hash != GENESIS_HASH:
                fail(f"{source}: wrong starting hash", 1)
                return False
            return True
        if seq > len(hashes):
            if chain_intact:
                fail(f"{source}: log ends at entry {len(hashes)} but entry {seq} was recorded (tail removed)",
                     len(hashes) + 1)
            return False
        if hashes[seq - 1] != head_hash:
            fail(f"{source}: entry {seq} differs from the recorded hash (history rewritten at or before it)", seq)
            return False
        return True

    # ---- public key ----------------------------------------------------------
    key = pinned_public_key if pinned_public_key is not None else stored_key
    if pinned_public_key is not None and stored_key and stored_key != pinned_public_key:
        fail("stored public key differs from the pinned key")
    if pinned_public_key is None:
        warnings.append("public key not pinned: it was read from the log directory")

    # ---- checkpoints ---------------------------------------------------------
    checkpoint_lines, checkpoint_partial = split_records(checkpoint_data)
    if checkpoint_partial:
        warnings.append("incomplete trailing checkpoint ignored")
    covered = 0
    valid_checkpoints = 0
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
        if compare(f"checkpoint {number}", seq, head_hash):
            valid_checkpoints += 1
            covered = max(covered, seq)

    # ---- pinned head ---------------------------------------------------------
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
            if compare("pinned head", seq, head_hash):
                covered = max(covered, seq)

    if not checkpoint_lines and pinned_head is None:
        warnings.append("no signed checkpoint or pinned head: a removed tail cannot be detected")
    elif len(hashes) > covered:
        warnings.append(f"{len(hashes) - covered} newest entries are not covered by a checkpoint or pin")

    return VerifyReport(
        ok=not errors,
        entries=len(hashes),
        checkpoints=valid_checkpoints,
        covered_seq=covered,
        head_hash=hashes[-1] if hashes else GENESIS_HASH,
        first_bad_seq=min(bad) if bad else None,
        errors=tuple(errors),
        warnings=tuple(warnings),
        key_pinned=pinned_public_key is not None,
        head_pinned=pinned_head is not None,
    )


def _read_files(folder: Path, warnings: list[str]) -> tuple[bytes, bytes, bytes]:
    """Read log, checkpoints and public key, under the lock when it can be taken."""

    def read() -> tuple[bytes, bytes, bytes]:
        return (
            read_bytes(folder / LOG_NAME),
            read_bytes(folder / CHECKPOINT_NAME),
            read_bytes(folder / PUBLIC_KEY_NAME),
        )

    try:
        with locked(folder):
            return read()
    except (OSError, AuditError):
        warnings.append("checked without the audit lock")  # e.g. a read-only copy
        return read()


def _signature_ok(public_key: bytes, message: bytes, signature: bytes) -> bool:
    from t4.crypto import sig

    return sig.verify(public_key, message, signature)
