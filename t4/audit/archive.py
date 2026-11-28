"""Archive a finished audit log segment so the live log stops growing without limit.

    python -m t4.audit.cli --dir <log dir> archive --to <archive folder>

What it does, in this order (each step durable before the next):
    1. Re-checks the whole live chain and signs its head (as ``head()`` does).
    2. Copies the segment (``audit.jsonl``, ``checkpoints.jsonl``, ``audit.pub`` and the anchor it
       started from, if any) into ``<archive>/segment-<n>/`` with ``pin.json`` (its signed head),
       fsyncs every file and the folder, and checks the copy against that pin.
    3. Builds the new anchor and signs it with the log's key: where the chain continues (seq,
       hash), the segment number, the SECURITY WATERMARK of everything archived so far (the
       highest ``epoch`` and ``generation`` any entry recorded) and the identities of entries
       written with ``append_once``. It is stored in the archive (``next-anchor.json``) and then
       in the live folder (``segment.json``).
    4. Empties the live log and checkpoint files.

Why the watermark: the service refuses saved state that is older than its log (every revocation
raises the epoch). Without it, archiving would move every epoch out of the live file and an old
``state.json`` could be put back unnoticed, restoring revoked access.

Crash safety: after step 3 and before step 4 the live log still holds the archived entries while
the anchor says the chain starts after them; every reader then fails closed until ``archive`` is
run again, which notices the situation and finishes step 4. Nothing is ever deleted: the archive
keeps every entry, and ``verify-log --archive`` checks old pins through it.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from t4.audit.log import (ANCHOR_TYPE, CHECKPOINT_NAME, LOG_NAME, PUBLIC_KEY_NAME, SEGMENT_NAME, AuditError,
                          AuditLog, _fsync_directory, _tail, _write_atomically, anchor_message, load_signer,
                          locked, once_digest, parse_line, read_bytes)
from t4.audit.verify import verify_log

SEGMENT_DIR = re.compile(r"segment-(\d{6})")
NEXT_ANCHOR = "next-anchor.json"
WATERMARK_FIELDS = ("epoch", "generation")


def segments(archive: Path | str) -> list[Path]:
    """Archived segment folders, oldest first."""
    root = Path(archive)
    if not root.is_dir():
        return []
    return sorted((p for p in root.iterdir() if p.is_dir() and SEGMENT_DIR.fullmatch(p.name)),
                  key=lambda p: int(SEGMENT_DIR.fullmatch(p.name).group(1)))


def _fsync_file(path: Path) -> None:
    # Opened for writing: Windows refuses to flush a read-only handle.
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _is_once(entry: dict) -> bool:
    """Entries that ``append_once`` may look up again: everything except reads and alerts."""
    return entry["action"] not in ("read", "protected_read") and entry["decision"] != "alert"


def _last_line(path: Path) -> dict | None:
    lines, _partial = _tail(path, 1)
    return parse_line(lines[-1]) if lines else None


def archive(log_dir: str | Path, archive_dir: str | Path) -> dict:
    """Archive the live segment. Returns ``{"segment", "seq", "hash", "folder", "watermark"}``. Raises ``AuditError``."""
    live, archive_root = Path(log_dir).resolve(), Path(archive_dir).resolve()
    if archive_root == live or live in archive_root.parents or archive_root in live.parents:
        raise AuditError("the archive must be outside the log folder")
    signer = load_signer(live)
    if signer is None:
        raise AuditError("only a signed log can be archived")
    archive_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = segments(archive_root)

    with locked(live):
        log = AuditLog(live, None)
        anchor = log.anchor()  # raises on a forged anchor: never build on one
        last = _last_line(live / LOG_NAME)
        if anchor and last is not None and last["seq"] == anchor["seq"] and last["hash"] == anchor["hash"]:
            # Interrupted after step 3: the anchor is in place, the archived entries are still here.
            _write_atomically(live / CHECKPOINT_NAME, b"")
            _write_atomically(live / LOG_NAME, b"")
            return {"segment": anchor["segment"], "seq": anchor["seq"], "hash": anchor["hash"],
                    "folder": str(existing[-1]) if existing else "", "watermark": anchor["watermark"],
                    "completed_earlier_run": True}
        if last is None:
            raise AuditError("the live log is empty: nothing to archive")

    head = AuditLog(live, signer).head()  # re-checks the whole chain, signs the head
    check = AuditLog(live, None).verify()  # takes the lock itself; must not be called while holding it
    if not check.ok or check.entries == 0:
        raise AuditError("the log failed verification; nothing was moved")
    pin = dict(head, public_key=signer.public_key.hex())
    number = int(SEGMENT_DIR.fullmatch(existing[-1].name).group(1)) + 1 if existing else 1
    folder = archive_root / f"segment-{number:06d}"

    # The watermark and once-identities of everything in this segment (iter_entries takes the
    # lock itself); the locked block below confirms nothing was appended since.
    previous = AuditLog(live, None).anchor()
    mark = {field: 0 for field in WATERMARK_FIELDS}
    once = set(previous["once"]) if previous else set()
    if previous:
        mark.update({k: v for k, v in previous["watermark"].items() if k in WATERMARK_FIELDS})
    counted = 0
    for entry in AuditLog(live, None).iter_entries():
        counted = entry["seq"]
        for field in WATERMARK_FIELDS:
            value = entry["detail"].get(field)
            if type(value) is int and value > mark[field]:
                mark[field] = value
        if _is_once(entry):
            once.add(once_digest(entry["request_id"], entry["rule"]))

    with locked(live):
        log = AuditLog(live, None)
        if log.last_seq() != pin["seq"] or counted != pin["seq"]:
            raise AuditError("the log changed while archiving; nothing was moved, run it again")

        # Step 2: a complete, durable, verified copy.
        folder.mkdir(mode=0o700)
        for name in (LOG_NAME, CHECKPOINT_NAME, PUBLIC_KEY_NAME, SEGMENT_NAME):
            if (live / name).exists():
                shutil.copyfile(live / name, folder / name)
                _fsync_file(folder / name)
        (folder / "pin.json").write_text(json.dumps(pin, sort_keys=True), encoding="ascii")
        _fsync_file(folder / "pin.json")
        _fsync_directory(folder)
        copied = verify_log(folder, pin, signer.public_key)
        if not copied.ok:
            shutil.rmtree(folder, ignore_errors=True)
            raise AuditError("the archived copy did not verify; nothing was moved")

        # Step 3: the signed anchor, first in the archive, then in the live folder.
        body = {"type": ANCHOR_TYPE, "seq": pin["seq"], "hash": pin["hash"], "ts": pin["ts"],
                "segment": number, "watermark": mark, "once": sorted(once)}
        body["sig"] = signer.sign(anchor_message(body)).hex()
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        _write_atomically(folder / NEXT_ANCHOR, encoded)
        _write_atomically(live / SEGMENT_NAME, encoded)

        # Step 4: only now empty the live files.
        _write_atomically(live / CHECKPOINT_NAME, b"")
        _write_atomically(live / LOG_NAME, b"")
    return {"segment": number, "seq": pin["seq"], "hash": pin["hash"], "folder": str(folder), "watermark": mark}
