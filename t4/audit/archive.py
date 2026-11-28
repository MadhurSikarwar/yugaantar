"""Archive a finished audit log segment so the live log stops growing without limit.

    python -m t4.audit.cli --dir <log dir> archive --to <archive folder>

What it does, in this order (each step durable before the next):
    1. Re-checks the whole live chain and signs its head (as ``head()`` does).
    2. Copies the segment (``audit.jsonl``, ``checkpoints.jsonl``, ``audit.pub`` and any earlier
       anchor) into ``<archive>/segment-<n>/`` with a ``pin.json`` of that head, and checks the
       copy against the pin.
    3. Empties the live log and checkpoint files.
    4. Writes ``segment.json`` in the live folder: the signed checkpoint of the archived head.
       New entries continue the same chain from it (numbering and hashes go on), so every
       reader and ``verify-log`` check the live segment from that signed anchor.

A crash after step 3 and before step 4 leaves an empty log without an anchor; the service then
refuses to work (its saved state knows later entries), and running ``archive`` again finishes the
job from the copy made in step 2. Nothing is ever deleted: the archive keeps every entry.

Limits: ``explain``, ``find`` and the detector read the live segment only; check an archived
segment with ``verify-log --pin <archive>/segment-<n>/pin.json`` in its own folder. Whoever can
write the log folder can still read the signing key (see the README).
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from t4.audit.log import (CHECKPOINT_NAME, LOG_NAME, PUBLIC_KEY_NAME, SEGMENT_NAME, AuditError, AuditLog,
                          _fsync_directory, _write_atomically, load_signer, locked, read_bytes)
from t4.audit.verify import verify_log

SEGMENT_DIR = re.compile(r"segment-(\d{6})")


def _segments(archive: Path) -> list[Path]:
    if not archive.is_dir():
        return []
    return sorted((p for p in archive.iterdir() if p.is_dir() and SEGMENT_DIR.fullmatch(p.name)),
                  key=lambda p: int(SEGMENT_DIR.fullmatch(p.name).group(1)))


def _anchor(pin: dict) -> bytes:
    return json.dumps({key: pin[key] for key in ("seq", "hash", "ts", "sig")},
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def archive(log_dir: str | Path, archive_dir: str | Path) -> dict:
    """Archive the live segment. Returns ``{"segment", "seq", "hash", "folder"}``. Raises ``AuditError``."""
    live, archive_root = Path(log_dir).resolve(), Path(archive_dir).resolve()
    if archive_root == live or live in archive_root.parents or archive_root in live.parents:
        raise AuditError("the archive must be outside the log folder")
    signer = load_signer(live)
    if signer is None:
        raise AuditError("only a signed log can be archived")
    archive_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = _segments(archive_root)
    with locked(live):
        log_empty = not read_bytes(live / LOG_NAME)
        if log_empty and not read_bytes(live / SEGMENT_NAME) and existing:
            # Finish an archive that stopped between emptying the log and writing the anchor.
            pin = json.loads((existing[-1] / "pin.json").read_text(encoding="ascii"))
            _write_atomically(live / SEGMENT_NAME, _anchor(pin))
            return {"segment": len(existing), "seq": pin["seq"], "hash": pin["hash"],
                    "folder": str(existing[-1]), "completed_earlier_run": True}
        if log_empty:
            raise AuditError("the live log is empty: nothing to archive")
    head = AuditLog(live, signer).head()  # re-checks the whole chain, signs the head
    pin = dict(head, public_key=signer.public_key.hex())
    number = int(SEGMENT_DIR.fullmatch(existing[-1].name).group(1)) + 1 if existing else 1
    folder = archive_root / f"segment-{number:06d}"
    check = AuditLog(live, None).verify()  # takes the lock itself; must not be called while holding it
    if not check.ok or check.entries == 0:
        raise AuditError("the log failed verification; nothing was moved")
    with locked(live):
        if AuditLog(live, None).last_seq() != pin["seq"]:
            raise AuditError("the log changed while archiving; nothing was moved, run it again")
        folder.mkdir(mode=0o700)
        for name in (LOG_NAME, CHECKPOINT_NAME, PUBLIC_KEY_NAME, SEGMENT_NAME):
            if (live / name).exists():
                shutil.copy2(live / name, folder / name)
        (folder / "pin.json").write_text(json.dumps(pin, sort_keys=True), encoding="ascii")
        _fsync_directory(folder)
        copied = verify_log(folder, pin, signer.public_key)
        if not copied.ok:
            shutil.rmtree(folder, ignore_errors=True)
            raise AuditError("the archived copy did not verify; nothing was moved")
        _write_atomically(live / CHECKPOINT_NAME, b"")
        _write_atomically(live / LOG_NAME, b"")
        _write_atomically(live / SEGMENT_NAME, _anchor(pin))
    return {"segment": number, "seq": pin["seq"], "hash": pin["hash"], "folder": str(folder)}
