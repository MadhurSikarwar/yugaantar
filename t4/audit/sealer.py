"""Sign a quiet log's unsigned tail on a timer, even when no new entry arrives.

    python -m t4.audit.cli --dir <log dir> seal [--max-age 60]           # once
    python -m t4.audit.cli --dir <log dir> seal --watch [--max-age 60]   # keep running

Why: the log signs a checkpoint on entry 1, every 16th entry, and on an entry written 60 s or more
after the newest checkpoint. A log that goes quiet keeps its newest entries unsigned until the
next write. The judged adapter runs one process per request and cannot own a timer, so this
operator process is the lifecycle owner: it signs the tail once the newest checkpoint is older
than ``max_age`` (the whole chain is re-checked first, as ``head()`` always does), and when it is
stopped it signs any unsigned tail before exiting. It takes the same audit lock as every writer,
so it is safe beside a running service and beside ``archive``.
"""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Callable

from t4.audit.log import AuditLog, load_signer


def _age(ts: str, now: float) -> float:
    return now - datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def seal_if_due(directory: str | Path, max_age: float = 60.0, now: float | None = None,
                force: bool = False) -> dict | None:
    """Sign the head if entries after the newest checkpoint exist and that checkpoint is old enough
    (or ``force``). Returns the checkpoint written, or ``None`` when nothing needed signing."""
    signer = load_signer(directory)
    if signer is None:
        return None
    log = AuditLog(directory, signer)
    last = log.last_seq()
    newest = log._newest_checkpoint()
    anchor = log.anchor()
    signed_to = max(newest["seq"] if newest else 0, anchor["seq"] if anchor else 0)
    if last <= signed_to:
        return None  # nothing unsigned
    clock = time.time() if now is None else now
    if not force and newest is not None and _age(newest["ts"], clock) < max_age:
        return None
    return log.head()  # re-checks the whole chain, then signs


def watch(directory: str | Path, max_age: float = 60.0, *, poll: float | None = None,
          sleep: Callable[[float], None] = time.sleep, rounds: int | None = None) -> int:
    """Seal on a timer until stopped; sign any unsigned tail on the way out. Returns checkpoints written."""
    written = 0
    interval = poll if poll is not None else max(1.0, max_age / 4)
    try:
        count = 0
        while rounds is None or count < rounds:
            if seal_if_due(directory, max_age):
                written += 1
            count += 1
            sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        if seal_if_due(directory, max_age, force=True):  # graceful shutdown: leave nothing unsigned
            written += 1
    return written
