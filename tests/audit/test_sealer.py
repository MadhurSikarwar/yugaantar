"""A quiet log's unsigned tail is signed on a timer and on shutdown (t4.audit.sealer)."""
from __future__ import annotations

import json

from t4.audit.archive import archive
from t4.audit.log import AuditLog, load_or_create_signer
from t4.audit.sealer import seal_if_due, watch
from t4.audit.verify import verify_log


def _seqs(folder):
    return [json.loads(line)["seq"] for line in (folder / "checkpoints.jsonl").read_text().splitlines()]


def _log(folder, stamps=None):
    clock = iter(stamps).__next__ if stamps else None
    kwargs = {"clock": clock} if clock else {}
    return AuditLog(folder, load_or_create_signer(folder), checkpoint_seconds=None, **kwargs)


def _add(log, n):
    for i in range(n):
        log.append(actor="u", action="read", target="x", decision="allow", rule="R", request_id=f"r{i}")


def test_a_quiet_tail_is_signed_once_the_newest_checkpoint_is_old(tmp_path):
    folder = tmp_path / "log"
    _add(_log(folder), 2)
    assert _seqs(folder) == [1]  # entry 2 is unsigned and nothing else is coming
    newest_ts = json.loads((folder / "checkpoints.jsonl").read_text().splitlines()[-1])["ts"]
    from datetime import datetime

    written_at = datetime.fromisoformat(newest_ts.replace("Z", "+00:00")).timestamp()
    assert seal_if_due(folder, 60, now=written_at + 30) is None  # not old enough yet
    assert seal_if_due(folder, 60, now=written_at + 600)["seq"] == 2  # ten minutes later
    assert seal_if_due(folder, 60, now=written_at + 1200) is None  # nothing unsigned any more
    assert verify_log(folder).covered_seq == 2


def test_watch_signs_the_tail_on_shutdown(tmp_path):
    folder = tmp_path / "log"
    _add(_log(folder), 3)
    assert _seqs(folder) == [1]
    assert watch(folder, max_age=3600, poll=0, sleep=lambda s: None, rounds=2) == 1
    assert _seqs(folder)[-1] == 3


def test_sealing_after_an_archive_and_an_empty_tail(tmp_path):
    folder = tmp_path / "log"
    _add(_log(folder), 2)
    archive(folder, tmp_path / "archive")
    assert seal_if_due(folder, 0, force=True) is None  # nothing unsigned after the anchor
    _add(_log(folder), 1)
    assert seal_if_due(folder, 0, force=True) is None or verify_log(folder).ok
