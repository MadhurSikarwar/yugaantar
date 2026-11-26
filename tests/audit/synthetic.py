"""Build large, valid, signed audit logs quickly, for tests and measurements.

``AuditLog.append`` fsyncs every entry, which is right for the service and far too slow to make a
10 MB log. This writes the same on-disk format directly (canonical JSON lines, the real hash chain,
real ML-DSA checkpoint signatures from the log's own key) in a few seconds. Synthetic data only.
"""
from __future__ import annotations

from pathlib import Path

from t4.audit.log import (
    CHECKPOINT_NAME,
    GENESIS_HASH,
    LOG_NAME,
    canonical,
    checkpoint_message,
    entry_hash,
    load_or_create_signer,
)


def build_log(directory: Path, entries: int, *, checkpoint_every: int = 16, pad: int = 0,
              start_seq: int = 0, previous: str = GENESIS_HASH) -> tuple[int, str]:
    """Write ``entries`` more entries to ``directory`` and return the new ``(seq, head hash)``.

    Call again with the returned values to extend a log. ``pad`` adds that many bytes of filler to
    each entry's detail so a log reaches a target size with fewer entries.
    """
    directory.mkdir(parents=True, exist_ok=True)
    signer = load_or_create_signer(directory)
    seq, head = start_seq, previous
    filler = "x" * pad
    log_lines: list[bytes] = []
    checkpoint_lines: list[bytes] = []
    for _ in range(entries):
        seq += 1
        entry = {
            "actor": f"actor-{seq % 7}", "action": "read", "target": f"asset-{seq % 11}",
            "decision": "allow" if seq % 5 else "deny", "rule": "POL-ALLOW-OWNER",
            "request_id": f"req-{seq}", "seq": seq, "ts": "2026-01-01T00:00:00.000Z",
            "detail": {"generation": 1, "epoch": 0, "reason": "synthetic", "pad": filler},
        }
        entry["hash"] = entry_hash(entry, head)
        head = entry["hash"]
        log_lines.append(canonical(entry) + b"\n")
        if seq % checkpoint_every == 0:
            ts = "2026-01-01T00:00:00.000Z"
            signature = signer.sign(checkpoint_message(seq, head, ts)).hex()
            checkpoint_lines.append(canonical({"seq": seq, "hash": head, "ts": ts, "sig": signature}) + b"\n")
    with (directory / LOG_NAME).open("ab") as handle:
        handle.write(b"".join(log_lines))
    if checkpoint_lines:
        with (directory / CHECKPOINT_NAME).open("ab") as handle:
            handle.write(b"".join(checkpoint_lines))
    return seq, head
