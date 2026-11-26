"""Record that the audit log itself can no longer be trusted.

The alert cannot go into the damaged log, so it goes into a second signed log in
``<state dir>/alerts``, read with ``python -m t4.audit.cli --dir <that folder> alerts``.
One alert is written per distinct damaged condition, however many requests then fail, so a
caller cannot use the failure to grow this log.

Limit: it sits in the same state directory. Whoever can delete the audit log can delete this
too; it is evidence for damage and careless tampering, not a trust anchor.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

ALERT_SUBDIR = "alerts"
RULE_AUDIT_INTEGRITY = "AUD-LOG-INTEGRITY-FAILURE"


def record_audit_failure(state_dir: Path, audit_dir: Path, reason: str) -> bool:
    """Best effort. Returns True if the alert is on disk. Never raises."""
    try:
        from t4.audit.log import AuditLog, load_or_create_signer

        seen = hashlib.sha256(reason.encode("utf-8", "replace"))
        for name in ("audit.jsonl", "checkpoints.jsonl"):
            try:
                seen.update(hashlib.sha256((audit_dir / name).read_bytes()).digest())
            except FileNotFoundError:
                seen.update(b"missing")
        folder = state_dir / ALERT_SUBDIR
        log = AuditLog(folder, load_or_create_signer(folder), checkpoint_every=1)
        log.append_once(
            actor="", action="alert", target="audit-log", decision="alert",
            rule=RULE_AUDIT_INTEGRITY, request_id="integrity-" + seen.hexdigest()[:32],
            detail={"explanation": "The audit log failed its integrity check. Requests that need "
                                   "it are refused until it is repaired. Reason: " + reason[:200],
                    "entries": "[]", "request_ids": "[]"})
        return True
    except Exception:  # noqa: BLE001 - reporting must never change an outcome
        return False
