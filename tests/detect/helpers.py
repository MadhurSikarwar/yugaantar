"""Builders for small synthetic event sets used by the detector tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from t4.detect.ingest import COLUMNS, events_to_csv, parse_approvals, parse_events

PRACTICE = Path(__file__).resolve().parent / "data" / "practice"
BASE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def ts(seconds: float) -> str:
    """UTC timestamp ``seconds`` after 09:00:00 on the practice day."""
    moment = BASE + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def row(event_id: str, at: float, *, delay: float = 0.1, offset_ms: int = 0, actor: str = "user-a",
        source: str = "portal", target: str = "catalog", action: str = "read", role: str = "viewer",
        role_after: str | None = None, outcome: str = "allow", approval_id: str = "",
        session: str = "sess-a", correlation: str = "flow-a") -> dict:
    """One event dict; ``at`` is the corrected time in seconds after 09:00."""
    raw = at + offset_ms / 1000
    return {
        "event_id": event_id,
        "event_time_utc": ts(raw),
        "received_time_utc": ts(at + delay),
        "source_clock_offset_ms": offset_ms,
        "actor": actor,
        "source_service": source,
        "target_service": target,
        "action": action,
        "role_before": role,
        "role_after": role if role_after is None else role_after,
        "outcome": outcome,
        "approval_id": approval_id,
        "session_id": session,
        "correlation_id": correlation,
    }


def events(*rows: dict):
    """Parse rows through the real CSV path so tests cover ingest too."""
    assert all(set(r) == set(COLUMNS) for r in rows)
    return parse_events(events_to_csv(rows))


def approvals(*changes: dict):
    return parse_approvals({"changes": list(changes)})


def grant(approval_id: str = "chg-1", subject: str = "user-a", role: str = "report-reader",
          start: float = 60, end: float = 420, approver: str = "user-admin",
          scope: tuple[str, ...] = ("reports",)) -> dict:
    return {"approval_id": approval_id, "approved_by": approver, "subject": subject,
            "operation": "grant_role", "role": role, "scope": list(scope),
            "valid_from_utc": ts(start).replace(".000Z", "Z"), "valid_until_utc": ts(end).replace(".000Z", "Z")}


def revoke(approval_id: str = "chg-2", subject: str = "user-a", role: str = "report-reader",
           at: float = 420, approver: str = "user-admin") -> dict:
    return {"approval_id": approval_id, "approved_by": approver, "subject": subject,
            "operation": "revoke_role", "role": role, "effective_at_utc": ts(at)}
