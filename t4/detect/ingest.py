"""Load access events and change approvals for the detector.

What it does
    Parses the practice event format (``events.csv``, the 14 columns listed in
    ``COLUMNS``) and the change-control file (``approvals.json``) into frozen
    dataclasses. Receipt order (row order) is kept as ``receipt_index``; the
    original timestamps are kept untouched, and the corrected event time is a
    derived value (``event_time_utc - source_clock_offset_ms``), so sorting a
    report never rewrites the source evidence.

What it defends against
    * Malformed input: wrong header, missing or extra columns, non-UTC or
      unparsable timestamps and non-integer offsets raise ``ValueError`` with
      the row number. The detector refuses to classify a file it cannot read
      exactly, instead of silently skipping rows an attacker could hide in.
    * Duplicate ``event_id`` values raise ``ValueError``: event IDs identify
      records, and two records with one ID would make every explanation
      ambiguous.
    * All values stay plain strings. Nothing is evaluated, and no field is used
      as a file path.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping

COLUMNS: tuple[str, ...] = (
    "event_id",
    "event_time_utc",
    "received_time_utc",
    "source_clock_offset_ms",
    "actor",
    "source_service",
    "target_service",
    "action",
    "role_before",
    "role_after",
    "outcome",
    "approval_id",
    "session_id",
    "correlation_id",
)

MAX_FIELD_CHARS = 4096
MAX_OFFSET_MS = 10**9  # about 11.6 days; larger values are not a clock offset
MAX_FILE_BYTES = 256 * 1024 * 1024


def parse_utc(value: str, *, field: str = "timestamp") -> datetime:
    """Parse an ISO 8601 UTC timestamp that ends in ``Z``.

    Raises ``ValueError`` for anything that is not an explicit UTC time.
    """
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field}: expected an ISO 8601 UTC time ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError(f"{field}: not an ISO 8601 time") from None
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field}: not UTC")
    return parsed.astimezone(timezone.utc)


def iso_z(moment: datetime) -> str:
    """Format a UTC datetime as ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


@dataclass(frozen=True)
class Event:
    """One access event, with its original fields and receipt position."""

    event_id: str
    event_time_utc: str
    received_time_utc: str
    source_clock_offset_ms: int
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str
    approval_id: str
    session_id: str
    correlation_id: str
    receipt_index: int
    event_time: datetime
    received_time: datetime

    @property
    def corrected_time(self) -> datetime:
        """Event time on the collector clock: source time minus known offset."""
        return self.event_time - timedelta(milliseconds=self.source_clock_offset_ms)

    @property
    def delivery_delay_ms(self) -> float:
        """Collector receipt time minus corrected event time, in milliseconds."""
        return (self.received_time - self.corrected_time) / timedelta(milliseconds=1)


@dataclass(frozen=True)
class Approval:
    """One change-control record from ``approvals.json``."""

    approval_id: str
    approved_by: str
    subject: str
    operation: str
    role: str
    scope: tuple[str, ...]
    valid_from: datetime | None
    valid_until: datetime | None  # exclusive
    effective_at: datetime | None

    def valid_at(self, moment: datetime) -> bool:
        """True if ``moment`` is inside ``[valid_from, valid_until)``."""
        if self.valid_from is None or self.valid_until is None:
            return False
        return self.valid_from <= moment < self.valid_until


def _event_from_row(row: Mapping[str, str], index: int, line: int) -> Event:
    for name in COLUMNS:
        value = row.get(name)
        if value is None:
            raise ValueError(f"row {line}: missing column {name}")
        if len(value) > MAX_FIELD_CHARS:
            raise ValueError(f"row {line}: {name} is too long")
    if not row["event_id"]:
        raise ValueError(f"row {line}: empty event_id")
    try:
        offset = int(row["source_clock_offset_ms"].strip())
    except ValueError:
        raise ValueError(f"row {line}: source_clock_offset_ms is not an integer") from None
    if abs(offset) > MAX_OFFSET_MS:
        raise ValueError(f"row {line}: source_clock_offset_ms is out of range")
    return Event(
        event_id=row["event_id"],
        event_time_utc=row["event_time_utc"],
        received_time_utc=row["received_time_utc"],
        source_clock_offset_ms=offset,
        actor=row["actor"],
        source_service=row["source_service"],
        target_service=row["target_service"],
        action=row["action"],
        role_before=row["role_before"],
        role_after=row["role_after"],
        outcome=row["outcome"],
        approval_id=row["approval_id"],
        session_id=row["session_id"],
        correlation_id=row["correlation_id"],
        receipt_index=index,
        event_time=parse_utc(row["event_time_utc"], field=f"row {line}: event_time_utc"),
        received_time=parse_utc(row["received_time_utc"], field=f"row {line}: received_time_utc"),
    )


def parse_events(text: str) -> list[Event]:
    """Parse events CSV text. Row order is receipt order."""
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError("events: empty file") from None
    except csv.Error:
        raise ValueError("events: unreadable header") from None
    if tuple(h.strip() for h in header) != COLUMNS:
        raise ValueError("events: header does not match the expected columns")
    events: list[Event] = []
    seen: set[str] = set()
    try:
        for cells in reader:
            line = reader.line_num
            if not cells or cells == [""]:
                continue
            if len(cells) != len(COLUMNS):
                raise ValueError(f"row {line}: expected {len(COLUMNS)} columns, got {len(cells)}")
            event = _event_from_row(dict(zip(COLUMNS, cells)), len(events), line)
            if event.event_id in seen:
                raise ValueError(f"row {line}: duplicate event_id")
            seen.add(event.event_id)
            events.append(event)
    except csv.Error:
        raise ValueError(f"events: malformed CSV near row {reader.line_num}") from None
    return events


def _read_text(path: Path) -> str:
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path.name}: file too large")
    return path.read_text(encoding="utf-8-sig")


def load_events(path: Path) -> list[Event]:
    """Load ``events.csv`` from disk."""
    return parse_events(_read_text(path))


def _opt_time(raw: Mapping, key: str, approval_id: str) -> datetime | None:
    value = raw.get(key)
    if value is None:
        return None
    return parse_utc(value, field=f"approval {approval_id}: {key}")


def parse_approvals(obj: object) -> dict[str, Approval]:
    """Parse the decoded ``approvals.json`` object into approvals keyed by ID."""
    if not isinstance(obj, dict) or not isinstance(obj.get("changes"), list):
        raise ValueError("approvals: expected an object with a 'changes' list")
    out: dict[str, Approval] = {}
    for raw in obj["changes"]:
        if not isinstance(raw, dict):
            raise ValueError("approvals: each change must be an object")
        approval_id = raw.get("approval_id")
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("approvals: missing approval_id")
        if approval_id in out:
            raise ValueError(f"approvals: duplicate approval_id {approval_id}")
        for key in ("approved_by", "subject", "operation", "role"):
            if not isinstance(raw.get(key), str):
                raise ValueError(f"approval {approval_id}: {key} must be a string")
        scope = raw.get("scope", [])
        if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
            raise ValueError(f"approval {approval_id}: scope must be a list of strings")
        out[approval_id] = Approval(
            approval_id=approval_id,
            approved_by=raw["approved_by"],
            subject=raw["subject"],
            operation=raw["operation"],
            role=raw["role"],
            scope=tuple(scope),
            valid_from=_opt_time(raw, "valid_from_utc", approval_id),
            valid_until=_opt_time(raw, "valid_until_utc", approval_id),
            effective_at=_opt_time(raw, "effective_at_utc", approval_id),
        )
    return out


def load_approvals(path: Path) -> dict[str, Approval]:
    """Load ``approvals.json`` from disk."""
    try:
        obj = json.loads(_read_text(path))
    except json.JSONDecodeError:
        raise ValueError("approvals: not valid JSON") from None
    return parse_approvals(obj)


def load_labels(path: Path) -> dict[str, str]:
    """Load ``labels.csv`` (``event_id,label,reason``) as ``{event_id: label}``.

    Used only by evaluation, never by detection.
    """
    reader = csv.DictReader(io.StringIO(_read_text(path), newline=""))
    if reader.fieldnames is None or not {"event_id", "label"} <= set(reader.fieldnames):
        raise ValueError("labels: expected columns event_id,label")
    labels: dict[str, str] = {}
    for row in reader:
        if row["event_id"] in labels:
            raise ValueError(f"labels: duplicate event_id {row['event_id']}")
        labels[row["event_id"]] = row["label"]
    return labels


def events_to_csv(events: Iterable[Mapping[str, object]]) -> str:
    """Write event dicts (keys = ``COLUMNS``) as events CSV text."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for event in events:
        writer.writerow([str(event.get(name, "")) for name in COLUMNS])
    return buffer.getvalue()
