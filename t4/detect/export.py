"""Alerts from our own access logs (M-C11, official mission requirement).

What it does
    1. Verifies every input log with the audit verifier (hash chain, signed
       checkpoints and, if supplied, a pinned head and public key). If any log
       fails verification, nothing is exported: the detector never reasons
       over a log that may have been altered.
    2. Converts the entries to the detector's event format:

       * node log entries for requests (``action`` in ``request_actions``,
         decision ``allow``/``deny``): the entry ``ts`` becomes both event and
         received time with zero offset; ``detail.device_id`` becomes the
         session; the target service is ``<node_id>/<asset>`` so an alert names
         the node *and* the file reached;
       * key-event log entries (authority): a permission grant becomes a role
         change ``user -> read:<asset>`` for the grant's subject, carrying the
         grant's ``approval_id``; removing a grant is the reverse change; other
         key events (enrol, rotate, revoke) become routine administration
         events.

       Reads are given the role ``read:<asset>`` while the actor holds a grant
       for that asset, else ``user``. The baseline of expected targets is the
       node provisioning (asset owners) when supplied, otherwise the targets
       each actor was allowed to read in the exported window.
    3. Runs the detector with the change register (``approvals.json`` format;
       an approval's ``role`` is ``read:<asset>`` and its ``scope`` lists
       ``<node_id>/<asset>`` targets) and appends each new alert to the chosen
       audit log with ``AuditLog.alert`` (rule, explanation, identity,
       services, event IDs, and the request IDs of the cited entries). Alerts
       already present (same ``alert_id``) are not appended twice.

What it defends against
    * Reasoning over tampered evidence: verification is a precondition.
    * Silent privilege grants: a grant with no valid approval raises
      ``DET-UNAPPROVED-ROLE-CHANGE``; its next use raises a review alert.
    * Probing across nodes: one actor denied on several unexpected node/file
      targets within W raises ``DET-LATERAL-MOVEMENT``.

Limits
    A learned baseline (no provisioning supplied) treats anything an actor was
    allowed to read in the window as expected. Verification proves a log is
    consistent with its checkpoints and pins; without a pin, a party who can
    rewrite a whole log directory can rebuild it (see the threat model).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from . import engine
from .config import DEFAULT_CONFIG, DetectConfig
from .ingest import MAX_FIELD_CHARS, Approval, events_to_csv, parse_events

GRANT_ACTIONS = frozenset({"grant", "grant_read"})
UNGRANT_ACTIONS = frozenset({"ungrant", "revoke_grant", "remove_grant"})
NO_ROLE = "user"
AUTHORITY_SERVICE = "authority"
UNVERIFIED_ACTOR = "(unverified)"
# One shared session for every request that did not prove its actor: the claimed device_id is
# attacker-chosen, so grouping by it would let a prober avoid movement chaining by changing it.
UNVERIFIED_SESSION = "(unverified)"
# Key events other than grants are routine administration by the authority.
ADMIN_ACTIONS = frozenset({"enroll", "rotate", "revoke_device", "revoke_actor"})
LOG_SUBDIR = "log"
# Node rules meaning "valid signature, but not sent by its signer to this node
# at this time": attributing these to the signer would let anyone who captures
# one request frame its signer (c3-to-c4-002).
NOT_FROM_SIGNER_RULES = frozenset({"NODE-WRONG-NODE", "NODE-REPLAY", "NODE-EXPIRED",
                                   "NODE-KEY-INACTIVE"})
# The node checks `actor == device owner` only AFTER the wrong-node and revoked-device/actor
# checks. A request denied at one of these rules (or at the owner check itself) proves the
# signature, not that the claimed actor is the signer's owner, so the actor name must not be
# attributed: a rogue enrolled device can name any victim (SA-006).
ACTOR_UNPROVEN_RULES = frozenset({"NODE-DEVICE-REVOKED", "NODE-ACTOR-REVOKED", "NODE-OWNER-MISMATCH"})


class ExportError(Exception):
    """A log could not be verified or read; nothing was exported."""


@dataclass(frozen=True)
class LogSource:
    """One audit log directory to export."""

    directory: Path
    kind: str  # "node" or "authority"
    name: str  # node ID (fallback when entries carry no node_id) or "authority"
    pinned_head: Mapping | None = None
    pinned_public_key: bytes | None = None


@dataclass
class Export:
    """The converted events, the detector result and the alerts appended."""

    rows: list[dict]
    result: engine.Result
    config: DetectConfig
    verified: list[dict] = field(default_factory=list)
    appended: list[str] = field(default_factory=list)
    request_ids: dict[str, str] = field(default_factory=dict)  # event_id -> request_id

    def csv(self) -> str:
        """The exported events in the practice CSV format."""
        return events_to_csv(self.rows)


def fit_field(value: str, limit: int = MAX_FIELD_CHARS) -> str:
    """Make ``value`` fit the detector's field limit without losing distinctness.

    Identifiers are opaque and may be up to 4 KiB, and the export adds
    prefixes (``claimed:``, ``<node_id>/``), so a converted field can exceed
    the limit. Over-long values become a readable prefix plus the SHA-256 of
    the whole value: deterministic, so grouping still works, and two
    different values never collapse into one. (c5-to-c4-002)
    """
    if len(value) <= limit:
        return value
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    suffix = f"…sha256:{digest}"
    return value[: limit - len(suffix)] + suffix


def _fit_row(row: dict) -> dict:
    return {key: fit_field(value) if isinstance(value, str) else value for key, value in row.items()}


def read_role(asset: str) -> str:
    """Role name a grant for ``asset`` confers."""
    return f"read:{asset}"


def log_directory(path: Path) -> Path:
    """Accept a node or authority directory (log in ``<dir>/log``) or the log itself."""
    path = Path(path)
    return path / LOG_SUBDIR if (path / LOG_SUBDIR / "audit.jsonl").exists() else path


def verify_sources(sources: Sequence[LogSource]) -> list[dict]:
    """Verify every log; raise ``ExportError`` naming the first that fails."""
    from t4.audit.verify import verify_log

    reports = []
    for source in sources:
        report = verify_log(log_directory(source.directory), dict(source.pinned_head) if source.pinned_head else None,
                            source.pinned_public_key)
        summary = {"log": source.name, "kind": source.kind, "ok": report.ok, "entries": report.entries,
                   "covered_seq": report.covered_seq, "head_pinned": report.head_pinned,
                   "key_pinned": report.key_pinned}
        reports.append(summary)
        if not report.ok:
            raise ExportError(f"log {source.name} failed verification at entry {report.first_bad_seq}: "
                              f"{'; '.join(report.errors[:3])}")
    return reports


def _read_entries(source: LogSource) -> list[dict]:
    from t4.audit.log import AuditError, AuditLog

    try:
        return AuditLog(log_directory(source.directory), None).entries()
    except AuditError as exc:
        raise ExportError(f"log {source.name} could not be read: {exc}") from None


def _detail(entry: Mapping, key: str, default: str = "") -> str:
    value = entry.get("detail", {}).get(key, default)
    return value if isinstance(value, str) else str(value)


def convert(node_logs: Mapping[str, Sequence[dict]], key_events: Sequence[dict],
            request_actions: Iterable[str] = ("read",)) -> tuple[list[dict], dict[str, str]]:
    """Map verified log entries to detector event rows, in timestamp order.

    Returns the rows and a map from event ID to the entry's request ID.
    """
    request_actions = frozenset(request_actions)
    staged: list[tuple[str, int, int, dict, str]] = []
    for order, entry in enumerate(key_events):
        staged.append((entry["ts"], 0, order, {"kind": "key", "entry": entry}, AUTHORITY_SERVICE))
    for node_index, (node_name, entries) in enumerate(sorted(node_logs.items()), start=1):
        for entry in entries:
            if entry.get("action") not in request_actions or entry.get("decision") not in ("allow", "deny"):
                continue
            staged.append((entry["ts"], node_index, entry["seq"], {"kind": "node", "entry": entry}, node_name))
    staged.sort(key=lambda item: (item[0], item[1], item[2]))

    grants: dict[tuple[str, str], bool] = {}
    rows: list[dict] = []
    request_ids: dict[str, str] = {}
    for ts, _, _, item, log_name in staged:
        entry = item["entry"]
        if item["kind"] == "key":
            event_id = f"{AUTHORITY_SERVICE}#{entry['seq']}"
            action = entry["action"]
            asset = entry["target"]
            subject = _detail(entry, "subject") or entry["actor"]
            base = {
                "event_id": event_id, "event_time_utc": ts, "received_time_utc": ts,
                "source_clock_offset_ms": 0, "source_service": AUTHORITY_SERVICE,
                "target_service": "identity", "approval_id": _detail(entry, "approval_id"),
                "session_id": f"{AUTHORITY_SERVICE}:{entry['actor']}",
                "correlation_id": entry.get("request_id", ""),
                "outcome": "success" if entry["decision"] in ("allow", "success", "ok") else "deny",
            }
            if action in GRANT_ACTIONS:
                rows.append({**base, "actor": subject, "action": "role_change",
                             "role_before": NO_ROLE, "role_after": read_role(asset)})
                if base["outcome"] == "success":
                    grants[(subject, asset)] = True
            elif action in UNGRANT_ACTIONS:
                rows.append({**base, "actor": subject, "action": "role_change",
                             "role_before": read_role(asset), "role_after": NO_ROLE})
                if base["outcome"] == "success":
                    grants.pop((subject, asset), None)
            else:
                rows.append({**base, "actor": entry["actor"], "action": action,
                             "role_before": NO_ROLE, "role_after": NO_ROLE, "approval_id": ""})
        else:
            node_id = _detail(entry, "node_id") or log_name
            asset = entry["target"]
            event_id = f"{node_id}#{entry['seq']}"
            device = _detail(entry, "device_id") or "no-device"
            verified = entry.get("detail", {}).get("signature_verified") is True
            if verified and (entry.get("rule") in NOT_FROM_SIGNER_RULES
                             or entry.get("rule") in ACTOR_UNPROVEN_RULES):
                # A genuine signature reused where or when its signer did not
                # send it (captured and forwarded to another node, replayed,
                # or delayed past the window). The node denied it; it proves
                # nothing about the signer's own behaviour, so it must not
                # make the signer look like they probed several nodes.
                actor, source = UNVERIFIED_ACTOR, f"forwarded:{entry['actor']}"
            elif verified:
                actor, source = entry["actor"], f"device:{device}"
            else:
                # The actor name is only a claim: never count it as that
                # actor's activity, or anyone could get an innocent actor
                # flagged. Unproven requests are grouped under one identity
                # (session = claimed device) so probing is still visible.
                actor, source = UNVERIFIED_ACTOR, f"claimed:{entry['actor']}"
            role = read_role(asset) if grants.get((actor, asset)) else NO_ROLE
            rows.append({
                "event_id": event_id, "event_time_utc": ts, "received_time_utc": ts,
                "source_clock_offset_ms": 0, "actor": actor, "source_service": source,
                "target_service": f"{node_id}/{asset}", "action": entry["action"],
                "role_before": role, "role_after": role, "outcome": entry["decision"],
                "approval_id": "", "session_id": device if actor != UNVERIFIED_ACTOR else UNVERIFIED_SESSION,
                "correlation_id": entry.get("request_id", ""),
            })
        request_ids[event_id] = entry.get("request_id", "")
    rows = [_fit_row(row) for row in rows]
    return rows, request_ids


def baseline_from_owners(owners: Mapping[str, Mapping[str, str]]) -> dict[str, frozenset[str]]:
    """``{node_id: {asset: owner}}`` -> ``{actor: {"node/asset", ...}}``."""
    out: dict[str, set[str]] = {}
    for node_id, assets in owners.items():
        for asset, owner in assets.items():
            out.setdefault(fit_field(owner), set()).add(fit_field(f"{node_id}/{asset}"))
    return {actor: frozenset(targets) for actor, targets in out.items()}


def baseline_from_rows(rows: Sequence[Mapping]) -> dict[str, frozenset[str]]:
    """Targets each actor was allowed to read in the window (learned baseline)."""
    out: dict[str, set[str]] = {}
    for r in rows:
        if r["outcome"] == "allow" and r["source_service"] != AUTHORITY_SERVICE and r["role_before"] == NO_ROLE:
            out.setdefault(r["actor"], set()).add(r["target_service"])
    return {actor: frozenset(targets) for actor, targets in out.items()}


def export_config(baseline: Mapping[str, frozenset[str]], approvers: Iterable[str] | None = None,
                  base: DetectConfig = DEFAULT_CONFIG) -> DetectConfig:
    """Detector config for our own logs: per-actor baseline, no fixed role scopes."""
    return replace(
        base,
        baseline=dict(baseline),
        role_scope={NO_ROLE: frozenset()},
        role_rank={NO_ROLE: 0},
        # Enrol, rotate and revoke are expected authority actions, not edges.
        session_actions=base.session_actions | ADMIN_ACTIONS,
        authorized_approvers=frozenset(approvers) if approvers is not None else base.authorized_approvers,
        review_same_session=False,
    )


def run_export(sources: Sequence[LogSource], approvals: Mapping[str, Approval], *,
               owners: Mapping[str, Mapping[str, str]] | None = None,
               approvers: Iterable[str] | None = None,
               alert_log: Path | None = None,
               request_actions: Iterable[str] = ("read",)) -> Export:
    """Verify, convert, detect and (optionally) append alerts to ``alert_log``."""
    verified = verify_sources(sources)
    node_logs: dict[str, list[dict]] = {}
    key_events: list[dict] = []
    for source in sources:
        entries = _read_entries(source)
        if source.kind == "authority":
            key_events.extend(entries)
        elif source.kind == "node":
            node_logs[source.name] = entries
        else:
            raise ExportError(f"unknown log kind {source.kind!r}")
    rows, request_ids = convert(node_logs, key_events, request_actions)
    baseline = baseline_from_owners(owners) if owners is not None else baseline_from_rows(rows)
    cfg = export_config(baseline, approvers)
    result = engine.analyze(parse_events(events_to_csv(rows)), approvals, cfg)
    export = Export(rows=rows, result=result, config=cfg, verified=verified, request_ids=request_ids)
    if alert_log is not None:
        export.appended = append_alerts(alert_log, result.alerts, request_ids)
    return export


def append_alerts(directory: Path, alerts: Sequence[engine.Alert], request_ids: Mapping[str, str]) -> list[str]:
    """Append alerts not already in the log; return the IDs appended."""
    from t4.audit.log import AuditError, AuditLog, load_signer

    try:
        directory = log_directory(directory)
        log = AuditLog(directory, load_signer(directory))
        present = {e["detail"].get("alert_id") for e in log.alerts()}
        appended = []
        for alert in alerts:
            if alert.alert_id in present:
                continue
            log.alert(
                rule=alert.rule,
                explanation=alert.explanation,
                actor=alert.identity,
                target=",".join(alert.services),
                request_ids=[request_ids.get(e, "") for e in alert.event_ids if request_ids.get(e)],
                detail={
                    "alert_id": alert.alert_id,
                    "severity": alert.severity,
                    "event_ids": json.dumps(list(alert.event_ids)),
                    "services": json.dumps(list(alert.services)),
                    "emitted_at": alert.emitted_at,
                    "order_uncertain": alert.order_uncertain,
                    "source": "t4.detect.export",
                },
            )
            appended.append(alert.alert_id)
        return appended
    except AuditError as exc:
        raise ExportError(f"alerts could not be appended: {exc}") from None
