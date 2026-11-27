"""Detector engine: label every event and raise explainable alerts.

What it does
    ``analyze(events, approvals, cfg)`` gives every event exactly one of the
    nine practice labels, with the rule ID and a plain-language reason, and
    returns the alerts an operator should review. ``run(...)`` returns only the
    alerts. Rules are applied in a fixed priority:

    1. approval administration events (approve/revoke) -> ``approved_change``,
       or ``unexpected_role_change`` if the approval or approver is invalid;
    2. successful role changes -> ``approved_change`` if an approval matches,
       else ``unexpected_role_change`` (alert ``DET-UNAPPROVED-ROLE-CHANGE``);
    3. the next allowed action in the same session using the unapproved role
       -> ``review_after_role_change`` (alert ``DET-REVIEW-AFTER-ROLE-CHANGE``);
    4. denials after an effective revocation -> ``routine_denial``;
       unexpected service edges chained by actor and session across at least
       N services within W -> ``lateral_movement_candidate`` (alert
       ``DET-LATERAL-MOVEMENT``); any other denial -> ``isolated_denial``;
       a lone allowed unexpected edge -> ``routine`` plus a
       ``DET-UNEXPECTED-EDGE`` alert: high if the access had been revoked,
       medium if its approval had ended, otherwise low;
    5. everything else -> ``routine_delayed_delivery`` (delay above the
       threshold), ``routine_clock_offset`` (non-zero known offset) or
       ``routine``.

    ``emitted_at`` is the collector receipt time of the event that triggers
    the alert: the time a streaming detector reading events in receipt order
    could have raised it.

What it defends against
    Unapproved privilege escalation, use of escalated privilege, and lateral
    movement across services, while keeping routine administration, delayed
    delivery, clock offsets and lone denials out of the alert queue.
    Detection is rules and statistics only: no learned model.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from . import rules
from .config import DEFAULT_CONFIG, DetectConfig
from .ingest import COLUMNS, Approval, Event, iso_z

LABELS: tuple[str, ...] = (
    "routine",
    "approved_change",
    "unexpected_role_change",
    "review_after_role_change",
    "lateral_movement_candidate",
    "routine_delayed_delivery",
    "routine_clock_offset",
    "routine_denial",
    "isolated_denial",
)
SUSPICIOUS_LABELS: frozenset[str] = frozenset(
    {"unexpected_role_change", "review_after_role_change", "lateral_movement_candidate"}
)


@dataclass(frozen=True)
class Alert:
    """An operator-facing alert."""

    alert_id: str
    rule: str
    severity: str
    identity: str
    services: tuple[str, ...]
    event_ids: tuple[str, ...]
    emitted_at: str
    explanation: str
    order_uncertain: bool

    def to_dict(self) -> dict:
        """JSON-ready form."""
        return {
            "alert_id": self.alert_id,
            "rule": self.rule,
            "severity": self.severity,
            "identity": self.identity,
            "services": list(self.services),
            "event_ids": list(self.event_ids),
            "emitted_at": self.emitted_at,
            "explanation": self.explanation,
            "order_uncertain": self.order_uncertain,
        }


@dataclass(frozen=True)
class Classification:
    """The label given to one event, with the rule and reason behind it."""

    label: str
    rule: str
    reason: str


@dataclass
class Result:
    """Everything the engine decided about one batch of events."""

    events: list[Event]
    labels: dict[str, Classification]
    alerts: list[Alert]
    order_uncertain: set[str] = field(default_factory=set)

    def predicted(self) -> dict[str, str]:
        """``{event_id: label}`` for evaluation."""
        return {event_id: c.label for event_id, c in self.labels.items()}


def _alert(rule: str, severity: str, trigger: Event, events: Sequence[Event],
           explanation: str, cfg: DetectConfig, evidence: Sequence[Event] = ()) -> Alert:
    """``evidence`` are events the alert cannot be raised without: it is emitted no earlier than
    the latest of their receipt times (out-of-order delivery can bring the trigger first)."""
    ordered = sorted(events, key=lambda e: (e.corrected_time, e.receipt_index))
    ids = tuple(dict.fromkeys(e.event_id for e in ordered))
    services: list[str] = []
    for event in ordered:
        if event.target_service not in services:
            services.append(event.target_service)
    digest = hashlib.sha256("\x1f".join((rule,) + ids).encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return Alert(
        alert_id=f"ALR-{digest}",
        rule=rule,
        severity=severity,
        identity=trigger.actor,
        services=tuple(services),
        event_ids=ids,
        emitted_at=iso_z(max(e.received_time for e in (trigger, *evidence))),
        explanation=explanation,
        order_uncertain=rules.pair_uncertain(ordered, cfg),
    )


def _conflict_explanation(event: Event) -> str:
    def short(value: object) -> str:
        text = repr(value)
        return text if len(text) <= 80 else text[:77] + "..."

    copies = []
    for other in event.conflicting[:3]:
        changed = [f"{name} {short(getattr(event, name))} -> {short(getattr(other, name))}"
                   for name in COLUMNS if name != "received_time_utc"
                   and getattr(event, name) != getattr(other, name)]
        copies.append("; ".join(changed))
    return (f"Event ID {event.event_id} arrived again with different content "
            f"({event.conflict_count} differing version(s)). Only the first record, by {event.actor}, "
            "was analysed by the other rules. Either version could be the false one: check the source. "
            "Differences (first -> later): " + " | ".join(copies))


@dataclass
class _PendingReview:
    change: Event
    remaining: int | None  # None: every follow-up


def analyze(events: Iterable[Event], approvals: Mapping[str, Approval],
            cfg: DetectConfig = DEFAULT_CONFIG) -> Result:
    """Label every event and collect alerts. Events must be in receipt order."""
    events = list(events)
    labels: dict[str, Classification] = {}
    alerts: list[Alert] = []
    pending: list[_PendingReview] = []

    def put(event: Event, label: str, rule: str, reason: str) -> None:
        labels[event.event_id] = Classification(label, rule, reason)

    # Steps 1 and 2: approval administration and role changes.
    for event in events:
        if event.action in cfg.approval_actions:
            check = rules.check_approval_action(event, approvals, cfg)
            if check.ok:
                put(event, "approved_change", "DET-APPROVED-CHANGE", check.reason)
            else:
                put(event, "unexpected_role_change", "DET-UNAUTHORIZED-APPROVAL", check.reason)
                alerts.append(_alert(
                    "DET-UNAUTHORIZED-APPROVAL", "high", event, [event],
                    f"{event.actor} ran {event.action} at {iso_z(event.corrected_time)}, but {check.reason}.",
                    cfg))
            continue
        if event.role_before == event.role_after or event.outcome not in cfg.allow_outcomes:
            continue
        if cfg.is_increase(event.role_before, event.role_after):
            check = rules.match_grant(event, approvals, cfg)
            if check.ok:
                put(event, "approved_change", "DET-APPROVED-CHANGE", check.reason)
            else:
                put(event, "unexpected_role_change", "DET-UNAPPROVED-ROLE-CHANGE", check.reason)
                alerts.append(_alert(
                    "DET-UNAPPROVED-ROLE-CHANGE", "high", event, [event],
                    f"{event.actor} changed role {event.role_before} -> {event.role_after} at "
                    f"{iso_z(event.corrected_time)} in session {event.session_id}: {check.reason}. "
                    "This records that the change happened; it does not show how or why.",
                    cfg))
                pending.append(_PendingReview(event, cfg.review_followups))
        else:
            revoke = rules.match_revoke(event, approvals, cfg)
            if revoke is not None:
                put(event, "approved_change", "DET-APPROVED-CHANGE",
                    f"{event.actor} {event.role_before} -> {event.role_after} follows {revoke.approval_id}")
            else:
                put(event, "routine", "DET-ROLE-DECREASE",
                    f"{event.actor} {event.role_before} -> {event.role_after} lowers privilege")

    # Step 3: follow-up use of an unapproved role, until the actor's role changes again.
    by_actor: dict[str, list[Event]] = {}
    for event in events:
        by_actor.setdefault(event.actor, []).append(event)
    for review in pending:
        change = review.change
        after = (change.corrected_time, change.receipt_index)
        later_changes = [(e.corrected_time, e.receipt_index) for e in by_actor[change.actor]
                         if e.role_before != e.role_after and e.outcome in cfg.allow_outcomes
                         and (e.corrected_time, e.receipt_index) > after]
        until = min(later_changes) if later_changes else None
        followups = sorted(
            (e for e in by_actor[change.actor]
             if e.event_id not in labels
             and (e.session_id == change.session_id or not cfg.review_same_session)
             and e.role_before == change.role_after
             and e.outcome in cfg.allow_outcomes
             and (e.corrected_time, e.receipt_index) > after
             and (until is None or (e.corrected_time, e.receipt_index) < until)),
            key=lambda e: (e.corrected_time, e.receipt_index),
        )
        for event in followups[: review.remaining]:
            reason = (f"allowed {event.action} on {event.target_service} with role {event.role_before} "
                      f"follows unapproved role change {change.event_id} in session {event.session_id}")
            put(event, "review_after_role_change", "DET-REVIEW-AFTER-ROLE-CHANGE", reason)
            alerts.append(_alert(
                "DET-REVIEW-AFTER-ROLE-CHANGE", "medium", event, [change, event],
                f"{event.actor} used role {event.role_before} ({event.action} on {event.target_service}, "
                f"{event.outcome}) after the unapproved change in {change.event_id}. Review this access.",
                cfg, evidence=[change]))

    # Step 4: denials and service edges. The rules used from here on only ever look at approvals
    # whose subject is the event's actor, so each event is checked against that subset (same
    # results, same order) instead of every approval: this keeps the run close to linear.
    by_subject: dict[str, dict[str, Approval]] = {}
    for approval_id, approval in approvals.items():
        by_subject.setdefault(approval.subject, {})[approval_id] = approval

    def mine(event: Event) -> Mapping[str, Approval]:
        return by_subject.get(event.actor, {})

    candidates: list[Event] = []
    for event in events:
        if event.event_id in labels:
            continue
        revoke = rules.revocation_for_denial(event, mine(event), cfg)
        if revoke is not None:
            put(event, "routine_denial", "DET-DENIAL-AFTER-REVOCATION",
                f"{event.target_service} denied {event.actor} after {revoke.approval_id} revoked "
                f"{revoke.role} at {iso_z(revoke.effective_at)}")
            continue
        ended = rules.ended_grant_for_denial(event, mine(event), cfg)
        if ended is not None:
            put(event, "routine_denial", "DET-DENIAL-AFTER-APPROVAL-ENDED",
                f"{event.target_service} denied {event.actor} after {ended.approval_id} "
                f"({ended.role}) ended at {iso_z(ended.valid_until)} (end exclusive)")
            continue
        if rules.is_unexpected_edge(event, mine(event), cfg):
            candidates.append(event)

    # Roles we know something about: configured, named by an approval, or granted in this data.
    known_roles = (set(cfg.role_scope) | set(cfg.role_rank) | {a.role for a in approvals.values()}
                   | {e.role_after for e in events if e.role_after != e.role_before})

    lone: list[Event] = []
    for chain in rules.movement_chains(candidates, cfg):
        services = {e.target_service for e in chain}
        if len(services) < cfg.movement_min_services:
            lone.extend(chain)
            continue
        trigger = rules.movement_trigger(chain, cfg) or chain[-1]
        path = ", ".join(f"{e.source_service}->{e.target_service} ({e.outcome}, {e.event_id})" for e in chain)
        allowed = [e.event_id for e in chain if e.outcome in cfg.allow_outcomes]
        access = (f"successful access in {', '.join(allowed)}" if allowed
                  else "all requests were denied: no successful access observed")
        for event in chain:
            put(event, "lateral_movement_candidate", "DET-LATERAL-MOVEMENT",
                f"edge {event.source_service}->{event.target_service} is outside the expected scope of "
                f"{event.role_before}; part of a {len(chain)}-event chain in session {event.session_id}")
        alerts.append(_alert(
            "DET-LATERAL-MOVEMENT", "high", trigger, chain,
            f"{chain[0].actor} touched {len(services)} services outside its expected scope within "
            f"{cfg.movement_window_s:g} s steps in session {chain[0].session_id} "
            f"(correlation {', '.join(sorted({e.correlation_id for e in chain}))}): {path}; {access}. "
            "Candidate sequence only: this does not establish compromise.",
            cfg))

    for event in lone:
        if event.outcome in cfg.deny_outcomes:
            put(event, "isolated_denial", "DET-ISOLATED-DENIAL",
                f"single denied edge {event.source_service}->{event.target_service}; one denial alone "
                "is not a movement sequence")
        else:
            rule = "DET-UNEXPECTED-EDGE"
            allowed = event.outcome in cfg.allow_outcomes
            revoked = rules.covering_revocation(event, mine(event), cfg) if allowed else None
            expired = rules.expired_grant(event, mine(event), cfg) if allowed and revoked is None else None
            if revoked is not None:
                severity = "high"
                why = (f"after {revoked.approval_id} revoked {revoked.role} at "
                       f"{iso_z(revoked.effective_at)}. The access should have been refused.")
            elif expired is not None:
                severity = "medium"
                why = (f"after {expired.approval_id} ended at {iso_z(expired.valid_until)}. "
                       "The access is no longer approved.")
            else:
                severity = "low"
                why = (f"outside the expected scope of role {event.role_before}. "
                       "Single edge: not a movement sequence.")
                if event.role_before not in known_roles:
                    rule = "DET-ROLE-NOT-CONFIGURED"
                    why = (f"with role {event.role_before}, which has no access rules configured, so "
                           "this access could not be judged. Add the role with --policy FILE.")
            # The label is unchanged (the nine practice labels have none for these cases).
            put(event, "routine", rule,
                f"{event.outcome} edge {event.source_service}->{event.target_service} is outside the "
                f"expected scope of {event.role_before}")
            alerts.append(_alert(
                rule, severity, event, [event],
                f"{event.actor} reached {event.target_service} ({event.outcome}) {why}", cfg))

    # Step 5: everything left is routine; explain delivery and clock effects.
    uncertain = rules.order_uncertain_ids(events, cfg)
    for event in events:
        if event.event_id in labels:
            continue
        if event.outcome in cfg.deny_outcomes:
            put(event, "isolated_denial", "DET-ISOLATED-DENIAL",
                f"{event.target_service} denied {event.actor} within its expected scope")
        elif event.delivery_delay_ms > cfg.delayed_delivery_ms:
            put(event, "routine_delayed_delivery", "DET-DELAYED-DELIVERY",
                f"received {event.delivery_delay_ms:.0f} ms after it occurred (threshold "
                f"{cfg.delayed_delivery_ms:.0f} ms); late delivery, not replay")
        elif event.source_clock_offset_ms != 0:
            put(event, "routine_clock_offset", "DET-CLOCK-OFFSET",
                f"source clock offset {event.source_clock_offset_ms:+d} ms; corrected time "
                f"{iso_z(event.corrected_time)} (raw {event.event_time_utc})")
        else:
            put(event, "routine", "DET-ROUTINE",
                f"{event.action} on {event.target_service} is within the expected scope of {event.role_before}")

    for event in events:
        if event.conflicting:
            alerts.append(_alert(
                "DET-CONFLICTING-DUPLICATE", "high", event, [event, *event.conflicting],
                _conflict_explanation(event), cfg, evidence=event.conflicting))

    alerts.sort(key=lambda a: (a.emitted_at, a.alert_id))
    return Result(events=events, labels=labels, alerts=alerts, order_uncertain=uncertain)


def run(events: Iterable[Event], approvals: Mapping[str, Approval],
        cfg: DetectConfig = DEFAULT_CONFIG, baseline: object | None = None) -> list[Alert]:
    """Return the alerts for ``events``. ``baseline`` is reserved."""
    return analyze(events, approvals, cfg).alerts
