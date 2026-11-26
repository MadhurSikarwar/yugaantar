"""Explainable detection rules (no ML): approvals, scope, revocation, movement, time.

What it does
    Small pure functions, each implementing one rule:

    * ``check_approval_action``: an approve/revoke administration event is an
      approved change only if the approval exists, matches the action, and the
      acting operator is the recorded and an authorized approver.
    * ``match_grant``: a role increase is approved only by a ``grant_role``
      approval for the same subject and role, valid at the corrected event
      time (end exclusive), not revoked, from an authorized approver, and the
      event's own ``approval_id`` (if any) must name that approval.
    * ``reachable_services`` / ``is_unexpected_edge``: the services a role may
      reach, plus approval scopes while valid (baseline).
    * ``revocation_for_denial``: a denial after an effective revocation of a
      role whose scope covered the target is routine.
    * ``movement_chains``: groups unexpected edges by actor and session into
      chains whose consecutive events are at most W apart.
    * ``timing_flags``: corrected time, delivery delay and order uncertainty
.

    Every function returns a plain-language reason, so each label and alert
    can say exactly which rule and which facts produced it.

What it defends against
    * Approval abuse: a change carrying another subject's approval ID, an
      expired or revoked approval, or one signed off by an unauthorized
      approver is not treated as approved.
    * Over-alerting: a single denial, or denials that follow an effective
      revocation, are not reported as lateral movement.
    * Clock confusion: a delayed or clock-offset event is explained as such,
      never as replay or as malicious activity.

Limits
    The baseline is a fixed role-to-service table plus approvals; it does not
    learn per-identity habits. Movement chains are per actor and session, so an
    attacker who changes session on every request is not chained (each edge
    then shows as an isolated denial or a low-severity unexpected-edge alert).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Mapping, Sequence

from .config import DetectConfig
from .ingest import Approval, Event, iso_z

Approvals = Mapping[str, Approval]


@dataclass(frozen=True)
class RuleResult:
    """Outcome of one rule check: whether it passed, and why."""

    ok: bool
    reason: str
    approval: Approval | None = None


def _revocation_time(subject: str, role: str, approvals: Approvals,
                     cfg: DetectConfig | None = None) -> datetime | None:
    """Earliest effective revocation of ``role`` for ``subject``, if any.

    With ``cfg`` the revocation must come from an authorized approver: an entry written by
    anyone else must not explain away denials or cancel a grant.
    """
    times = [
        a.effective_at
        for a in approvals.values()
        if a.operation == "revoke_role"
        and a.subject == subject
        and a.role == role
        and a.effective_at is not None
        and a.approved_by
        and (cfg is None or a.approved_by in cfg.authorized_approvers)
    ]
    return min(times) if times else None


def check_approval_action(event: Event, approvals: Approvals, cfg: DetectConfig) -> RuleResult:
    """Validate an approve/revoke administration event (actor = operator)."""
    expected_op = cfg.approval_actions[event.action]
    approval = approvals.get(event.approval_id) if event.approval_id else None
    if approval is None:
        return RuleResult(False, f"{event.action} names no known approval (approval_id={event.approval_id!r})")
    if approval.operation != expected_op:
        return RuleResult(False, f"{event.action} names {approval.approval_id}, which is a {approval.operation} change", approval)
    if event.actor not in cfg.authorized_approvers:
        return RuleResult(False, f"{event.actor} is not an authorized approver", approval)
    if approval.approved_by != event.actor:
        return RuleResult(False, f"{approval.approval_id} was approved by {approval.approved_by}, not {event.actor}", approval)
    return RuleResult(
        True,
        f"{event.actor} (authorized approver) records {approval.approval_id}: "
        f"{approval.operation} {approval.role} for {approval.subject}",
        approval,
    )


def _scope_covers(approval: Approval, event: Event, cfg: DetectConfig) -> bool:
    """A scoped approval only covers changes aimed at a service in its scope.

    A change recorded against the identity service (how our own logs record grants, with the
    asset carried in the role name) is not narrowed by scope: the role match is the check.
    """
    return (not approval.scope or event.target_service == cfg.identity_service
            or event.target_service in approval.scope)


def match_grant(event: Event, approvals: Approvals, cfg: DetectConfig) -> RuleResult:
    """Find a grant approval covering a role increase, or explain why none does."""
    moment = event.corrected_time
    candidates = [
        a for a in approvals.values()
        if a.operation == "grant_role" and a.subject == event.actor and a.role == event.role_after
        and _scope_covers(a, event, cfg)
    ]
    if event.approval_id:
        named = approvals.get(event.approval_id)
        if named is None:
            return RuleResult(False, f"approval_id {event.approval_id} does not exist")
        if (named.operation == "grant_role" and named.subject == event.actor and named.role == event.role_after
                and not _scope_covers(named, event, cfg)):
            return RuleResult(
                False,
                f"{named.approval_id} is scoped to {', '.join(named.scope)}, not {event.target_service}",
                named,
            )
        if named not in candidates:
            return RuleResult(
                False,
                f"{named.approval_id} covers {named.operation} {named.role} for {named.subject}, "
                f"not {event.role_after} for {event.actor}",
                named,
            )
        candidates = [named]
    if not candidates:
        return RuleResult(False, f"no approval exists for {event.actor} becoming {event.role_after}")
    reasons = []
    for approval in candidates:
        if approval.approved_by not in cfg.authorized_approvers:
            reasons.append(f"{approval.approval_id} approver {approval.approved_by} is not authorized "
                           "(authorized approvers are set with --approver)")
            continue
        if not approval.valid_at(moment):
            reasons.append(
                f"{approval.approval_id} is valid "
                f"{iso_z(approval.valid_from) if approval.valid_from else '?'} to "
                f"{iso_z(approval.valid_until) if approval.valid_until else '?'} (end exclusive), "
                f"change happened at {iso_z(moment)}"
            )
            continue
        revoked_at = _revocation_time(event.actor, approval.role, approvals, cfg)
        if revoked_at is not None and revoked_at <= moment:
            reasons.append(f"{approval.role} for {event.actor} was revoked at {iso_z(revoked_at)}")
            continue
        return RuleResult(
            True,
            f"{event.actor} {event.role_before} -> {event.role_after} matches {approval.approval_id} "
            f"(subject, role and time within the approved window; approver {approval.approved_by})",
            approval,
        )
    return RuleResult(False, "; ".join(reasons))


def match_revoke(event: Event, approvals: Approvals, cfg: DetectConfig | None = None) -> Approval | None:
    """A revoke approval that explains a role decrease, if one is effective and authorized."""
    for approval in approvals.values():
        if (
            approval.operation == "revoke_role"
            and (cfg is None or approval.approved_by in cfg.authorized_approvers)
            and approval.subject == event.actor
            and approval.role == event.role_before
            and approval.effective_at is not None
            and approval.effective_at <= event.corrected_time
        ):
            return approval
    return None


def reachable_services(actor: str, role: str, moment: datetime, approvals: Approvals, cfg: DetectConfig) -> set[str]:
    """Services ``actor`` holding ``role`` may reach at ``moment``."""
    services = set(cfg.scope_for(role)) | set(cfg.baseline.get(actor, frozenset()))
    revoked_at = _revocation_time(actor, role, approvals, cfg)
    for approval in approvals.values():
        if (
            approval.operation == "grant_role"
            and approval.subject == actor
            and approval.role == role
            and approval.approved_by in cfg.authorized_approvers
            and approval.valid_at(moment)
            and not (revoked_at is not None and revoked_at <= moment)
        ):
            services.update(approval.scope)
    return services


def is_unexpected_edge(event: Event, approvals: Approvals, cfg: DetectConfig) -> bool:
    """True if the event's target is outside what the actor's role may reach."""
    if event.target_service == cfg.identity_service and event.action in cfg.session_actions:
        return False
    allowed = reachable_services(event.actor, event.role_before, event.corrected_time, approvals, cfg)
    return event.target_service not in allowed


def revocation_for_denial(event: Event, approvals: Approvals, cfg: DetectConfig) -> Approval | None:
    """A revocation that explains this denial: effective before it, covering its target."""
    if event.outcome not in cfg.deny_outcomes:
        return None
    return covering_revocation(event, approvals, cfg)


def expired_grant(event: Event, approvals: Approvals, cfg: DetectConfig) -> Approval | None:
    """An authorized grant that covered this target but had ended before the event."""
    for approval in approvals.values():
        if (approval.operation == "grant_role" and approval.subject == event.actor
                and approval.role == event.role_before and approval.approved_by in cfg.authorized_approvers
                and approval.valid_until is not None and approval.valid_until <= event.corrected_time
                and event.target_service in approval.scope):
            return approval
    return None


def covering_revocation(event: Event, approvals: Approvals, cfg: DetectConfig) -> Approval | None:
    """An authorized revocation effective before the event and covering its target."""
    moment = event.corrected_time
    for approval in approvals.values():
        if (
            approval.operation != "revoke_role"
            or approval.approved_by not in cfg.authorized_approvers
            or approval.subject != event.actor
            or approval.effective_at is None
            or approval.effective_at > moment
        ):
            continue
        covered = set(cfg.scope_for(approval.role))
        for grant in approvals.values():
            if (grant.operation == "grant_role" and grant.subject == event.actor and grant.role == approval.role
                    and grant.approved_by in cfg.authorized_approvers):
                covered.update(grant.scope)
        if event.target_service in covered:
            return approval
    return None


def group_key(event: Event, cfg: DetectConfig) -> tuple[str, ...]:
    """Grouping key for movement chains (default: actor and session)."""
    return tuple(getattr(event, name) for name in cfg.movement_group_by)


def movement_chains(candidates: Iterable[Event], cfg: DetectConfig) -> list[list[Event]]:
    """Split unexpected-edge events into per-group chains, gap at most W."""
    groups: dict[tuple[str, ...], list[Event]] = {}
    for event in candidates:
        groups.setdefault(group_key(event, cfg), []).append(event)
    window = timedelta(seconds=cfg.movement_window_s)
    chains: list[list[Event]] = []
    for events in groups.values():
        events.sort(key=lambda e: (e.corrected_time, e.receipt_index))
        chain: list[Event] = []
        for event in events:
            if chain and event.corrected_time - chain[-1].corrected_time > window:
                chains.append(chain)
                chain = []
            chain.append(event)
        if chain:
            chains.append(chain)
    chains.sort(key=lambda c: c[0].receipt_index)
    return chains


def movement_trigger(chain: Sequence[Event], cfg: DetectConfig) -> Event | None:
    """The event, in receipt order, at which the chain first reaches N services."""
    seen: set[str] = set()
    for event in sorted(chain, key=lambda e: e.receipt_index):
        seen.add(event.target_service)
        if len(seen) >= cfg.movement_min_services:
            return event
    return None


def event_uncertainty_ms(event: Event, cfg: DetectConfig) -> float:
    """Timeline uncertainty of one event; infinite outside the supported range."""
    delay = event.delivery_delay_ms
    if (
        abs(event.source_clock_offset_ms) > cfg.max_supported_offset_ms
        or delay > cfg.max_supported_delay_ms
        or delay < -cfg.clock_uncertainty_ms
    ):
        return float("inf")
    return cfg.clock_uncertainty_ms


def order_uncertain_ids(events: Sequence[Event], cfg: DetectConfig) -> set[str]:
    """Event IDs whose order against a neighbour in the same actor stream is uncertain.

    Two events are uncertain when the gap between their corrected times is
    smaller than the sum of their uncertainties.
    """
    uncertain: set[str] = set()
    by_actor: dict[str, list[Event]] = {}
    for event in events:
        if event_uncertainty_ms(event, cfg) == float("inf"):
            uncertain.add(event.event_id)
        by_actor.setdefault(event.actor, []).append(event)
    for stream in by_actor.values():
        stream.sort(key=lambda e: (e.corrected_time, e.receipt_index))
        # Out-of-range events are already flagged; they do not taint neighbours.
        stream = [e for e in stream if e.event_id not in uncertain]
        for left, right in zip(stream, stream[1:]):
            gap = (right.corrected_time - left.corrected_time) / timedelta(milliseconds=1)
            if gap < event_uncertainty_ms(left, cfg) + event_uncertainty_ms(right, cfg):
                uncertain.update((left.event_id, right.event_id))
    return uncertain


def pair_uncertain(events: Sequence[Event], cfg: DetectConfig) -> bool:
    """True if any two of ``events`` cannot be ordered within the uncertainty."""
    ordered = sorted(events, key=lambda e: e.corrected_time)
    for event in ordered:
        if event_uncertainty_ms(event, cfg) == float("inf"):
            return True
    for left, right in zip(ordered, ordered[1:]):
        gap = (right.corrected_time - left.corrected_time) / timedelta(milliseconds=1)
        if gap < event_uncertainty_ms(left, cfg) + event_uncertainty_ms(right, cfg):
            return True
    return False
