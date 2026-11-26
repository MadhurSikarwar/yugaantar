"""Detector configuration: every threshold and policy table in one place.

What it does
    Holds the tunable values the rules use, with the defaults documented below.
    The defaults encode the service context described in the toolkit's
    ``practice/README.md`` (which roles may reach which services, who may
    approve changes). Nothing here is learned from data.

What it defends against
    Hidden or drifting thresholds. A reviewer can read every number that
    decides an alert here, and tests pin the defaults.

Supported range (M-C8)
    * Known source clock offsets up to +/- ``max_supported_offset_ms`` (5 s).
    * Delivery delay (receipt minus corrected event time) up to
      ``max_supported_delay_ms`` (60 s); a negative delay beyond the clock
      uncertainty is accepted but flagged.
    Events outside this range are still classified, but marked
    ``order_uncertain`` because their position on the timeline cannot be
    trusted to within the stated uncertainty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


def _frozen(mapping: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class DetectConfig:
    """Thresholds and policy tables for the detector rules."""

    # M-C7 lateral movement: at least N distinct unexpected services touched by
    # one group within a chain whose consecutive events are at most W apart.
    movement_min_services: int = 2
    movement_window_s: float = 60.0
    # Events are grouped by these Event attributes for movement chains.
    movement_group_by: tuple[str, ...] = ("actor", "session_id")

    # M-C6: only these identities may approve or revoke role changes.
    authorized_approvers: frozenset[str] = frozenset({"user-admin"})

    # Role order: a change to a higher rank is an increase and needs approval.
    # A role that is not listed counts as an increase from any role.
    role_rank: Mapping[str, int] = field(
        default_factory=lambda: _frozen(
            {"viewer": 1, "service-reader": 1, "report-reader": 2, "operator": 3}
        )
    )

    # Services each role may reach without a time-limited approval. Approval
    # scopes (e.g. change-100's reports nodes) are added while the approval is
    # valid and not revoked.
    role_scope: Mapping[str, frozenset[str]] = field(
        default_factory=lambda: _frozen(
            {
                "viewer": frozenset({"catalog"}),
                "service-reader": frozenset({"catalog"}),
                "report-reader": frozenset({"catalog"}),
                "operator": frozenset({"catalog", "identity"}),
            }
        )
    )

    # Session bookkeeping against the identity service is always expected.
    identity_service: str = "identity"
    session_actions: frozenset[str] = frozenset({"sign_in", "sign_out"})

    # Administrative actions that act on an approval, mapped to the approval
    # operation they must match.
    approval_actions: Mapping[str, str] = field(
        default_factory=lambda: _frozen(
            {"approve_role_change": "grant_role", "revoke_role": "revoke_role"}
        )
    )

    allow_outcomes: frozenset[str] = frozenset({"allow", "success"})
    deny_outcomes: frozenset[str] = frozenset({"deny"})

    # How many allowed actions after an unapproved role change are labelled
    # review_after_role_change (PRD M-C6: "the next privileged read").
    review_followups: int = 1

    # M-C8 clock and order.
    delayed_delivery_ms: float = 1000.0
    clock_uncertainty_ms: float = 100.0
    max_supported_offset_ms: int = 5000
    max_supported_delay_ms: float = 60000.0

    def scope_for(self, role: str) -> frozenset[str]:
        """Services ``role`` may reach without an approval."""
        return frozenset(self.role_scope.get(role, frozenset()))

    def is_increase(self, before: str, after: str) -> bool:
        """True if moving from ``before`` to ``after`` raises privilege."""
        if before == after:
            return False
        rank_after = self.role_rank.get(after)
        rank_before = self.role_rank.get(before)
        if rank_after is None or rank_before is None:
            return True
        return rank_after > rank_before


DEFAULT_CONFIG = DetectConfig()
