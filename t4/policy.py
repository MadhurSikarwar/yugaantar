"""Access policy: one function, one ordered list of rules.

What it does
    ``decide`` answers one question: may ``actor`` read ``asset``? ``read`` and
    ``protected_read`` both call it, so the two can never disagree.

Rules, checked in this order. The first match wins and gives the stable rule ID
that is written to the audit log (never to the caller):

    POL-REVOKED        the actor was revoked
    POL-DISABLED       the actor is on the ``disabled`` list from ``setup``
    POL-UNKNOWN-ASSET  the asset does not exist
    POL-NOT-OWNER      the actor does not own the asset
    POL-ALLOW-OWNER    allowed: the actor owns the asset

Why this order: a denial is explained by the actor's status before the asset's,
so an operator reading the log sees "revoked" rather than "not owner".

What it is NOT
    Authorization only. The adapter never receives a credential, so it cannot
    verify *who* is asking. Identifiers are compared as exact strings:
    no case folding, no Unicode normalization.
"""
from __future__ import annotations

from t4.api import Decision
from t4.identity import VaultState

RULE_REVOKED = "POL-REVOKED"
RULE_DISABLED = "POL-DISABLED"
RULE_UNKNOWN_ASSET = "POL-UNKNOWN-ASSET"
RULE_NOT_OWNER = "POL-NOT-OWNER"
RULE_ALLOW_OWNER = "POL-ALLOW-OWNER"

# The rule table itself, in the order ``decide`` checks it: (rule ID, condition, allows).
# This is the single source for anything that lists the rules (the web console reads it through
# the bridge), so no copy of the policy exists elsewhere.
RULES: tuple[tuple[str, str, bool], ...] = (
    (RULE_REVOKED, "actor revoked", False),
    (RULE_DISABLED, "actor disabled at setup", False),
    (RULE_UNKNOWN_ASSET, "asset does not exist", False),
    (RULE_NOT_OWNER, "actor does not own the asset", False),
    (RULE_ALLOW_OWNER, "actor owns the asset", True),
)
_REASON = {rule: reason for rule, reason, _allow in RULES}
_ALLOWS = {rule: allow for rule, _reason, allow in RULES}


def _matching_rule(state: VaultState, actor: str, asset: str) -> str:
    if state.is_revoked(actor):
        return RULE_REVOKED
    if state.is_disabled(actor):
        return RULE_DISABLED
    owner = state.owner_of(asset)
    if owner is None:
        return RULE_UNKNOWN_ASSET
    if owner != actor:
        return RULE_NOT_OWNER
    return RULE_ALLOW_OWNER


def decide(state: VaultState, actor: str, asset: str, request_id: str) -> Decision:
    """Return the decision for one read; never raises for well-formed input."""
    rule = _matching_rule(state, actor, asset)
    return Decision(_ALLOWS[rule], _REASON[rule], rule, request_id, state.epoch)
