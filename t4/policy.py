"""Access policy: one function, one ordered list of rules (owner: c1; PRD M-A2).

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
    verify *who* is asking (PRD 4.2). Identifiers are compared as exact strings:
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


def decide(state: VaultState, actor: str, asset: str, request_id: str) -> Decision:
    """Return the decision for one read; never raises for well-formed input."""
    epoch = state.epoch
    if state.is_revoked(actor):
        return Decision(False, "actor revoked", RULE_REVOKED, request_id, epoch)
    if state.is_disabled(actor):
        return Decision(False, "actor disabled at setup", RULE_DISABLED, request_id, epoch)
    owner = state.owner_of(asset)
    if owner is None:
        return Decision(False, "asset does not exist", RULE_UNKNOWN_ASSET, request_id, epoch)
    if owner != actor:
        return Decision(False, "actor does not own the asset", RULE_NOT_OWNER, request_id, epoch)
    return Decision(True, "actor owns the asset", RULE_ALLOW_OWNER, request_id, epoch)
