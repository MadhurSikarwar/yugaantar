"""The vault service: the five operations, orchestrated.

What it does
    ``VaultService`` runs one validated request against the state store, the
    policy, the audit log and (for ``protected_read``) the crypto wrappers. It
    returns the response dictionary or raises a ``Track4Error``. It knows nothing
    about stdin, stdout or exit codes; ``track4_service.py`` owns those.

Ordering guarantees
    Everything happens while the state lock is held, in this order:

        read / protected_read:  decide -> (crypto) -> append audit entry ->
                                update + commit state -> respond
        revoke:                 update + commit state -> append audit entry
        setup:                  append audit entry -> update + commit state

    * A read can never be answered unless its audit entry was written, so a
      failing audit log fails the read **closed**.
    * A revocation is made durable *first*: if the audit log fails afterwards,
      the actor is still revoked (revoking must never be blocked by logging).
    * Alerts are written after the decision entry and are best effort: a failed
      alert never turns a correct answer into an error.

Lock order across the project: state lock first, then the audit log's own lock.

What this module never does
    * It never puts content, ciphertext or proof in a denial.
    * It never stores ``key_material`` or the KEM shared secret, and never logs
      keys, ciphertext, bodies or public keys. For ``protected_read`` the audit
      entry records only the SHA-256 of the challenge so a decision can be
      traced from the test input (``explain --challenge``).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import dataclass, replace
from typing import Callable

from t4.api import (
    AuditSink,
    Decision,
    InputError,
    IntegrityError,
    KemProvider,
    ProofProvider,
    Store,
)
from t4.guard import Alert, Guard, integrity_alert
from t4.identity import VaultState
from t4.policy import decide
from t4.validate_in import (
    AuditRequest,
    ProtectedReadRequest,
    ReadRequest,
    RevokeRequest,
    SetupRequest,
)

SETUP_POLICY_ENV = "TRACK4_SETUP_POLICY"  # "once" refuses a second setup; anything else keeps the contract's reset
RULE_SETUP = "ADM-SETUP"
RULE_REVOKE = "ADM-REVOKE"
RULE_CRYPTO_REJECTED_KEY = "CRY-KEY-REJECTED"

UNATTRIBUTED = "unauthenticated-caller"


@dataclass(frozen=True)
class Dependencies:
    """Everything the service needs, injected so tests can substitute doubles.

    The audit log and the crypto modules are created lazily: an ``audit``
    request, for example, never imports ``pqcrypto``.
    """

    store: Store
    audit_factory: Callable[[], AuditSink]
    kem_factory: Callable[[], KemProvider]
    proof_factory: Callable[[], ProofProvider]
    # Told about a failure of the audit log itself (see t4.integrity_alert). Never raises.
    on_audit_failure: Callable[[Exception], None] = lambda error: None


class AuditHistoryLost(IntegrityError):
    """The audit log ends before an entry that the saved state knows was written."""


class StateRolledBack(IntegrityError):
    """The saved state is older than what the audit log recorded (an earlier copy was restored)."""

    category = "state-rollback"

    def __init__(self, message: str, logged_epoch: int) -> None:
        super().__init__(message)
        self.logged_epoch = logged_epoch


class VaultService:
    def __init__(self, deps: Dependencies) -> None:
        self._deps = deps
        self._audit_cache: AuditSink | None = None

    # -- helpers ----------------------------------------------------------

    def _audit(self) -> AuditSink:
        if self._audit_cache is None:
            self._audit_cache = self._deps.audit_factory()
        return self._audit_cache

    def _require_history(self, state: VaultState) -> None:
        """Refuse to read from or add to a log that has lost entries.

        Every number saved in ``state.audit_seq`` was returned by an append that had already
        reached the disk, so an honest log can never be behind it. Checked BEFORE appending:
        appending to a shortened log would let it grow back past the saved number.
        """
        last_seq = getattr(self._audit(), "last_seq", None)
        if state.audit_seq and callable(last_seq) and last_seq() < state.audit_seq:
            error = AuditHistoryLost("the audit log has lost entries the state recorded")
            self._deps.on_audit_failure(error)
            raise error

    def _require_current_state(self, state: VaultState) -> None:
        """Refuse to decide from saved state that is older than the audit log.

        Every decision and revocation entry records the epoch the state had, and the epoch only
        ever goes up (also across ``setup``). If the newest entries name a higher epoch than the
        loaded state, the state file was replaced by an earlier copy, and revocations made since
        would silently stop applying. That is treated like any other integrity failure: the request
        fails closed and an alert is recorded. (Restoring the WHOLE folder, log included, still
        passes; only a pin kept elsewhere exposes that. See the README.)
        """
        newest = getattr(self._audit(), "newest_value", None)
        if not callable(newest):
            return
        logged = newest("epoch")
        if logged is not None and logged > state.epoch:
            raise StateRolledBack("the saved state is older than the audit log", logged)

    @staticmethod
    def _internal_id() -> str:
        return "sys-" + os.urandom(8).hex()

    @staticmethod
    def _note(message: str) -> None:
        """Fixed-text diagnostics only; never request data."""
        print(message, file=sys.stderr)

    def _emit_alerts(self, alerts: list[Alert], *, actor: str, target: str, request_id: str) -> None:
        """Append alerts to the audit log. Best effort: never raises.

        Uses the log's own ``alert`` method when it has one (it stores the
        triggering entry numbers and request IDs in the form the operator
        commands read). A sink without it gets the same information through
        ``append`` so nothing is lost.
        """
        for alert in alerts:
            try:
                audit = self._audit()
                native = getattr(audit, "alert", None)
                if callable(native):
                    native(
                        rule=alert.rule,
                        explanation=alert.explanation,
                        actor=actor,
                        target=target,
                        request_id=request_id,
                        entries=alert.entries,
                        request_ids=alert.request_ids,
                        detail=alert.detail,
                    )
                else:
                    audit.append(
                        actor=actor,
                        action="alert",
                        target=target,
                        decision="alert",
                        rule=alert.rule,
                        request_id=request_id,
                        detail={
                            "explanation": alert.explanation,
                            "entries": json.dumps(list(alert.entries)),
                            "request_ids": json.dumps(list(alert.request_ids)),
                            **alert.detail,
                        },
                    )
            except Exception:  # noqa: BLE001 - alerts must never break a correct answer
                self._note("An alert could not be logged.")

    # -- setup ------------------------------------------------------------

    def setup(self, request: SetupRequest) -> dict:
        with self._deps.store.locked() as txn:
            state = VaultState.load(txn)
            if state.is_provisioned and os.environ.get(SETUP_POLICY_ENV, "").strip().lower() == "once":
                # Opt-in deployment guard. The official contract lets ``setup`` run again and start a
                # new generation (open organizer question 6), so the default stays "reset". A
                # deployment that must not be wiped by a stray or hostile ``setup`` sets
                # TRACK4_SETUP_POLICY=once: the operator then resets by removing the state folder.
                raise InputError("setup is locked: this state is already initialized")
            state.initialize(request.owners, request.contents, request.disabled)
            try:
                self._require_history(state)
            except AuditHistoryLost:
                self._note("Earlier audit history is missing; an alert was recorded.")
            # A new generation continues from the highest epoch the log has seen, so the epoch keeps
            # going up even if the state file was replaced by an older copy: ``setup`` is how an
            # operator recovers from that (see ``_require_current_state``).
            newest = getattr(self._audit(), "newest_value", None)
            logged = newest("epoch") if callable(newest) else None
            if logged is not None and logged > state.epoch:
                state.epoch = logged
            entry = self._audit().append(
                actor=UNATTRIBUTED,
                action="setup",
                target="vault",
                decision="ok",
                rule=RULE_SETUP,
                request_id=self._internal_id(),
                detail={
                    "generation": state.generation,
                    "epoch": state.epoch,
                    "assets": len(state.assets),
                    "disabled": len(state.disabled),
                },
            )
            state.audit_seq = int(entry["seq"])  # starts again from the log as it is now
            state.save(txn)
        return {"ready": True}

    # -- read -------------------------------------------------------------

    def read(self, request: ReadRequest) -> dict:
        with self._deps.store.locked() as txn:
            state = VaultState.load(txn)
            self._require_current_state(state)
            decision = decide(state, request.actor, request.asset, request.request_id)
            label = "allow" if decision.allow else "deny"
            self._require_history(state)
            entry = self._audit().append(
                actor=request.actor,
                action="read",
                target=request.asset,
                decision=label,
                rule=decision.rule,
                request_id=request.request_id,
                detail=self._decision_detail(state, decision),
            )
            state.audit_seq = int(entry["seq"])
            alerts = self._update_after_decision(
                state,
                decision=decision,
                actor=request.actor,
                asset=request.asset,
                request_id=request.request_id,
                entry_seq=int(entry["seq"]),
                index_it=True,
            )
            body = state.body_of(request.asset) if decision.allow else None
            state.save(txn)
            txn.commit()
            self._emit_alerts(alerts, actor=request.actor, target=request.asset, request_id=request.request_id)
        if decision.allow and body is not None:
            return {"decision": "allow", "body": body}
        return {"decision": "deny"}

    # -- revoke -----------------------------------------------------------

    def revoke(self, request: RevokeRequest) -> dict:
        with self._deps.store.locked() as txn:
            state = VaultState.load(txn)
            # Before changing anything: a revocation written into an older copy of the state would
            # raise its epoch back to the log's and hide that earlier revocations were lost.
            self._require_current_state(state)
            newly_revoked = state.revoke(request.actor)
            state.save(txn)
            txn.commit()  # durable BEFORE logging
            try:
                self._require_history(state)
                self._audit().append(
                    actor=request.actor,
                    action="revoke",
                    target=request.actor,
                    decision="ok",
                    rule=RULE_REVOKE,
                    request_id=self._internal_id(),
                    detail={
                        "generation": state.generation,
                        "epoch": state.epoch,
                        "newly_revoked": newly_revoked,
                    },
                )
            except Exception as error:  # noqa: BLE001 - the revocation already happened
                if not isinstance(error, AuditHistoryLost):  # already reported
                    self._deps.on_audit_failure(error)
                self._note("The revocation was saved but its audit entry could not be written.")
        return {}

    # -- audit ------------------------------------------------------------

    def audit(self, request: AuditRequest) -> dict:
        with self._deps.store.locked() as txn:
            record = VaultState.load(txn).first_record(request.request_id)
        if record is None:
            return {"error": "unknown_request"}
        return {"request_id": request.request_id, "decision": record["decision"], "rule": record["rule"]}

    # -- protected_read ---------------------------------------------------

    def protected_read(self, request: ProtectedReadRequest) -> dict:
        request_id = self._internal_id()
        challenge_sha256 = hashlib.sha256(request.challenge.encode("utf-8")).hexdigest()
        with self._deps.store.locked() as txn:
            state = VaultState.load(txn)
            self._require_current_state(state)
            decision = decide(state, request.actor, request.asset, request_id)
            detail = {**self._decision_detail(state, decision), "challenge_sha256": challenge_sha256}
            self._require_history(state)

            if not decision.allow:
                entry = self._audit().append(
                    actor=request.actor,
                    action="protected_read",
                    target=request.asset,
                    decision="deny",
                    rule=decision.rule,
                    request_id=request_id,
                    detail=detail,
                )
                state.audit_seq = int(entry["seq"])
                alerts = self._update_after_decision(
                    state,
                    decision=decision,
                    actor=request.actor,
                    asset=request.asset,
                    request_id=request_id,
                    entry_seq=int(entry["seq"]),
                    index_it=False,
                )
                state.save(txn)
                txn.commit()
                self._emit_alerts(alerts, actor=request.actor, target=request.asset, request_id=request_id)
                return {"decision": "deny"}

            # Authorized: only now touch the public key.
            body = state.body_of(request.asset) or ""
            try:
                if request.public_key is None:
                    raise ValueError("unusable public key")
                ciphertext, shared_secret = self._deps.kem_factory().encapsulate(request.public_key)
                proof = self._deps.proof_factory().make_proof(
                    shared_secret, request.challenge.encode("utf-8"), body.encode("utf-8")
                )
            except ValueError:
                self._audit().append(
                    actor=request.actor,
                    action="protected_read",
                    target=request.asset,
                    decision="error",
                    rule=RULE_CRYPTO_REJECTED_KEY,
                    request_id=request_id,
                    detail=detail,
                )
                raise InputError("public key rejected") from None
            finally:
                # This only drops our reference so the object can be collected. Python bytes cannot be
                # erased in place, so it is NOT zeroization; see the README's limits section.
                shared_secret = b""

            self._audit().append(
                actor=request.actor,
                action="protected_read",
                target=request.asset,
                decision="allow",
                rule=decision.rule,
                request_id=request_id,
                detail=detail,
            )
        return {"ciphertext": base64.b64encode(ciphertext).decode("ascii"), "proof": proof}

    # -- shared pieces ------------------------------------------------------

    @staticmethod
    def _decision_detail(state: VaultState, decision: Decision) -> dict[str, str | int | bool]:
        return {"generation": state.generation, "epoch": decision.epoch, "reason": decision.reason}

    def _update_after_decision(
        self,
        state: VaultState,
        *,
        decision: Decision,
        actor: str,
        asset: str,
        request_id: str,
        entry_seq: int,
        index_it: bool,
    ) -> list[Alert]:
        """Update the request index and the guard counters; return alerts to log."""
        guard = Guard(state.guard)
        alerts: list[Alert] = []
        if index_it:
            first = state.first_record(request_id)
            if first is None:
                state.remember_request(request_id, "allow" if decision.allow else "deny", decision.rule, entry_seq)
            else:
                alerts += guard.on_duplicate_request_id(
                    request_id, first_entry_seq=int(first["seq"]), entry_seq=entry_seq
                )
        if not decision.allow:
            alerts += guard.on_denial(actor, asset=asset, entry_seq=entry_seq, request_id=request_id)
        state.guard = guard.to_doc()
        return alerts

    # -- failure reporting (called by the adapter, never raises) -------------

    def report_input_failure(self, kind: str) -> None:
        """Count a malformed request and alert on the back-off schedule.

        Only acts when state already exists: an unprovisioned service has
        nowhere trustworthy to record anything, and a malformed request must not
        be able to create state.
        """
        try:
            store = self._deps.store
            exists = getattr(store, "exists", None)
            if callable(exists) and not exists():
                return
            with store.locked() as txn:
                state = VaultState.load(txn)
                self._require_history(state)
                guard = Guard(state.guard)
                alerts = guard.on_invalid_input(kind)
                state.guard = guard.to_doc()
                state.save(txn)
                txn.commit()
                self._emit_alerts(alerts, actor=UNATTRIBUTED, target="vault", request_id=self._internal_id())
        except Exception:  # noqa: BLE001 - reporting must never raise
            return

    def report_integrity_failure(self, error: IntegrityError) -> None:
        """Record that stored state could not be trusted (state itself is not touched)."""
        alert = integrity_alert(error.category)
        if isinstance(error, StateRolledBack):
            # The alert keeps the epoch the log had reached, so a stream of refused requests (each
            # adding an alert) can never push that epoch out of the log tail the check reads.
            alert = replace(alert, detail={**alert.detail, "epoch": error.logged_epoch})
        try:
            self._emit_alerts([alert], actor=UNATTRIBUTED, target="vault", request_id=self._internal_id())
        except Exception:  # noqa: BLE001
            return
