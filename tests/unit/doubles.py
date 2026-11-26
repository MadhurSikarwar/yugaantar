"""Test doubles for the modules c1 depends on but does not own (audit log, crypto).

Unit tests use these so they pass on a branch that does not contain c2's code.
Nothing here is shipped; it is test support only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Callable

from t4.service import Dependencies, VaultService
from t4.store import FileStore


class FakeAudit:
    """In-memory audit sink. ``fail_when`` can make chosen appends raise."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.fail_when: Callable[[dict], bool] = lambda entry: False

    def append(self, **entry) -> dict:
        if self.fail_when(entry):
            raise RuntimeError("audit unavailable")
        seq = len(self.entries) + 1
        self.entries.append({**entry, "seq": seq})
        return {"seq": seq, "hash": hashlib.sha256(str(seq).encode()).hexdigest()}

    def alert(self, *, rule, explanation, actor="", target="", request_id="", entries=(), request_ids=(), detail=None) -> dict:
        """Mirrors ``t4.audit.log.AuditLog.alert``: lists are stored as JSON strings."""
        extra = {**(detail or {}), "explanation": explanation, "entries": json.dumps(list(entries)), "request_ids": json.dumps(list(request_ids))}
        return self.append(actor=actor, action="alert", target=target, decision="alert", rule=rule, request_id=request_id, detail=extra)

    def by_action(self, action: str) -> list[dict]:
        return [e for e in self.entries if e["action"] == action]

    def rules(self) -> list[str]:
        return [e["rule"] for e in self.entries]


class PlainAudit(FakeAudit):
    """A sink that only has ``append`` (no native ``alert``), to test the fallback path."""

    alert = None  # type: ignore[assignment]


class FakeKem:
    """Returns fixed values and records every call; ``reject`` simulates a bad key."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []
        self.reject = False
        self.ciphertext = b"C" * 1088
        self.secret = b"S" * 32

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        self.calls.append(public_key)
        if self.reject:
            raise ValueError("bad key")
        return self.ciphertext, self.secret


class RealProof:
    """The documented proof construction, written independently of c2's code."""

    @staticmethod
    def make_proof(shared_secret: bytes, challenge: bytes, stored_body: bytes) -> str:
        return hmac.new(shared_secret, challenge + stored_body, hashlib.sha256).hexdigest()


def make_service(state_dir: Path, audit: FakeAudit | None = None) -> tuple[VaultService, FakeAudit, FakeKem, FileStore]:
    audit, kem, store = audit or FakeAudit(), FakeKem(), FileStore(state_dir)
    deps = Dependencies(
        store=store,
        audit_factory=lambda: audit,
        kem_factory=lambda: kem,
        proof_factory=lambda: RealProof(),
    )
    return VaultService(deps), audit, kem, store
