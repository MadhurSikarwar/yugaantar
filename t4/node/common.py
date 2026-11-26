"""Shared helpers for the node layer.

What it does: one canonical byte encoding for everything that gets signed,
strict decoding of untrusted values, and the interfaces we expect from other
modules (signature scheme, audit log).

What it defends against: two different messages sharing one signature input,
loosely typed or oversized input, and signature confusion (every signed body
carries a "type" that the verifier checks).
"""
from __future__ import annotations

import base64
import binascii
import json
import math
from pathlib import Path
from typing import Any, Mapping, Protocol

MAX_TEXT = 4096
MAX_TIME = 1e12


class NodeError(Exception):
    """An operation was refused. The message never contains key material."""


class Signer(Protocol):
    """The shape of the ``t4.crypto.sig`` module (ML-DSA-65)."""

    def sig_keygen(self) -> tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, msg: bytes) -> bytes: ...
    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool: ...


class KeyLog(Protocol):
    """The part of ``t4.audit.log.AuditLog`` that the node layer uses."""

    def append(self, *, actor: str, action: str, target: str, decision: str,
               rule: str, request_id: str,
               detail: Mapping[str, str | int | bool]) -> dict: ...


try:  # The interface owner's type wins once it exists.
    from t4.api import Decision  # type: ignore
except ImportError:
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Decision:  # type: ignore[no-redef]
        """Same fields as PRD 5.1."""

        allow: bool
        reason: str
        rule: str
        request_id: str
        epoch: int


def load_signer() -> Signer:
    """Return the real ML-DSA wrapper. There is deliberately no fallback."""
    try:
        from t4.crypto import sig  # type: ignore
    except ImportError:
        raise NodeError("t4.crypto.sig is not available") from None
    return sig


def open_log(directory: str | Path) -> KeyLog:
    """Return the real audit log. There is deliberately no fallback."""
    try:
        from t4.audit.log import AuditLog  # type: ignore
    except ImportError:
        raise NodeError("t4.audit.log is not available") from None
    return AuditLog(Path(directory), None)


def canonical(value: Any) -> bytes:
    """Sorted keys, no spaces, ASCII only, no NaN."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: Any) -> bytes:
    if not isinstance(text, str):
        raise NodeError("expected Base64 text")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeError, ValueError):
        raise NodeError("invalid Base64") from None


def check_text(value: Any) -> str:
    """Identifiers are opaque: any characters, non-empty, bounded length."""
    if not isinstance(value, str) or not 0 < len(value) <= MAX_TEXT:
        raise NodeError("invalid text field")
    return value


def check_int(value: Any) -> int:
    if type(value) is not int or not 0 <= value < 2 ** 63:
        raise NodeError("invalid integer field")
    return value


def check_time(value: Any) -> float:
    if type(value) not in (int, float) or not 0 <= value <= MAX_TIME or not math.isfinite(value):
        raise NodeError("invalid time field")
    return value


def signed_envelope(signer: Signer, sk: bytes, body: Mapping[str, Any]) -> dict:
    body = dict(body)
    return {"body": body, "signature": b64e(signer.sign(sk, canonical(body)))}


def open_envelope(envelope: Any, kind: str, fields: frozenset[str]) -> tuple[dict, bytes]:
    """Check the shape only. The caller must still verify the signature."""
    if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
        raise NodeError("invalid envelope")
    body = envelope["body"]
    if not isinstance(body, dict) or set(body) != fields or body.get("type") != kind:
        raise NodeError("invalid signed body")
    return body, b64d(envelope["signature"])
