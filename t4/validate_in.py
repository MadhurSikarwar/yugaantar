"""Strict input validation.

What it does
    Turns raw stdin bytes into one small, typed request object, or raises
    ``InputError``. Nothing downstream ever sees an unchecked dictionary.

What it defends against
    * Oversized input: stdin is read with a hard cap (1 MiB) before parsing.
    * Encoding tricks: strict UTF-8; strings that cannot be encoded as UTF-8
      (lone surrogates) are rejected because the HMAC proof is defined over
      UTF-8 bytes and an undefined encoding would make it ambiguous.
    * JSON ambiguity: duplicate object keys, ``NaN``/``Infinity`` and deeply
      nested documents are rejected (nesting is measured with an iterative scan,
      so a hostile document cannot trigger a RecursionError).
    * Type confusion: every field of every operation has an exact type.
      Unknown extra fields are ignored and never acted on.
    * Base64 games: ``public_key`` is usable only if it is canonical standard
      Base64 that decodes to exactly 1184 bytes (an ML-KEM-768 public key). A
      string that is not is passed on as ``None``, not rejected here: the
      service decides permission first, so a caller who is not allowed gets the
      ordinary deny, and only an authorized caller is told the key is bad. A
      value that is not a string at all is malformed input.

Deliberately NOT restricted
    Identifiers are opaque strings (contract). Any characters, including
    newlines and null bytes, are accepted and later escaped as JSON string
    values; only their *length* is capped (4 KiB). They are never used in file
    paths.

Error messages are fixed labels. They never contain request data.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import BinaryIO, Union

from t4.api import ML_KEM_768_PUBLIC_KEY_BYTES, InputError

MAX_STDIN_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_IDENTIFIER_BYTES = 4096
MAX_ENTRIES = 10_000
MAX_OP_CHARS = 32

KNOWN_OPS = ("setup", "read", "revoke", "audit", "protected_read")


# ---------------------------------------------------------------------------
# Typed requests
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SetupRequest:
    owners: dict[str, str]
    contents: dict[str, str]
    disabled: tuple[str, ...]


@dataclass(frozen=True)
class ReadRequest:
    actor: str
    asset: str
    request_id: str


@dataclass(frozen=True)
class RevokeRequest:
    actor: str


@dataclass(frozen=True)
class AuditRequest:
    request_id: str


@dataclass(frozen=True)
class ProtectedReadRequest:
    actor: str
    asset: str
    challenge: str
    public_key: bytes | None  # None: a string that is not a usable ML-KEM-768 public key


@dataclass(frozen=True)
class UnsupportedOperation:
    """A well-formed request whose ``op`` we do not implement."""


Request = Union[SetupRequest, ReadRequest, RevokeRequest, AuditRequest, ProtectedReadRequest, UnsupportedOperation]


# ---------------------------------------------------------------------------
# Reading and parsing JSON
# ---------------------------------------------------------------------------


def read_request(stream: BinaryIO, *, max_bytes: int = MAX_STDIN_BYTES) -> dict:
    """Read at most ``max_bytes`` from a binary stream and parse one JSON object."""
    data = stream.read(max_bytes + 1)
    return parse_request_bytes(data, max_bytes=max_bytes)


def parse_request_bytes(data: bytes, *, max_bytes: int = MAX_STDIN_BYTES) -> dict:
    if len(data) > max_bytes:
        raise InputError("input too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("input is not valid UTF-8") from None
    _check_depth(text)
    try:
        value = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        raise InputError("input is not valid JSON") from None
    if not isinstance(value, dict):
        raise InputError("request must be a JSON object")
    return value


def _reject_constant(_name: str) -> None:
    raise ValueError("NaN and Infinity are not allowed")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _check_depth(text: str) -> None:
    """Reject nesting deeper than ``MAX_JSON_DEPTH`` without recursion."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise InputError("input nested too deeply")
        elif char in "}]":
            depth -= 1


# ---------------------------------------------------------------------------
# Field validators
# ---------------------------------------------------------------------------


def _utf8_len(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise InputError("string cannot be encoded as UTF-8") from None


def _identifier(value: object) -> str:
    if not isinstance(value, str):
        raise InputError("identifier must be a string")
    if _utf8_len(value) > MAX_IDENTIFIER_BYTES:
        raise InputError("identifier too long")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise InputError("field must be a string")
    _utf8_len(value)
    return value


def _string_map(value: object, *, values_are_identifiers: bool) -> dict[str, str]:
    if not isinstance(value, dict):
        raise InputError("field must be an object")
    if len(value) > MAX_ENTRIES:
        raise InputError("too many entries")
    checker = _identifier if values_are_identifiers else _text
    return {_identifier(k): checker(v) for k, v in value.items()}


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InputError("field must be a list")
    if len(value) > MAX_ENTRIES:
        raise InputError("too many entries")
    return tuple(dict.fromkeys(_identifier(item) for item in value))


def _public_key(value: object) -> bytes | None:
    if not isinstance(value, str):
        raise InputError("public key must be a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if base64.b64encode(raw).decode("ascii") != value or len(raw) != ML_KEM_768_PUBLIC_KEY_BYTES:
        return None
    return raw


def _require(request: dict, field: str) -> object:
    if field not in request:
        raise InputError("required field missing")
    return request[field]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def validate_request(request: dict) -> Request:
    """Validate a parsed request and return its typed form.

    ``setup``: ``owners`` is required; ``contents`` and ``disabled`` default to
    empty; ``key_material`` is accepted and ignored (we never store it).
    """
    op = request.get("op")
    if not isinstance(op, str) or len(op) > MAX_OP_CHARS:
        raise InputError("operation must be a short string")
    if op not in KNOWN_OPS:
        return UnsupportedOperation()

    if op == "setup":
        owners = _string_map(_require(request, "owners"), values_are_identifiers=True)
        contents = _string_map(request.get("contents", {}), values_are_identifiers=False)
        disabled = _string_list(request.get("disabled", []))
        if "key_material" in request:
            _text(request["key_material"])  # type-check only; the value is never kept
        return SetupRequest(owners=owners, contents=contents, disabled=disabled)
    if op == "read":
        return ReadRequest(
            actor=_identifier(_require(request, "actor")),
            asset=_identifier(_require(request, "asset")),
            request_id=_identifier(_require(request, "request_id")),
        )
    if op == "revoke":
        return RevokeRequest(actor=_identifier(_require(request, "actor")))
    if op == "audit":
        return AuditRequest(request_id=_identifier(_require(request, "request_id")))
    # protected_read
    return ProtectedReadRequest(
        actor=_identifier(_require(request, "actor")),
        asset=_identifier(_require(request, "asset")),
        challenge=_text(_require(request, "challenge")),
        public_key=_public_key(_require(request, "public_key")),
    )
