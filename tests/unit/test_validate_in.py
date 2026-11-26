"""Input validation: every malformed shape must raise InputError, valid ones must parse."""
from __future__ import annotations

import base64
import io
import json

import pytest

from t4.api import InputError
from t4.validate_in import (
    MAX_IDENTIFIER_BYTES,
    AuditRequest,
    ProtectedReadRequest,
    ReadRequest,
    RevokeRequest,
    SetupRequest,
    UnsupportedOperation,
    parse_request_bytes,
    read_request,
    validate_request,
)

GOOD_KEY = base64.b64encode(bytes(1184)).decode()


# --- raw bytes -> dict ------------------------------------------------------


def test_parses_a_normal_object():
    assert parse_request_bytes(b'{"op":"audit","request_id":"r1"}') == {"op": "audit", "request_id": "r1"}


def test_read_request_reads_from_a_stream():
    assert read_request(io.BytesIO(b'{"op":"revoke","actor":"a"}'))["actor"] == "a"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"   ",
        b"{",
        b"[]",
        b'"text"',
        b"null",
        b"123",
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":1,"a":2}',  # duplicate keys
        b'{"a":{"b":1,"b":2}}',  # nested duplicate keys
        b"\xff\xfe\x00",  # not UTF-8
        b'{"a":"\xc3("}',  # truncated UTF-8 sequence
        b"\xef\xbb\xbf{}",  # BOM is not valid JSON
    ],
)
def test_rejects_malformed_documents(data):
    with pytest.raises(InputError):
        parse_request_bytes(data)


def test_rejects_input_over_the_size_cap():
    with pytest.raises(InputError):
        parse_request_bytes(b" " * 11, max_bytes=10)


def test_exactly_at_the_cap_is_accepted():
    body = b'{"a":1}'
    assert parse_request_bytes(body, max_bytes=len(body)) == {"a": 1}


def test_stream_reader_stops_reading_at_the_cap():
    requested: list[int] = []

    class Endless:
        """A stream that never ends; the reader must ask for at most max_bytes + 1."""

        def read(self, size=-1):
            requested.append(size)
            return b"a" * size

    with pytest.raises(InputError):
        read_request(Endless(), max_bytes=64)
    assert requested == [65]


def test_rejects_deep_nesting_without_recursing():
    deep = b"[" * 100000 + b"]" * 100000
    with pytest.raises(InputError):
        parse_request_bytes(deep)


def test_brackets_inside_strings_do_not_count_as_nesting():
    text = json.dumps({"op": "read", "actor": "[" * 500 + "{" * 500, "asset": "a", "request_id": "r"})
    assert parse_request_bytes(text.encode())["actor"].startswith("[")


def test_escaped_quote_inside_a_string_does_not_end_the_string():
    text = '{"a":"x\\"[[[[[[[[[[[[[[[[[[[[[[[[[[[["}'
    assert parse_request_bytes(text.encode())["a"].endswith("[")


# --- typed requests ------------------------------------------------------------


def test_read_request():
    got = validate_request({"op": "read", "actor": "maya", "asset": "brief", "request_id": "r01"})
    assert got == ReadRequest(actor="maya", asset="brief", request_id="r01")


def test_extra_fields_are_ignored():
    got = validate_request({"op": "revoke", "actor": "maya", "admin": True, "x": {"y": 1}})
    assert got == RevokeRequest(actor="maya")


def test_audit_request():
    assert validate_request({"op": "audit", "request_id": "r"}) == AuditRequest(request_id="r")


def test_unknown_operation_is_not_an_error():
    assert isinstance(validate_request({"op": "delete_everything"}), UnsupportedOperation)


@pytest.mark.parametrize("op", [None, 5, ["read"], {"a": 1}, "x" * 33])
def test_operation_must_be_a_short_string(op):
    with pytest.raises(InputError):
        validate_request({"op": op})


def test_missing_operation():
    with pytest.raises(InputError):
        validate_request({"actor": "a"})


@pytest.mark.parametrize(
    "request_",
    [
        {"op": "read", "asset": "a", "request_id": "r"},
        {"op": "read", "actor": "a", "request_id": "r"},
        {"op": "read", "actor": "a", "asset": "a"},
        {"op": "read", "actor": 1, "asset": "a", "request_id": "r"},
        {"op": "read", "actor": None, "asset": "a", "request_id": "r"},
        {"op": "read", "actor": ["a"], "asset": "a", "request_id": "r"},
        {"op": "revoke"},
        {"op": "revoke", "actor": {"x": 1}},
        {"op": "audit"},
        {"op": "audit", "request_id": 7},
    ],
)
def test_wrong_or_missing_fields_are_rejected(request_):
    with pytest.raises(InputError):
        validate_request(request_)


def test_identifiers_are_opaque_any_characters_are_accepted():
    weird = "line1\nline2\r\x00   ../../etc/passwd ‮ \U0001f600"
    got = validate_request({"op": "read", "actor": weird, "asset": weird, "request_id": weird})
    assert got.actor == weird == got.request_id


def test_identifier_length_cap_is_in_utf8_bytes():
    ok = "é" * (MAX_IDENTIFIER_BYTES // 2)  # 2 bytes each -> exactly the cap
    assert validate_request({"op": "revoke", "actor": ok}).actor == ok
    with pytest.raises(InputError):
        validate_request({"op": "revoke", "actor": ok + "é"})


def test_lone_surrogates_are_rejected():
    parsed = parse_request_bytes(b'{"op":"revoke","actor":"\\ud800"}')
    with pytest.raises(InputError):
        validate_request(parsed)


# --- setup ---------------------------------------------------------------------


def test_setup_full():
    got = validate_request(
        {"op": "setup", "owners": {"a": "u1"}, "contents": {"a": "body"}, "disabled": ["x", "x", "y"], "key_material": "s"}
    )
    assert got == SetupRequest(owners={"a": "u1"}, contents={"a": "body"}, disabled=("x", "y"))


def test_setup_defaults_and_key_material_is_never_kept():
    got = validate_request({"op": "setup", "owners": {"a": "u1"}})
    assert got.contents == {} and got.disabled == ()
    assert "key_material" not in repr(validate_request({"op": "setup", "owners": {}, "key_material": "TOP-SECRET"}))


@pytest.mark.parametrize(
    "request_",
    [
        {"op": "setup"},
        {"op": "setup", "owners": []},
        {"op": "setup", "owners": {"a": 1}},
        {"op": "setup", "owners": {"a": "u"}, "contents": {"a": 1}},
        {"op": "setup", "owners": {"a": "u"}, "contents": []},
        {"op": "setup", "owners": {"a": "u"}, "disabled": "x"},
        {"op": "setup", "owners": {"a": "u"}, "disabled": [1]},
        {"op": "setup", "owners": {"a": "u"}, "key_material": 5},
    ],
)
def test_setup_shape_errors(request_):
    with pytest.raises(InputError):
        validate_request(request_)


# --- protected_read ---------------------------------------------------------------


def _pr(**override):
    base = {"op": "protected_read", "actor": "a", "asset": "b", "challenge": "c", "public_key": GOOD_KEY}
    base.update(override)
    return base


def test_protected_read_ok():
    got = validate_request(_pr())
    assert isinstance(got, ProtectedReadRequest) and len(got.public_key) == 1184


@pytest.mark.parametrize(
    "public_key",
    [
        "",
        "not base64!!",
        base64.b64encode(bytes(1183)).decode(),
        base64.b64encode(bytes(1185)).decode(),
        GOOD_KEY[:-1],  # broken padding
        GOOD_KEY + "\n",  # trailing newline is not canonical
        base64.urlsafe_b64encode(bytes([251] * 1184)).decode(),  # URL-safe alphabet
        12345,
        None,
        ["x"],
    ],
)
def test_protected_read_rejects_bad_keys(public_key):
    if isinstance(public_key, str):
        # Not usable, but not rejected here: the service decides permission first.
        assert validate_request(_pr(public_key=public_key)).public_key is None
    else:
        with pytest.raises(InputError):
            validate_request(_pr(public_key=public_key))


def test_protected_read_requires_all_fields():
    for field in ("actor", "asset", "challenge", "public_key"):
        request = _pr()
        del request[field]
        with pytest.raises(InputError):
            validate_request(request)


def test_challenge_must_be_a_string():
    with pytest.raises(InputError):
        validate_request(_pr(challenge=5))
