"""Judge-style tests: a fresh process per request, a fresh state directory per scenario.

These drive ``track4_service.py`` exactly as the worker does. They need c2's
audit log and crypto modules, so on a branch that does not contain them they are
skipped (they run on the ``integration`` branch and in ``scripts/check_all.py``).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("t4.audit.log", reason="needs c2's audit log")
pytest.importorskip("t4.crypto.kem", reason="needs c2's crypto wrappers")
pytest.importorskip("t4.crypto.proof", reason="needs c2's crypto wrappers")
pytest.importorskip("t4.crypto.sig", reason="needs c2's crypto wrappers")

from pqcrypto.kem import ml_kem_768  # noqa: E402  (independent client side of the KEM)

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRY = REPO_ROOT / "track4_service.py"
GENERIC_STDERR = re.compile(rb"^Request failed \([a-z-]+\)\.\r?\n$")
MARKER = "KEY-MATERIAL-MARKER-9f3a61c2e7b4d058"


class Adapter:
    """Starts a new process for each call, like the judging worker."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.env = {**os.environ, "TRACK4_STATE_DIR": str(state_dir)}
        self.transcript: list[tuple[bytes, bytes]] = []

    def raw(self, data: bytes, timeout: float = 30) -> subprocess.CompletedProcess:
        done = subprocess.run(
            [sys.executable, "-B", str(ENTRY)], input=data, capture_output=True, cwd=REPO_ROOT, env=self.env, timeout=timeout
        )
        self.transcript.append((done.stdout, done.stderr))
        return done

    def call(self, **request) -> dict:
        done = self.raw(json.dumps(request).encode("utf-8"))
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout)


@pytest.fixture
def adapter(state_dir) -> Adapter:
    return Adapter(state_dir)


def provision(adapter: Adapter, **extra) -> None:
    owners = {"brief": "maya", "notes": "ravi"}
    contents = {"brief": "demo note", "notes": "ravi body"}
    reply = adapter.call(op="setup", owners=owners, contents=contents, disabled=["mallory"], key_material=MARKER, **extra)
    assert reply == {"ready": True}


# --- the lost-device story ---------------------------------------------------------------------


def test_lost_device_story_across_processes(adapter):
    provision(adapter)
    assert adapter.call(op="read", actor="maya", asset="brief", request_id="r01") == {"decision": "allow", "body": "demo note"}
    assert adapter.call(op="read", actor="ravi", asset="notes", request_id="r02") == {"decision": "allow", "body": "ravi body"}
    assert adapter.call(op="read", actor="maya", asset="notes", request_id="r03") == {"decision": "deny"}
    assert adapter.call(op="revoke", actor="maya") == {}
    assert adapter.call(op="read", actor="maya", asset="brief", request_id="r04") == {"decision": "deny"}
    assert adapter.call(op="audit", request_id="r04") == {"request_id": "r04", "decision": "deny", "rule": "POL-REVOKED"}
    assert adapter.call(op="read", actor="ravi", asset="notes", request_id="r05") == {"decision": "allow", "body": "ravi body"}


def test_unknown_operation_and_unknown_request(adapter):
    provision(adapter)
    assert adapter.call(op="format_disk") == {"error": "unsupported_operation"}
    assert adapter.call(op="audit", request_id="nope") == {"error": "unknown_request"}


def test_stdout_is_exactly_one_ascii_json_line(adapter):
    provision(adapter)
    done = adapter.raw(json.dumps({"op": "read", "actor": "maya", "asset": "brief", "request_id": "é😀"}).encode())
    assert done.returncode == 0 and done.stderr == b""
    done.stdout.decode("ascii")
    assert done.stdout.endswith(b"\n") and done.stdout.count(b"\n") == 1


def test_non_ascii_bodies_round_trip_exactly(adapter):
    body = "héllo wörld \U0001f600 \x00 end"
    adapter.call(op="setup", owners={"a": "u"}, contents={"a": body}, disabled=[])
    assert adapter.call(op="read", actor="u", asset="a", request_id="r") == {"decision": "allow", "body": body}


# --- protected_read: independent client side ----------------------------------------------------


def test_protected_read_round_trip_with_an_independent_client(adapter):
    adapter.call(op="setup", owners={"a": "maya"}, contents={"a": "bödy \U0001f600"}, disabled=[])
    public_key, secret_key = ml_kem_768.generate_keypair()
    challenge = "fresh-chällenge-\U0001f511"
    reply = adapter.call(
        op="protected_read", actor="maya", asset="a", challenge=challenge, public_key=base64.b64encode(public_key).decode()
    )
    assert set(reply) == {"ciphertext", "proof"}
    ciphertext = base64.b64decode(reply["ciphertext"], validate=True)
    assert len(ciphertext) == 1088
    shared = ml_kem_768.decrypt(secret_key, ciphertext)  # only the key holder can do this
    expected = hmac.new(shared, challenge.encode("utf-8") + "bödy \U0001f600".encode("utf-8"), hashlib.sha256).hexdigest()
    assert reply["proof"] == expected


def test_protected_read_after_revocation_is_a_plain_deny(adapter):
    provision(adapter)
    adapter.call(op="revoke", actor="maya")
    public_key, _ = ml_kem_768.generate_keypair()
    reply = adapter.call(
        op="protected_read", actor="maya", asset="brief", challenge="c", public_key=base64.b64encode(public_key).decode()
    )
    assert reply == {"decision": "deny"}


def test_protected_read_for_another_owners_asset_is_denied(adapter):
    provision(adapter)
    public_key, _ = ml_kem_768.generate_keypair()
    reply = adapter.call(
        op="protected_read", actor="ravi", asset="brief", challenge="c", public_key=base64.b64encode(public_key).decode()
    )
    assert reply == {"decision": "deny"}


def test_each_protected_read_uses_a_fresh_shared_secret(adapter):
    provision(adapter)
    public_key, secret_key = ml_kem_768.generate_keypair()
    request = dict(op="protected_read", actor="maya", asset="brief", challenge="same", public_key=base64.b64encode(public_key).decode())
    first, second = adapter.call(**request), adapter.call(**request)
    assert first["ciphertext"] != second["ciphertext"] and first["proof"] != second["proof"]
    assert ml_kem_768.decrypt(secret_key, base64.b64decode(first["ciphertext"])) != ml_kem_768.decrypt(
        secret_key, base64.b64decode(second["ciphertext"])
    )


# --- malformed input fails closed ------------------------------------------------------------------


MALFORMED = {
    "empty": b"",
    "not-json": b"{",
    "array": b"[]",
    "nan": b'{"op":"read","actor":NaN}',
    "duplicate-keys": b'{"op":"read","op":"revoke","actor":"a"}',
    "bad-utf8": b'{"op":"revoke","actor":"\xff"}',
    "lone-surrogate": b'{"op":"revoke","actor":"\\ud800"}',
    "wrong-type": b'{"op":"revoke","actor":123}',
    "missing-field": b'{"op":"read","actor":"a"}',
    "bad-op-type": b'{"op":["read"]}',
    "short-key": b'{"op":"protected_read","actor":"a","asset":"b","challenge":"c","public_key":"AAAA"}',
    "deep": b"[" * 50000 + b"]" * 50000,
    "too-big": b'{"op":"audit","request_id":"' + b"a" * (1024 * 1024) + b'"}',
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_input_is_refused_cleanly(adapter, name):
    provision(adapter)
    done = adapter.raw(MALFORMED[name])
    assert done.returncode == 1
    assert done.stdout == b""
    assert GENERIC_STDERR.match(done.stderr), done.stderr
    assert b"Traceback" not in done.stderr


def test_state_is_untouched_by_malformed_requests(adapter):
    provision(adapter)
    before = (adapter.state_dir / "state.json").read_bytes()
    adapter.raw(b"{")
    after = (adapter.state_dir / "state.json").read_bytes()
    # only the guard counter may change; policy data must not
    assert json.loads(before)["docs"]["assets"] == json.loads(after)["docs"]["assets"]
    assert json.loads(before)["docs"]["actors"] == json.loads(after)["docs"]["actors"]


def test_malformed_requests_before_setup_create_no_state(adapter):
    done = adapter.raw(b"{")
    assert done.returncode == 1
    assert not (adapter.state_dir / "state.json").exists()


def test_invalid_input_is_alerted_in_the_audit_log(adapter):
    provision(adapter)
    adapter.raw(b"{")
    logged = b"".join(p.read_bytes() for p in (adapter.state_dir / "audit").rglob("*") if p.is_file())
    assert b"AUD-INVALID-INPUT" in logged


# --- tampering ------------------------------------------------------------------------------------------


def test_a_tampered_state_file_fails_closed_and_is_alerted(adapter):
    provision(adapter)
    path = adapter.state_dir / "state.json"
    raw = bytearray(path.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    path.write_bytes(bytes(raw))
    done = adapter.raw(json.dumps({"op": "read", "actor": "maya", "asset": "brief", "request_id": "r"}).encode())
    assert done.returncode == 1 and done.stdout == b""
    assert GENERIC_STDERR.match(done.stderr)
    logged = b"".join(p.read_bytes() for p in (adapter.state_dir / "audit").rglob("*") if p.is_file())
    assert b"STO-INTEGRITY-FAILURE" in logged


def test_a_missing_state_key_never_grants_access(adapter):
    provision(adapter)
    (adapter.state_dir / "state.key").unlink()
    done = adapter.raw(json.dumps({"op": "read", "actor": "maya", "asset": "brief", "request_id": "r"}).encode())
    assert done.returncode == 1 and b"demo note" not in done.stdout


# --- secrets never leak -------------------------------------------------------------------------------------


def test_the_key_marker_is_never_in_any_output_or_stored_file(adapter):
    provision(adapter)
    adapter.call(op="read", actor="maya", asset="brief", request_id="r1")
    adapter.call(op="revoke", actor="maya")
    adapter.call(op="read", actor="maya", asset="brief", request_id="r2")
    adapter.call(op="audit", request_id="r2")
    adapter.raw(b"{")
    seen = b"".join(out + err for out, err in adapter.transcript)
    assert MARKER.encode() not in seen
    for path in adapter.state_dir.rglob("*"):
        if path.is_file():
            assert MARKER.encode() not in path.read_bytes(), path.name


def test_private_keys_are_never_printed(adapter):
    provision(adapter)
    seen = b"".join(out + err for out, err in adapter.transcript)
    key_hex = (adapter.state_dir / "state.key").read_text().strip().encode()
    assert key_hex not in seen
    audit_secret = (adapter.state_dir / "audit" / "audit.key").read_bytes()
    assert len(audit_secret) == 4032  # an ML-DSA-65 secret key
    for form in (audit_secret.hex().encode(), base64.b64encode(audit_secret)):
        assert form not in seen


def test_outputs_stay_far_below_the_64_kib_stream_cap(adapter):
    provision(adapter)
    for out, err in adapter.transcript:
        assert len(out) < 4096 and len(err) < 4096


# --- the operator's view (c2's audit CLI reading what the adapter wrote) -------------------------------


def _audit_cli(adapter: Adapter, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "t4.audit.cli", "--dir", str(adapter.state_dir / "audit"), *args],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=60,
    )


def test_the_operator_can_verify_explain_and_list_alerts(adapter):
    provision(adapter)
    adapter.call(op="read", actor="maya", asset="brief", request_id="r1")
    for i in range(5):
        adapter.call(op="read", actor="mallory", asset="brief", request_id=f"bad{i}")
    public_key, _ = ml_kem_768.generate_keypair()
    adapter.call(op="protected_read", actor="maya", asset="brief", challenge="trace-me", public_key=base64.b64encode(public_key).decode())

    verified = _audit_cli(adapter, "verify-log")
    assert verified.returncode == 0 and json.loads(verified.stdout)["ok"] is True

    explained = _audit_cli(adapter, "explain", "r1")
    assert explained.returncode == 0 and "POL-ALLOW-OWNER" in explained.stdout

    traced = _audit_cli(adapter, "explain", "--challenge", hashlib.sha256(b"trace-me").hexdigest())
    assert traced.returncode == 0 and "protected_read" in traced.stdout

    alerts = _audit_cli(adapter, "alerts")
    assert alerts.returncode == 0 and "GRD-REPEATED-DENIAL" in alerts.stdout
    alert = json.loads(alerts.stdout.strip().splitlines()[0])
    assert json.loads(alert["detail"]["entries"]) and json.loads(alert["detail"]["request_ids"]) == ["bad4"]


def test_editing_the_audit_log_is_caught_by_verify(adapter):
    provision(adapter)
    for i in range(3):
        adapter.call(op="read", actor="maya", asset="brief", request_id=f"r{i}")
    path = adapter.state_dir / "audit" / "audit.jsonl"
    path.write_bytes(path.read_bytes().replace(b'"allow"', b'"deny"', 1))
    verified = _audit_cli(adapter, "verify-log")
    assert verified.returncode == 1 and json.loads(verified.stdout)["ok"] is False


# --- concurrency ----------------------------------------------------------------------------------------------


def test_parallel_requests_lose_no_revocation_and_corrupt_nothing(adapter):
    provision(adapter)
    requests = [
        {"op": "read", "actor": "ravi", "asset": "notes", "request_id": f"par{i}"} for i in range(12)
    ] + [{"op": "revoke", "actor": "maya"}] + [
        {"op": "read", "actor": "maya", "asset": "brief", "request_id": f"mid{i}"} for i in range(6)
    ]
    procs = [
        subprocess.Popen([sys.executable, "-B", str(ENTRY)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=REPO_ROOT, env=adapter.env)
        for _ in requests
    ]
    outputs = [p.communicate(json.dumps(r).encode(), timeout=120) for p, r in zip(procs, requests)]
    assert [p.returncode for p in procs] == [0] * len(requests)
    for (out, _), request in zip(outputs, requests):
        reply = json.loads(out)
        if request["actor"] == "ravi":
            assert reply == {"decision": "allow", "body": "ravi body"}
    # the revocation survived the storm and the state still verifies
    assert adapter.call(op="read", actor="maya", asset="brief", request_id="after") == {"decision": "deny"}
    assert all(adapter.call(op="audit", request_id=f"par{i}")["decision"] == "allow" for i in range(12))


# --- official validator ----------------------------------------------------------------------------------------


def _toolkit() -> Path | None:
    candidates = [os.environ.get("TRACK4_TOOLKIT"), str(REPO_ROOT.parent / "Track-4-Toolkit")]
    for candidate in candidates:
        if candidate and (Path(candidate) / "validate.py").is_file():
            return Path(candidate)
    return None


def test_official_validator_passes():
    toolkit = _toolkit()
    if toolkit is None:
        pytest.skip("official toolkit not found (set TRACK4_TOOLKIT or clone it next to the repo)")
    done = subprocess.run(
        [sys.executable, str(toolkit / "validate.py"), "--entry", str(ENTRY)], capture_output=True, text=True, timeout=300
    )
    assert done.returncode == 0, done.stdout + done.stderr
