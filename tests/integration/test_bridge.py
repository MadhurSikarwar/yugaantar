"""The frontend bridge (tools/bridge.py) against the real adapter and node layer.

Nothing here is mocked: each test starts a synthetic world in a temporary folder, drives the
real ``track4_service.py`` process and the real ``t4.node`` modules, and checks what the
frontend would be shown. The HTTP tests start the real server on a random local port.
"""
from __future__ import annotations

import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from tools import bridge as bridge_module
from tools.bridge import BridgeError, Workspace, make_handler

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    workspace = Workspace(tmp_path_factory.mktemp("bridge"))
    yield workspace


@pytest.fixture()
def ws(world):
    world.start()  # a fresh synthetic world for every test
    return world


def act(ws, **body):
    return ws.act(body)


def test_a_new_world_is_consistent_and_every_log_verifies(ws):
    snap = ws.snapshot()
    assert snap["schemaVersion"] == 1
    assert {d["id"]: d["state"] for d in snap["devices"]} == {
        "eve-laptop": "active", "maya-phone": "active", "noor-tablet": "active"}
    assert {n["id"]: n["state"] for n in snap["nodes"]} == {
        "node-a": "current", "node-b": "current", "node-c": "current"}
    assert all(n["listVersion"] > 0 and len(n["deviceIds"]) == 3 for n in snap["nodes"])
    chains = [v for v in snap["verifications"] if v["kind"] == "audit-chain"]
    assert len(chains) == 6 and all(v["outcome"] == "valid" for v in chains)  # + the gateway log
    assert not any(v["outcome"] == "invalid" for v in snap["verifications"])


def test_lost_device_story_through_the_real_node_layer(ws):
    ok = act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")
    assert (ok["decision"], ok["rule"]) == ("allow", "NODE-ALLOW-OWNER")
    other = act(ws, name="request", device_id="noor-tablet", node_id="node-a", asset="plan")
    assert other["decision"] == "deny"

    act(ws, name="revoke_device", device_id="maya-phone")
    # Until a list is delivered the node does not know: the bounded window, not instant.
    assert act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")["decision"] == "allow"
    act(ws, name="deliver")
    denied = act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")
    assert (denied["decision"], denied["rule"]) == ("deny", "NODE-DEVICE-REVOKED")
    assert act(ws, name="request", device_id="noor-tablet", node_id="node-b", asset="budget")["decision"] == "allow"

    snap = ws.snapshot()
    assert {d["id"]: d["state"] for d in snap["devices"]}["maya-phone"] == "revoked"
    rules = {(row["actor"], row["rule"]) for row in snap["audit"] if row["decision"] == "deny"}
    assert ("maya", "NODE-DEVICE-REVOKED") in rules


def test_an_offline_node_goes_stale_and_denies_everyone(ws):
    act(ws, name="set_offline", node_id="node-c", offline=True)
    assert act(ws, name="deliver")["accepted"] == {"node-a": True, "node-b": True, "node-c": False}
    states = {n["id"]: n["state"] for n in ws.snapshot()["nodes"]}
    assert states["node-c"] == "offline"
    act(ws, name="advance", seconds=70)  # past T = 60 s
    stale = act(ws, name="request", device_id="noor-tablet", node_id="node-c", asset="budget")
    assert (stale["decision"], stale["rule"]) == ("deny", "NODE-STALE-LIST")
    states = {n["id"]: n["state"] for n in ws.snapshot()["nodes"]}
    assert states["node-a"] == "stale" and states["node-c"] == "offline"
    act(ws, name="set_offline", node_id="node-c", offline=False)
    act(ws, name="deliver")
    assert {n["id"]: n["state"] for n in ws.snapshot()["nodes"]} == {
        "node-a": "current", "node-b": "current", "node-c": "current"}


def test_a_request_changed_after_signing_is_refused_and_reported(ws):
    forged = act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan", tamper=True)
    assert (forged["decision"], forged["rule"]) == ("deny", "NODE-BAD-SIGNATURE")
    checks = {v["id"]: v for v in ws.snapshot()["verifications"]}
    assert checks["signatures-node-a"]["outcome"] == "invalid"


def test_the_judged_adapter_is_called_for_real(ws):
    assert ws.call_adapter({"op": "read", "actor": "maya", "asset": "plan", "request_id": "r1"}) == {
        "decision": "allow", "body": "synthetic plan"}
    assert ws.call_adapter({"op": "revoke", "actor": "maya"}) == {}
    assert ws.call_adapter({"op": "read", "actor": "maya", "asset": "plan", "request_id": "r2"}) == {
        "decision": "deny"}
    assert ws.call_adapter({"op": "audit", "request_id": "r2"})["rule"] == "POL-REVOKED"
    rows = [r for r in ws.snapshot()["audit"] if r["action"] == "read"]
    assert [(r["actor"], r["decision"], r["rule"]) for r in rows] == [
        ("maya", "allow", "POL-ALLOW-OWNER"), ("maya", "deny", "POL-REVOKED")]


def test_protected_read_proof_is_checked_like_an_independent_client(ws):
    assert act(ws, name="protected_check", actor="noor", asset="budget")["outcome"] == "valid"
    assert act(ws, name="protected_check", actor="maya", asset="budget")["outcome"] == "not-checked"
    results = [v for v in ws.snapshot()["verifications"] if v["kind"] == "protected-read"]
    assert [v["outcome"] for v in results] == ["valid", "not-checked"]


def test_key_rotation_and_a_new_device(ws):
    act(ws, name="enroll", device_id="maya-laptop", owner="maya")
    act(ws, name="rotate", device_id="noor-tablet")
    snap = ws.snapshot()
    assert "maya-laptop" in {d["id"] for d in snap["devices"]}
    # The new key is not active until its activation time, so the version shown is still 1.
    assert {d["id"]: d["keyVersion"] for d in snap["devices"]}["noor-tablet"] == 1
    act(ws, name="advance", seconds=300)
    assert {d["id"]: d["keyVersion"] for d in ws.snapshot()["devices"]}["noor-tablet"] == 2


@pytest.mark.parametrize(
    "body",
    [
        {"name": "nope"},
        {"name": "advance", "seconds": -1},
        {"name": "advance", "seconds": 0},
        {"name": "advance", "seconds": True},
        {"name": "advance", "seconds": 10**9},
        {"name": "enroll", "device_id": "../escape", "owner": "maya"},
        {"name": "enroll", "device_id": "maya-phone", "owner": "maya"},
        {"name": "request", "device_id": "ghost", "node_id": "node-a", "asset": "plan"},
        {"name": "request", "device_id": "maya-phone", "node_id": "node-z", "asset": "plan"},
        {"name": "request", "device_id": "maya-phone", "node_id": "node-a", "asset": ""},
        {"name": "set_offline", "node_id": "node-a", "offline": "yes"},
        {"name": "deliver", "nodes": ["node-a", 7]},
        {"name": "protected_check", "actor": "maya", "asset": "no-such-file"},
    ],
)
def test_bad_actions_are_refused_with_a_fixed_label(ws, body):
    with pytest.raises(BridgeError) as error:
        ws.act(body)
    assert error.value.status == 400 and error.value.label.replace("_", "").isalpha()


def test_only_the_five_adapter_operations_are_reachable(ws):
    for request in ({"op": "dump_state"}, {"op": 7}, {}, [], "read"):
        with pytest.raises(BridgeError):
            ws.call_adapter(request)
    with pytest.raises(BridgeError) as error:  # the adapter itself refuses a malformed request
        ws.call_adapter({"op": "read", "actor": 1, "asset": "plan", "request_id": "x"})
    assert error.value.label == "adapter_refused_request"


def test_a_tampered_log_is_reported_invalid_by_the_backends_verifier(ws):
    act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")
    path = ws.base / "logs" / "node-a" / "audit.jsonl"
    data = path.read_bytes()
    assert b'"accept"' in data
    path.write_bytes(data.replace(b'"accept"', b'"reject"', 1))
    checks = {v["id"]: v for v in ws.snapshot()["verifications"]}
    assert checks["chain-node-a"]["outcome"] == "invalid"
    assert checks["chain-node-b"]["outcome"] == "valid"


def test_not_started_refuses_everything(tmp_path):
    fresh = Workspace(tmp_path / "w")
    for call in (fresh.snapshot, lambda: fresh.act({"name": "deliver"}),
                 lambda: fresh.call_adapter({"op": "audit", "request_id": "x"})):
        with pytest.raises(BridgeError) as error:
            call()
        assert error.value.status == 409


def test_a_workspace_folder_that_holds_files_is_never_adopted(tmp_path):
    (tmp_path / "important.txt").write_text("mine")
    with pytest.raises(BridgeError):
        Workspace(tmp_path)
    assert (tmp_path / "important.txt").read_text() == "mine"


# ------------------------------------------------------------------ HTTP ---


@pytest.fixture()
def http_server(ws, tmp_path):
    static = tmp_path / "dist"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>t</title>")
    (tmp_path / "secret.txt").write_text("outside the static folder")
    allowed: set[str] = set()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(ws, static, allowed))
    port = server.server_address[1]
    allowed.update({f"127.0.0.1:{port}", f"localhost:{port}"})
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    server.server_close()


def fetch(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, dict(response.getheaders()), data


JSON = {"Content-Type": "application/json"}


def test_http_serves_snapshot_actions_and_the_built_page(http_server):
    status, headers, data = fetch(http_server, "GET", "/api/health")
    assert status == 200 and json.loads(data) == {"ok": True, "started": True}
    assert "Access-Control-Allow-Origin" not in headers  # no CORS: other sites cannot read answers
    assert headers["Cache-Control"] == "no-store" and "Content-Security-Policy" in headers
    status, _, data = fetch(http_server, "GET", "/api/snapshot")
    assert status == 200 and json.loads(data)["schemaVersion"] == 1
    status, _, data = fetch(http_server, "POST", "/api/action", json.dumps(
        {"name": "request", "device_id": "maya-phone", "node_id": "node-a", "asset": "plan"}), JSON)
    assert status == 200 and json.loads(data)["rule"] == "NODE-ALLOW-OWNER"
    status, _, data = fetch(http_server, "POST", "/api/adapter", json.dumps(
        {"op": "read", "actor": "noor", "asset": "plan", "request_id": "h1"}), JSON)
    assert status == 200 and json.loads(data) == {"decision": "deny"}
    status, headers, data = fetch(http_server, "GET", "/#/console")
    assert status == 200 and b"<title>t</title>" in data and headers["Content-Type"].startswith("text/html")


def test_http_refuses_a_foreign_host_origin_and_content_type(http_server):
    body = json.dumps({"name": "deliver"})
    assert fetch(http_server, "GET", "/api/health", headers={"Host": "evil.example"})[0] == 403
    assert fetch(http_server, "POST", "/api/action", body, {**JSON, "Origin": "http://evil.example"})[0] == 403
    assert fetch(http_server, "POST", "/api/action", body, {"Content-Type": "text/plain"})[0] == 415
    assert fetch(http_server, "POST", "/api/action", "not json", JSON)[0] == 400
    assert fetch(http_server, "POST", "/api/action", "[]", JSON)[0] == 400
    assert fetch(http_server, "POST", "/api/nope", "{}", JSON)[0] == 404
    assert fetch(http_server, "GET", "/api/nope")[0] == 404


def test_a_refused_post_is_always_answered_never_reset(http_server):
    # Answering before reading the body made Windows reset the connection now and then.
    body = json.dumps({"name": "deliver", "pad": "x" * 200_000})
    for _ in range(40):
        assert fetch(http_server, "POST", "/api/action", body, {**JSON, "Origin": "http://evil.example"})[0] == 403
        assert fetch(http_server, "POST", "/api/action", body, {"Content-Type": "text/plain"})[0] == 415
        assert fetch(http_server, "POST", "/api/nope", body, JSON)[0] == 404


def test_http_limits_the_request_size(http_server):
    big = json.dumps({"name": "deliver", "pad": "x" * (bridge_module.MAX_BODY + 10)})
    assert fetch(http_server, "POST", "/api/action", big, JSON)[0] == 413


def test_http_never_serves_files_outside_the_static_folder(http_server):
    status, _, data = fetch(http_server, "GET", "/..%2fsecret.txt")
    assert b"outside the static folder" not in data
    status, _, data = fetch(http_server, "GET", "/../secret.txt")
    assert b"outside the static folder" not in data


def test_http_adapter_errors_carry_only_a_label(http_server):
    status, _, data = fetch(http_server, "POST", "/api/adapter", json.dumps(
        {"op": "read", "actor": 1, "asset": "plan", "request_id": "x"}), JSON)
    assert status == 422 and json.loads(data) == {"error": "adapter_refused_request"}


# -- every backend feature reachable from the console -------------------------


def test_adapter_audit_explain_and_setup_again(ws):
    ws.call_adapter({"op": "read", "actor": "maya", "asset": "plan", "request_id": "ui-1"})
    assert ws.call_adapter({"op": "audit", "request_id": "ui-1"})["rule"] == "POL-ALLOW-OWNER"
    rows = act(ws, name="explain", request_id="ui-1")["rows"]
    assert [(r["log"], r["rule"]) for r in rows] == [("adapter", "POL-ALLOW-OWNER")]
    act(ws, name="setup", disabled=["noor"])
    assert ws.call_adapter({"op": "read", "actor": "noor", "asset": "budget", "request_id": "ui-2"}) == {"decision": "deny"}
    assert ws.call_adapter({"op": "audit", "request_id": "ui-2"})["rule"] == "POL-DISABLED"


def test_grants_reach_nodes_and_the_detector_flags_the_unapproved_one(ws):
    act(ws, name="grant", actor="eve", asset="budget", approved=False)
    act(ws, name="grant", actor="noor", asset="plan", approved=True)
    act(ws, name="deliver")
    assert act(ws, name="request", device_id="eve-laptop", node_id="node-b", asset="budget")["rule"] == "NODE-ALLOW-GRANT"
    assert act(ws, name="request", device_id="noor-tablet", node_id="node-a", asset="plan")["rule"] == "NODE-ALLOW-GRANT"
    for node_id in ("node-a", "node-c"):
        act(ws, name="request", device_id="eve-laptop", node_id=node_id, asset="plan")
    found = {(r["rule"], r["identity"]) for r in act(ws, name="detect")["rows"]}
    assert ("DET-UNAPPROVED-ROLE-CHANGE", "eve") in found
    assert ("DET-LATERAL-MOVEMENT", "eve") in found
    assert not any(identity == "noor" for _rule, identity in found)
    alerts = {r["rule"] for r in act(ws, name="alerts")["rows"]}
    assert "DET-UNAPPROVED-ROLE-CHANGE" in alerts
    act(ws, name="ungrant", actor="eve", asset="budget")
    act(ws, name="deliver")
    assert act(ws, name="request", device_id="eve-laptop", node_id="node-b", asset="budget")["decision"] == "deny"


def test_a_restore_keeps_a_revocation_made_after_the_backup(ws):
    act(ws, name="backup")
    act(ws, name="revoke_actor", actor="maya")
    act(ws, name="restore")
    act(ws, name="deliver")
    assert act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")["rule"] == "NODE-ACTOR-REVOKED"


def test_pins_verify_and_a_tampered_log_is_caught_and_refused_by_the_detector(ws):
    act(ws, name="request", device_id="eve-laptop", node_id="node-a", asset="plan")
    pinned = act(ws, name="pin")["rows"]
    assert all(r["pinned"] == "yes" for r in pinned)
    assert all(r["result"] == "ok" for r in act(ws, name="verify")["rows"])
    act(ws, name="tamper", log="node-a")
    rows = {r["log"]: r for r in act(ws, name="verify")["rows"]}
    assert rows["node-a"]["result"] == "FAILED" and rows["node-a"]["first_bad_entry"] != ""
    assert rows["node-b"]["result"] == "ok"
    with pytest.raises(BridgeError) as error:
        act(ws, name="detect")
    assert error.value.label == "detector_refused_a_log_that_does_not_verify"
    assert "pin" in {v["id"]: v for v in ws.snapshot()["verifications"]}["chain-node-b"]["detail"]


def test_health_reports_a_consistent_state(ws):
    rows = act(ws, name="health")["rows"]
    assert rows[0]["result"] == "ok" and rows[1]["result"] == "ok"


@pytest.mark.parametrize(
    "body",
    [
        {"name": "grant", "actor": "eve", "asset": "payroll"},
        {"name": "grant", "actor": "Eve!", "asset": "plan"},
        {"name": "revoke_actor", "actor": ""},
        {"name": "explain", "request_id": ""},
        {"name": "tamper", "log": "../state"},
        {"name": "setup", "disabled": ["mallory"]},
    ],
)
def test_bad_operator_actions_are_refused_with_a_fixed_label(ws, body):
    with pytest.raises(BridgeError) as error:
        ws.act(body)
    assert error.value.status == 400


def test_the_messaging_demo_hides_the_text_and_refuses_a_replay(ws):
    pytest.importorskip("cryptography")
    rows = act(ws, name="message", sender="noor", recipient="maya", text="meet at noon")["rows"]
    assert [r["result"] for r in rows] == ["text hidden", "delivered: text matches", "refused"]


def test_snapshot_shows_grants_and_alerts_and_pins_are_files(ws):
    act(ws, name="grant", actor="eve", asset="budget", approved=False)
    act(ws, name="grant", actor="noor", asset="plan", approved=True)
    for _ in range(5):
        ws.call_adapter({"op": "read", "actor": "eve", "asset": "plan", "request_id": "x"})
    snap = ws.snapshot()
    grants = {(g["actor"], g["asset"]): g.get("approvalId") for g in snap["grants"]}
    assert grants == {("eve", "budget"): None, ("noor", "plan"): "chg-1"}
    assert any(a["rule"] == "GRD-REPEATED-DENIAL" and a["source"] == "adapter" for a in snap["alerts"])
    act(ws, name="pin")
    pins = sorted(p.name for p in ws.pins_dir.iterdir())
    assert pins == ["adapter.json", "authority.json", "gateway.json", "node-a.json", "node-b.json", "node-c.json"]
    for log_dir in ws._log_dirs().values():  # pins are never kept inside a log folder
        assert log_dir.resolve() not in ws.pins_dir.resolve().parents and log_dir.resolve() != ws.pins_dir.resolve()
    pin = json.loads((ws.pins_dir / "node-a.json").read_text())
    assert pin["public_key"] and pin["seq"] >= 1


def test_one_key_version_is_revoked_on_every_node_and_survives_a_restore(ws):
    act(ws, name="backup")
    act(ws, name="revoke_key", device_id="noor-tablet")
    act(ws, name="restore")  # the vault ledger re-applies the key revocation
    act(ws, name="deliver")
    for node_id in ("node-a", "node-b"):
        assert act(ws, name="request", device_id="noor-tablet", node_id=node_id, asset="budget")["rule"] == "NODE-KEY-REVOKED"
    # Only that key: the device is still enrolled, and other devices are untouched.
    assert act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")["decision"] == "allow"
    assert {d["id"]: d["state"] for d in ws.snapshot()["devices"]}["noor-tablet"] == "active"
    # Rotating to a new version restores access once the new key is active.
    act(ws, name="rotate", device_id="noor-tablet")
    act(ws, name="advance", seconds=70)
    act(ws, name="deliver")
    assert act(ws, name="request", device_id="noor-tablet", node_id="node-a", asset="budget")["decision"] == "allow"


def test_the_console_runs_the_adapter_with_the_strict_challenge_policy(ws):
    assert act(ws, name="protected_check", actor="maya", asset="plan")["outcome"] == "valid"


def test_the_gateway_authenticates_callers_in_front_of_the_real_adapter(ws):
    ok = act(ws, name="gateway", caller="maya-app", op="read", actor="maya", asset="plan")
    assert ok["rows"][0]["rule"] == "GW-FORWARDED" and '"allow"' in ok["rows"][0]["reply"]
    assert act(ws, name="gateway", caller="maya-app", op="read", actor="noor", asset="budget")["rows"][0]["rule"] == "GW-ACTOR-MISMATCH"
    assert act(ws, name="gateway", caller="maya-app", op="read", actor="maya", asset="plan",
               wrong_key=True)["rows"][0]["rule"] == "GW-BAD-SIGNATURE"
    act(ws, name="gateway", caller="noor-app", op="read", actor="noor", asset="budget")
    assert act(ws, name="gateway", replay=True)["rows"][0]["rule"] == "GW-REPLAY"
    assert act(ws, name="gateway", caller="maya-app", op="revoke", actor="noor")["rows"][0]["rule"] == "GW-NOT-PERMITTED"
    assert act(ws, name="gateway", caller="ops-console", op="revoke", actor="noor")["rows"][0]["rule"] == "GW-FORWARDED"
    rows = act(ws, name="review", alert_id="authority-7", verdict="reject", reason="no approval on record")["rows"]
    assert rows == [{"alert": "authority-7", "verdict": "reject", "reviewer": "reviewer-ana",
                     "signature": "valid", "why": "no approval on record"}]
    assert {v["id"]: v["outcome"] for v in ws.snapshot()["verifications"]}["chain-gateway"] == "valid"


def test_the_session_demo_covers_loss_reordering_restart_and_forward_secrecy(ws):
    pytest.importorskip("cryptography")
    rows = {r["step"]: r["result"] for r in act(ws, name="session")["rows"]}
    assert rows["receiver reports missing"] == "[2]"
    assert rows["resend of 2"] == "two"
    assert rows["the original 2 arrives late"] == "refused"
    assert rows["forward secrecy"] == "prekey secrets of delivered messages deleted"


def test_a_log_is_archived_and_keeps_verifying(ws):
    act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")
    row = act(ws, name="archive", log="node-a")["rows"][0]
    assert row["segment"] == 1 and row["archived_to_entry"] >= 2
    act(ws, name="request", device_id="maya-phone", node_id="node-a", asset="plan")
    assert {r["log"]: r["result"] for r in act(ws, name="verify")["rows"]}["node-a"] == "ok"


def test_revoking_a_key_version_raises_no_detector_alert_against_the_authority(ws):
    act(ws, name="revoke_key", device_id="eve-laptop")
    act(ws, name="deliver")
    assert not any(r["identity"] == "authority" for r in act(ws, name="detect")["rows"])


def test_replay_resends_the_last_genuine_gateway_request(ws):
    act(ws, name="gateway", caller="maya-app", op="read", actor="maya", asset="plan")
    act(ws, name="gateway", caller="maya-app", op="read", actor="maya", asset="plan", wrong_key=True)
    assert act(ws, name="gateway", replay=True)["rows"][0]["rule"] == "GW-REPLAY"
