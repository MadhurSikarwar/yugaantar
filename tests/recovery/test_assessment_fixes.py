"""Regression tests for the fixes made after the independent assessment.

Each test names the defect it pins down. Synthetic data, temporary folders, disposable keys.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from t4.audit.log import AuditLog, load_or_create_signer
from t4.audit.verify import verify_log
from t4.node.authority import Authority
from t4.node.common import NodeError, load_signer, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_800_000_000.0
T, S = 60.0, 2.0


def _append(log: AuditLog, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        log.append(actor="u", action="read", target="x", decision="allow", rule="R", request_id=f"r{i}")


# -- F-00: a crash between an entry and its scheduled checkpoint must not stop the service ------------

def test_missing_scheduled_checkpoint_is_re_signed_and_appends_continue(tmp_path):
    d = tmp_path / "log"
    log = AuditLog(d, load_or_create_signer(d))  # checkpoint every 16, as the adapter uses
    _append(log, 32)
    # Simulate the crash: entry 32 is on disk, its checkpoint never was.
    lines = (d / "checkpoints.jsonl").read_bytes().splitlines(keepends=True)
    assert json.loads(lines[-1])["seq"] == 32
    (d / "checkpoints.jsonl").write_bytes(b"".join(lines[:-1]))
    _append(log, 3, start=32)  # the window no longer reaches the older anchor
    _append(log, 40, start=35)  # and the service keeps working afterwards
    report = verify_log(d)
    assert report.ok and report.entries == 75
    seqs = [json.loads(l)["seq"] for l in (d / "checkpoints.jsonl").read_text().splitlines()]
    assert 33 in seqs or 34 in seqs or 35 in seqs  # the missed anchor was re-signed after a full check


def test_missing_checkpoint_never_hides_an_edit(tmp_path):
    d = tmp_path / "log"
    log = AuditLog(d, load_or_create_signer(d))
    _append(log, 32)
    lines = (d / "checkpoints.jsonl").read_bytes().splitlines(keepends=True)
    (d / "checkpoints.jsonl").write_bytes(b"".join(lines[:-1]))
    _append(log, 3, start=32)
    raw = (d / "audit.jsonl").read_bytes().split(b"\n")
    raw[20] = raw[20].replace(b'"decision":"allow"', b'"decision":"deny"')
    (d / "audit.jsonl").write_bytes(b"\n".join(raw))
    from t4.audit.log import AuditIntegrityError
    with pytest.raises(AuditIntegrityError):
        _append(log, 1, start=99)


# -- export: convert exactly the snapshot that was verified --------------------------------------------

def _node_world(base: Path):
    sig = load_signer()
    auth = Authority.create(base / "authority", sig, open_log(base / "authority" / "log"), freshness=T, skew=S)
    node = Node.provision(base / "node", sig, open_log(base / "node" / "log"), node_id="n",
                          authority_pk=auth.public_key, owners={"a": "maya"}, contents={"a": "body"},
                          freshness=T, skew=S)
    dev = Device.create(base / "dev", sig, "phone", "maya")
    dev.enroll(auth, NOW)
    node.accept_list(auth.issue_list(NOW), NOW)
    for i in range(3):
        respond(node, dev.make_request("n", "a", NOW + 1 + i), NOW + 1 + i)
    return sig, auth, node, dev


def test_export_converts_the_verified_snapshot_not_a_later_substitute(tmp_path, monkeypatch):
    from t4.detect import export as exp
    from t4.audit import verify as verify_mod

    _node_world(tmp_path)
    node_log = tmp_path / "node" / "log"
    pin = AuditLog(node_log, load_or_create_signer(node_log)).head()
    key = (node_log / "audit.pub").read_bytes()
    real_verify = verify_mod.verify_log
    substitute = tmp_path / "evil"

    def verify_then_swap(directory, pinned_head=None, pinned_public_key=None):
        report = real_verify(directory, pinned_head, pinned_public_key)
        # After verification, an attacker replaces the LIVE log with a self-consistent forgery.
        if not substitute.exists():
            forged = AuditLog(substitute, load_or_create_signer(substitute), checkpoint_every=1)
            for i in range(9):
                forged.append(actor="maya", action="read", target="other", decision="deny", rule="NODE-NOT-PERMITTED",
                              request_id=f"f{i}", detail={"node_id": "n", "device_id": "phone",
                                                          "signature_verified": True})
            for name in ("audit.jsonl", "checkpoints.jsonl"):
                (node_log / name).write_bytes((substitute / name).read_bytes())
        return report

    monkeypatch.setattr(verify_mod, "verify_log", verify_then_swap)
    result = exp.run_export([exp.LogSource(node_log, "node", "n", pin, key)], {})
    targets = {row["target_service"] for row in result.rows}
    assert targets == {"n/a"}  # only the verified entries, never the substituted ones
    assert result.verified[0]["verified"] == "snapshot"


@pytest.mark.parametrize("attack", ["truncate", "drop_checkpoints", "new_key"])
def test_export_refuses_damaged_or_rekeyed_logs(tmp_path, attack):
    from t4.detect import export as exp

    _node_world(tmp_path)
    node_log = tmp_path / "node" / "log"
    pin = AuditLog(node_log, load_or_create_signer(node_log)).head()
    key = (node_log / "audit.pub").read_bytes()
    if attack == "truncate":
        lines = (node_log / "audit.jsonl").read_bytes().splitlines(keepends=True)
        (node_log / "audit.jsonl").write_bytes(b"".join(lines[:-2]))
    elif attack == "drop_checkpoints":
        (node_log / "checkpoints.jsonl").write_bytes(b"")
        lines = (node_log / "audit.jsonl").read_bytes().splitlines(keepends=True)
        (node_log / "audit.jsonl").write_bytes(b"".join(lines[:-1]))
    else:
        import shutil
        shutil.rmtree(node_log)
        forged = AuditLog(node_log, load_or_create_signer(node_log), checkpoint_every=1)
        _append(forged, 3)
    with pytest.raises(exp.ExportError):
        exp.run_export([exp.LogSource(node_log, "node", "n", pin, key)], {})


def test_export_labels_an_inferred_baseline(tmp_path):
    from t4.detect import export as exp

    _node_world(tmp_path)
    src = [exp.LogSource(tmp_path / "node" / "log", "node", "n")]
    assert exp.run_export(src, {}).baseline_source == "inferred"
    assert exp.run_export(src, {}, owners={"n": {"a": "maya"}}).baseline_source == "provisioning"


# -- rotation: committed cutoff, device and audit agree after an interrupted publication -------------

def test_rotation_interrupted_after_audit_then_rescheduled_agrees_everywhere(tmp_path, monkeypatch):
    from t4.node import state as node_state

    sig = load_signer()
    auth_log = tmp_path / "authority" / "log"
    auth = Authority.create(tmp_path / "authority", sig, open_log(auth_log), freshness=T, skew=S)
    node = Node.provision(tmp_path / "node", sig, open_log(tmp_path / "node" / "log"), node_id="n",
                          authority_pk=auth.public_key, owners={"a": "maya"}, contents={"a": "body"},
                          freshness=T, skew=S)
    dev = Device.create(tmp_path / "dev", sig, "phone", "maya")
    dev.enroll(auth, NOW)
    first_cutoff = NOW + 1 + T + S + 5

    real_write = node_state.FileStore._write
    calls = {"n": 0}

    def crash_authority_save(self, key, version, records):
        # The authority's state save fails once, AFTER the rotation entry reached the audit log.
        if "authority" in records and calls["n"] == 0 and any(
                len(d["keys"]) > 1 for d in records["authority"]["devices"].values()):
            calls["n"] += 1
            raise OSError("simulated crash before the authority state was saved")
        return real_write(self, key, version, records)

    monkeypatch.setattr(node_state.FileStore, "_write", crash_authority_save)
    with pytest.raises(OSError):
        dev.rotate(auth, NOW + 1, first_cutoff)
    monkeypatch.setattr(node_state.FileStore, "_write", real_write)
    logged = [e for e in AuditLog(auth_log, None).entries() if e["action"] == "rotate"]
    assert len(logged) == 1 and logged[0]["detail"]["activate_at"] == repr(first_cutoff)
    assert len(auth._record()["devices"]["phone"]["keys"]) == 1  # never committed

    # The device retries much later: the original cutoff is no longer far enough ahead.
    later = first_cutoff - 10
    new_cutoff = later + T + S + 5
    accepted = dev.rotate(auth, later, new_cutoff)
    assert accepted == new_cutoff
    committed = auth._record()["devices"]["phone"]["keys"][-1]["activate_at"]
    device_cutoff = dev.info()["keys"]["2"]["activate_at"]
    entries = AuditLog(auth_log, None).entries()
    rotate = [e for e in entries if e["action"] == "rotate"]
    resched = [e for e in entries if e["action"] == "rotate_reschedule"]
    assert committed == device_cutoff == new_cutoff
    assert len(rotate) == 1  # the original signed entry is untouched
    assert len(resched) == 1 and resched[0]["detail"]["activate_at"] == repr(new_cutoff)
    assert resched[0]["detail"]["replaces_activate_at"] == repr(first_cutoff)
    # Retrying again logs nothing new.
    dev.rotate(auth, later + 1, new_cutoff) if not dev.info()["keys"]["2"]["published"] else None
    assert len([e for e in AuditLog(auth_log, None).entries() if e["action"].startswith("rotate")]) == 2
    # Every node enforces the COMMITTED cutoff: old key refused from it, never earlier.
    node.accept_list(auth.issue_list(new_cutoff - 1), new_cutoff - 1)
    assert respond(node, dev.make_request("n", "a", new_cutoff - 0.5), new_cutoff - 0.5)["decision"] == "allow"
    from t4 import rotation
    from t4.node.common import b64d
    from t4.node.request import sign_request
    old_sk = b64d(rotation.recover(dev.store)["keys"]["1"]["sk"])
    stale = sign_request(old_sk, {"node_id": "n", "device_id": "phone", "key_version": 1, "actor": "maya",
                                  "action": "read", "asset": "a", "nonce": "x1", "issued_at": new_cutoff + 0.5},
                         signer=sig)
    assert respond(node, stale, new_cutoff + 0.5)["decision"] == "deny"


# -- detector: an alert never claims emission before the evidence it cites ----------------------------

def test_alert_separates_initial_evidence_from_later_evidence():
    from t4.detect import engine
    from t4.detect.ingest import parse_events

    header = ("event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,source_service,"
              "target_service,action,role_before,role_after,outcome,approval_id,session_id,correlation_id\n")
    rows = [
        "e1,2026-01-15T09:04:00.000Z,2026-01-15T09:04:00.100Z,0,w,reports,billing,read,service-reader,service-reader,deny,,s,f",
        "e2,2026-01-15T09:04:02.000Z,2026-01-15T09:04:02.100Z,0,w,billing,archive,read,service-reader,service-reader,deny,,s,f",
        # e3 happened before the chain completed but ARRIVES 50 s later
        "e3,2026-01-15T09:04:03.000Z,2026-01-15T09:04:53.000Z,0,w,archive,identity,list_roles,service-reader,service-reader,deny,,s,f",
    ]
    result = engine.analyze(parse_events(header + "\n".join(rows) + "\n"), {})
    [alert] = [a for a in result.alerts if a.rule == "DET-LATERAL-MOVEMENT"]
    assert set(alert.event_ids) == {"e1", "e2", "e3"}
    assert alert.emitted_at == "2026-01-15T09:04:02.100Z"
    assert set(alert.initial_event_ids) == {"e1", "e2"}  # e3 had not arrived at emission
    assert alert.evidence_complete_at == "2026-01-15T09:04:53.000Z"
    d = alert.to_dict()
    assert d["timing_basis"] == engine.TIMING_BASIS
    by_id = {e.event_id: e for e in result.events}
    for event_id in alert.initial_event_ids:
        assert by_id[event_id].received_time <= by_id["e2"].received_time
    assert by_id["e3"].event_time_utc == "2026-01-15T09:04:03.000Z"  # raw time preserved


# -- adapter: setup raises the epoch, so a state file from an earlier generation is refused -----------

def _call(state: Path, request: dict) -> subprocess.CompletedProcess:
    env = {**os.environ, "TRACK4_STATE_DIR": str(state), "TMPDIR": str(state)}
    return subprocess.run([sys.executable, "-B", str(ROOT / "track4_service.py")], input=json.dumps(request).encode(),
                          cwd=ROOT, env=env, capture_output=True)


def test_state_file_from_an_earlier_generation_is_refused(tmp_path):
    from t4.store import locate_state_dir

    setup = {"op": "setup", "owners": {"x": "alice"}, "contents": {"x": "old"}, "disabled": [], "key_material": "k"}
    assert _call(tmp_path, setup).returncode == 0
    state_file = locate_state_dir(tmp_path) / "state.json"
    first_generation = state_file.read_bytes()
    assert _call(tmp_path, {**setup, "owners": {"x": "bob"}, "contents": {"x": "new"}}).returncode == 0
    state_file.write_bytes(first_generation)
    p = _call(tmp_path, {"op": "read", "actor": "alice", "asset": "x", "request_id": "r"})
    assert p.returncode == 1 and p.stdout == b"" and b"state-rollback" in p.stderr


# -- degraded logging: in force, queued, reported, reconciled exactly once --------------------------

class FlakyLog:
    """Wraps a real log; writes fail while ``broken`` is set."""

    def __init__(self, log):
        self.log, self.broken = log, False

    def _check(self):
        if self.broken:
            raise OSError("simulated disk failure")

    def append(self, **kw):
        self._check()
        return self.log.append(**kw)

    def append_once(self, **kw):
        self._check()
        return self.log.append_once(**kw)

    def alert(self, **kw):
        self._check()
        return self.log.alert(**kw)

    def find(self, **kw):
        return self.log.find(**kw)


def test_authority_revocation_survives_a_failing_log_and_is_reconciled_once(tmp_path):
    sig = load_signer()
    flaky = FlakyLog(open_log(tmp_path / "alog"))
    auth = Authority.create(tmp_path / "authority", sig, flaky, freshness=T, skew=S)
    dev = Device.create(tmp_path / "dev", sig, "phone", "maya")
    dev.enroll(auth, NOW)
    flaky.broken = True
    with pytest.raises(NodeError, match="queued"):
        auth.revoke_device("phone", NOW + 1)
    assert auth.pending_events() == 1
    assert "phone" in auth.issue_list(NOW + 2)["body"]["revoked_devices"]  # in force regardless
    flaky.broken = False
    auth.issue_list(NOW + 3)  # any later operation reconciles
    assert auth.pending_events() == 0
    assert auth.reconcile() == 0
    revokes = [e for e in AuditLog(tmp_path / "alog", None).entries() if e["action"] == "revoke_device"]
    assert len(revokes) == 1 and revokes[0]["target"] == "phone"


def test_node_keeps_an_accepted_list_when_its_log_fails_and_logs_it_later(tmp_path):
    sig = load_signer()
    auth = Authority.create(tmp_path / "authority", sig, open_log(tmp_path / "alog"), freshness=T, skew=S)
    flaky = FlakyLog(open_log(tmp_path / "nlog"))
    node = Node.provision(tmp_path / "node", sig, flaky, node_id="n", authority_pk=auth.public_key,
                          owners={"a": "maya"}, contents={"a": "b"}, freshness=T, skew=S)
    dev = Device.create(tmp_path / "dev", sig, "phone", "maya")
    dev.enroll(auth, NOW)
    auth.revoke_device("phone", NOW + 1)
    flaky.broken = True
    assert node.accept_list(auth.issue_list(NOW + 2), NOW + 2) is True
    assert node.pending_events() == 1
    flaky.broken = False
    assert node.reconcile() == 1 and node.pending_events() == 0
    assert respond(node, dev.make_request("n", "a", NOW + 3), NOW + 3)["decision"] == "deny"
    accepted = [e for e in AuditLog(tmp_path / "nlog", None).entries() if e["action"] == "deliver_list"]
    assert len(accepted) == 1


def test_storage_status_reports_degraded_logging(tmp_path):
    from t4.storage_status import report
    from t4.store import locate_state_dir

    state = tmp_path / "s"
    state.mkdir()
    assert _call(state, {"op": "setup", "owners": {"x": "a"}, "contents": {"x": "b"}, "disabled": [],
                         "key_material": "k"}).returncode == 0
    assert report(state)["audit_logging"] == "ok"
    audit = locate_state_dir(state) / "audit"
    os.chmod(audit / "audit.jsonl", 0o400)  # the log can no longer be written
    if os.access(audit / "audit.jsonl", os.W_OK):
        pytest.skip("running as root: file permissions cannot simulate a write failure")
    p = _call(state, {"op": "revoke", "actor": "a"})
    assert p.returncode == 0 and json.loads(p.stdout) == {"audit": "pending"}
    status = report(state)
    assert status["audit_logging"] == "degraded" and status["pending_audit_entries"] == 1
    os.chmod(audit / "audit.jsonl", 0o600)
    p = _call(state, {"op": "read", "actor": "a", "asset": "x", "request_id": "r"})
    assert json.loads(p.stdout) == {"decision": "deny"}
    assert report(state)["audit_logging"] == "ok"


# -- node: alerts name the signing device; existing folders are made private --------------------------

def test_node_alert_names_the_signing_device(tmp_path):
    sig = load_signer()
    auth = Authority.create(tmp_path / "authority", sig, open_log(tmp_path / "alog"), freshness=T, skew=S)
    nlog = tmp_path / "nlog"
    node = Node.provision(tmp_path / "node", sig, open_log(nlog), node_id="n", authority_pk=auth.public_key,
                          owners={"a": "maya"}, contents={"a": "b"}, freshness=T, skew=S)
    eve = Device.create(tmp_path / "eve", sig, "eve-laptop", "eve")
    eve.enroll(auth, NOW)
    node.accept_list(auth.issue_list(NOW), NOW)
    respond(node, eve.make_request("n", "a", NOW + 1, actor="maya"), NOW + 1)
    [alert] = [e for e in AuditLog(nlog, None).alerts() if e["rule"] == "NODE-OWNER-MISMATCH"]
    assert alert["detail"]["device_id"] == "eve-laptop" and alert["detail"]["claimed_actor"] == "maya"
    assert alert["detail"]["signature_verified"] is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_node_state_folder_is_made_private_even_if_it_existed(tmp_path):
    from t4.node.state import FileStore

    folder = tmp_path / "pre-existing"
    folder.mkdir(mode=0o755)
    os.chmod(folder, 0o755)
    FileStore.create(folder, {"x": {}})
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700
