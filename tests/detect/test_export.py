"""alerts raised from our own signed logs (needs ``t4.audit``)."""

import json
from datetime import timedelta

import pytest

pytest.importorskip("t4.audit.log")
pytest.importorskip("pqcrypto")

from t4.audit.log import AuditLog, load_or_create_signer  # noqa: E402
from t4.detect import export as exp  # noqa: E402
from t4.detect.ingest import iso_z  # noqa: E402

from .helpers import BASE, approvals  # noqa: E402

OWNERS = {
    "node-a": {"file-alice": "alice", "file-bob": "bob"},
    "node-b": {"file-alice": "alice", "file-bob": "bob"},
    "node-c": {"file-carol": "carol"},
}


class Clock:
    """Shared simulated time across all logs, advanced explicitly."""

    def __init__(self):
        self.seconds = 0.0

    def at(self, seconds):
        self.seconds = seconds

    def __call__(self):
        return iso_z(BASE + timedelta(seconds=self.seconds))


def _ts(seconds):
    return iso_z(BASE + timedelta(seconds=seconds)).replace(".000Z", "Z")


def _change_register():
    return approvals({
        "approval_id": "chg-7", "approved_by": "user-admin", "subject": "carol",
        "operation": "grant_role", "role": "read:file-alice", "scope": ["node-a/file-alice"],
        "valid_from_utc": _ts(0), "valid_until_utc": _ts(3600),
    })


@pytest.fixture()
def world(tmp_path):
    clock = Clock()
    dirs = {name: tmp_path / name for name in ("authority", "node-a", "node-b", "node-c")}
    logs = {name: AuditLog(d, load_or_create_signer(d), clock=clock, checkpoint_every=4)
            for name, d in dirs.items()}

    def key(at, action, target, subject, approval_id=""):
        clock.at(at)
        detail = {"subject": subject}
        if approval_id:
            detail["approval_id"] = approval_id
        logs["authority"].append(actor="user-admin", action=action, target=target, decision="allow",
                                 rule="KEY-" + action.upper(), request_id=f"k{at}", detail=detail)

    def read(at, node, actor, asset, decision, device, verified=True):
        clock.at(at)
        logs[node].append(actor=actor, action="read", target=asset, decision=decision,
                          rule="POL-OWNER" if decision == "allow" else "POL-NOT-OWNER",
                          request_id=f"r-{node}-{at}",
                          detail={"node_id": node, "device_id": device, "signature_verified": verified})

    # Routine owner reads.
    read(1, "node-a", "alice", "file-alice", "allow", "dev-alice")
    read(2, "node-b", "bob", "file-bob", "allow", "dev-bob")
    # Approved grant and its use: no alert.
    key(10, "grant", "file-alice", "carol", "chg-7")
    read(11, "node-a", "carol", "file-alice", "allow", "dev-carol")
    # Unapproved grant and its use: alert plus review.
    key(20, "grant", "file-bob", "mallory")
    read(21, "node-a", "mallory", "file-bob", "allow", "dev-mallory")
    # One actor probing several nodes: lateral movement candidate.
    read(30, "node-a", "eve", "file-alice", "deny", "dev-eve")
    read(31, "node-b", "eve", "file-bob", "deny", "dev-eve")
    read(32, "node-c", "eve", "file-carol", "deny", "dev-eve")
    # One isolated denial: no alert.
    read(40, "node-c", "bob", "file-carol", "deny", "dev-bob")
    # Routine authority administration: no alert.
    clock.at(50)
    logs["authority"].append(actor="authority", action="enroll", target="dev-new", decision="allow",
                             rule="KEY-ENROLL", request_id="k50", detail={"owner": "bob", "version": 1})
    # Forged requests naming an innocent actor (bad signature): never attributed to her.
    read(100, "node-a", "maya", "file-alice", "deny", "dev-x", verified=False)
    read(101, "node-b", "maya", "file-bob", "deny", "dev-x", verified=False)
    read(102, "node-c", "maya", "file-carol", "deny", "dev-x", verified=False)
    for log in logs.values():
        log.head()
    sources = [exp.LogSource(dirs["authority"], "authority", "authority")]
    sources += [exp.LogSource(dirs[n], "node", n) for n in ("node-a", "node-b", "node-c")]
    return dirs, sources


def test_alerts_from_our_own_logs(world):
    dirs, sources = world
    result = exp.run_export(sources, _change_register(), owners=OWNERS, alert_log=dirs["authority"])
    rules = sorted(a.rule for a in result.result.alerts)
    assert rules == ["DET-LATERAL-MOVEMENT", "DET-LATERAL-MOVEMENT",
                     "DET-REVIEW-AFTER-ROLE-CHANGE", "DET-UNAPPROVED-ROLE-CHANGE"]
    by_rule = {a.rule: a for a in result.result.alerts if a.identity != exp.UNVERIFIED_ACTOR}
    move = by_rule["DET-LATERAL-MOVEMENT"]
    assert move.identity == "eve"
    assert move.services == ("node-a/file-alice", "node-b/file-bob", "node-c/file-carol")
    assert by_rule["DET-UNAPPROVED-ROLE-CHANGE"].identity == "mallory"
    labels = result.result.predicted()
    assert labels["authority#1"] == "approved_change"  # carol's approved grant
    assert labels["node-c#2"] == "isolated_denial"
    assert all(v["ok"] for v in result.verified)


def test_alerts_are_appended_once_and_logged_with_request_ids(world):
    dirs, sources = world
    first = exp.run_export(sources, _change_register(), owners=OWNERS, alert_log=dirs["authority"])
    assert len(first.appended) == 4
    alerts = AuditLog(dirs["authority"], None).alerts()
    move = next(a for a in alerts if a["rule"] == "DET-LATERAL-MOVEMENT")
    assert json.loads(move["detail"]["request_ids"]) == ["r-node-a-30", "r-node-b-31", "r-node-c-32"]
    assert move["actor"] == "eve"
    # Re-running appends nothing new (the authority log now has alert entries,
    # which are not key events and do not change the result).
    second = exp.run_export(sources, _change_register(), owners=OWNERS, alert_log=dirs["authority"])
    assert second.appended == []


def test_learned_baseline_without_owners(world):
    _, sources = world
    result = exp.run_export(sources, _change_register())
    assert "DET-LATERAL-MOVEMENT" in {a.rule for a in result.result.alerts}


def test_tampered_log_is_refused(world):
    dirs, sources = world
    path = dirs["node-b"] / "audit.jsonl"
    path.write_bytes(path.read_bytes().replace(b'"deny"', b'"allow"'))
    with pytest.raises(exp.ExportError, match="node-b"):
        exp.run_export(sources, _change_register(), owners=OWNERS)


def test_exported_csv_parses(world):
    _, sources = world
    result = exp.run_export(sources, _change_register(), owners=OWNERS)
    from t4.detect.ingest import parse_events
    assert len(parse_events(result.csv())) == len(result.rows)


def test_unverified_requests_are_never_attributed_to_the_named_actor(world):
    _, sources = world
    result = exp.run_export(sources, _change_register(), owners=OWNERS)
    assert all(a.identity != "maya" for a in result.result.alerts)
    forged = [a for a in result.result.alerts if a.identity == exp.UNVERIFIED_ACTOR]
    assert len(forged) == 1 and forged[0].rule == "DET-LATERAL-MOVEMENT"
    assert all(r["actor"] != "maya" for r in result.rows)


def test_routine_admin_key_events_raise_no_alert(world):
    _, sources = world
    result = exp.run_export(sources, _change_register(), owners=OWNERS)
    assert all(a.identity != "authority" for a in result.result.alerts)
    enroll = next(r for r in result.rows if r["action"] == "enroll")
    assert result.result.labels[enroll["event_id"]].label == "routine"


def test_accepts_node_directory_with_log_subfolder(tmp_path):
    (tmp_path / "log").mkdir()
    (tmp_path / "log" / "audit.jsonl").write_bytes(b"")
    assert exp.log_directory(tmp_path) == tmp_path / "log"
    assert exp.log_directory(tmp_path / "log") == tmp_path / "log"
