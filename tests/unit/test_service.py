"""The five operations end to end, against the real store and test doubles for audit and crypto."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from t4 import identity
from t4.api import InputError
from t4.guard import RULE_DUPLICATE_ID, RULE_INVALID_INPUT, RULE_REPEATED_DENIAL
from t4.policy import RULE_ALLOW_OWNER, RULE_NOT_OWNER, RULE_REVOKED
from t4.validate_in import (
    AuditRequest,
    ProtectedReadRequest,
    ReadRequest,
    RevokeRequest,
    SetupRequest,
)
from tests.unit.doubles import RealProof, make_service

MARKER = "KEY-MATERIAL-MARKER-0123456789"


def setup_request(**kw):
    args = dict(owners={"brief": "maya", "notes": "ravi"}, contents={"brief": "demo note", "notes": "ravi body"}, disabled=("mallory",))
    args.update(kw)
    return SetupRequest(**args)


def read(service, actor, asset, request_id):
    return service.read(ReadRequest(actor=actor, asset=asset, request_id=request_id))


@pytest.fixture
def env(state_dir):
    service, audit, kem, store = make_service(state_dir)
    assert service.setup(setup_request()) == {"ready": True}
    return service, audit, kem, store


# --- the lost-device story -------------------------------------------------------------


def test_lost_device_story(env):
    service, audit, _, _ = env
    assert read(service, "maya", "brief", "r01") == {"decision": "allow", "body": "demo note"}
    assert read(service, "ravi", "notes", "r02") == {"decision": "allow", "body": "ravi body"}
    assert read(service, "maya", "notes", "r03") == {"decision": "deny"}
    assert service.revoke(RevokeRequest("maya")) == {}
    assert read(service, "maya", "brief", "r04") == {"decision": "deny"}
    assert service.audit(AuditRequest("r04")) == {"request_id": "r04", "decision": "deny", "rule": RULE_REVOKED}
    assert read(service, "ravi", "notes", "r05") == {"decision": "allow", "body": "ravi body"}
    assert read(service, "maya", "brief", "r06") == {"decision": "deny"}  # still denied later


def test_a_denial_discloses_nothing(env):
    service, *_ = env
    for actor, asset in [("maya", "notes"), ("ghost", "brief"), ("mallory", "brief"), ("maya", "nope")]:
        assert read(service, actor, asset, f"r-{actor}-{asset}") == {"decision": "deny"}
    service.revoke(RevokeRequest("maya"))
    assert read(service, "maya", "brief", "rx") == {"decision": "deny"}
    audit_reply = service.audit(AuditRequest("rx"))
    assert "demo note" not in json.dumps(audit_reply) and "body" not in audit_reply


def test_disabled_actor_is_denied_even_for_their_own_asset(state_dir):
    service, *_ = make_service(state_dir)
    service.setup(setup_request(owners={"a": "mallory"}, contents={"a": "x"}, disabled=("mallory",)))
    assert read(service, "mallory", "a", "r") == {"decision": "deny"}
    assert service.audit(AuditRequest("r"))["rule"] == "POL-DISABLED"


def test_unknown_request_id(env):
    service, *_ = env
    assert service.audit(AuditRequest("never-seen")) == {"error": "unknown_request"}


def test_audit_for_an_allowed_read(env):
    service, *_ = env
    read(service, "maya", "brief", "r1")
    assert service.audit(AuditRequest("r1")) == {"request_id": "r1", "decision": "allow", "rule": RULE_ALLOW_OWNER}


def test_revoking_an_unknown_actor_returns_an_empty_object(env):
    service, audit, *_ = env
    assert service.revoke(RevokeRequest("ghost")) == {}
    assert audit.by_action("revoke")[-1]["detail"]["newly_revoked"] is True


def test_revocation_is_durable_across_service_instances(state_dir):
    first, *_ = make_service(state_dir)
    first.setup(setup_request())
    first.revoke(RevokeRequest("maya"))
    second, *_ = make_service(state_dir)  # a "new process"
    assert read(second, "maya", "brief", "r") == {"decision": "deny"}


# --- audit log content -----------------------------------------------------------------------


def test_every_decision_is_logged_with_rule_and_ids(env):
    service, audit, *_ = env
    read(service, "maya", "brief", "r1")
    read(service, "maya", "notes", "r2")
    entries = audit.by_action("read")
    assert [(e["actor"], e["target"], e["decision"], e["rule"], e["request_id"]) for e in entries] == [
        ("maya", "brief", "allow", RULE_ALLOW_OWNER, "r1"),
        ("maya", "notes", "deny", RULE_NOT_OWNER, "r2"),
    ]
    assert entries[0]["detail"]["generation"] == 1


def test_setup_and_revoke_are_logged(env):
    service, audit, *_ = env
    service.revoke(RevokeRequest("maya"))
    assert [e["action"] for e in audit.entries] == ["setup", "revoke"]
    assert audit.entries[0]["detail"] == {"generation": 1, "epoch": 1, "assets": 2, "disabled": 1}


def test_key_material_is_never_stored_logged_or_returned(state_dir):
    from t4.validate_in import validate_request

    service, audit, _, store = make_service(state_dir)
    request = validate_request(
        {"op": "setup", "owners": {"a": "u"}, "contents": {"a": "b"}, "disabled": [], "key_material": MARKER}
    )
    response = service.setup(request)
    everything = json.dumps(response) + json.dumps(audit.entries) + store.state_path.read_text()
    assert MARKER not in everything


# --- ordering and failure behaviour  ---------------------------------------------------


def test_a_failing_audit_log_fails_a_read_closed_and_changes_no_state(env):
    service, audit, _, store = env
    before = store.state_path.read_bytes()
    audit.fail_when = lambda entry: entry["action"] == "read"
    with pytest.raises(RuntimeError):
        read(service, "maya", "brief", "r1")
    assert store.state_path.read_bytes() == before
    audit.fail_when = lambda entry: False
    assert service.audit(AuditRequest("r1")) == {"error": "unknown_request"}


def test_a_revocation_persists_even_if_the_audit_log_fails(env):
    service, audit, *_ = env
    audit.fail_when = lambda entry: entry["action"] == "revoke"
    # In force at once, and the reply does not claim the audit entry was written.
    assert service.revoke(RevokeRequest("maya")) == {"audit": "pending"}
    assert audit.by_action("revoke") == []
    audit.fail_when = lambda entry: False
    assert read(service, "maya", "brief", "r1") == {"decision": "deny"}
    # The next request that reaches the log writes the queued entry, exactly once.
    read(service, "maya", "brief", "r2")
    assert len(audit.by_action("revoke")) == 1


def test_a_failing_audit_log_keeps_setup_in_force_and_queues_its_entry(state_dir):
    service, audit, _, store = make_service(state_dir)
    audit.fail_when = lambda entry: entry["action"] == "setup"
    assert service.setup(setup_request()) == {"ready": True, "audit": "pending"}
    assert audit.by_action("setup") == []
    audit.fail_when = lambda entry: False
    assert read(service, "maya", "brief", "r") == {"decision": "allow", "body": "demo note"}
    assert len(audit.by_action("setup")) == 1  # written by the next request, once


def test_alert_failures_never_break_a_correct_answer(env):
    service, audit, *_ = env
    audit.fail_when = lambda entry: entry["action"] == "alert"
    for i in range(5):
        assert read(service, "maya", "notes", f"r{i}") == {"decision": "deny"}  # 5th triggers an alert that fails


# --- duplicates, alerts and the guard ---------------------------------------------------------------


def test_duplicate_request_id_keeps_the_first_record_and_still_applies_policy(env):
    service, audit, *_ = env
    assert read(service, "maya", "notes", "dup") == {"decision": "deny"}  # first: denied
    assert read(service, "maya", "brief", "dup") == {"decision": "allow", "body": "demo note"}  # owner not blocked
    assert service.audit(AuditRequest("dup"))["decision"] == "deny"  # first record is immutable
    alerts = [e for e in audit.by_action("alert") if e["rule"] == RULE_DUPLICATE_ID]
    assert len(alerts) == 1
    first_entry, triggering_entry = json.loads(alerts[0]["detail"]["entries"])
    assert first_entry < triggering_entry
    assert json.loads(alerts[0]["detail"]["request_ids"]) == ["dup"]
    assert "explanation" in alerts[0]["detail"]


def test_repeated_denials_raise_an_alert_but_never_block_the_real_owner(env):
    service, audit, *_ = env
    for i in range(12):  # someone hammers maya's name with a wrong asset
        read(service, "maya", "notes", f"bad{i}")
    rules = [e["rule"] for e in audit.by_action("alert")]
    assert rules.count(RULE_REPEATED_DENIAL) == 2  # at the 5th and 10th denial
    assert read(service, "maya", "brief", "good") == {"decision": "allow", "body": "demo note"}


def test_alerts_name_the_triggering_entries(env):
    service, audit, *_ = env
    for i in range(5):
        read(service, "maya", "notes", f"bad{i}")
    alert = audit.by_action("alert")[0]
    last_read = audit.by_action("read")[-1]
    assert json.loads(alert["detail"]["entries"]) == [last_read["seq"]]
    assert json.loads(alert["detail"]["request_ids"]) == [last_read["request_id"]]
    assert alert["request_id"] == last_read["request_id"]


def test_alerts_still_carry_their_evidence_when_the_sink_has_no_alert_method(state_dir):
    from tests.unit.doubles import PlainAudit

    service, audit, *_ = make_service(state_dir, PlainAudit())
    service.setup(setup_request())
    for i in range(5):
        read(service, "maya", "notes", f"bad{i}")
    alert = audit.by_action("alert")[0]
    last_read = audit.by_action("read")[-1]
    assert alert["rule"] == RULE_REPEATED_DENIAL
    assert json.loads(alert["detail"]["entries"]) == [last_read["seq"]]
    assert json.loads(alert["detail"]["request_ids"]) == [last_read["request_id"]]
    assert "explanation" in alert["detail"]


def test_invalid_input_is_counted_and_alerted_only_when_state_exists(state_dir):
    service, audit, _, store = make_service(state_dir)
    service.report_input_failure("invalid-input")  # nothing provisioned yet
    assert not store.state_path.exists() and audit.entries == []
    service.setup(setup_request())
    service.report_input_failure("invalid-input")
    service.report_input_failure("invalid-input")
    service.report_input_failure("invalid-input")
    assert [e["rule"] for e in audit.by_action("alert")] == [RULE_INVALID_INPUT, RULE_INVALID_INPUT]  # 1st and 2nd; 3rd waits


def test_report_failures_never_raise(state_dir):
    service, audit, *_ = make_service(state_dir)
    service.setup(setup_request())
    audit.fail_when = lambda entry: True
    service.report_input_failure("invalid-input")
    from t4.api import IntegrityError

    service.report_integrity_failure(IntegrityError("x"))


def test_integrity_failure_is_logged_as_an_alert(state_dir):
    from t4.api import IntegrityError

    service, audit, *_ = make_service(state_dir)
    service.report_integrity_failure(IntegrityError("state integrity check failed"))
    alert = audit.entries[0]
    assert alert["rule"] == "STO-INTEGRITY-FAILURE" and alert["detail"]["category"] == "integrity"


# --- generations -----------------------------------------------------------------------------------------


def test_a_second_setup_starts_a_new_generation(env):
    service, audit, *_ = env
    service.revoke(RevokeRequest("maya"))
    read(service, "maya", "brief", "old")
    service.setup(setup_request(owners={"x": "zed"}, contents={"x": "new"}))
    assert read(service, "maya", "brief", "r") == {"decision": "deny"}  # old data is gone
    assert read(service, "zed", "x", "r2") == {"decision": "allow", "body": "new"}
    assert service.audit(AuditRequest("old")) == {"error": "unknown_request"}  # index replaced
    assert [e["detail"]["generation"] for e in audit.by_action("setup")] == [1, 2]
    first, second = (e["detail"]["epoch"] for e in audit.by_action("setup"))
    assert second > first  # the epoch continued upwards across generations


def test_the_request_index_is_bounded(state_dir, monkeypatch):
    monkeypatch.setattr(identity, "MAX_INDEX_ENTRIES", 5)
    service, *_ = make_service(state_dir)
    service.setup(setup_request())
    for i in range(8):
        read(service, "maya", "brief", f"r{i}")
    assert service.audit(AuditRequest("r0")) == {"error": "unknown_request"}
    assert service.audit(AuditRequest("r7"))["decision"] == "allow"


# --- protected_read ----------------------------------------------------------------------------------------


PUBLIC_KEY = bytes(range(256)) * 4 + bytes(160)  # 1184 bytes; content is irrelevant to the double


def protected(service, actor="maya", asset="brief", challenge="fresh-challenge"):
    return service.protected_read(ProtectedReadRequest(actor=actor, asset=asset, challenge=challenge, public_key=PUBLIC_KEY[:1184]))


def test_protected_read_returns_ciphertext_and_the_documented_proof(env):
    service, audit, kem, _ = env
    response = protected(service)
    assert set(response) == {"ciphertext", "proof"}
    assert base64.b64decode(response["ciphertext"]) == kem.ciphertext
    assert response["proof"] == RealProof.make_proof(kem.secret, b"fresh-challenge", b"demo note")
    assert response["proof"] == response["proof"].lower() and len(response["proof"]) == 64
    assert kem.calls == [PUBLIC_KEY[:1184]]


def test_protected_read_never_sends_the_body(env):
    service, *_ = env
    assert "demo note" not in json.dumps(protected(service))


def test_protected_read_authorizes_before_touching_the_public_key(env):
    service, audit, kem, _ = env
    service.revoke(RevokeRequest("maya"))
    assert protected(service) == {"decision": "deny"}
    assert protected(service, actor="ghost") == {"decision": "deny"}
    assert protected(service, asset="missing") == {"decision": "deny"}
    assert kem.calls == []


def test_protected_read_records_the_challenge_hash_not_the_challenge_or_key(env):
    service, audit, *_ = env
    protected(service, challenge="my-secret-challenge")
    entry = audit.by_action("protected_read")[-1]
    assert entry["detail"]["challenge_sha256"] == hashlib.sha256(b"my-secret-challenge").hexdigest()
    flat = json.dumps(audit.entries)
    assert "my-secret-challenge" not in flat and base64.b64encode(PUBLIC_KEY[:1184]).decode() not in flat


def test_protected_read_decisions_use_the_same_policy_and_are_logged(env):
    service, audit, *_ = env
    protected(service, actor="ravi", asset="brief")  # not the owner
    protected(service)  # owner
    rules = [(e["decision"], e["rule"]) for e in audit.by_action("protected_read")]
    assert rules == [("deny", RULE_NOT_OWNER), ("allow", RULE_ALLOW_OWNER)]


def test_protected_read_denials_count_toward_the_guard(env):
    service, audit, *_ = env
    for _ in range(5):
        protected(service, actor="ghost")
    assert [e["rule"] for e in audit.by_action("alert")] == [RULE_REPEATED_DENIAL]


def test_a_rejected_key_fails_the_request_and_is_logged(env):
    service, audit, kem, _ = env
    kem.reject = True
    with pytest.raises(InputError):
        protected(service)
    entry = audit.by_action("protected_read")[-1]
    assert (entry["decision"], entry["rule"]) == ("error", "CRY-KEY-REJECTED")


def test_protected_read_does_not_index_a_request_id(env):
    service, audit, *_ = env
    protected(service)
    assert audit.by_action("protected_read")[-1]["request_id"].startswith("sys-")
    assert service.audit(AuditRequest(audit.by_action("protected_read")[-1]["request_id"])) == {"error": "unknown_request"}


def test_protected_read_fails_closed_when_the_audit_log_is_down(env):
    service, audit, *_ = env
    audit.fail_when = lambda entry: entry["action"] == "protected_read"
    with pytest.raises(RuntimeError):
        protected(service)
