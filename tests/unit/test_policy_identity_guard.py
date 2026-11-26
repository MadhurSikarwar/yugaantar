"""Policy rules, the vault state model and the guard's back-off logic."""
from __future__ import annotations

import pytest

from t4 import identity
from t4.guard import (
    COUNTER_CAP,
    MAX_TRACKED_ACTORS,
    OTHER_BUCKET,
    RULE_DUPLICATE_ID,
    RULE_INTEGRITY,
    RULE_INVALID_INPUT,
    RULE_REPEATED_DENIAL,
    Guard,
    integrity_alert,
)
from t4.identity import VaultState
from t4.policy import (
    RULE_ALLOW_OWNER,
    RULE_DISABLED,
    RULE_NOT_OWNER,
    RULE_REVOKED,
    RULE_UNKNOWN_ASSET,
    decide,
)


def provisioned() -> VaultState:
    state = VaultState()
    state.initialize({"brief": "maya", "notes": "ravi"}, {"brief": "demo", "notes": "n"}, ("mallory",))
    return state


# --- policy ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("actor", "asset", "allow", "rule"),
    [
        ("maya", "brief", True, RULE_ALLOW_OWNER),
        ("ravi", "notes", True, RULE_ALLOW_OWNER),
        ("maya", "notes", False, RULE_NOT_OWNER),
        ("nobody", "brief", False, RULE_NOT_OWNER),
        ("maya", "missing", False, RULE_UNKNOWN_ASSET),
        ("mallory", "brief", False, RULE_DISABLED),
        ("MAYA", "brief", False, RULE_NOT_OWNER),  # exact string comparison: no case folding
        ("maya ", "brief", False, RULE_NOT_OWNER),  # no trimming
        ("", "", False, RULE_UNKNOWN_ASSET),
    ],
)
def test_decisions(actor, asset, allow, rule):
    decision = decide(provisioned(), actor, asset, "r1")
    assert (decision.allow, decision.rule, decision.request_id) == (allow, rule, "r1")


def test_unicode_lookalikes_are_different_identities():
    state = VaultState()
    state.initialize({"a": "maya"}, {}, ())
    assert not decide(state, "mayа", "a", "r").allow  # Cyrillic 'a'


def test_revoked_beats_every_other_rule():
    state = provisioned()
    state.revoke("maya")
    assert decide(state, "maya", "brief", "r").rule == RULE_REVOKED
    assert decide(state, "maya", "missing", "r").rule == RULE_REVOKED
    state.disabled.add("maya")
    assert decide(state, "maya", "brief", "r").rule == RULE_REVOKED


def test_revoking_one_actor_leaves_others_alone():
    state = provisioned()
    state.revoke("maya")
    assert decide(state, "ravi", "notes", "r").allow


def test_decision_carries_the_epoch():
    state = provisioned()
    state.revoke("maya")
    assert decide(state, "ravi", "notes", "r").epoch == 1


# --- vault state ---------------------------------------------------------------------------


def test_initialize_starts_generation_one_with_no_revocations():
    state = provisioned()
    assert (state.generation, state.epoch, state.revoked) == (1, 0, {})
    assert state.is_provisioned


def test_asset_without_contents_has_an_empty_body():
    state = VaultState()
    state.initialize({"a": "u"}, {}, ())
    assert state.body_of("a") == ""


def test_contents_without_an_owner_are_unreadable():
    state = VaultState()
    state.initialize({}, {"orphan": "secret"}, ())
    assert state.owner_of("orphan") is None
    assert not decide(state, "anyone", "orphan", "r").allow


def test_revoke_is_idempotent_and_the_epoch_only_goes_up():
    state = provisioned()
    assert state.revoke("maya") is True and state.epoch == 1
    assert state.revoke("maya") is False and state.epoch == 1
    assert state.revoke("ravi") is True and state.epoch == 2


def test_revoking_an_unknown_actor_is_recorded():
    state = provisioned()
    assert state.revoke("ghost") is True
    assert state.is_revoked("ghost")


def test_new_generation_clears_data_but_the_epoch_never_decreases():
    state = provisioned()
    state.revoke("maya")
    state.remember_request("r1", "allow", RULE_ALLOW_OWNER, 4)
    state.initialize({"x": "u"}, {"x": "b"}, ())
    assert state.generation == 2
    assert state.revoked == {} and state.requests == {}
    assert state.epoch == 1
    assert state.owner_of("brief") is None


def test_first_record_for_a_request_id_is_never_overwritten():
    state = provisioned()
    assert state.remember_request("r1", "deny", RULE_NOT_OWNER, 1) is True
    assert state.remember_request("r1", "allow", RULE_ALLOW_OWNER, 2) is False
    assert state.first_record("r1")["decision"] == "deny"


def test_first_record_returns_a_copy():
    state = provisioned()
    state.remember_request("r1", "deny", RULE_NOT_OWNER, 1)
    state.first_record("r1")["decision"] = "allow"
    assert state.first_record("r1")["decision"] == "deny"


def test_request_index_is_bounded_and_evicts_the_oldest(monkeypatch):
    monkeypatch.setattr(identity, "MAX_INDEX_ENTRIES", 3)
    state = provisioned()
    for i in range(5):
        state.remember_request(f"r{i}", "deny", RULE_NOT_OWNER, i)
    assert [state.first_record(f"r{i}") is not None for i in range(5)] == [False, False, True, True, True]
    assert len(state.requests) == 3


def test_persistence_roundtrip(state_dir):
    from t4.store import FileStore

    store = FileStore(state_dir)
    with store.locked() as txn:
        original = provisioned()
        original.revoke("maya")
        original.remember_request("r1", "deny", RULE_REVOKED, 9)
        original.guard = {"duplicates": 2}
        original.save(txn)
    with store.locked() as txn:
        loaded = VaultState.load(txn)
    assert loaded == original


# --- guard ---------------------------------------------------------------------------------------


def test_denial_alerts_follow_the_backoff_schedule():
    guard = Guard()
    alerted_at = [n for n in range(1, 81) if guard.on_denial("maya", asset="a", entry_seq=n)]
    assert alerted_at == [5, 10, 20, 40, 80]


def test_denial_alert_contents():
    guard = Guard()
    alerts = []
    for n in range(1, 6):
        alerts = guard.on_denial("maya", asset="brief", entry_seq=n, request_id=f"r{n}")
    assert [a.rule for a in alerts] == [RULE_REPEATED_DENIAL]
    detail = alerts[0].detail
    assert detail["denials"] == 5 and detail["asset"] == "brief"
    assert alerts[0].entries == (5,) and alerts[0].request_ids == ("r5",)
    assert "no request was blocked" in alerts[0].explanation


def test_denials_are_counted_per_identity():
    guard = Guard()
    for _ in range(4):
        guard.on_denial("a", asset="x", entry_seq=1)
        guard.on_denial("b", asset="x", entry_seq=1)
    assert guard.on_denial("a", asset="x", entry_seq=2)  # a reaches 5
    assert guard.on_denial("b", asset="x", entry_seq=2)  # and so does b


def test_invalid_input_alerts_at_powers_of_two():
    guard = Guard()
    alerted_at = [n for n in range(1, 40) if guard.on_invalid_input("invalid-input")]
    assert alerted_at == [1, 2, 4, 8, 16, 32]
    assert all(a.rule == RULE_INVALID_INPUT for a in Guard().on_invalid_input("x"))


def test_duplicate_alerts_at_powers_of_two_and_reference_the_first_entry():
    guard = Guard()
    first = guard.on_duplicate_request_id("r1", first_entry_seq=3, entry_seq=7)
    assert first[0].rule == RULE_DUPLICATE_ID
    assert first[0].entries == (3, 7) and first[0].request_ids == ("r1",)
    assert guard.on_duplicate_request_id("r1", first_entry_seq=3, entry_seq=8)  # 2nd
    assert not guard.on_duplicate_request_id("r1", first_entry_seq=3, entry_seq=9)  # 3rd


def test_guard_state_roundtrips_through_its_document():
    guard = Guard()
    for _ in range(3):
        guard.on_denial("a", asset="x", entry_seq=1)
    again = Guard(guard.to_doc())
    assert again.to_doc() == guard.to_doc()
    assert again.on_denial("a", asset="x", entry_seq=2) == [] and again.to_doc()["denials"][identity.identifier_key("a")] == 4


def test_tracked_identities_are_capped():
    guard = Guard()
    for i in range(MAX_TRACKED_ACTORS + 50):
        guard.on_denial(f"actor-{i}", asset="x", entry_seq=1)
    doc = guard.to_doc()["denials"]
    assert len(doc) == MAX_TRACKED_ACTORS + 1  # the tracked ones plus the shared bucket
    assert doc[OTHER_BUCKET] == 50


def test_counters_saturate():
    guard = Guard({"denials": {"a": COUNTER_CAP}})
    guard.on_denial("a", asset="x", entry_seq=1)
    assert guard.to_doc()["denials"]["a"] == COUNTER_CAP


def test_integrity_alert():
    alert = integrity_alert("integrity")
    assert alert.rule == RULE_INTEGRITY and alert.detail == {"category": "integrity"}


def test_the_guard_exposes_no_way_to_block_anything():
    """Structural check for the rule 'the guard never changes an outcome' (PRD S-A9)."""
    public = {name for name in dir(Guard) if not name.startswith("_")}
    assert public == {"on_denial", "on_duplicate_request_id", "on_invalid_input", "to_doc"}
    assert all(callable(getattr(Guard, name)) for name in public)
