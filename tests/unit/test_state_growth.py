"""State growth and first-setup robustness.

Finding 1: identifiers up to 4 KiB were stored raw in the request index, the revoked
set and the guard counters, so a flood of long identifiers could push state.json past
the size the store accepts on load, after which every request, including `revoke`,
failed. Finding 2: a crash during the very first `setup` could leave an empty key file
that blocked every later `setup`.
"""
from __future__ import annotations

import json
import os

import pytest

from t4 import identity
from t4 import store as store_module
from t4.api import IntegrityError, StoreFullError
from t4.guard import Guard
from t4.identity import identifier_key
from t4.store import FileStore
from t4.validate_in import ReadRequest, RevokeRequest, SetupRequest
from tests.unit.doubles import make_service

LONG = "\x01" * 4096  # 4 KiB of control characters: 6 bytes each once JSON-escaped


def setup_request():
    return SetupRequest(owners={"brief": "maya"}, contents={"brief": "demo"}, disabled=())


def state_size(store: FileStore) -> int:
    return store.state_path.stat().st_size


# --- finding 1 -------------------------------------------------------------------------------


def test_identifier_keys_are_fixed_size_and_distinct():
    keys = {identifier_key(x) for x in ("a", "b", LONG, LONG + "x", "")}
    assert len(keys) == 5 and {len(k) for k in keys} == {64}


def test_identifier_keys_handle_any_valid_text():
    identifier_key("line\nbreak \x00 \u2028 \U0001f600")  # must not raise


def test_a_long_request_id_costs_a_small_constant_amount_of_state(state_dir):
    service, _, _, store = make_service(state_dir)
    service.setup(setup_request())
    before = state_size(store)
    service.read(ReadRequest(actor="maya", asset="brief", request_id=LONG))
    growth = state_size(store) - before
    assert growth < 400, growth  # was about 24 600 bytes before the fix


def test_flooding_long_identifiers_cannot_grow_state_without_bound_and_revoke_still_works(state_dir, monkeypatch):
    monkeypatch.setattr(identity, "MAX_INDEX_ENTRIES", 200)
    service, _, _, store = make_service(state_dir)
    service.setup(setup_request())
    for i in range(600):
        service.read(ReadRequest(actor=LONG + str(i), asset=LONG, request_id=LONG + str(i)))
    assert state_size(store) < 200_000  # the index is capped and each record is tiny
    assert service.revoke(RevokeRequest("maya")) == {}  # the service is alive
    assert service.read(ReadRequest(actor="maya", asset="brief", request_id="after")) == {"decision": "deny"}


def test_revoking_many_long_actors_costs_a_small_constant_amount_each(state_dir):
    service, _, _, store = make_service(state_dir)
    service.setup(setup_request())
    before = state_size(store)
    for i in range(100):
        service.revoke(RevokeRequest(LONG + str(i)))
    assert (state_size(store) - before) / 100 < 150  # raw storage would have cost about 24 600 bytes each


def test_guard_counters_never_store_raw_identifiers():
    guard = Guard()
    for i in range(50):
        guard.on_denial(LONG + str(i), asset="a", entry_seq=i)
    doc = json.dumps(guard.to_doc())
    assert len(doc) < 10_000 and LONG not in doc
    assert all(len(key) == 64 for key in guard.to_doc()["denials"])


def test_raw_identifiers_do_not_appear_in_the_state_file(state_dir):
    service, _, _, store = make_service(state_dir)
    service.setup(setup_request())
    secret_id = "very-identifying-request-id-123"
    service.read(ReadRequest(actor="mallory-the-actor", asset="brief", request_id=secret_id))
    service.revoke(RevokeRequest("revoked-person-456"))
    raw = store.state_path.read_text()
    for text in (secret_id, "mallory-the-actor", "revoked-person-456"):
        assert text not in raw


def test_the_store_refuses_to_write_a_state_it_could_not_load_back(state_dir, monkeypatch):
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"ok": True})
    before = store.state_path.read_bytes()
    monkeypatch.setattr(store_module, "MAX_WRITE_BYTES", 500)
    with pytest.raises(StoreFullError):
        with store.locked() as txn:
            txn.put("big", {"x": "y" * 5000})
    monkeypatch.undo()
    assert store.state_path.read_bytes() == before  # the old state is intact
    with store.locked() as txn:  # ...and still loads and accepts writes
        assert txn.get("doc") == {"ok": True}
        txn.put("doc", {"ok": False})


def test_the_write_limit_sits_below_the_load_limit():
    assert store_module.MAX_WRITE_BYTES < store_module.MAX_STATE_BYTES


# --- finding 2 --------------------------------------------------------------------------------


@pytest.mark.parametrize("content", ["", "   \n", "abc", "zz" * 32, "00" * 31, "00" * 33])
def test_an_interrupted_first_setup_does_not_brick_the_directory(state_dir, content):
    (state_dir / "state.key").write_text(content)  # what a crash between create and write leaves
    service, *_ = make_service(state_dir)
    assert service.setup(setup_request()) == {"ready": True}
    assert len(bytes.fromhex((state_dir / "state.key").read_text())) == 32
    assert service.read(ReadRequest(actor="maya", asset="brief", request_id="r")) == {"decision": "allow", "body": "demo"}


def test_a_crash_while_writing_the_first_key_leaves_no_partial_key(state_dir, monkeypatch):
    store = FileStore(state_dir)

    def crash(src, dst):
        raise OSError("power cut")

    monkeypatch.setattr(store_module.os, "replace", crash)
    with pytest.raises(IntegrityError):
        with store.locked():
            pass
    monkeypatch.undo()
    assert not (state_dir / "state.key").exists()
    assert [p.name for p in state_dir.iterdir() if p.name.endswith(".tmp")] == []
    with store.locked() as txn:  # the next attempt works
        txn.put("doc", {"ok": True})


def test_a_damaged_key_with_an_existing_state_is_still_never_replaced(state_dir):
    store = FileStore(state_dir)
    with store.locked() as txn:
        txn.put("doc", {"n": 1})
    store.key_path.write_text("abc")
    with pytest.raises(IntegrityError):
        with store.locked():
            pass
    assert store.key_path.read_text() == "abc"  # not regenerated: that would un-protect the state


def test_the_key_file_is_written_atomically_with_a_private_mode(state_dir):
    store = FileStore(state_dir)
    with store.locked():
        pass
    assert len(bytes.fromhex(store.key_path.read_text())) == 32
    if os.name != "nt":
        assert oct(store.key_path.stat().st_mode & 0o777) == "0o600"
