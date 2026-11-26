"""The opt-in setup guard: default behaviour is the contract's, ``once`` protects a deployment."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pqcrypto")

ROOT = Path(__file__).resolve().parents[2]
SETUP = {"op": "setup", "owners": {"a": "maya"}, "contents": {"a": "first"}, "disabled": [], "key_material": "k"}


def call(state: Path, request: dict, policy: str | None = None):
    env = dict(os.environ, TRACK4_STATE_DIR=str(state))
    env.pop("TRACK4_SETUP_POLICY", None)
    if policy is not None:
        env["TRACK4_SETUP_POLICY"] = policy
    done = subprocess.run([sys.executable, "-B", str(ROOT / "track4_service.py")], input=json.dumps(request).encode(),
                          capture_output=True, env=env, cwd=ROOT, timeout=60)
    return done.returncode, (json.loads(done.stdout) if done.stdout.strip() else None), done.stderr.decode()


def test_by_default_a_second_setup_starts_a_new_generation_as_the_contract_expects(tmp_path):
    state = tmp_path / "s"
    assert call(state, SETUP)[1] == {"ready": True}
    call(state, {"op": "revoke", "actor": "maya"})
    assert call(state, {**SETUP, "contents": {"a": "second"}})[1] == {"ready": True}
    read = {"op": "read", "actor": "maya", "asset": "a", "request_id": "r"}
    assert call(state, read)[1] == {"decision": "allow", "body": "second"}  # revocation cleared, as documented


def test_with_the_once_policy_a_second_setup_is_refused_and_nothing_changes(tmp_path):
    state = tmp_path / "s"
    assert call(state, SETUP, "once")[1] == {"ready": True}
    call(state, {"op": "revoke", "actor": "maya"}, "once")
    code, out, err = call(state, {**SETUP, "owners": {"a": "eve"}, "contents": {"a": "attacker"}}, "once")
    assert code == 1 and out is None and "Traceback" not in err
    read = {"op": "read", "actor": "maya", "asset": "a", "request_id": "r"}
    assert call(state, read, "once")[1] == {"decision": "deny"}  # the revocation survived the attempt


def test_the_once_policy_still_allows_the_first_setup_and_a_setup_after_the_state_is_removed(tmp_path):
    import shutil

    state = tmp_path / "s"
    assert call(state, SETUP, "once")[1] == {"ready": True}
    shutil.rmtree(state)
    assert call(state, SETUP, "once")[1] == {"ready": True}


def test_an_unrecognised_policy_value_keeps_the_contract_behaviour(tmp_path):
    state = tmp_path / "s"
    assert call(state, SETUP, "bogus")[1] == {"ready": True}
    assert call(state, SETUP, "bogus")[1] == {"ready": True}
