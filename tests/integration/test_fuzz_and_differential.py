"""Randomized attack campaigns against the real adapter (owner: c1).

Two kinds of checks, both deterministic for a given seed:

1. Fuzzing. Thousands of structurally mutated and byte-mutated requests are sent, one
   process each, and after EVERY request these invariants must hold:
     * exit code is 0 or 1 and the process never hangs;
     * exit 0: stdout is exactly one ASCII JSON object line;
     * exit 1: stdout is empty and stderr is the fixed generic line (no traceback);
     * the key material marker never appears in any output;
     * the protected body appears only in an exact allow reply to the real owner;
     * every few requests a canary proves the state still loads, an innocent owner can
       still read, and the audit log still verifies.
2. A differential test against the official demo adapter from the toolkit: the same
   random but legitimate request sequences go to both, and every difference is reported.
   A difference is where a hidden functional test could disagree with us.

Size: ``T4_FUZZ_ITERATIONS`` (default 60) and ``T4_DIFF_STEPS`` (default 40). For a real
campaign run, for example:  T4_FUZZ_ITERATIONS=3000 python -m pytest tests/integration/test_fuzz_and_differential.py
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("t4.audit.log", reason="needs c2's audit log")
pytest.importorskip("t4.crypto.kem", reason="needs c2's crypto wrappers")

from pqcrypto.kem import ml_kem_768  # noqa: E402

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRY = REPO_ROOT / "track4_service.py"
ITERATIONS = int(os.environ.get("T4_FUZZ_ITERATIONS", "60"))
DIFF_STEPS = int(os.environ.get("T4_DIFF_STEPS", "40"))
GENERIC_STDERR = re.compile(rb"^Request failed \([a-z-]+\)\.\r?\n$")
ALLOWED_STDERR_NOTES = (b"An alert could not be logged.", b"The revocation was saved but its audit entry could not be written.")
MARKER = "KEY-MATERIAL-MARKER-fuzz-5c1e9a07b3d2"
SECRET_BODY = "SECRET-BODY-fuzz-8d41f6a02c9e"

PUBLIC_KEY_B64 = base64.b64encode(ml_kem_768.generate_keypair()[0]).decode()


class Runner:
    def __init__(self, state_dir: Path, entry: Path = ENTRY, cwd: Path = REPO_ROOT) -> None:
        self.env = {**os.environ, "TRACK4_STATE_DIR": str(state_dir)}
        self.entry, self.cwd, self.state_dir = entry, cwd, state_dir

    def run(self, data: bytes) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", str(self.entry)], input=data, capture_output=True, cwd=self.cwd, env=self.env, timeout=60)

    def call(self, request: dict) -> dict:
        done = self.run(json.dumps(request).encode())
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout)


def provision(runner: Runner) -> None:
    owners = {"brief": "maya", "notes": "ravi"}
    contents = {"brief": SECRET_BODY, "notes": "ravi body"}
    assert runner.call({"op": "setup", "owners": owners, "contents": contents, "disabled": ["mallory"], "key_material": MARKER}) == {"ready": True}


# --- generating hostile input ------------------------------------------------------------------------


def hostile_value(rng: random.Random):
    long_text = "x" * rng.randint(1, 5000)
    options = [
        None, True, False, 0, -1, 2**70, 1.5, "", "a", long_text, "\x00", "\n", "\r\n", " ", "\ud800", "../../etc/passwd",
        "'; DROP TABLE users; --", "é😀", "\x01" * rng.randint(1, 4096), [], {}, [1, [2, [3]]], {"a": {"b": 1}}, ["maya"], {"maya": "brief"},
        "maya\x00", " maya", "MAYA", "maуa", "brief\n", "$(id)", "{{7*7}}", "A" * 1184, PUBLIC_KEY_B64[:-4] + "AAAA",
    ]
    return rng.choice(options)


def templates() -> list[dict]:
    return [
        {"op": "read", "actor": "maya", "asset": "brief", "request_id": "fz"},
        {"op": "read", "actor": "ravi", "asset": "notes", "request_id": "fz"},
        {"op": "read", "actor": "mallory", "asset": "brief", "request_id": "fz"},
        {"op": "revoke", "actor": "intruder"},
        {"op": "audit", "request_id": "fz"},
        {"op": "protected_read", "actor": "maya", "asset": "brief", "challenge": "c", "public_key": PUBLIC_KEY_B64},
        {"op": "protected_read", "actor": "intruder", "asset": "brief", "challenge": "c", "public_key": PUBLIC_KEY_B64},
    ]


def mutate_structure(rng: random.Random) -> dict:
    request = json.loads(json.dumps(rng.choice(templates())))
    for _ in range(rng.randint(0, 3)):
        roll = rng.random()
        if roll < 0.25 and request:
            del request[rng.choice(list(request))]
        elif roll < 0.55 and request:
            request[rng.choice(list(request))] = hostile_value(rng)
        elif roll < 0.7:
            request[rng.choice(["admin", "__proto__", "op", "actor", "x" * 50])] = hostile_value(rng)
        elif roll < 0.85:
            request["op"] = rng.choice(["READ", " read", "read\n", "Read", "protected_read\x00", "setup ", "REVOKE", "delete", "", "audit "])
    return request


def encode_request(rng: random.Random, request: dict) -> bytes:
    try:
        return json.dumps(request, ensure_ascii=rng.random() < 0.7).encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(request, ensure_ascii=True).encode("ascii")


def mutate_bytes(rng: random.Random) -> bytes:
    data = bytearray(json.dumps(rng.choice(templates())).encode())
    for _ in range(rng.randint(1, 3)):
        roll = rng.random()
        position = rng.randrange(len(data)) if data else 0
        if roll < 0.3 and data:
            data[position] ^= 1 << rng.randrange(8)
        elif roll < 0.5 and data:
            del data[position : position + rng.randint(1, 8)]
        elif roll < 0.7:
            data[position:position] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif roll < 0.85 and data:
            data[position:position] = data[position : position + rng.randint(1, 20)]
        else:
            data = data[: rng.randint(0, len(data))]
    return bytes(data)


# --- the invariants -----------------------------------------------------------------------------------


def check_outcome(done: subprocess.CompletedProcess, sent: bytes) -> None:
    assert done.returncode in (0, 1), (done.returncode, done.stderr[:200], sent[:200])
    seen = done.stdout + done.stderr
    assert MARKER.encode() not in seen, "key material leaked"
    assert b"Traceback" not in done.stderr, done.stderr[:300]
    if done.returncode == 1:
        assert done.stdout == b"", done.stdout[:200]
        assert GENERIC_STDERR.match(done.stderr), done.stderr[:200]
        return
    assert done.stdout.endswith(b"\n") and done.stdout.count(b"\n") == 1, done.stdout[:200]
    done.stdout.decode("ascii")
    reply = json.loads(done.stdout)
    assert isinstance(reply, dict)
    stderr_lines = [line for line in done.stderr.splitlines() if line.strip()]
    assert all(line.strip() in ALLOWED_STDERR_NOTES for line in stderr_lines), done.stderr[:200]
    if SECRET_BODY.encode() in done.stdout:
        assert reply == {"decision": "allow", "body": SECRET_BODY}, reply
        request = json.loads(sent)  # a body may only ever go to the real owner
        assert request.get("actor") == "maya" and request.get("asset") == "brief" and request.get("op") == "read", request
    if "ciphertext" in reply:
        assert set(reply) == {"ciphertext", "proof"} and SECRET_BODY not in json.dumps(reply)


def canary(runner: Runner) -> None:
    """The state must still load, an innocent owner must still be served, and the log must verify."""
    assert runner.call({"op": "read", "actor": "ravi", "asset": "notes", "request_id": f"canary-{random.random()}"}) == {"decision": "allow", "body": "ravi body"}
    verified = subprocess.run(
        [sys.executable, "-m", "t4.audit.cli", "--dir", str(runner.state_dir / "audit"), "verify-log"], capture_output=True, text=True, cwd=REPO_ROOT, timeout=120
    )
    assert verified.returncode == 0 and json.loads(verified.stdout)["ok"] is True, verified.stdout[:400]


# --- fuzzing --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", [20261126, 7, 424242])
def test_structured_fuzzing_never_breaks_an_invariant(state_dir, seed):
    rng = random.Random(seed)
    runner = Runner(state_dir)
    provision(runner)
    for i in range(ITERATIONS):
        sent = encode_request(rng, mutate_structure(rng))
        check_outcome(runner.run(sent), sent)
        if i % 20 == 19:
            canary(runner)
    canary(runner)


@pytest.mark.parametrize("seed", [1, 99])
def test_raw_byte_mutation_never_breaks_an_invariant(state_dir, seed):
    rng = random.Random(seed)
    runner = Runner(state_dir)
    provision(runner)
    for i in range(ITERATIONS):
        sent = mutate_bytes(rng)
        done = runner.run(sent)
        try:
            json.loads(sent)
            parsed = True
        except ValueError:
            parsed = False
        if parsed and done.returncode == 0 and SECRET_BODY.encode() in done.stdout:
            check_outcome(done, sent)
        else:
            assert done.returncode in (0, 1) and b"Traceback" not in done.stderr and MARKER.encode() not in done.stdout + done.stderr, (done.stderr[:200], sent[:200])
            if done.returncode == 1:
                assert done.stdout == b"" and GENERIC_STDERR.match(done.stderr)
        if i % 20 == 19:
            canary(runner)
    canary(runner)


@pytest.mark.parametrize("seed", [5])
def test_setup_shape_fuzzing_never_crashes_or_leaks(state_dir, seed):
    rng = random.Random(seed)
    runner = Runner(state_dir)
    for _ in range(ITERATIONS):
        request = {"op": "setup", "owners": hostile_value(rng), "contents": hostile_value(rng), "disabled": hostile_value(rng), "key_material": MARKER}
        if rng.random() < 0.3:
            key = hostile_value(rng)
            request["owners"] = {key if isinstance(key, str) else "a": rng.choice(["u", "v", "w"])}
        sent = encode_request(rng, request)
        done = runner.run(sent)
        assert done.returncode in (0, 1) and b"Traceback" not in done.stderr
        assert MARKER.encode() not in done.stdout + done.stderr
        if done.returncode == 1:
            assert done.stdout == b"" and GENERIC_STDERR.match(done.stderr)


# --- differential test against the official demo ---------------------------------------------------------


def _toolkit() -> Path | None:
    for candidate in (os.environ.get("TRACK4_TOOLKIT"), str(REPO_ROOT.parent / "Track-4-Toolkit")):
        if candidate and (Path(candidate) / "demo" / "python" / "team_app.py").is_file():
            return Path(candidate)
    return None


def _normalize(op: str, reply: dict) -> dict:
    """Ignore the demo's extra `rule` field. The demo adds it to read and audit replies; the
    contract requires neither (a denial is exactly `{"decision":"deny"}`), and we add it only to
    `audit`. Everything else, decisions, bodies, errors and fields, must match exactly."""
    return {k: v for k, v in reply.items() if k != "rule"}


@pytest.mark.parametrize("seed", [2026, 31337])
def test_legitimate_sequences_match_the_official_demo(tmp_path, seed):
    toolkit = _toolkit()
    if toolkit is None:
        pytest.skip("official toolkit not found (set TRACK4_TOOLKIT or clone it next to the repo)")
    demo_dir = tmp_path / "demo-adapter"
    demo_dir.mkdir()
    shutil.copy(toolkit / "starters" / "python" / "track4_service.py", demo_dir)
    shutil.copy(toolkit / "demo" / "python" / "team_app.py", demo_dir)
    (tmp_path / "ours").mkdir(mode=0o700)
    (tmp_path / "theirs").mkdir(mode=0o700)
    ours, theirs = Runner(tmp_path / "ours"), Runner(tmp_path / "theirs", entry=demo_dir / "track4_service.py", cwd=demo_dir)

    rng = random.Random(seed)
    actors, assets = ["maya", "ravi", "zed", "mallory", "nobody"], ["brief", "notes", "memo", "ghost"]
    issued: list[str] = []
    counter = 0
    differences: list[str] = []

    def both(request: dict) -> None:
        a = _normalize(request["op"], ours.call(request))
        b = _normalize(request["op"], theirs.call(request))
        if a != b:
            differences.append(f"{json.dumps(request)} -> ours {json.dumps(a)} | demo {json.dumps(b)}")

    def fresh_setup() -> dict:
        owners = {"brief": rng.choice(actors[:3]), "notes": rng.choice(actors[:3]), "memo": rng.choice(actors[:3])}
        return {"op": "setup", "owners": owners, "contents": {k: f"body-{k}-{rng.randint(0, 99)}" for k in owners}, "disabled": ["mallory"], "key_material": MARKER}

    both(fresh_setup())
    for _ in range(DIFF_STEPS):
        roll = rng.random()
        if roll < 0.5:
            counter += 1
            request_id = f"r{seed}-{counter}"
            issued.append(request_id)
            both({"op": "read", "actor": rng.choice(actors), "asset": rng.choice(assets), "request_id": request_id})
        elif roll < 0.65:
            both({"op": "revoke", "actor": rng.choice(actors)})
        elif roll < 0.85:
            both({"op": "audit", "request_id": rng.choice(issued) if issued and rng.random() < 0.8 else f"never-{rng.randint(0, 9)}"})
        elif roll < 0.93:
            both({"op": rng.choice(["delete", "protected_write", "SETUP"])})
        else:
            both(fresh_setup())
            issued.clear()
    assert not differences, "\n" + "\n".join(differences)
