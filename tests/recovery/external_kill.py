"""Kill a rotating device from OUTSIDE its process, then check recovery.

    python -m tests.recovery.external_kill --trials 100 --seed 7

Unlike the ``os._exit`` tests, the parent kills the child (SIGKILL on Linux,
TerminateProcess on Windows). Two parts:

* held: the child pauses at each fault step and the parent kills it there;
* random: no fault hook at all; the parent kills at a random moment while the
  rotation runs, so the cut can fall inside a write.

Uses the real ML-DSA wrapper and the real signed audit log. Not collected by
pytest (the file name does not start with ``test_``). Exit 1 on any violation.
"""
from __future__ import annotations

import argparse
import collections
import json
import platform
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from t4 import rotation
from t4.node.authority import Authority
from t4.node.common import load_signer, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond

REPO = Path(__file__).resolve().parents[2]
NOW, CUTOFF = 1_000_000.0, 1_000_200.0
STEPS = ("prepared", "committed", "applied", "published", "acknowledged")


def authority_at(directory: Path, signer) -> Authority:
    return Authority(directory, signer, open_log(directory / "log"))


def child(device_dir: str, authority_dir: str, hold_at: str) -> None:
    signer = load_signer()
    authority = authority_at(Path(authority_dir), signer)
    device = Device(device_dir, signer)
    signer.sig_keygen()  # Load the library before the parent starts its clock.

    def hold(step: str) -> None:
        if step == hold_at:
            print("held", flush=True)
            time.sleep(120)

    print("ready", flush=True)
    device.rotate(authority, NOW + 1, CUTOFF, hold)


def start_child(root: Path, hold_at: str) -> subprocess.Popen:
    process = subprocess.Popen(
        [sys.executable, "-B", "-m", "tests.recovery.external_kill", "--child",
         str(root / "d"), str(root / "a"), hold_at],
        cwd=REPO, stdout=subprocess.PIPE, text=True)
    assert process.stdout.readline().strip() == "ready", "child did not start"
    return process


def prepare(root: Path, signer) -> None:
    authority = Authority.create(root / "a", signer, open_log(root / "a" / "log"),
                                 freshness=60.0, skew=2.0)
    device = Device.create(root / "d", signer, "phone", "maya")
    device.enroll(authority, NOW)
    rotation.revoke_key(device.store, 99, NOW)  # Must survive every kill.


def require(condition: bool, what: str) -> None:
    if not condition:
        raise AssertionError(what)


def check_after_kill(root: Path, signer) -> tuple[str, int]:
    """Return (state found on disk, rotate entries in the key-event log)."""
    authority = authority_at(root / "a", signer)
    device = Device(root / "d", signer)
    with device.store.locked() as txn:  # Raw state, before recovery runs.
        raw = txn.get(rotation.RECORD)
    with authority.store.locked() as txn:
        published = len(txn.get("authority")["devices"]["phone"]["keys"]) == 2
    journal = raw["journal"]["state"] if raw["journal"] else "none"
    acknowledged = raw["keys"][str(raw["current"])]["published"]
    found = (f"journal={journal} version={raw['current']} acknowledged={acknowledged} "
             f"authority_has_new_key={published}")

    ring = rotation.recover(device.store)
    require(ring["journal"] is None, "journal left behind")
    require(ring["current"] == (2 if journal == "COMMITTED" else raw["current"]),
            "wrong version after recovery")
    require("99" in ring["revoked_keys"], "a revoked key was forgotten")
    require(rotation.signing_key(device.store, NOW + 2)[0] == 1, "old key unusable before C")
    if ring["current"] == 1 or not ring["keys"]["2"]["published"]:
        require(device.rotate(authority, NOW + 3, CUTOFF) == CUTOFF, "rotation not finishable")

    keys = authority.issue_list(NOW + 4)["body"]["devices"]["phone"]["keys"]
    require([k["version"] for k in keys] == [1, 2], "authority has wrong versions")
    require(keys[1]["public_key"] == device.info()["keys"]["2"]["public_key"],
            "authority and device disagree on the new key")

    node = Node.provision(root / "n", signer, open_log(root / "n" / "log"), node_id="n1",
                          authority_pk=authority.public_key, owners={"f": "maya"},
                          contents={"f": "synthetic"})
    require(node.accept_list(authority.issue_list(CUTOFF - 20), CUTOFF - 20), "list rejected")
    for at, version in ((CUTOFF - 5, 1), (CUTOFF, 2)):
        request = device.make_request("n1", "f", at)
        require(request["body"]["key_version"] == version, "wrong key version used")
        require(respond(node, request, at)["decision"] == "allow", "authorized read denied")
    authority.revoke_device("phone", CUTOFF + 1)
    require(node.accept_list(authority.issue_list(CUTOFF + 2), CUTOFF + 2), "list rejected")
    request = device.make_request("n1", "f", CUTOFF + 3)
    require(respond(node, request, CUTOFF + 3) == {"decision": "deny"}, "revoked device served")

    for log_dir in (root / "a" / "log", root / "n" / "log"):
        report = open_log(log_dir).verify()
        require(report.ok, f"log does not verify: {report.errors}")
    rotations = sum(e["rule"] == "KEY-ROTATE" for e in open_log(root / "a" / "log").entries())
    return found, rotations


def kill(process: subprocess.Popen) -> bool:
    """Kill from outside. True if it was still running."""
    running = process.poll() is None
    process.kill()
    process.wait(timeout=30)
    process.stdout.close()
    return running and process.returncode != 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--child", nargs=3, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child:
        child(*args.child)
        return 0
    signer = load_signer()
    rng = random.Random(args.seed)  # Kill timing only; never used for keys.
    failures: list[str] = []
    held, states = {}, collections.Counter()
    killed = finished = repeated_log = 0

    for step in STEPS:
        with tempfile.TemporaryDirectory(prefix="t4-kill-") as folder:
            root = Path(folder)
            prepare(root, signer)
            process = start_child(root, step)
            require(process.stdout.readline().strip() == "held", "child did not reach the step")
            require(kill(process), "child was not running when killed")
            code = process.returncode
            try:
                found, _ = check_after_kill(root, signer)
                held[step] = {"exit": code, "found": found, "result": "ok"}
            except Exception as error:
                held[step] = {"exit": code, "result": "FAIL"}
                failures.append(f"held {step}: {type(error).__name__}: {error}")

    durations = []
    for _ in range(5):  # How long does an undisturbed rotation take?
        with tempfile.TemporaryDirectory(prefix="t4-kill-") as folder:
            prepare(Path(folder), signer)
            process = start_child(Path(folder), "never")
            started = time.perf_counter()
            require(process.wait(timeout=60) == 0, "undisturbed rotation failed")
            durations.append(time.perf_counter() - started)
            process.stdout.close()
    span = sorted(durations)[2] * 1.1

    for trial in range(args.trials):
        with tempfile.TemporaryDirectory(prefix="t4-kill-") as folder:
            root = Path(folder)
            prepare(root, signer)
            process = start_child(root, "never")
            time.sleep(rng.uniform(0, span))
            if kill(process):
                killed += 1
            else:
                finished += 1
            try:
                found, rotations = check_after_kill(root, signer)
                states[found] += 1
                repeated_log += rotations > 1
                # One logical rotation must leave exactly one KEY-ROTATE entry once it has been
                # finished (check_after_kill finishes it). More than one is a real failure.
                require(rotations == 1, f"{rotations} KEY-ROTATE entries for one rotation")
            except Exception as error:
                failures.append(f"random trial {trial}: {type(error).__name__}: {error}")

    print(json.dumps({
        "platform": f"{platform.system()} Python {platform.python_version()}",
        "held_at_each_step": held,
        "random": {"trials": args.trials, "seed": args.seed,
                   "killed_while_running": killed, "finished_before_kill": finished,
                   "kill_window_ms": round(span * 1000, 1),
                   "states_found": dict(sorted(states.items())),
                   "trials_with_repeated_rotate_log_entry": repeated_log},
        "failures": failures,
    }, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
