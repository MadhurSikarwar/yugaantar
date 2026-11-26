#!/usr/bin/env python3
"""Imitate the organizers' judging worker against a CLEAN copy of the submission.

    python scripts/sandbox_sim.py --ref origin/main --toolkit ../Track-4-Toolkit
    python scripts/sandbox_sim.py --submission /submission --toolkit /toolkit      (inside a container)

What it imitates, from the toolkit's adapter contract (the only description we have):
  * the submission is built from COMMITTED files only (`git archive REF`), so a file that exists
    only on one laptop cannot hide a problem; the tree is made read-only;
  * a NEW process per request, started from the submission folder, one JSON object on stdin and
    one on stdout, in a minimal environment, with `TRACK4_STATE_DIR` unset (the judging fallback
    is the OS temp folder) and also set the way the local checker and a careless harness set it;
  * a fresh, empty container for every scenario; no network (a blocker is injected, and Docker's
    `--network none` adds the real thing);
  * the official `validate.py`, plus the `protected_read` cryptography check the local validator
    lacks, written independently with pqcrypto: encapsulate, decapsulate, recompute the proof.

What it cannot do: it is NOT the organizers' sandbox (we have no access to it). On Windows the
tree is only marked read-only and the POSIX folder cases are skipped; run it on Linux or WSL for
full fidelity, ideally through scripts/sandbox_docker.sh as well.

Exit status 0 only if every check passed. Standard library only, plus pqcrypto for the client side.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import shutil
import stat
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MARKER = "KEY-MATERIAL-MARKER-sandbox-sim-7d0c41ae95"
OUTPUT_CAP = 64 * 1024
OP_TIMEOUT = 8.0  # the official validator's default per-operation limit
KEEP_ENV = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR", "LANG", "LC_ALL")
IS_POSIX = os.name == "posix"

results: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f": {detail}" if detail else ""), flush=True)


def skip(name: str, why: str) -> None:
    print(f"SKIP  {name}: {why}", flush=True)


def normalize_python(path: str) -> str:
    """Make the interpreter path absolute WITHOUT following symlinks.

    On Linux a virtual environment's `python` is a symlink to the base interpreter. Resolving it would
    silently drop the venv (and its packages), so the adapter would run without pqcrypto.
    """
    return os.path.abspath(path) if (os.sep in path or "/" in path) else path


def preflight(python: str) -> None:
    """Fail early and clearly if the adapter's interpreter cannot run the product."""
    done = subprocess.run(
        [python, "-c", "import sys, pqcrypto.kem.ml_kem_768, pqcrypto.sign.ml_dsa_65; print(sys.version_info[:2])"],
        capture_output=True, text=True, timeout=60,
    )
    if done.returncode != 0:
        raise SystemExit(
            f"The interpreter used for the adapter cannot import pqcrypto: {python}\n"
            "Run this script with the virtual environment's python (the one where you installed pqcrypto==0.4.0),\n"
            f"or pass --python PATH. Error: {done.stderr.strip()[-200:]}"
        )
    if done.stdout.strip() != "(3, 12)":
        print(f"WARNING: the judging runtime is Python 3.12; this interpreter reports {done.stdout.strip()}")


# --- building the clean, read-only submission ------------------------------------------------------


def extract_ref(ref: str, destination: Path) -> None:
    done = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar", ref], capture_output=True, timeout=300)
    if done.returncode != 0:
        raise SystemExit(f"git archive {ref} failed: {done.stderr.decode(errors='replace')[:300]}")
    with tarfile.open(fileobj=io.BytesIO(done.stdout), mode="r:") as archive:
        archive.extractall(destination, filter="data")


def make_read_only(root: Path) -> None:
    """POSIX: remove every write bit (a root user would still be able to write). Windows: read-only attribute on files."""
    for path in sorted(root.rglob("*"), reverse=True):
        mode = path.stat().st_mode
        if IS_POSIX:
            os.chmod(path, mode & ~0o222)
        elif path.is_file():
            os.chmod(path, stat.S_IREAD)
    if IS_POSIX:
        os.chmod(root, root.stat().st_mode & ~0o222)


def make_writable(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        try:
            os.chmod(path, stat.S_IRWXU if path.is_dir() else stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def snapshot(root: Path) -> dict[str, str]:
    """Hash of every file, ignoring __pycache__ (Python may legitimately try to write bytecode)."""
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


# --- the simulated container ----------------------------------------------------------------------------


class Sandbox:
    def __init__(self, submission: Path, work: Path, python: str) -> None:
        self.submission, self.work, self.python = submission, work, python
        self.offline_dir = work / "offline"
        self.offline_dir.mkdir(parents=True, exist_ok=True)
        (self.offline_dir / "sitecustomize.py").write_text(
            "import socket\n"
            "def _blocked(*a, **k):\n"
            "    raise OSError('network is disabled in the sandbox simulation')\n"
            "socket.socket.connect = _blocked\n"
            "socket.socket.connect_ex = _blocked\n"
            "socket.create_connection = _blocked\n"
            "socket.getaddrinfo = _blocked\n",
            encoding="utf-8",
        )
        self.containers = 0

    def new_container(self) -> tuple[Path, dict[str, str]]:
        """A fresh empty 'container': its own /tmp (sticky on POSIX) and a minimal environment."""
        self.containers += 1
        tmp = self.work / f"container-{self.containers}" / "tmp"
        tmp.mkdir(parents=True)
        if IS_POSIX:
            os.chmod(tmp, 0o1777)
        env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
        env.update(
            TMPDIR=str(tmp), TEMP=str(tmp), TMP=str(tmp),
            PYTHONPATH=str(self.offline_dir),
            PYTHONPYCACHEPREFIX=str(tmp / "pyc"),  # a read-only tree cannot hold bytecode: put it elsewhere
        )
        return tmp, env

    def call(self, request: dict | bytes, env: dict[str, str], timeout: float = OP_TIMEOUT) -> tuple[int, bytes, bytes, float]:
        data = request if isinstance(request, bytes) else json.dumps(request).encode("utf-8")
        start = time.perf_counter()
        done = subprocess.run(
            [self.python, "track4_service.py"], input=data, capture_output=True, cwd=self.submission, env=env, timeout=timeout
        )
        return done.returncode, done.stdout, done.stderr, time.perf_counter() - start

    def json_call(self, request: dict, env: dict[str, str]) -> tuple[dict | None, str]:
        """Returns (reply, problem). `problem` is empty when the call behaved like a well-formed worker exchange."""
        rc, out, err, _ = self.call(request, env)
        if rc != 0:
            return None, f"exit {rc}"
        if len(out) > OUTPUT_CAP or len(err) > OUTPUT_CAP:
            return None, "output over 64 KiB"
        if MARKER.encode() in out + err:
            return None, "key material leaked"
        try:
            reply = json.loads(out)
        except ValueError:
            return None, "stdout is not one JSON object"
        if not isinstance(reply, dict) or out.count(b"\n") != 1:
            return None, "stdout is not exactly one JSON object line"
        return reply, ""


# --- scenarios ------------------------------------------------------------------------------------------------


def state_env(mode: str, tmp: Path, env: dict[str, str]) -> dict[str, str] | None:
    env = dict(env)
    env.pop("TRACK4_STATE_DIR", None)
    if mode == "unset":
        return env
    folder = tmp / f"state-{mode}"
    folder.mkdir()
    if mode == "fresh":
        os.chmod(folder, 0o700) if IS_POSIX else None
    elif mode == "existing0755":
        if not IS_POSIX:
            return None
        os.chmod(folder, 0o755)
    elif mode == "sticky":
        if not IS_POSIX:
            return None
        os.chmod(folder, 0o1777)
    env["TRACK4_STATE_DIR"] = str(folder)
    return env


def lost_device_story(sb: Sandbox, mode: str) -> None:
    from pqcrypto.kem import ml_kem_768

    tmp, base = sb.new_container()
    env = state_env(mode, tmp, base)
    label = f"[{mode}]"
    if env is None:
        skip(f"{label} lost-device story", "needs POSIX folder modes")
        return
    owners, contents = {"brief": "maya", "notes": "ravi"}, {"brief": "demo note é\U0001f600", "notes": "ravi body"}

    def step(name: str, request: dict, expect: dict | None = None, check=None) -> dict | None:
        reply, problem = sb.json_call(request, env)
        ok = not problem and (expect is None or reply == expect) and (check is None or check(reply))
        record(f"{label} {name}", ok, problem or ("" if ok else f"got {json.dumps(reply)[:120]}"))
        return reply

    step("setup", {"op": "setup", "owners": owners, "contents": contents, "disabled": ["mallory"], "key_material": MARKER}, {"ready": True})
    step("owner reads own file", {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r01"}, {"decision": "allow", "body": contents["brief"]})
    step("peer reads own file", {"op": "read", "actor": "ravi", "asset": "notes", "request_id": "r02"}, {"decision": "allow", "body": contents["notes"]})
    step("wrong owner is denied", {"op": "read", "actor": "maya", "asset": "notes", "request_id": "r03"}, {"decision": "deny"})
    step("disabled actor is denied", {"op": "read", "actor": "mallory", "asset": "brief", "request_id": "r04"}, {"decision": "deny"})

    public_key, secret_key = ml_kem_768.generate_keypair()
    challenge = "fresh-chällenge-\U0001f511"
    pr = step("protected_read answers", {"op": "protected_read", "actor": "maya", "asset": "brief", "challenge": challenge, "public_key": base64.b64encode(public_key).decode()},
              check=lambda r: set(r) == {"ciphertext", "proof"})
    if pr and set(pr) == {"ciphertext", "proof"}:
        shared = ml_kem_768.decrypt(secret_key, base64.b64decode(pr["ciphertext"], validate=True))
        expected = hmac.new(shared, challenge.encode() + contents["brief"].encode(), hashlib.sha256).hexdigest()
        record(f"{label} protected_read proof matches an independent client", pr["proof"] == expected)

    step("revoke", {"op": "revoke", "actor": "maya"}, {})
    step("revoked owner is denied", {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r05"}, {"decision": "deny"})
    step("audit explains the denial", {"op": "audit", "request_id": "r05"}, check=lambda r: r.get("request_id") == "r05" and r.get("decision") == "deny")
    step("peer is unaffected", {"op": "read", "actor": "ravi", "asset": "notes", "request_id": "r06"}, {"decision": "allow", "body": contents["notes"]})
    step("revocation persists across processes", {"op": "read", "actor": "maya", "asset": "brief", "request_id": "r07"}, {"decision": "deny"})
    step("denied protected_read is a plain deny", {"op": "protected_read", "actor": "maya", "asset": "brief", "challenge": "c", "public_key": base64.b64encode(public_key).decode()}, {"decision": "deny"})
    step("unknown operation", {"op": "format_disk"}, {"error": "unsupported_operation"})

    rc, out, err, _ = sb.call(b"{", env)
    record(f"{label} malformed input fails cleanly", rc == 1 and out == b"" and b"Traceback" not in err)


def fresh_container_is_empty(sb: Sandbox) -> None:
    tmp, base = sb.new_container()
    env = state_env("unset", tmp, base)
    reply, problem = sb.json_call({"op": "read", "actor": "maya", "asset": "brief", "request_id": "x"}, env)
    record("a fresh container starts empty: nothing is readable before setup", not problem and reply == {"decision": "deny"}, problem)


def parallel_requests(sb: Sandbox) -> None:
    tmp, base = sb.new_container()
    env = state_env("fresh", tmp, base)
    sb.json_call({"op": "setup", "owners": {"a": "u"}, "contents": {"a": "body"}, "disabled": []}, env)

    def one(i: int):
        return sb.json_call({"op": "read", "actor": "u", "asset": "a", "request_id": f"p{i}"}, env)

    with ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(one, range(16)))
    ok = all(not problem and reply == {"decision": "allow", "body": "body"} for reply, problem in replies)
    record("16 parallel requests all answered correctly", ok)


def latency(sb: Sandbox) -> None:
    from pqcrypto.kem import ml_kem_768

    tmp, base = sb.new_container()
    env = state_env("unset", tmp, base)
    sb.json_call({"op": "setup", "owners": {"a": "u"}, "contents": {"a": "body"}, "disabled": []}, env)
    public_key = base64.b64encode(ml_kem_768.generate_keypair()[0]).decode()
    requests = {
        "read": lambda i: {"op": "read", "actor": "u", "asset": "a", "request_id": f"l{i}"},
        "audit": lambda i: {"op": "audit", "request_id": "l0"},
        "protected_read": lambda i: {"op": "protected_read", "actor": "u", "asset": "a", "challenge": "c", "public_key": public_key},
    }
    for name, make in requests.items():
        times, bad = [], 0
        for i in range(12):
            rc, out, err, seconds = sb.call(make(i), env)
            times.append(seconds)
            try:
                reply = json.loads(out) if rc == 0 else None
            except ValueError:
                reply = None
            expected_ok = reply is not None and (("ciphertext" in reply) if name == "protected_read" else (reply.get("decision") in ("allow", "deny") if name != "audit" else "request_id" in reply))
            bad += 0 if expected_ok else 1
        times.sort()
        p50, p95 = statistics.median(times), times[int(len(times) * 0.95) - 1]
        record(f"cold-process latency {name}: p50 {p50 * 1000:.0f} ms, p95 {p95 * 1000:.0f} ms (limit {OP_TIMEOUT:.0f} s), {12 - bad}/12 correct replies", p95 < OP_TIMEOUT and bad == 0)


def official_validator(sb: Sandbox, toolkit: Path, python: str) -> None:
    tmp, env = sb.new_container()
    done = subprocess.run(
        [python, str(toolkit / "validate.py"), "--entry", str(sb.submission / "track4_service.py")],
        capture_output=True, text=True, env=env, cwd=sb.submission, timeout=600,
    )
    failed = [line for line in done.stdout.splitlines() if line.startswith("FAIL")]
    detail = "; ".join(failed)[:300]
    if done.returncode != 0 and not detail:
        detail = f"exit {done.returncode}; stdout tail: {done.stdout.strip()[-300:]!r}; stderr tail: {done.stderr.strip()[-300:]!r}"
    record("official validate.py exits 0", done.returncode == 0, detail)


def offline_selftest(sb: Sandbox) -> None:
    tmp, env = sb.new_container()
    done = subprocess.run(
        [sb.python, "-c", "import socket; socket.create_connection(('203.0.113.1', 9), timeout=2)"],
        capture_output=True, env=env, cwd=sb.submission, timeout=30,
    )
    record("simulation self-test: the network is really blocked", done.returncode != 0 and b"network is disabled" in done.stderr)


def threat_model_file(sb: Sandbox) -> None:
    path = sb.submission / "threat-model.json"
    if not path.is_file():
        skip("threat-model.json", "not present (optional)")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ok = isinstance(data.get("asset"), str) and isinstance(data.get("boundary"), str)
    except ValueError:
        ok = False
    record("threat-model.json is valid and has asset and boundary", ok)


def layout(submission: Path) -> None:
    adapters = [p.name for p in submission.iterdir() if p.is_file() and p.name.startswith("track4_service.")]
    record("exactly one adapter at the submission root", adapters == ["track4_service.py"], ", ".join(adapters))
    record("README.md and requirements.txt are present", (submission / "README.md").is_file() and (submission / "requirements.txt").is_file())


# --- main -------------------------------------------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--ref", default="HEAD", help="git ref of the repository to test (default HEAD): built with `git archive`")
    source.add_argument("--submission", help="use this existing folder as the submission (for a container); it is not copied or modified")
    parser.add_argument("--toolkit", help="path to the official Track-4-Toolkit checkout (for validate.py)")
    parser.add_argument("--python", default=sys.executable, help="interpreter to run the adapter with (default: this one)")
    parser.add_argument("--keep", action="store_true", help="keep the temporary folders")
    args = parser.parse_args()
    if args.toolkit:
        args.toolkit = str(Path(args.toolkit).resolve())  # the validator runs from another folder: a relative path would break
    args.python = normalize_python(args.python)

    try:
        import pqcrypto.kem.ml_kem_768  # noqa: F401  (client side of the protected_read check)
    except ImportError:
        raise SystemExit("pqcrypto is needed by this script: pip install pqcrypto==0.4.0")
    preflight(args.python)

    work = Path(tempfile.mkdtemp(prefix="t4-sandbox-"))
    try:
        if args.submission:
            submission = Path(args.submission).resolve()
            print(f"Using the existing submission folder {submission} (not modified)")
        else:
            submission = work / "submission"
            submission.mkdir()
            extract_ref(args.ref, submission)
            make_read_only(submission)
            print(f"Built a clean copy of {args.ref} from committed files only, made read-only: {submission}")
        print(f"Interpreter: {args.python}   OS: {sys.platform}   POSIX folder cases: {'on' if IS_POSIX else 'skipped (Windows)'}\n")

        before = snapshot(submission)
        sb = Sandbox(submission, work, args.python)
        layout(submission)
        offline_selftest(sb)
        if args.toolkit and (Path(args.toolkit) / "validate.py").is_file():
            official_validator(sb, Path(args.toolkit), args.python)
        else:
            skip("official validate.py", "pass --toolkit PATH")
        for mode in ("unset", "fresh", "existing0755", "sticky"):
            lost_device_story(sb, mode)
        fresh_container_is_empty(sb)
        parallel_requests(sb)
        latency(sb)
        threat_model_file(sb)
        after = snapshot(submission)
        changed = sorted({*before, *after} - {k for k in before if before.get(k) == after.get(k)})
        record("the submission tree was never modified (ignoring __pycache__)", not changed, ", ".join(changed[:5]))
    finally:
        if args.keep:
            print(f"\nkept: {work}")
        else:
            make_writable(work)
            shutil.rmtree(work, ignore_errors=True)

    failed = [name for name, ok, _ in results if not ok]
    print("\n" + ("SANDBOX SIMULATION PASSED" if not failed else f"FAILED ({len(failed)}): " + "; ".join(failed[:6])))
    print("Reminder: this imitates the documented worker; it is not the organizers' sandbox.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
