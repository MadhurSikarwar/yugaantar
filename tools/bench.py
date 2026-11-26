#!/usr/bin/env python3
"""Latency benchmark for the judged adapter (PRD M-D8).

What it does
    Starts ``track4_service.py`` as a **new process per request**, exactly as
    the judges do (``python -B <entry>`` from the repository root, state in a
    fresh temporary directory), and measures the wall-clock time of each run,
    from process start to exit. It reports p50, p95 and max per operation,
    the growth of the state directory (audit log plus state file) per
    operation and, on POSIX, the peak resident memory of the child processes.

    Operations measured: ``setup``, ``read`` (allow), ``read`` (deny),
    ``revoke``, ``audit``, ``protected_read`` (allow). The ``protected_read``
    result is checked once against an independent client: decapsulate with
    ``pqcrypto``, recompute the HMAC proof and compare.

    Targets from the PRD: p50 under 200 ms and p95 under 1 s per request,
    far from the validator's 8 s timeout.

Usage
    python tools/bench.py [--runs 30] [--entry track4_service.py] [--json] [--out FILE]

What it defends against
    Untested performance claims: every number in the evidence sheet comes from
    this script, with the run count, Python version and platform printed with it.
    It uses only synthetic data and runtime-generated keys; nothing secret is
    printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import secrets
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile (``fraction`` in 0..1)."""
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-fraction * len(ordered) // 1))))
    return ordered[rank - 1]


def dir_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


class Service:
    """Runs one request per fresh process against one state directory."""

    def __init__(self, entry: Path, state: Path):
        self.entry = entry
        self.state = state
        self.env = dict(os.environ)
        for name in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
            self.env[name] = str(state)

    def call(self, request: dict) -> tuple[dict, float]:
        started = time.perf_counter()
        proc = subprocess.run([sys.executable, "-B", str(self.entry)], input=json.dumps(request).encode(),
                              cwd=self.entry.parent, env=self.env, capture_output=True, timeout=30)
        elapsed = (time.perf_counter() - started) * 1000
        if proc.returncode != 0:
            raise RuntimeError(f"{request.get('op')} failed with exit {proc.returncode}")
        return json.loads(proc.stdout), elapsed


def peak_child_rss_mb() -> float | None:
    """Peak resident set size over all finished child processes (POSIX only)."""
    try:
        import resource
    except ImportError:
        return None
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024


def check_protected_read(response: dict, secret_key: bytes, challenge: str, body: str) -> bool:
    """Independent client check: decapsulate, recompute the proof, compare."""
    from pqcrypto.kem import ml_kem_768

    shared = ml_kem_768.decrypt(secret_key, base64.b64decode(response["ciphertext"], validate=True))
    expected = hmac.new(shared, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, response["proof"])


def run(entry: Path, runs: int) -> dict:
    from pqcrypto.kem import ml_kem_768

    with tempfile.TemporaryDirectory(prefix="t4-bench-") as folder:
        svc = Service(entry, Path(folder))
        owners = {f"file-{i}": f"user-{i}" for i in range(8)}
        contents = {asset: f"synthetic body of {asset}" for asset in owners}
        setup = {"op": "setup", "owners": owners, "contents": contents, "disabled": ["user-disabled"],
                 "key_material": secrets.token_hex(16)}
        public_key, secret_key = ml_kem_768.generate_keypair()
        pk_b64 = base64.b64encode(public_key).decode()

        plans = {
            "setup": lambda i: setup,
            "read (allow)": lambda i: {"op": "read", "actor": "user-1", "asset": "file-1", "request_id": f"ra-{i}"},
            "read (deny)": lambda i: {"op": "read", "actor": "user-2", "asset": "file-1", "request_id": f"rd-{i}"},
            "audit": lambda i: {"op": "audit", "request_id": f"rd-{i}"},
            "protected_read": lambda i: {"op": "protected_read", "actor": "user-3", "asset": "file-3",
                                         "challenge": f"challenge-{i}", "public_key": pk_b64},
            "revoke": lambda i: {"op": "revoke", "actor": f"ghost-{i}"},
        }
        results: dict[str, dict] = {}
        svc.call(setup)  # warm-up: first setup creates keys
        proof_ok = None
        for name, plan in plans.items():
            times = []
            before = dir_bytes(svc.state)
            for i in range(runs):
                response, elapsed = svc.call(plan(i))
                times.append(elapsed)
                if name == "protected_read" and proof_ok is None:
                    proof_ok = check_protected_read(response, secret_key, f"challenge-{i}", contents["file-3"])
                if name == "read (deny)" and response != {"decision": "deny"}:
                    raise RuntimeError("deny response carried extra data")
            growth = (dir_bytes(svc.state) - before) / runs
            results[name] = {
                "runs": runs,
                "p50_ms": round(statistics.median(times), 1),
                "p95_ms": round(percentile(times, 0.95), 1),
                "max_ms": round(max(times), 1),
                "state_growth_bytes_per_op": round(growth),
            }
        return {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "runs_per_operation": runs,
            "operations": results,
            "protected_read_proof_verified": proof_ok,
            "peak_child_rss_mb": peak_child_rss_mb(),
            "state_dir_bytes_final": dir_bytes(svc.state),
            "targets": {"p50_ms": 200, "p95_ms": 1000},
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--entry", default=str(ROOT / "track4_service.py"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", help="also write the JSON report here")
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    report = run(Path(args.entry).resolve(), args.runs)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Python {report['python']} on {report['platform']}, {args.runs} cold processes per operation\n")
        print(f"{'operation':<16} {'p50 ms':>8} {'p95 ms':>8} {'max ms':>8} {'state +bytes/op':>16}")
        for name, row in report["operations"].items():
            print(f"{name:<16} {row['p50_ms']:>8} {row['p95_ms']:>8} {row['max_ms']:>8} "
                  f"{row['state_growth_bytes_per_op']:>16}")
        rss = report["peak_child_rss_mb"]
        print(f"\nprotected_read proof verified by independent client: {report['protected_read_proof_verified']}")
        print(f"peak child memory: {f'{rss:.1f} MB' if rss is not None else 'not measured on this platform'}")
        print(f"targets: p50 < 200 ms, p95 < 1000 ms")
    over = [n for n, r in report["operations"].items() if r["p50_ms"] >= 200 or r["p95_ms"] >= 1000]
    return 1 if over or report["protected_read_proof_verified"] is False else 0


if __name__ == "__main__":
    sys.exit(main())
