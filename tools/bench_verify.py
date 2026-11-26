#!/usr/bin/env python3
"""Measure full audit-log verification time and memory as the log grows.

    python tools/bench_verify.py [--sizes 1 10 50 100] [--reps 3] [--old PATH_TO_OLD_verify.py] [--out FILE]

Builds synthetic, validly signed logs (tests/audit/synthetic.py) of roughly the given sizes in MB in
a temporary folder, then times ``verify_log`` ``--reps`` times and measures peak Python memory with
``tracemalloc`` in a separate pass (tracemalloc slows the run, so time and memory are never taken in
the same pass). ``--old`` also measures a previous copy of ``t4/audit/verify.py`` the same way, for a
before-and-after comparison on identical logs.

Honest limits: tracemalloc counts Python allocations only (not the interpreter, libraries or the OS
file cache); the numbers describe this machine and these synthetic entries (about 0.4 KB each, a signed
checkpoint every 16); nothing here is an estimate: every figure printed was measured.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from t4.audit.log import LOG_NAME  # noqa: E402
from t4.audit.verify import verify_log as new_verify  # noqa: E402
from tests.audit.synthetic import build_log  # noqa: E402


def load_old(path: str):
    spec = importlib.util.spec_from_file_location("old_verify", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["old_verify"] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module.verify_log


def measure(verify, folder: Path, reps: int) -> dict:
    times = []
    for _ in range(reps):
        started = time.perf_counter()
        report = verify(folder)
        times.append(time.perf_counter() - started)
        assert report.ok, report.errors
    tracemalloc.start()
    verify(folder)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return {"median_s": round(statistics.median(times), 3), "min_s": round(min(times), 3),
            "max_s": round(max(times), 3), "peak_python_mb": round(peak / (1024 * 1024), 1)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sizes", type=float, nargs="+", default=[1, 10, 50])
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--old", help="a previous copy of t4/audit/verify.py to compare against")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    old = load_old(args.old) if args.old else None
    rows = []
    for size_mb in args.sizes:
        with tempfile.TemporaryDirectory(prefix="t4-benchv-") as folder:
            folder = Path(folder) / "audit"
            built = time.perf_counter()
            entries = int(size_mb * 1024 * 1024 / 400)
            build_log(folder, entries)
            actual = (folder / LOG_NAME).stat().st_size / (1024 * 1024)
            row = {"target_mb": size_mb, "actual_log_mb": round(actual, 1), "entries": entries,
                   "build_s": round(time.perf_counter() - built, 1), "new": measure(new_verify, folder, args.reps)}
            if old is not None:
                row["old"] = measure(old, folder, args.reps)
            rows.append(row)
            print(json.dumps(row), flush=True)
    report = {"platform": f"{platform.system()} Python {platform.python_version()}", "reps": args.reps, "rows": rows}
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
