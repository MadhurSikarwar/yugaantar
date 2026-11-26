"""Operator command: how much storage the service is using, and whether it is running short.

    python -m t4.storage_status [--state-dir DIR] [--warn-free-mb N] [--critical-free-mb N]
                                [--warn-audit-mb N] [--warn-state-mb N]

Prints one JSON object. Exit status: 0 fine, 1 a warning threshold is crossed, 2 a critical one is.

What this is, and is not: a report, run by an operator or a scheduler. It does not reserve any disk
space, it does not stop anything from being written, and the adapter does not call it (the adapter's
output must stay exactly what the contract defines). A warning threshold is not protection against a
full disk. It only gives time to act before one. It reads file sizes and the filesystem's free space;
it never opens the state file's contents or any key.

The audit log is append-only and is never trimmed by this service. Keeping the volume from filling
(more space, moving old history to verified archive storage) is an operator decision; see
docs/FINAL_THREAT_MODEL.md.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from t4.store import MAX_WRITE_BYTES, locate_state_dir, resolve_state_dir

MB = 1024 * 1024


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def report(state_dir: Path, *, warn_free_mb: float = 512, critical_free_mb: float = 64,
           warn_audit_mb: float = 256, warn_state_mb: float = MAX_WRITE_BYTES / MB * 0.75) -> dict:
    """Sizes, free space and the warnings they imply, for the effective state directory."""
    effective = locate_state_dir(state_dir)
    audit = effective / "audit"
    usage = shutil.disk_usage(effective if effective.exists() else effective.parent)
    sizes = {
        "state_file_bytes": _size(effective / "state.json"),
        "audit_log_bytes": _size(audit / "audit.jsonl"),
        "audit_checkpoints_bytes": _size(audit / "checkpoints.jsonl"),
    }
    sizes["audit_total_bytes"] = sizes["audit_log_bytes"] + sizes["audit_checkpoints_bytes"]
    warnings: list[str] = []
    critical = False
    free_mb = usage.free / MB
    if free_mb < critical_free_mb:
        critical = True
        warnings.append(f"CRITICAL: only {free_mb:.0f} MiB free on this volume (below {critical_free_mb:g}): "
                        "state, audit and revocation writes will start to fail")
    elif free_mb < warn_free_mb:
        warnings.append(f"only {free_mb:.0f} MiB free on this volume (below {warn_free_mb:g})")
    if sizes["audit_total_bytes"] > warn_audit_mb * MB:
        warnings.append(f"the audit log is {sizes['audit_total_bytes'] / MB:.0f} MiB (above {warn_audit_mb:g}); "
                        "it only grows: plan archival or more space")
    if sizes["state_file_bytes"] > warn_state_mb * MB:
        warnings.append(f"the state file is {sizes['state_file_bytes'] / MB:.1f} MiB; new writes are refused at "
                        f"{MAX_WRITE_BYTES / MB:.0f} MiB (the revoked set is never trimmed)")
    return {
        "state_dir": str(effective),
        **sizes,
        "state_write_limit_bytes": MAX_WRITE_BYTES,
        "state_limit_used_percent": round(100 * sizes["state_file_bytes"] / MAX_WRITE_BYTES, 2),
        "volume_free_bytes": usage.free,
        "volume_total_bytes": usage.total,
        "warnings": warnings,
        "status": "critical" if critical else ("warning" if warnings else "ok"),
        "note": "A report only: no space is reserved and nothing is blocked by it.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t4.storage_status", description=__doc__.split("\n\n")[0])
    parser.add_argument("--state-dir", help="state directory (default: TRACK4_STATE_DIR or the OS temp folder)")
    parser.add_argument("--warn-free-mb", type=float, default=512)
    parser.add_argument("--critical-free-mb", type=float, default=64)
    parser.add_argument("--warn-audit-mb", type=float, default=256)
    parser.add_argument("--warn-state-mb", type=float, default=MAX_WRITE_BYTES / MB * 0.75)
    args = parser.parse_args(argv)
    directory = Path(args.state_dir).absolute() if args.state_dir else resolve_state_dir()
    try:
        result = report(directory, warn_free_mb=args.warn_free_mb, critical_free_mb=args.critical_free_mb,
                        warn_audit_mb=args.warn_audit_mb, warn_state_mb=args.warn_state_mb)
    except OSError:
        print("the storage could not be inspected", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return {"ok": 0, "warning": 1, "critical": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
