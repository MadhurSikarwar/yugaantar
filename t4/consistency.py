"""Operator command: does the saved state agree with what the audit log says it was?

    python -m t4.consistency [--state-dir DIR]

Exit status: 0 consistent, 1 inconsistent (state looks older than the log), 2 could not be checked.

Why: every audit entry for a decision records the ``generation`` and ``epoch`` the service had at
that moment, and both only ever go up (the epoch also across a repeated ``setup``). If the state
file's epoch or generation is LOWER than the highest one the log has recorded, the state was
replaced by an older copy while the log kept going: revocations made since are no longer in force.
This catches that case, for example one file restored from a backup or from another folder.

What it does NOT catch (stated so nobody relies on it for more):
  * a copy of the WHOLE directory, audit log included, restored together: state and log then agree
    with each other. That is only exposed by comparing the log with a head you saved OUTSIDE the
    directory (``python -m t4.audit.cli ... verify-log --pin FILE``), and only back to the date of
    that pin;
  * an attacker who can also rewrite the audit log and its signing key;
  * anything while this command is not being run: it detects when run, it does not prevent.

It reads state through the normal integrity-checked path (a damaged or forged state file is
reported, not trusted) and the audit log through the verifying reader, so a damaged log is reported
as damaged. It changes nothing except the lock files.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from t4.audit.log import DEFAULT_CHECKPOINT_EVERY, AuditError, AuditLog
from t4.api import Track4Error
from t4.store import FileStore, locate_state_dir, resolve_state_dir


def check(state_dir: Path) -> dict:
    """Compare the state's generation and epoch with the highest the audit log has recorded."""
    effective = locate_state_dir(state_dir)
    result = {"state_dir": str(effective), "problems": [], "checked": False}
    if not (effective / "state.json").is_file():
        result["problems"].append("no state file: nothing to compare")
        return result
    try:
        with FileStore(effective).locked() as txn:
            meta = txn.get("meta") or {}
        state_generation, state_epoch = int(meta.get("generation", 0)), int(meta.get("epoch", 0))
        state_audit_seq = int(meta.get("audit_seq", 0))
    except (Track4Error, OSError, ValueError, TypeError):
        result["problems"].append("the state file could not be read or failed its integrity check")
        return result
    log_generation = log_epoch = entries = 0
    try:
        for entry in AuditLog(effective / "audit", None).iter_entries():
            entries += 1
            detail = entry.get("detail", {})
            for key, current in (("generation", log_generation), ("epoch", log_epoch)):
                value = detail.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value > current:
                    if key == "generation":
                        log_generation = value
                    else:
                        log_epoch = value
    except AuditError as error:
        result["problems"].append(f"the audit log could not be read as intact: {error}")
        return result
    result.update(checked=True, state={"generation": state_generation, "epoch": state_epoch},
                  audit={"entries": entries, "highest_generation": log_generation, "highest_epoch": log_epoch})
    if state_generation >= 1 and entries == 0:
        result["problems"].append(
            "the state was set up but the audit log has no entries: the log was deleted or emptied, "
            "so nothing here can show whether this state is current")
    else:
        # The reader above checks the hash chain; this also checks every checkpoint signature
        # (and a checkpoint that names an entry the log no longer holds).
        report = AuditLog(effective / "audit", None).verify()
        if not report.ok:
            result["problems"].append("the audit log failed full verification (hash chain or signed checkpoints)")
        else:
            # The service signs a checkpoint at every multiple of the interval, so a log without one
            # at its last multiple has had checkpoints removed (a rebuilt chain would otherwise pass).
            due = (entries // DEFAULT_CHECKPOINT_EVERY) * DEFAULT_CHECKPOINT_EVERY
            if due and report.covered_seq < due:
                result["problems"].append(
                    f"the audit log has {entries} entries but is signed only up to entry {report.covered_seq}: "
                    "signed checkpoints are missing")
    if entries < state_audit_seq:
        result["problems"].append(
            f"the state has seen audit entry {state_audit_seq} but the log holds only {entries}: "
            "audit history was lost")
    if state_generation < log_generation:
        result["problems"].append(
            f"the state is at generation {state_generation} but the audit log has recorded generation "
            f"{log_generation}: the state is older than the log")
    if state_epoch < log_epoch:
        result["problems"].append(
            f"the state is at epoch {state_epoch} but the audit log has recorded epoch {log_epoch}: "
            "revocations made since are not in force in this state")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="t4.consistency", description=__doc__.split("\n\n")[0])
    parser.add_argument("--state-dir", help="state directory (default: TRACK4_STATE_DIR or the OS temp folder)")
    args = parser.parse_args(argv)
    directory = Path(args.state_dir).absolute() if args.state_dir else resolve_state_dir()
    result = check(directory)
    result["consistent"] = result["checked"] and not result["problems"]
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    if not result["checked"]:
        return 2
    return 0 if result["consistent"] else 1


if __name__ == "__main__":
    sys.exit(main())
