"""Operator commands for an audit log.

    python -m t4.audit.cli --dir DIR head [--out FILE]
    python -m t4.audit.cli --dir DIR verify-log [--pin FILE]
    python -m t4.audit.cli --dir DIR pin init --pin FILE
    python -m t4.audit.cli --dir DIR pin advance --pin FILE
    python -m t4.audit.cli --dir DIR explain REQUEST_ID
    python -m t4.audit.cli --dir DIR explain --challenge SHA256
    python -m t4.audit.cli --dir DIR alerts

``head`` prints the signed head and the public key. Save that output *outside* the
log directory and pass it to ``verify-log --pin`` later: that is what exposes a
rebuilt or rolled-back log.

A pin is only worth anything if whoever can edit the log cannot also edit the pin, so keep it
on media or an account the audit directory's users cannot write (for example another host, a
read-only mount, or a signed ticket). These commands cannot check that; they enforce what they can:
  * a pin is never overwritten silently: ``head --out`` refuses to replace an existing file;
  * ``pin init`` writes the first pin only after the WHOLE log verifies, and refuses a path
    inside the audit directory;
  * ``pin advance`` moves an existing pin forward only after the whole log verifies against
    that pin (same key, the pinned entry still has the pinned hash); on any mismatch the pin
    is left untouched and the command fails with exit status 1.

Attacks defended against: all output is ASCII-escaped JSON, so text stored in the
log cannot move the cursor, fake extra lines or spoof the operator's terminal.
Secret keys are never printed.

Exit status: 0 success, 1 verification failed or log damaged, 2 usage or file error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from t4.audit.log import (
    PUBLIC_KEY_NAME,
    AuditError,
    AuditIntegrityError,
    AuditLog,
    load_signer,
    read_bytes,
)


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="t4.audit.cli", description="Inspect and verify an audit log.")
    parser.add_argument("--dir", default=os.environ.get("T4_AUDIT_DIR"), help="audit log directory")
    commands = parser.add_subparsers(dest="command", required=True)
    head = commands.add_parser("head", help="sign and print the current head")
    head.add_argument("--out", help="also save the pin to this file (refuses to replace an existing file)")
    pin = commands.add_parser("pin", help="create or advance a trusted pin safely")
    pin.add_argument("action", choices=("init", "advance"))
    pin.add_argument("--pin", required=True, help="the pin file (kept outside the audit directory)")
    verify = commands.add_parser("verify-log", help="check the whole log")
    verify.add_argument("--pin", help="file saved earlier with 'head --out'")
    explain = commands.add_parser("explain", help="show the entries behind a decision")
    explain.add_argument("request_id", nargs="?")
    explain.add_argument("--challenge", help="SHA-256 (hex) of a protected_read challenge")
    commands.add_parser("alerts", help="list alerts")
    archive = commands.add_parser("archive", help="move the finished segment to an archive folder; the log continues")
    archive.add_argument("--to", required=True, help="archive folder, outside the log folder")
    return parser


def _write_pin(path: Path, head: dict, *, replace: bool) -> None:
    """Write a pin without ever leaving a half-written one: temp file, fsync, then rename.

    A new pin is created exclusively; an advanced pin replaces the old one atomically.
    """
    data = json.dumps(head, sort_keys=True).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # fails if the pin appeared meanwhile: never replaces one
            os.unlink(temporary)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _pin_key(pin: dict) -> bytes:
    """The public key a pin names. A pin without one would let the log's own key file decide."""
    key = pin.get("public_key") if isinstance(pin, dict) else None
    if not isinstance(key, str) or not key:
        raise ValueError("the pin has no public key")
    return bytes.fromhex(key)


def _pin(args: argparse.Namespace) -> int:
    pin_path, audit_dir = Path(args.pin).resolve(), Path(args.dir).resolve()
    if pin_path == audit_dir or audit_dir in pin_path.parents:
        print("the pin must be kept outside the audit directory: whoever can edit the log could "
              "edit a pin stored next to it", file=sys.stderr)
        return 2
    if args.action == "init":
        if pin_path.exists():
            print("a pin already exists here; it is never replaced by 'init'. Use 'pin advance'.",
                  file=sys.stderr)
            return 2
        report = AuditLog(args.dir, None).verify()  # the WHOLE log, unpinned
        if not report.ok:
            _emit(report.as_dict())
            print("not pinning a log that does not verify", file=sys.stderr)
            return 1
        if not read_bytes(Path(args.dir) / PUBLIC_KEY_NAME):
            print("this log is not signed: a pin without a public key cannot be advanced safely, "
                  "so none was written", file=sys.stderr)
            return 2
        replace, expected, pin = False, None, None
    else:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
        expected = _pin_key(pin)
        report = AuditLog(args.dir, None).verify(pin, expected)
        if not report.ok:
            _emit(report.as_dict())
            print("the log does not match the trusted pin: the pin was left unchanged", file=sys.stderr)
            return 1
        replace = True
    signer = load_signer(args.dir)
    head = AuditLog(args.dir, signer).head()  # re-checks the whole chain before it signs
    public_key = read_bytes(Path(args.dir) / PUBLIC_KEY_NAME)
    if expected is not None and public_key != expected:
        print("the signing key changed: the pin was left unchanged", file=sys.stderr)
        return 1
    if pin is not None:
        # The log is read twice above (the pin check, then the new head). Check the OLD pin again
        # against what was just signed, so a rewrite in between cannot be blessed as the new pin.
        again = AuditLog(args.dir, None).verify(pin, expected)
        if not again.ok:
            _emit(again.as_dict())
            print("the log changed while the pin was being advanced: the pin was left unchanged",
                  file=sys.stderr)
            return 1
    if not public_key:
        print("this log is not signed: no pin was written", file=sys.stderr)
        return 2
    head["public_key"] = public_key.hex()
    _write_pin(pin_path, head, replace=replace)
    _emit(head)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.dir or not Path(args.dir).is_dir():
        print("audit log directory not found; pass --dir", file=sys.stderr)
        return 2
    try:
        if args.command == "verify-log":
            pin = json.loads(Path(args.pin).read_text(encoding="utf-8")) if args.pin else None
            public_key = _pin_key(pin) if pin is not None else None
            started = time.perf_counter()
            report = AuditLog(args.dir, None).verify(pin, public_key)
            result = report.as_dict()
            # What was checked and how long it took, so an operator can see the verified range.
            result["checked_range"] = [1, report.entries] if report.entries else []
            result["pinned_range"] = [1, report.covered_seq] if report.covered_seq else []
            result["seconds"] = round(time.perf_counter() - started, 3)
            _emit(result)
            return 0 if report.ok else 1
        if args.command == "pin":
            return _pin(args)
        if args.command == "archive":
            from t4.audit.archive import archive

            _emit(archive(args.dir, args.to))
            return 0
        if args.command == "head":
            if args.out and Path(args.out).exists():
                print("refusing to overwrite an existing pin; use 'pin advance' to move it forward safely",
                      file=sys.stderr)
                return 2
            signer = load_signer(args.dir)
            head = AuditLog(args.dir, signer).head()
            public_key = read_bytes(Path(args.dir) / PUBLIC_KEY_NAME)
            head["public_key"] = public_key.hex() or None
            _emit(head)
            if args.out:
                _write_pin(Path(args.out), head, replace=False)
            return 0
        log = AuditLog(args.dir, None)
        if args.command == "alerts":
            found = log.alerts()
        elif (args.request_id is None) == (args.challenge is None):
            parser.error("explain needs exactly one of REQUEST_ID or --challenge")
        elif args.challenge is not None:
            found = []
            for entry in log.find(challenge_sha256=args.challenge.lower()):
                related = log.explain(entry["request_id"]) if entry["request_id"] else [entry]
                found.extend(item for item in related if item not in found)
        else:
            found = log.explain(args.request_id)
        for entry in found:
            _emit(entry)
        if not found:
            print("no matching entries", file=sys.stderr)
        return 0
    except AuditIntegrityError as error:
        print(f"audit log is damaged: {error}", file=sys.stderr)
        return 1
    except (AuditError, OSError, ValueError, KeyError, TypeError):
        print("command failed: check the directory and input files", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
