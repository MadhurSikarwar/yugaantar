"""Operator commands for an audit log (PRD M-A10, M-A12).

    python -m t4.audit.cli --dir DIR head [--out FILE]
    python -m t4.audit.cli --dir DIR verify-log [--pin FILE]
    python -m t4.audit.cli --dir DIR explain REQUEST_ID
    python -m t4.audit.cli --dir DIR explain --challenge SHA256
    python -m t4.audit.cli --dir DIR alerts

``head`` prints the signed head and the public key. Save that output *outside* the
log directory and pass it to ``verify-log --pin`` later: that is what exposes a
rebuilt or rolled-back log.

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
    head.add_argument("--out", help="also save the pin to this file")
    verify = commands.add_parser("verify-log", help="check the whole log")
    verify.add_argument("--pin", help="file saved earlier with 'head --out'")
    explain = commands.add_parser("explain", help="show the entries behind a decision")
    explain.add_argument("request_id", nargs="?")
    explain.add_argument("--challenge", help="SHA-256 (hex) of a protected_read challenge")
    commands.add_parser("alerts", help="list alerts")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.dir or not Path(args.dir).is_dir():
        print("audit log directory not found; pass --dir", file=sys.stderr)
        return 2
    try:
        if args.command == "verify-log":
            pin = json.loads(Path(args.pin).read_text(encoding="utf-8")) if args.pin else None
            public_key = bytes.fromhex(pin["public_key"]) if pin and pin.get("public_key") else None
            report = AuditLog(args.dir, None).verify(pin, public_key)
            _emit(report.as_dict())
            return 0 if report.ok else 1
        if args.command == "head":
            signer = load_signer(args.dir)
            head = AuditLog(args.dir, signer).head()
            public_key = read_bytes(Path(args.dir) / PUBLIC_KEY_NAME)
            head["public_key"] = public_key.hex() or None
            _emit(head)
            if args.out:
                Path(args.out).write_text(json.dumps(head, sort_keys=True), encoding="utf-8")
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
