"""Operator command line for rotation, backup and restore.

    python -m t4.cli rotate  --authority DIR --device DIR
    python -m t4.cli init-vault --vault-keys DIR --vault-backups DIR --subject authority
    python -m t4.cli backup  --vault-keys DIR --vault-backups DIR --source DIR --kind authority
    python -m t4.cli restore --vault-keys DIR --vault-backups DIR --target DIR --kind authority

``--kind`` is ``authority`` or ``device``. Restore prints every damaged backup it
found and exits with code 2 if it had to fall back to an older one.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from t4.backup import BackupError, Vault
from t4.node.cli import authority_at, outside_repo, rotate
from t4.node.common import NodeError, load_signer
from t4.node.device import Device
from t4.node.state import FileStore

RECORDS = {"authority": "authority", "device": "keyring"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="t4.cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("rotate")
    sub.add_argument("--authority", required=True)
    sub.add_argument("--device", required=True)
    sub.add_argument("--lead", type=float)
    for name, extra in (("init-vault", ("subject",)), ("backup", ("source", "kind")),
                        ("restore", ("target", "kind"))):
        sub = commands.add_parser(name)
        for option in ("vault-keys", "vault-backups", *extra):
            sub.add_argument(f"--{option}", required=True,
                             choices=tuple(RECORDS) if option == "kind" else None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "rotate":
            at = rotate(authority_at(args.authority), Device(args.device, load_signer()),
                        args.lead)
            print(json.dumps({"activate_at": at}))
        elif args.command == "init-vault":
            Vault.create(outside_repo(args.vault_keys), outside_repo(args.vault_backups),
                         args.subject)
            print(json.dumps({"created": "vault"}))
        elif args.command == "backup":
            vault = Vault(args.vault_keys, args.vault_backups)
            number = vault.backup(FileStore(Path(args.source)), RECORDS[args.kind], time.time())
            print(json.dumps({"backup_id": number}))
        else:
            vault = Vault(args.vault_keys, args.vault_backups)
            report = vault.restore(outside_repo(args.target), RECORDS[args.kind])
            print(json.dumps({"restored_from": report.used_id,
                              "newest_expected": report.newest_expected_id,
                              "damaged": list(report.damaged)}))
            return 2 if report.fell_back else 0
    except BackupError as error:
        print(json.dumps({"error": str(error), "damaged": list(error.damaged)}), file=sys.stderr)
        return 1
    except NodeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("error: could not read or write a required file", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
