"""Command line for the node layer.

    python -m t4.node.cli <command> --help

Each authority and node directory keeps its audit log in ``<dir>/log``. Keep all
of these directories outside the repository. No command prints private keys.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from t4.node.authority import Authority
from t4.node.common import NodeError, load_signer, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond

REPO = Path(__file__).resolve().parents[2]


def outside_repo(path: str) -> str:
    resolved = Path(path).resolve()
    if resolved == REPO or REPO in resolved.parents:
        raise NodeError("keep state and key directories outside the repository")
    return str(resolved)


def authority_at(directory: str) -> Authority:
    return Authority(directory, load_signer(), open_log(Path(directory) / "log"))


def node_at(directory: str) -> Node:
    return Node(directory, load_signer(), open_log(Path(directory) / "log"))


def read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str, value) -> None:
    Path(path).write_text(json.dumps(value), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="t4.node.cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, *required: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name)
        for option in required:
            sub.add_argument(f"--{option}", required=True)
        return sub

    sub = add("init-authority", "authority")
    sub.add_argument("--freshness", type=float, default=60.0, help="T in seconds")
    sub.add_argument("--skew", type=float, default=2.0, help="s in seconds")
    sub.add_argument("--vault-keys")
    sub.add_argument("--vault-backups")
    add("init-device", "device", "device-id", "owner")
    sub = add("provision-node", "node", "authority", "node-id", "data")
    sub.add_argument("--window", type=float, default=30.0, help="W in seconds")
    add("enroll", "authority", "device")
    add("revoke-device", "authority", "device-id")
    add("revoke-actor", "authority", "actor")
    sub = add("grant", "authority", "actor", "asset")
    sub.add_argument("--approval-id", default="")
    sub.add_argument("--granted-by", default="authority")
    add("ungrant", "authority", "actor", "asset")
    add("issue-list", "authority", "out")
    add("deliver", "node", "list")
    add("request", "device", "node-id", "asset", "out")
    add("handle", "node", "request")
    sub = add("owners", "out")
    sub.add_argument("--node", action="append", required=True, help="repeat for each node")
    sub = add("rotate", "authority", "device")
    sub.add_argument("--lead", type=float, help="seconds until activation (default T + s + 5)")
    return parser


def rotate(authority: Authority, device: Device, lead: float | None) -> float:
    freshness, skew = authority.bounds
    now = time.time()
    return device.rotate(authority, now, now + (freshness + skew + 5 if lead is None else lead))


def run(args: argparse.Namespace) -> dict:
    command = args.command
    if command == "init-authority":
        directory = outside_repo(args.authority)
        vault = None
        if bool(args.vault_keys) != bool(args.vault_backups):
            raise NodeError("give both vault directories or neither")
        if args.vault_keys:
            from t4.backup import Vault

            vault = Vault.create(outside_repo(args.vault_keys),
                                 outside_repo(args.vault_backups), "authority").location()
        Authority.create(directory, load_signer(), open_log(Path(directory) / "log"),
                         freshness=args.freshness, skew=args.skew, vault=vault)
        return {"created": "authority"}
    if command == "init-device":
        Device.create(outside_repo(args.device), load_signer(), args.device_id, args.owner)
        return {"created": "device"}
    if command == "provision-node":
        directory = outside_repo(args.node)
        authority = authority_at(args.authority)
        data = read_json(args.data)
        freshness, skew = authority.bounds
        Node.provision(directory, load_signer(), open_log(Path(directory) / "log"),
                       node_id=args.node_id, authority_pk=authority.public_key,
                       owners=data["owners"], contents=data["contents"],
                       freshness=freshness, skew=skew, window=args.window)
        return {"created": "node"}
    if command == "owners":
        result = dict(node_at(directory).owners() for directory in args.node)
        write_json(args.out, result)
        return {"nodes": len(result)}
    if command == "enroll":
        Device(args.device, load_signer()).enroll(authority_at(args.authority), time.time())
        return {"enrolled": True}
    if command == "revoke-device":
        at = authority_at(args.authority).revoke_device(args.device_id, time.time())
        return {"revoked_at": at}
    if command == "revoke-actor":
        return {"revoked_at": authority_at(args.authority).revoke_actor(args.actor, time.time())}
    if command == "grant":
        authority_at(args.authority).grant(args.actor, args.asset, time.time(),
                                           approval_id=args.approval_id,
                                           granted_by=args.granted_by)
        return {"granted": True}
    if command == "ungrant":
        authority_at(args.authority).ungrant(args.actor, args.asset, time.time())
        return {"removed": True}
    if command == "issue-list":
        signed = authority_at(args.authority).issue_list(time.time())
        write_json(args.out, signed)
        return {"seq": signed["body"]["seq"]}
    if command == "deliver":
        return {"accepted": node_at(args.node).accept_list(read_json(args.list), time.time())}
    if command == "request":
        device = Device(args.device, load_signer())
        write_json(args.out, device.make_request(args.node_id, args.asset, time.time()))
        return {"signed": True}
    if command == "handle":
        return respond(node_at(args.node), read_json(args.request), time.time())
    activate_at = rotate(authority_at(args.authority), Device(args.device, load_signer()),
                         args.lead)
    return {"activate_at": activate_at}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except NodeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        print("error: could not read or write a required file", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
