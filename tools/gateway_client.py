#!/usr/bin/env python3
"""A gateway caller that holds its own ML-DSA-65 key (the bridge never sees the secret).

    python tools/gateway_client.py keygen --out maya-app.key.json        # keep this file private
    python tools/gateway_client.py pubkey --key maya-app.key.json --out maya-app.pub.json
    # operator enrolls the PUBLIC key:  python tools/bridge.py --gateway-only \\
    #     --enroll-caller maya-app:user:maya=maya-app.pub.json
    python tools/gateway_client.py send --key maya-app.key.json --caller maya-app --op read \\
        --body '{"actor": "maya", "asset": "plan", "request_id": "r1"}' --url http://127.0.0.1:8765

Each request is signed over the caller name, operation, body, a fresh random nonce and the time,
so a captured request cannot be replayed, re-targeted or replayed later. The transport is plain
HTTP on 127.0.0.1 (the bridge's own limit); put TLS or an SSH tunnel in front for any other use.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _write_private(path: Path, data: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)  # refuses to overwrite an existing key
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        json.dump(data, handle)
    # On Windows the file inherits its folder's access rules: keep keys under your user profile, or
    # make a dedicated key folder private first with tools/windows_private.py.


def keygen(out: Path) -> None:
    from t4.crypto import sig

    public_key, secret_key = sig.sig_keygen()
    _write_private(out, {"public_key": public_key.hex(), "secret_key": secret_key.hex()})


def pubkey(key: Path, out: Path) -> None:
    data = json.loads(key.read_text(encoding="ascii"))
    out.write_text(json.dumps({"public_key": data["public_key"]}), encoding="ascii")


def signed_request(key: Path, caller: str, op: str, body: dict, now: float | None = None) -> dict:
    from t4.crypto import sig
    from t4.gateway import sign_request

    data = json.loads(key.read_text(encoding="ascii"))
    return sign_request(sig, bytes.fromhex(data["secret_key"]), caller=caller, op=op, body=body,
                        nonce=secrets.token_hex(16), issued_at=time.time() if now is None else now)


def send(url: str, signed: dict) -> dict:
    request = urllib.request.Request(url.rstrip("/") + "/api/gateway", data=json.dumps({"signed": signed}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - local bridge only
        return json.loads(response.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="A gateway caller holding its own signing key.")
    commands = parser.add_subparsers(dest="command", required=True)
    k = commands.add_parser("keygen")
    k.add_argument("--out", required=True)
    p = commands.add_parser("pubkey")
    p.add_argument("--key", required=True)
    p.add_argument("--out", required=True)
    s = commands.add_parser("send")
    s.add_argument("--key", required=True)
    s.add_argument("--caller", required=True)
    s.add_argument("--op", required=True)
    s.add_argument("--body", default="{}")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    args = parser.parse_args(argv)
    if args.command == "keygen":
        keygen(Path(args.out))
    elif args.command == "pubkey":
        pubkey(Path(args.key), Path(args.out))
    else:
        print(json.dumps(send(args.url, signed_request(Path(args.key), args.caller, args.op, json.loads(args.body)))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
