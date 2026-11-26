"""Test double only: a small service used to check that the red-team suite itself works.

This is not the team's adapter and must never be submitted as it. It exists so the
suite can be shown to pass a service that behaves correctly, and to fail one that
does not. Set ``DOUBLE_FLAW`` to plant a specific defect.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

REPO = Path(os.environ["DOUBLE_REPO"])
sys.path.insert(0, str(REPO))

from t4.audit.log import AuditLog, load_or_create_signer, locked  # noqa: E402
from t4.crypto import kem, proof  # noqa: E402

FLAW = os.environ.get("DOUBLE_FLAW", "")


def text(request, name):
    value = request[name]
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError(name)
    return value


def save(state, data):
    body = json.dumps(data, sort_keys=True).encode()
    tag = hmac.new((state / "state.key").read_bytes(), body, hashlib.sha256).hexdigest()
    (state / "state.tmp").write_bytes(tag.encode() + b"\n" + body)
    os.replace(state / "state.tmp", state / "state.bin")


def load(state):
    tag, body = (state / "state.bin").read_bytes().split(b"\n", 1)
    expected = hmac.new((state / "state.key").read_bytes(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected.encode()):
        raise ValueError("state")
    return json.loads(body)


def handle(request, state, log):
    op = request["op"]
    if op == "setup":
        owners, contents, disabled = request["owners"], request["contents"], request["disabled"]
        if not (isinstance(owners, dict) and isinstance(contents, dict) and isinstance(disabled, list)):
            raise ValueError("setup")
        if not all(isinstance(v, str) for v in (*owners.values(), *contents.values(), *disabled)):
            raise ValueError("setup")
        if not (state / "state.key").exists():
            (state / "state.key").write_bytes(secrets.token_bytes(32))
        generation = secrets.token_hex(8)
        save(state, {"owners": owners, "contents": contents, "disabled": disabled,
                     "generation": generation})
        log.append(actor="", action="setup", target="", decision="info", rule="SETUP", request_id="")
        return {"ready": True}
    data = load(state)
    generation = data["generation"]
    if op == "revoke":
        actor = text(request, "actor")
        data["disabled"].append(actor)
        save(state, data)
        log.append(actor=actor, action="revoke", target="", decision="info", rule="REVOKE", request_id="")
        return {}
    if op == "audit":
        wanted = text(request, "request_id")
        for entry in log.find(request_id=wanted, generation=generation):
            if entry["decision"] in ("allow", "deny"):
                return {"request_id": wanted, "decision": entry["decision"], "rule": entry["rule"]}
        return {"error": "unknown_request"}
    if op not in ("read", "protected_read"):
        return {"error": "unsupported_operation"}
    actor, asset = text(request, "actor"), text(request, "asset")
    request_id = text(request, "request_id") if op == "read" else secrets.token_hex(16)
    allowed = data["owners"].get(asset) == actor and (actor not in data["disabled"] or FLAW == "ignore-revoke")
    response = {"decision": "deny"}
    if allowed and op == "read":
        response = {"decision": "allow", "body": data["contents"][asset]}
    elif allowed:
        challenge = text(request, "challenge")
        public_key = base64.b64decode(text(request, "public_key"), validate=True)
        ciphertext, shared = kem.encapsulate(public_key)
        response = {"ciphertext": base64.b64encode(ciphertext).decode(),
                    "proof": proof.make_proof(shared, challenge.encode(), data["contents"][asset].encode())}
    if FLAW == "leak" and not allowed:
        response["hint"] = data["contents"].get(asset, "")
    log.append(actor=actor, action=op, target=asset, decision="allow" if allowed else "deny",
               rule="OWNER" if allowed else "DENY", request_id=request_id,
               detail={"generation": generation})
    return response


def main():
    try:
        raw = sys.stdin.buffer.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("size")
        request = json.loads(raw.decode("utf-8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(request, dict) or not isinstance(request.get("op"), str):
            raise ValueError("request")
        state = Path(os.environ["TRACK4_STATE_DIR"]) / "double"
        state.mkdir(exist_ok=True)
        log = AuditLog(state / "audit", load_or_create_signer(state / "audit"))
        with locked(state):  # state lock first, then the audit log's own lock
            response = handle(request, state, log)
        print(json.dumps(response))
        return 0
    except Exception:
        print("Request failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
