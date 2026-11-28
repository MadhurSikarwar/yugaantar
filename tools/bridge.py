#!/usr/bin/env python3
"""Local bridge between the frontend and the real backend (demo tool, not the judged adapter).

    python tools/bridge.py [--port 8765] [--static frontend/dist] [--workspace DIR] [--no-start]

A browser cannot start a Python process, so this small HTTP server sits next to it and does what
``demo/run_demo.py`` does, on request:

  * every adapter call runs ``track4_service.py`` as a NEW process with a JSON request on stdin,
    exactly as the judges run it (ML-KEM-768 protected reads, HMAC proofs, the signed audit log);
  * a node layer (authority, three nodes, three enrolled devices) is driven through the real
    ``t4.node`` modules on a simulated clock, so key rotation, revocation and a stale node can be
    shown in a minute instead of waiting out the freshness bound;
  * ``GET /api/snapshot`` turns what those modules and logs hold into the frontend's snapshot
    format. The audit chains are checked here with ``t4.audit.verify``; the browser still runs no
    cryptography of its own.

Endpoints (JSON only):

    GET  /api/health      {"ok": true, "started": bool}
    POST /api/start       build a fresh workspace (synthetic data, temporary directories)
    GET  /api/snapshot    the frontend snapshot, schemaVersion 1
    POST /api/adapter     one adapter request: setup, read, revoke, audit, protected_read
    POST /api/action      one action. Node layer: request, deliver, revoke_device, revoke_actor,
                          set_offline, advance, rotate, enroll, grant, ungrant, protected_check.
                          Adapter: setup (run again, optionally disabling actors). Operator:
                          explain, alerts, pin, verify, tamper (edits a synthetic log on disk),
                          detect, health, backup, restore.

Safety, stated plainly:
  * It binds to 127.0.0.1 only and refuses a request whose Host header is not the address it
    listens on (DNS rebinding) or whose Origin is another site. It sends no CORS headers, so a web
    page on another origin cannot read its answers.
  * Request bodies are capped at 1 MiB and must be JSON. Adapter errors return a fixed label,
    never stderr, request data, keys or contents.
  * It is NOT an authentication layer. The adapter decides permission from the actor it is given
    (see the README's limits section), and so does this bridge: anyone who can reach this port can act as any
    actor. Run it on a developer machine, never on a shared host or a public interface.
  * Everything lives in a temporary directory outside the repository and holds synthetic data.
    This file is demo tooling and is not part of the judged runtime (check_all.py does not scan it).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MAX_BODY = 1024 * 1024
MAX_AUDIT_ROWS = 5000
ADAPTER_OPS = frozenset({"setup", "read", "revoke", "audit", "protected_read"})
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
MAX_ADVANCE_SECONDS = 24 * 3600

OWNERS = {"plan": "maya", "budget": "noor", "notes": "eve"}
CONTENTS = {"plan": "synthetic plan", "budget": "synthetic budget", "notes": "synthetic notes"}
DEVICES = (("maya-phone", "maya"), ("noor-tablet", "noor"), ("eve-laptop", "eve"))
NODES = ("node-a", "node-b", "node-c")
APPROVER = "ops-lead"
# Gateway callers the bridge plays (it holds their keys, as their client apps would).
GATEWAY_CALLERS = (("maya-app", "user", "maya"), ("noor-app", "user", "noor"),
                   ("ops-console", "admin", None), ("reviewer-ana", "reviewer", None))
MAX_ROWS = 200
SIGNATURE_UNCHECKED = {"NODE-STALE-LIST", "NODE-CLOCK-ROLLBACK", "NODE-UNKNOWN-DEVICE",
                       "NODE-KEY-INACTIVE", "NODE-KEY-REVOKED", "NODE-BAD-SIGNATURE"}


class BridgeError(Exception):
    """An error whose text is a fixed label that is safe to show a client."""

    def __init__(self, label: str, status: int = 400) -> None:
        super().__init__(label)
        self.label = label
        self.status = status


def default_pins_root() -> Path:
    """A persistent folder for trusted pins, outside every disposable workspace."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "latticelock" / "pins"


def iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Workspace:
    """One synthetic world: an adapter state folder, an authority, three nodes and some devices."""

    def __init__(self, base: Path | None = None, freshness: float = 60.0, skew: float = 2.0,
                 pins_root: Path | None = None) -> None:
        self._own_base = base is None
        # Pins outlive the workspace: closing or restarting the bridge never erases them.
        self.pins_root = Path(pins_root) if pins_root is not None else default_pins_root()
        self.world_id = ""
        if base is None:
            self.base = Path(tempfile.mkdtemp(prefix="t4-bridge-"))
        else:
            self.base = Path(base)
            self.base.mkdir(parents=True, exist_ok=True)
            # start() clears this folder, so never adopt one that already holds somebody's files.
            if any(self.base.iterdir()):
                raise BridgeError("workspace_must_be_an_empty_folder")
        self.freshness, self.skew = freshness, skew
        self.check_count = 0
        self.lock = threading.RLock()
        self.started = False
        self.offset = 0.0
        self.offline: set[str] = set()
        self.checks: list[dict] = []
        self.approvals: dict[str, dict] = {}
        self.message_keys: dict[str, tuple] = {}
        self.message_seq: dict[str, int] = {}
        self.started_at = time.time()

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        if self._own_base:
            shutil.rmtree(self.base, ignore_errors=True)

    def now(self) -> float:
        return time.time() + self.offset

    def start(self) -> None:
        from t4.node.authority import Authority
        from t4.node.common import load_signer, open_log
        from t4.node.device import Device
        from t4.node.freshness import Node

        with self.lock:
            self.started = False
            for child in self.base.iterdir():
                shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink()
            if os.name == "nt":
                # Private BEFORE any key or file is written into the workspace (fail closed).
                from tools.windows_private import make_private

                try:
                    make_private(self.base)
                except OSError:
                    raise BridgeError("workspace_could_not_be_made_private", 500) from None
            self.offset, self.offline, self.checks = 0.0, set(), []
            self.approvals = {}
            # Each new synthetic world gets its own pin folder; earlier worlds' pins stay on disk.
            self.world_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
            self.message_keys, self.message_seq = {}, {}
            self.started_at = time.time()
            self.state = self.base / "adapter-state"
            self.state.mkdir(mode=0o700)
            os.chmod(self.state, 0o700)
            logs = self.base / "logs"
            self.signer = load_signer()
            # The backup vault keeps its key and its backups apart from each other and from the authority.
            from t4.backup import Vault

            try:  # encrypted backups when the vetted cipher package is installed (requirements-demo.txt)
                import cryptography  # noqa: F401

                encrypt = True
            except ImportError:
                encrypt = False
            self.vault = Vault.create(self.base / "vault-key", self.base / "vault-backups", "authority",
                                      encrypt=encrypt)
            self.authority = Authority.create(self.base / "authority", self.signer, open_log(logs / "authority"),
                                              freshness=self.freshness, skew=self.skew,
                                              vault=self.vault.location())
            self.nodes = {nid: Node.provision(self.base / nid, self.signer, open_log(logs / nid), node_id=nid,
                                              authority_pk=self.authority.public_key, owners=OWNERS,
                                              contents=CONTENTS, freshness=self.freshness, skew=self.skew)
                          for nid in NODES}
            self.devices = {}
            for device_id, owner in DEVICES:
                device = Device.create(self.base / f"dev-{device_id}", self.signer, device_id, owner)
                device.enroll(self.authority, self.now())
                self.devices[device_id] = device
            self.contents = dict(CONTENTS)
            from t4.gateway import Gateway

            self.gateway = Gateway.create(self.base / "gateway", self.signer, open_log(logs / "gateway"))
            self.gateway_keys, self.gateway_last = {}, None
            for caller, role, actor in GATEWAY_CALLERS:
                public_key, secret_key = self.signer.sig_keygen()
                self.gateway.enroll(caller, role, public_key, actor=actor)
                self.gateway_keys[caller] = (public_key, secret_key)
            reply = self.adapter({"op": "setup", "owners": OWNERS, "contents": CONTENTS, "disabled": [],
                                  "key_material": secrets.token_hex(16)})
            if reply != {"ready": True}:
                raise BridgeError("setup_failed", 500)
            self.deliver()
            if os.name == "nt":
                # Windows has no 0700: make the whole synthetic workspace private to this user.
                from tools.windows_private import make_private

                try:
                    make_private(self.base)
                except OSError:
                    raise BridgeError("workspace_could_not_be_made_private", 500) from None
            self.started = True

    def need_started(self) -> None:
        if not self.started:
            raise BridgeError("not_started", 409)

    # -- the judged adapter -------------------------------------------------

    def adapter(self, request: dict) -> dict:
        if not isinstance(request, dict) or request.get("op") not in ADAPTER_OPS:
            raise BridgeError("unsupported_operation")
        env = dict(os.environ)
        for name in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
            env[name] = str(self.state)
        # The console shows the stricter setting: a protected_read challenge is answered once.
        env["TRACK4_CHALLENGE_POLICY"] = "once"
        try:
            proc = subprocess.run([sys.executable, "-B", str(ROOT / "track4_service.py")],
                                  input=json.dumps(request).encode("utf-8"), cwd=ROOT, env=env,
                                  capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise BridgeError("adapter_unavailable", 502) from None
        if proc.returncode != 0:
            raise BridgeError("adapter_refused_request", 422)
        try:
            return json.loads(proc.stdout)
        except ValueError:
            raise BridgeError("adapter_bad_reply", 502) from None

    def call_adapter(self, request: dict) -> dict:
        with self.lock:
            self.need_started()
            return self.adapter(request)

    # -- node-layer actions -------------------------------------------------

    def act(self, body: dict) -> dict:
        name = body.get("name")
        handlers = {
            "request": self.signed_request, "deliver": self.deliver_action,
            "revoke_device": self.revoke_device, "set_offline": self.set_offline,
            "advance": self.advance, "rotate": self.rotate, "enroll": self.enroll,
            "protected_check": self.protected_check,
            "setup": self.setup, "revoke_actor": self.revoke_actor, "grant": self.grant,
            "ungrant": self.ungrant, "explain": self.explain, "alerts": self.alerts,
            "pin": self.pin, "verify": self.verify, "tamper": self.tamper, "detect": self.detect,
            "health": self.health, "backup": self.backup, "restore": self.restore, "message": self.message,
            "revoke_key": self.revoke_key, "gateway": self.gateway_request,
            "review": self.review, "session": self.session, "archive": self.archive,
        }
        if name not in handlers:
            raise BridgeError("unknown_action")
        with self.lock:
            self.need_started()
            try:
                return handlers[name](body)
            except BridgeError:
                raise
            except Exception as error:  # noqa: BLE001 - node errors carry fixed text; anything else is generic
                from t4.node.common import NodeError

                raise BridgeError(str(error) if isinstance(error, NodeError) else "action_failed") from None

    def _device(self, value: object):
        if not isinstance(value, str) or value not in self.devices:
            raise BridgeError("unknown_device")
        return self.devices[value]

    def _node(self, value: object):
        if not isinstance(value, str) or value not in self.nodes:
            raise BridgeError("unknown_node")
        return value, self.nodes[value]

    def signed_request(self, body: dict) -> dict:
        from t4.node.common import open_log
        from t4.node.request import respond

        device = self._device(body.get("device_id"))
        node_id, node = self._node(body.get("node_id"))
        asset = body.get("asset")
        if not isinstance(asset, str) or not asset or len(asset) > 200:
            raise BridgeError("bad_asset")
        now = self.now()
        signed = device.make_request(node_id, asset, now)
        if body.get("tamper") is True:
            signed["body"]["actor"] = "noor" if signed["body"]["actor"] != "noor" else "maya"
        reply = respond(node, signed, now)
        rule = ""
        for entry in reversed(open_log(self.base / "logs" / node_id).entries()):
            if entry["action"] == "read" and entry["decision"] in ("allow", "deny"):
                rule = entry["rule"]
                break
        return {"decision": reply["decision"], "rule": rule, "node_id": node_id}

    def deliver(self, only: list[str] | None = None) -> dict:
        now = self.now()
        signed = self.authority.issue_list(now)
        accepted = {}
        for node_id, node in self.nodes.items():
            if only is not None and node_id not in only:
                continue
            if node_id in self.offline:
                accepted[node_id] = False
                continue
            accepted[node_id] = node.accept_list(signed, now)
        return {"accepted": accepted}

    def deliver_action(self, body: dict) -> dict:
        only = body.get("nodes")
        if only is not None:
            if not isinstance(only, list) or not all(isinstance(n, str) and n in self.nodes for n in only):
                raise BridgeError("unknown_node")
        return self.deliver(only)

    def revoke_device(self, body: dict) -> dict:
        self._device(body.get("device_id"))
        at = self.authority.revoke_device(body["device_id"], self.now())
        return {"revoked": True, "effective_at": iso(at)}

    def set_offline(self, body: dict) -> dict:
        node_id, _ = self._node(body.get("node_id"))
        if not isinstance(body.get("offline"), bool):
            raise BridgeError("bad_value")
        (self.offline.add if body["offline"] else self.offline.discard)(node_id)
        return {"node_id": node_id, "offline": node_id in self.offline}

    def advance(self, body: dict) -> dict:
        seconds = body.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 < seconds <= MAX_ADVANCE_SECONDS:
            raise BridgeError("bad_seconds")
        self.offset += float(seconds)
        return {"clock": iso(self.now())}

    def rotate(self, body: dict) -> dict:
        device = self._device(body.get("device_id"))
        now = self.now()
        activate = device.rotate(self.authority, now, now + self.freshness + self.skew + 5)
        return {"activates_at": iso(activate)}

    def enroll(self, body: dict) -> dict:
        from t4.node.device import Device

        device_id, owner = body.get("device_id"), body.get("owner")
        if not (isinstance(device_id, str) and NAME.match(device_id) and isinstance(owner, str) and NAME.match(owner)):
            raise BridgeError("bad_name")
        if device_id in self.devices:
            raise BridgeError("device_exists")
        device = Device.create(self.base / f"dev-{device_id}", self.signer, device_id, owner)
        device.enroll(self.authority, self.now())
        self.devices[device_id] = device
        return {"enrolled": device_id}

    def protected_check(self, body: dict) -> dict:
        """Ask the adapter for a protected read and verify its proof like an independent client."""
        from pqcrypto.kem import ml_kem_768

        actor, asset = body.get("actor"), body.get("asset")
        if not (isinstance(actor, str) and isinstance(asset, str) and asset in self.contents):
            raise BridgeError("bad_request")
        public_key, secret_key = ml_kem_768.generate_keypair()
        challenge = secrets.token_hex(8)
        reply = self.adapter({"op": "protected_read", "actor": actor, "asset": asset, "challenge": challenge,
                              "public_key": base64.b64encode(public_key).decode("ascii")})
        self.check_count += 1
        number = self.check_count
        if reply.get("decision") == "deny" or "ciphertext" not in reply:
            result = {"id": f"protected-read-{number}", "kind": "protected-read", "outcome": "not-checked",
                      "detail": f"{actor} asked for {asset}: the adapter denied the request, so there is no proof to check."}
        else:
            shared = ml_kem_768.decrypt(secret_key, base64.b64decode(reply["ciphertext"]))
            expected = hmac.new(shared, (challenge + self.contents[asset]).encode("utf-8"), hashlib.sha256).hexdigest()
            good = hmac.compare_digest(expected, str(reply.get("proof", "")))
            result = {"id": f"protected-read-{number}", "kind": "protected-read",
                      "outcome": "valid" if good else "invalid",
                      "detail": f"{actor} read {asset}: the client decapsulated the ML-KEM-768 secret and "
                                f"{'matched' if good else 'did not match'} the HMAC-SHA256 proof."}
        self.checks.append(result)
        del self.checks[:-200]
        return {"outcome": result["outcome"]}


    # -- adapter administration ---------------------------------------------

    def setup(self, body: dict) -> dict:
        """Run the adapter's setup again (a new generation), optionally disabling some actors."""
        disabled = body.get("disabled", [])
        actors = sorted(set(OWNERS.values()))
        if not isinstance(disabled, list) or not all(isinstance(a, str) and a in actors for a in disabled):
            raise BridgeError("unknown_actor")
        reply = self.adapter({"op": "setup", "owners": OWNERS, "contents": CONTENTS, "disabled": disabled,
                              "key_material": secrets.token_hex(16)})
        note = f"; disabled: {', '.join(disabled)}" if disabled else ""
        return {**reply, "summary": f"Setup ran again: a new generation, adapter revocations cleared{note}"}

    # -- authority -----------------------------------------------------------

    @staticmethod
    def _actor(value: object) -> str:
        if not isinstance(value, str) or not NAME.match(value):
            raise BridgeError("bad_name")
        return value

    @staticmethod
    def _asset(value: object) -> str:
        if not isinstance(value, str) or value not in CONTENTS:
            raise BridgeError("bad_asset")
        return value

    def revoke_actor(self, body: dict) -> dict:
        actor = self._actor(body.get("actor"))
        at = self.authority.revoke_actor(actor, self.now())
        return {"summary": f"Authority revoked {actor} on every device (effective {iso(at)}). "
                           "Nodes enforce it once they receive the next list."}

    def grant(self, body: dict) -> dict:
        actor, asset = self._actor(body.get("actor")), self._asset(body.get("asset"))
        approval_id = ""
        if body.get("approved") is True:
            approval_id = f"chg-{len(self.approvals) + 1}"
            now = datetime.fromtimestamp(self.now(), timezone.utc)
            self.approvals[approval_id] = {
                "approval_id": approval_id, "approved_by": APPROVER, "subject": actor,
                "operation": "grant_role", "role": f"read:{asset}",
                "scope": [f"{node_id}/{asset}" for node_id in NODES],
                "valid_from_utc": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "valid_until_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.authority.grant(actor, asset, self.now(), approval_id=approval_id, granted_by=APPROVER)
        how = f"with approval {approval_id}" if approval_id else "with no approval on record"
        return {"summary": f"{actor} may now read {asset} ({how}). Deliver a list so the nodes learn it."}

    def revoke_key(self, body: dict) -> dict:
        """Revoke the key version the device signs with now (not the whole device)."""
        device_id = body.get("device_id")
        self._device(device_id)
        record = self.authority._record()["devices"][device_id]
        now = self.now()
        usable = [key for key in record["keys"] if key["activate_at"] <= now] or record["keys"]
        version = max(key["version"] for key in usable)
        at = self.authority.revoke_key(device_id, version, now)
        return {"summary": f"Key version {version} of {device_id} revoked (effective {iso(at)}). The device "
                           "must rotate to sign again; deliver a list so the nodes learn it."}

    def ungrant(self, body: dict) -> dict:
        actor, asset = self._actor(body.get("actor")), self._asset(body.get("asset"))
        self.authority.ungrant(actor, asset, self.now(), granted_by=APPROVER)
        return {"summary": f"Grant removed: {actor} on {asset}. Deliver a list so the nodes learn it."}

    # -- operator tools ------------------------------------------------------

    def _log_dirs(self) -> dict[str, Path]:
        from t4.store import prepare_state_dir

        logs = self.base / "logs"
        dirs = {"adapter": Path(prepare_state_dir(self.state)) / "audit", "authority": logs / "authority",
                "gateway": logs / "gateway"}
        dirs.update({node_id: logs / node_id for node_id in NODES})
        return dirs

    @property
    def pins_dir(self) -> Path:
        """This world's trusted pins: under ``pins_root``, outside the workspace and every log folder."""
        return self.pins_root / self.world_id

    def _pin_of(self, name: str) -> dict | None:
        try:
            return json.loads((self.pins_dir / f"{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _pin_args(self, name: str) -> tuple[dict | None, bytes | None]:
        pin = self._pin_of(name)
        return pin, (bytes.fromhex(pin["public_key"]) if pin else None)

    @staticmethod
    def _row(name: str, entry: dict) -> dict:
        detail = entry.get("detail", {})
        why = detail.get("explanation") or detail.get("reason") or ""
        return {"log": name, "seq": entry["seq"], "time": entry["ts"], "actor": entry["actor"][:80],
                "action": entry["action"], "target": entry["target"][:80], "decision": entry["decision"],
                "rule": entry["rule"], "request_id": entry["request_id"][:80], "why": str(why)[:300]}

    def explain(self, body: dict) -> dict:
        """Every entry, in every log, that carries this request ID (as ``audit.cli explain`` does)."""
        from t4.audit.log import AuditLog

        request_id = body.get("request_id")
        if not isinstance(request_id, str) or not request_id or len(request_id) > 200:
            raise BridgeError("bad_request_id")
        rows, damaged = [], []
        for name, directory in self._log_dirs().items():
            try:
                rows += [self._row(name, entry) for entry in AuditLog(directory, None).explain(request_id)]
            except Exception:  # noqa: BLE001 - a damaged log is named, never read past
                damaged.append(name)
        note = f" Could not read: {', '.join(damaged)}." if damaged else ""
        return {"summary": f"{len(rows)} log {'entry' if len(rows) == 1 else 'entries'} for {request_id}.{note}", "rows": rows[:MAX_ROWS]}

    def alerts(self, body: dict) -> dict:
        """Alerts from every log, and from the second log that records damage to the adapter's log."""
        from t4.audit.log import AuditLog
        from t4.store import prepare_state_dir

        sources = dict(self._log_dirs())
        sources["adapter-alerts"] = Path(prepare_state_dir(self.state)) / "alerts"
        rows, damaged = [], []
        for name, directory in sources.items():
            if not directory.is_dir():
                continue
            try:
                rows += [self._row(name, entry) for entry in AuditLog(directory, None).alerts()]
            except Exception:  # noqa: BLE001
                damaged.append(name)
        rows.sort(key=lambda row: row["time"], reverse=True)
        note = f" Could not read: {', '.join(damaged)}." if damaged else ""
        return {"summary": f"{len(rows)} alert{'' if len(rows) == 1 else 's'}.{note}", "rows": rows[:MAX_ROWS]}

    def pin(self, body: dict) -> dict:
        """Sign the head of every log that verifies and keep it here, outside the log folders."""
        from t4.audit.log import AuditLog, load_signer, read_bytes

        from t4.audit.verify import verify_log
        from t4.node.state import atomic_write

        workspace = self.base.resolve()
        pins = self.pins_dir.resolve()
        if pins == workspace or workspace in pins.parents:
            raise BridgeError("pins_must_be_outside_the_workspace")
        self.pins_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "nt":
            from tools.windows_private import make_private

            try:
                make_private(self.pins_dir)
            except OSError:
                raise BridgeError("pins_folder_could_not_be_made_private", 500) from None
        rows = []
        for name, directory in self._log_dirs().items():
            # Advance only from a pin that still checks (as 'audit.cli pin advance'): a log whose
            # key was replaced, or whose history no longer matches, is never silently re-pinned.
            archive_dir = self.base / "archive" / name
            report = verify_log(directory, *self._pin_args(name), archive_dir if archive_dir.is_dir() else None)
            if not report.ok:
                rows.append({"log": name, "pinned": "no",
                             "why": "the log does not verify against its trusted pin, so the pin was left unchanged"})
                continue
            head = AuditLog(directory, load_signer(directory)).head()
            pin = dict(head, public_key=read_bytes(directory / "audit.pub").hex())
            atomic_write(self.pins_dir / f"{name}.json", json.dumps(pin, sort_keys=True).encode("ascii"))
            rows.append({"log": name, "pinned": "yes", "seq": head["seq"], "hash": head["hash"][:16] + "…",
                         "why": ""})
        done = sum(1 for row in rows if row["pinned"] == "yes")
        return {"summary": f"Pinned {done} of {len(rows)} logs in {self.pins_dir} (kept after the bridge stops; "
                           "same format as 'audit.cli head --out').",
                "rows": rows}

    def verify(self, body: dict) -> dict:
        """Check every log from its first entry, against its pin when there is one (``verify-log``)."""
        from t4.audit.verify import verify_log

        rows = []
        for name, directory in self._log_dirs().items():
            archive_dir = self.base / "archive" / name
            report = verify_log(directory, *self._pin_args(name), archive_dir if archive_dir.is_dir() else None)
            rows.append({"log": name, "result": "ok" if report.ok else "FAILED", "entries": report.entries,
                         "signed_to": report.covered_seq, "pinned": "yes" if self._pin_of(name) else "no",
                         "first_bad_entry": report.first_bad_seq if report.first_bad_seq is not None else "",
                         "why": (report.errors[0] if report.errors else "")[:300]})
        bad = [row["log"] for row in rows if row["result"] != "ok"]
        return {"summary": f"Verification failed for: {', '.join(bad)}." if bad else "Every log verifies.",
                "rows": rows}

    def archive(self, body: dict) -> dict:
        """Archive the finished segment of one log (``t4.audit.archive``); the log continues from a signed anchor."""
        from t4.audit.archive import archive
        from t4.audit.log import AuditError

        dirs = self._log_dirs()
        name = body.get("log")
        if not isinstance(name, str) or name not in dirs:
            raise BridgeError("unknown_log")
        try:
            result = archive(dirs[name], self.base / "archive" / name)
        except AuditError:
            raise BridgeError("archive_refused_the_log_is_empty_or_does_not_verify") from None
        return {"summary": f"Archived the {name} log up to entry {result['seq']} as segment {result['segment']}; "
                           "new entries continue the same chain.",
                "rows": [{"log": name, "segment": result["segment"], "archived_to_entry": result["seq"],
                          "head": result["hash"][:16] + "…"}]}

    def tamper(self, body: dict) -> dict:
        """Edit one stored decision in a synthetic log file, as someone with disk access could."""
        dirs = self._log_dirs()
        name = body.get("log")
        if not isinstance(name, str) or name not in dirs:
            raise BridgeError("unknown_log")
        path = dirs[name] / "audit.jsonl"
        data = path.read_bytes() if path.is_file() else b""
        for old, new in ((b'"decision":"deny"', b'"decision":"allow"'),
                         (b'"decision":"allow"', b'"decision":"deny"')):
            if old in data:
                path.write_bytes(data.replace(old, new, 1))
                return {"summary": f"Edited one entry of the {name} log on disk ({old.decode()} became "
                                   f"{new.decode()}). Verify the logs to see it caught."}
        raise BridgeError("nothing_to_edit")

    def detect(self, body: dict) -> dict:
        """Verify our own signed logs, run the rule-based detector, append its alerts (``detect export``)."""
        from t4.detect import export as exp
        from t4.detect.ingest import parse_approvals

        dirs = self._log_dirs()
        sources = [exp.LogSource(dirs[name], "authority" if name == "authority" else "node", name,
                                 *self._pin_args(name)) for name in ("authority", *NODES)]
        register = parse_approvals({"changes": list(self.approvals.values())})
        try:
            result = exp.run_export(sources, register, owners={node_id: dict(OWNERS) for node_id in NODES},
                                    approvers=[APPROVER], alert_log=dirs["authority"])
        except exp.ExportError:
            raise BridgeError("detector_refused_a_log_that_does_not_verify") from None
        rows = [{"severity": alert.severity, "rule": alert.rule, "identity": alert.identity,
                 "services": ", ".join(alert.services), "why": alert.explanation[:300]}
                for alert in result.result.alerts]
        return {"summary": f"Verified {len(result.verified)} logs and {len(result.rows)} events: {len(rows)} alert{'' if len(rows) == 1 else 's'} "
                           f"({len(result.appended)} new, appended to the signed authority log).",
                "rows": rows[:MAX_ROWS]}

    def health(self, body: dict) -> dict:
        """State against audit log, and storage use (``t4.consistency``, ``t4.storage_status``)."""
        from t4.consistency import check
        from t4.storage_status import report

        consistent = check(self.state)
        storage = report(self.state)
        good = consistent.get("checked") and not consistent.get("problems")
        rows = [{"check": "State matches the audit log", "result": "ok" if good else "PROBLEM",
                 "why": "; ".join(consistent.get("problems", []))[:300]},
                {"check": "Audit logging", "result": storage["audit_logging"],
                 "why": f"{storage['pending_audit_entries']} entries waiting to be written"},
                {"check": "State file", "result": f"{storage['state_file_bytes']} bytes",
                 "why": f"{storage['state_limit_used_percent']}% of the write limit"},
                {"check": "Audit log", "result": f"{storage['audit_total_bytes']} bytes",
                 "why": "grows without limit; archive with a pin"}]
        rows += [{"check": "Warning", "result": "", "why": warning[:300]} for warning in storage["warnings"]]
        return {"summary": "Health checked." if good else "Health check found a problem.", "rows": rows}

    def backup(self, body: dict) -> dict:
        number = self.vault.backup(self.authority.store, "authority", self.now())
        how = "encrypted with ChaCha20-Poly1305" if (self.base / "vault-key" / "vault.enc").exists() else "not encrypted"
        return {"summary": f"Authority backed up (backup {number}, {how}). Revocations made after it are kept "
                           "in the vault ledger, so a restore cannot undo them."}

    def restore(self, body: dict) -> dict:
        from t4.backup import BackupError

        try:
            report = self.vault.restore(self.base / "authority", "authority")
        except BackupError:
            raise BridgeError("no_backup_could_be_restored") from None
        damaged = f" Damaged backups skipped: {len(report.damaged)}." if report.damaged else ""
        return {"summary": f"Authority restored from backup {report.used_id}; revocations and key versions "
                           f"recorded after it were re-applied.{damaged}"}

    # -- authenticated gateway (t4.gateway) ----------------------------------

    def _gateway_send(self, caller: str, op: str, body: dict, *, wrong_key: bool = False) -> tuple[dict, str]:
        from t4.audit.log import AuditLog
        from t4.gateway import sign_request

        if caller not in self.gateway_keys:
            raise BridgeError("unknown_caller")
        key = self.gateway_keys["ops-console" if wrong_key and caller != "ops-console" else
                                "maya-app" if wrong_key else caller][1]
        signed = sign_request(self.signer, key, caller=caller, op=op, body=body,
                              nonce=secrets.token_hex(16), issued_at=self.now())
        if not wrong_key:
            self.gateway_last = signed  # "replay" re-sends the last genuine request
        reply = self.gateway.handle(signed, self.now(), self.adapter)
        rule = AuditLog(self.base / "logs" / "gateway", None).entries()[-1]["rule"]
        return reply, rule

    def gateway_request(self, body: dict) -> dict:
        """Send a signed request through the gateway as one of its enrolled callers."""
        from t4.audit.log import AuditLog

        if body.get("replay") is True:
            if self.gateway_last is None:
                raise BridgeError("nothing_to_replay")
            reply = self.gateway.handle(self.gateway_last, self.now(), self.adapter)
            rule = AuditLog(self.base / "logs" / "gateway", None).entries()[-1]["rule"]
            return {"summary": f"Replayed the last signed request: {rule}", "rows": [{"rule": rule, "reply": json.dumps(reply)}]}
        caller, op = body.get("caller"), body.get("op")
        actor = self._actor(body.get("actor"))
        if op not in ("read", "audit", "revoke"):
            raise BridgeError("unsupported_operation")
        request = ({"actor": actor, "asset": self._asset(body.get("asset")), "request_id": f"gw-{secrets.token_hex(6)}"}
                   if op == "read" else {"actor": actor} if op == "revoke" else {"request_id": str(body.get("request_id", ""))})
        reply, rule = self._gateway_send(str(caller), op, request, wrong_key=body.get("wrong_key") is True)
        return {"summary": f"{caller} → {op}: {rule}", "rows": [{"rule": rule, "reply": json.dumps(reply)[:300]}]}

    def review(self, body: dict) -> dict:
        """A reviewer signs approve or reject for an alert; the gateway records it as evidence."""
        from t4.audit.log import AuditLog
        from t4.gateway import verify_decision

        alert_id, verdict = body.get("alert_id"), body.get("verdict")
        if not isinstance(alert_id, str) or not alert_id or len(alert_id) > 200 or verdict not in ("approve", "reject"):
            raise BridgeError("bad_decision")
        reason = body.get("reason", "")
        if not isinstance(reason, str) or len(reason) > 300:
            raise BridgeError("bad_decision")
        reply, rule = self._gateway_send("reviewer-ana", "decide",
                                         {"alert_id": alert_id, "verdict": verdict, "reason": reason})
        rows = []
        for entry in AuditLog(self.base / "logs" / "gateway", None).find(rule="REV-DECISION"):
            good = verify_decision(self.signer, self.gateway_keys[entry["actor"]][0], entry) \
                if entry["actor"] in self.gateway_keys else False
            rows.append({"alert": entry["target"], "verdict": entry["decision"], "reviewer": entry["actor"],
                         "signature": "valid" if good else "INVALID", "why": entry["detail"].get("reason", "")})
        return {"summary": f"Decision {rule}: {verdict} on {alert_id}, signed by reviewer-ana.", "rows": rows}

    # -- optional demo layer: signed, encrypted messages ---------------------

    def message(self, body: dict) -> dict:
        """Send one message with ``demo/messaging.py`` (ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305).

        The receiver's replay counters live in a file (``FileReplayGuard``), so a replay is refused
        even across bridge restarts within this workspace. Not forward secret; demo layer only.
        """
        sender, recipient = self._actor(body.get("sender")), self._actor(body.get("recipient"))
        actors = set(OWNERS.values())
        if sender not in actors or recipient not in actors or sender == recipient:
            raise BridgeError("unknown_actor")
        text = body.get("text")
        if not isinstance(text, str) or not text or len(text) > 200:
            raise BridgeError("bad_text")
        try:
            from demo import messaging as m

            m._aead()
        except Exception:  # noqa: BLE001 - the optional package is missing
            raise BridgeError("messaging_needs_requirements_demo_txt") from None
        from t4.crypto import kem, sig

        for actor in (sender, recipient):
            if actor not in self.message_keys:
                self.message_keys[actor] = (*sig.sig_keygen(), *kem.keygen())
        sender_sig_pk, sender_sig_sk, _pk, _sk = self.message_keys[sender]
        _a, _b, recipient_kem_pk, recipient_kem_sk = self.message_keys[recipient]
        seq = self.message_seq.get(sender, 0) + 1
        self.message_seq[sender] = seq
        wire = json.dumps(m.seal(sender=sender, sender_sig_secret=sender_sig_sk, recipient=recipient,
                                 recipient_kem_public=recipient_kem_pk, plaintext=text, seq=seq))
        guard = m.FileReplayGuard(self.base / "messages" / f"{recipient}-replay.json")

        def receive() -> str:
            try:
                read = m.open_message(json.loads(wire), recipient=recipient, recipient_kem_secret=recipient_kem_sk,
                                      expected_sender=sender, sender_sig_public=sender_sig_pk, guard=guard)
                return "delivered: " + ("text matches" if read == text else "TEXT DIFFERS")
            except m.MessagingError:
                return "refused"

        rows = [{"step": "on the wire", "result": "text hidden" if text not in wire else "TEXT VISIBLE",
                 "why": f"{len(wire)} bytes: ML-KEM-768 capsule, ChaCha20-Poly1305 body, ML-DSA-65 signature"},
                {"step": f"{recipient} receives it", "result": receive(),
                 "why": f"signature from {sender} checked, then decrypted"},
                {"step": "the same message again", "result": receive(),
                 "why": f"sequence {seq} was already accepted, so a replay is refused"}]
        return {"summary": f"{sender} sent {recipient} an encrypted, signed message (demo layer, not forward secret).",
                "rows": rows}

    def session(self, body: dict) -> dict:
        """Run the demo-layer session (``demo/sessions.py``): a lost and a reordered message, a
        restart in the middle, and the forward-secrecy check after delivery."""
        try:
            from demo import messaging as m
            from demo.sessions import Receiver, Sender

            m._aead()
        except Exception:  # noqa: BLE001 - the optional package is missing
            raise BridgeError("messaging_needs_requirements_demo_txt") from None
        from t4.crypto import sig

        folder = self.base / "sessions" / secrets.token_hex(4)
        maya_pk, maya_sk = sig.sig_keygen()
        noor_pk, noor_sk = sig.sig_keygen()
        receiver = Receiver.create(folder / "noor.json", me="noor", peer="maya", peer_sig_public=maya_pk,
                                   identity_secret=noor_sk, prekeys=8)
        sender = Sender.create(folder / "maya.json", me="maya", peer="noor", identity_secret=maya_sk,
                               peer_sig_public=noor_pk)
        rows = [{"step": "signed prekey bundle", "result": f"{sender.accept_bundle(receiver.bundle())} prekeys accepted"}]
        one, two, three = (sender.send(text) for text in ("one", "two", "three"))
        rows.append({"step": "3 sent, 2 lost, 3 before 1", "result": f"{receiver.receive(three)}, {receiver.receive(one)}"})
        rows.append({"step": "receiver reports missing", "result": str(receiver.missing())})
        rows.append({"step": "signed ack to sender", "result": f"confirmed {sender.handle_ack(receiver.ack())}"})
        sender, receiver = Sender.load(sender.path), Receiver.load(receiver.path)
        rows.append({"step": "both sides restart and resume", "result": f"unacknowledged {sender.unacknowledged()}"})
        (again,) = sender.resend()
        rows.append({"step": "resend of 2", "result": receiver.receive(again)})
        try:
            receiver.receive(two)
            duplicate = "ACCEPTED"
        except m.MessagingError:
            duplicate = "refused"
        rows.append({"step": "the original 2 arrives late", "result": duplicate})
        rows.append({"step": "forward secrecy", "result": "prekey secrets of delivered messages deleted"
                     if not any(e["prekey"] in receiver.state["prekeys"] for e in (one, again, three)) else "KEPT"})
        return {"summary": "Session demo: loss, reordering, restart and forward secrecy (demo layer only).", "rows": rows}

    # -- snapshot -----------------------------------------------------------

    def snapshot(self) -> dict:
        from t4.audit.log import AuditLog
        from t4.audit.verify import verify_log
        from t4.node.freshness import RECORD
        from t4.node.common import require_record
        from t4.store import prepare_state_dir

        with self.lock:
            self.need_started()
            now = self.now()
            authority = self.authority._record()
            devices = []
            for device_id, device in sorted(authority["devices"].items()):
                keys = device["keys"]
                usable = [key for key in keys if key["activate_at"] <= now] or keys
                revoked = device_id in authority["revoked_devices"] or device["owner"] in authority["revoked_actors"]
                devices.append({"id": device_id, "owner": device["owner"],
                                "keyVersion": max(key["version"] for key in usable),
                                "state": "revoked" if revoked else "active"})

            nodes = []
            for node_id, node in self.nodes.items():
                with node.store.locked() as txn:
                    record = require_record(txn.get(RECORD), "node")
                listed = record["list"]
                if listed is None:
                    state, version, ids, updated = "stale", 0, [], self.started_at
                else:
                    age = now - listed["issued_at"]
                    state = "stale" if age >= record["T"] else "current"
                    version, ids, updated = listed["seq"], sorted(listed["devices"]), listed["issued_at"]
                if node_id in self.offline:
                    state = "offline"
                nodes.append({"id": node_id, "state": state, "listVersion": int(version),
                              "deviceIds": ids, "lastUpdated": iso(updated)})

            adapter_logs = Path(prepare_state_dir(self.state)) / "audit"
            sources = [("adapter", adapter_logs, False)]
            sources += [(f"authority", self.base / "logs" / "authority", False),
                        ("gateway", self.base / "logs" / "gateway", False)]
            sources += [(node_id, self.base / "logs" / node_id, True) for node_id in NODES]

            audit, verifications = [], []
            for name, directory, is_node in sources:
                try:
                    entries = AuditLog(directory, None).entries()
                except Exception:  # noqa: BLE001 - a damaged log is reported below, never raised here
                    entries = None
                if name not in ("authority", "gateway") and entries is not None:
                    for entry in entries:
                        if entry["decision"] in ("allow", "deny") and entry["action"] in ("read", "protected_read"):
                            audit.append({"requestId": entry["request_id"], "timestamp": entry["ts"],
                                          "actor": entry["actor"] or "(none)",
                                          "action": f"{entry['action']} @ {name}" if is_node else entry["action"],
                                          "asset": entry["target"] or "(none)",
                                          "decision": entry["decision"], "rule": entry["rule"]})
                pin = self._pin_of(name)
                archive_dir = self.base / "archive" / name
                report = verify_log(directory, pin, bytes.fromhex(pin["public_key"]) if pin else None,
                                    archive_dir if archive_dir.is_dir() else None)
                if report.ok:
                    detail = (f"{report.entries} entries, hash chain intact. "
                              + (f"Matches the pin at entry {pin['seq']} and the pinned public key." if pin else
                                 "The signing key was read from the log folder, not pinned."))
                    verifications.append({"id": f"chain-{name}", "kind": "audit-chain", "outcome": "valid",
                                          "detail": f"{name}: {detail}"})
                    verifications.append({"id": f"checkpoint-{name}", "kind": "checkpoint",
                                          "outcome": "valid" if report.checkpoints else "not-checked",
                                          "detail": f"{name}: {report.checkpoints} signed ML-DSA-65 checkpoints, "
                                                    f"covering entries up to {report.covered_seq}."})
                else:
                    first = (report.errors[0] if report.errors else "verification failed")[:300]
                    verifications.append({"id": f"chain-{name}", "kind": "audit-chain", "outcome": "invalid",
                                          "detail": f"{name}: {first}"})
                    verifications.append({"id": f"checkpoint-{name}", "kind": "checkpoint", "outcome": "invalid",
                                          "detail": f"{name}: checkpoints not trusted because the log failed."})
                if is_node and entries is not None:
                    signed = [e for e in entries if e["action"] == "read" and e["decision"] in ("allow", "deny")]
                    bad = sum(1 for e in signed if e["rule"] == "NODE-BAD-SIGNATURE")
                    checked = sum(1 for e in signed if e["rule"] not in SIGNATURE_UNCHECKED)
                    if bad:
                        outcome, detail = "invalid", f"{bad} of {len(signed)} signed requests failed signature verification."
                    elif checked:
                        outcome, detail = "valid", f"{checked} of {len(signed)} signed requests verified against the enrolled key."
                    else:
                        outcome, detail = "not-checked", "No request reached the signature check on this node yet."
                    verifications.append({"id": f"signatures-{name}", "kind": "device-signature",
                                          "outcome": outcome, "detail": f"{name}: {detail}"})
            verifications.extend(self.checks)
            audit.sort(key=lambda row: row["timestamp"])
            grants = [{"actor": grant["actor"], "asset": grant["asset"],
                       **({"approvalId": grant["approval_id"]} if grant.get("approval_id") else {})}
                      for _key, grant in sorted(authority["grants"].items())]
            alerts = [{"id": f"{row['log']}-{row['seq']}", "timestamp": row["time"], "rule": row["rule"],
                       "source": row["log"], "identity": row["actor"] or "(none)",
                       "detail": row["why"] or row["rule"]}
                      for row in self.alerts({})["rows"]]
            return {"schemaVersion": 1, "capturedAt": iso(time.time()), "devices": devices, "nodes": nodes,
                    "audit": audit[-MAX_AUDIT_ROWS:], "verifications": verifications[:MAX_AUDIT_ROWS],
                    "grants": grants[:MAX_AUDIT_ROWS], "alerts": alerts[:MAX_AUDIT_ROWS],
                    "clock": iso(now), "clockOffsetSeconds": round(self.offset, 3)}


# ---------------------------------------------------------------- HTTP ------

CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def make_handler(workspace: Workspace, static: Path | None, allowed_hosts: set[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "t4-bridge"
        sys_version = ""

        def log_message(self, *_args) -> None:  # request lines can carry identifiers: stay quiet
            return

        # -- helpers
        def send_bytes(self, status: int, data: bytes, content_type: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, status: int, value: object) -> None:
            self.send_bytes(status, json.dumps(value, allow_nan=False).encode("utf-8"), "application/json")

        def trusted(self) -> bool:
            if self.headers.get("Host", "").lower() not in allowed_hosts:
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin.lower() in {f"http://{h}" for h in allowed_hosts}

        def take_body(self) -> BridgeError | bytes:
            """Read the request body before anything is answered.

            Answering without reading it makes the OS reset the connection on close, so a client
            sometimes sees a network error instead of our 4xx. A body over the cap is read and
            thrown away (up to a limit) for the same reason, then the connection is closed.
            """
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                length = -1
            if length < 0:
                self.close_connection = True
                return BridgeError("length_required", 411)
            if length > MAX_BODY:
                remaining = min(length, 8 * MAX_BODY)
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                self.close_connection = True
                return BridgeError("body_too_large", 413)
            return self.rfile.read(length)

        def read_json(self, data: bytes) -> dict:
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                raise BridgeError("content_type_must_be_json", 415)
            try:
                value = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                raise BridgeError("body_is_not_json") from None
            if not isinstance(value, dict):
                raise BridgeError("body_must_be_an_object")
            return value

        def guarded(self, work) -> None:
            if not self.trusted():
                self.send_json(403, {"error": "untrusted_origin"})
                return
            try:
                self.send_json(200, work())
            except BridgeError as error:
                self.send_json(error.status, {"error": error.label})
            except Exception:  # noqa: BLE001 - never leak details
                self.send_json(500, {"error": "internal_error"})

        # -- routes
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/api/health":
                self.guarded(lambda: {"ok": True, "started": workspace.started})
            elif path == "/api/snapshot":
                self.guarded(workspace.snapshot)
            elif path.startswith("/api/"):
                self.send_json(404, {"error": "not_found"})
            else:
                self.serve_static(path)

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            body = self.take_body()

            def need() -> dict:
                if isinstance(body, BridgeError):
                    raise body
                return self.read_json(body)

            routes = {
                "/api/start": lambda: (need(), workspace.start(), {"started": True})[2],
                "/api/adapter": lambda: workspace.call_adapter(need()),
                "/api/action": lambda: workspace.act(need()),
            }
            if path not in routes:
                self.send_json(404, {"error": "not_found"})
                return
            self.guarded(routes[path])

        def serve_static(self, path: str) -> None:
            if static is None or not self.trusted():
                self.send_json(404, {"error": "not_found"})
                return
            relative = path.lstrip("/") or "index.html"
            target = (static / relative).resolve()
            try:
                target.relative_to(static.resolve())
            except ValueError:
                self.send_json(404, {"error": "not_found"})
                return
            if not target.is_file():
                target = static / "index.html"  # single-page app: the console uses #/ routes
                if not target.is_file():
                    self.send_json(404, {"error": "not_found"})
                    return
            kind = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if kind.startswith("text/") or kind in ("application/javascript", "application/json"):
                kind += "; charset=utf-8"
            self.send_bytes(200, target.read_bytes(), kind)

    return Handler


def serve(port: int, static: Path | None, base: Path | None, start: bool, pins_root: Path | None = None) -> int:
    workspace = Workspace(base, pins_root=pins_root)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(
        workspace, static, {f"127.0.0.1:{port}", f"localhost:{port}"}))
    try:
        if start:
            print("building the synthetic workspace ...", flush=True)
            workspace.start()
        print(f"bridge ready: http://127.0.0.1:{server.server_address[1]}/  (Ctrl C stops it)", flush=True)
        if static is None:
            print("no built frontend found: use the Vite dev server, which proxies /api here", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        workspace.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the frontend and connect it to the real backend.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--static", default=str(ROOT / "frontend" / "dist"), help="built frontend folder")
    parser.add_argument("--workspace", help="keep the synthetic world here (default: a temporary folder)")
    parser.add_argument("--no-start", action="store_true", help="wait for POST /api/start")
    parser.add_argument("--pins-dir", help="persistent folder for trusted pins (default: your local app-data "
                                           "folder, latticelock/pins); never inside the workspace")
    args = parser.parse_args(argv)
    static = Path(args.static)
    return serve(args.port, static if static.is_dir() else None,
                 Path(args.workspace) if args.workspace else None, not args.no_start,
                 Path(args.pins_dir) if args.pins_dir else None)


if __name__ == "__main__":
    sys.exit(main())
