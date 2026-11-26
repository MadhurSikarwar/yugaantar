"""Black-box attacks against our own adapter (PRD section 8).

    python tools/selfattack.py --entry track4_service.py [--items 1,2,4] [--report docs/selfattack-report.md]

What it does: starts the adapter as the judges do (a new process per request, a
fresh temporary state directory per scenario), sends hostile and ordinary requests,
and reports each check as PASS, FAIL (with a severity), SKIP or INFO.

Scope: it only ever runs a local file from this machine. It opens no network
connection and must not be pointed at anything that is not our own service.

Report text never contains request bodies, service output or secret values.

Exit status: 0 no failures, 1 at least one failure, 2 the suite could not run.

Not covered: items 6 (node part), 9 and 10 need the node, rotation and backup
commands; they are reported as SKIP. A PASS means these probes found nothing, not
that the service is secure.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_LIMIT = 65536
AUDIT_FILES = {"audit.jsonl", "checkpoints.jsonl", "audit.pub", "audit.key", "audit.lock"}
SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class Reply:
    code: int | None  # None means the process timed out
    stdout: bytes
    stderr: bytes
    data: dict | None

    @property
    def allowed(self) -> bool:
        return bool(self.data) and (self.data.get("decision") == "allow" or "ciphertext" in self.data)

    @property
    def denied(self) -> bool:
        return self.code == 0 and bool(self.data) and self.data.get("decision") == "deny"

    @property
    def refused(self) -> bool:
        """Denied or rejected: nothing was granted."""
        return self.code is not None and not self.allowed

    @property
    def clean(self) -> bool:
        """No traceback, no oversized output, no hang."""
        return (self.code is not None and b"Traceback" not in self.stdout + self.stderr
                and len(self.stdout) <= OUTPUT_LIMIT and len(self.stderr) <= OUTPUT_LIMIT)


@dataclass
class Result:
    item: int
    name: str
    status: str  # PASS, FAIL, SKIP, INFO
    severity: str = ""
    detail: str = ""


class Scenario:
    """One service state directory seeded with the two-owner story."""

    def __init__(self, suite: "Suite", state: Path) -> None:
        self.suite, self.state = suite, state
        tag = secrets.token_hex(6)
        self.owner, self.peer, self.disabled = f"maya-{tag}", f"noor-{tag}", f"sam-{tag}"
        self.asset, self.other, self.locked = f"brief-{tag}", f"memo-{tag}", f"old-{tag}"
        self.body = "body-" + secrets.token_hex(24)
        self.other_body = "body-" + secrets.token_hex(24)
        self.locked_body = "body-" + secrets.token_hex(24)
        self.marker = "marker-" + secrets.token_hex(24)

    @property
    def protected(self) -> tuple[str, ...]:
        return self.body, self.other_body, self.locked_body, self.marker

    def call(self, request: object) -> Reply:
        payload = request if isinstance(request, bytes) else json.dumps(request).encode("utf-8")
        return self.suite.run(self.state, payload)

    def setup(self, **changes: object) -> Reply:
        request = {
            "op": "setup",
            "owners": {self.asset: self.owner, self.other: self.peer, self.locked: self.disabled},
            "contents": {self.asset: self.body, self.other: self.other_body, self.locked: self.locked_body},
            "disabled": [self.disabled],
            "key_material": self.marker,
        }
        request.update(changes)
        return self.call(request)

    def read(self, actor: str | None = None, asset: str | None = None, request_id: str | None = None) -> Reply:
        return self.call({
            "op": "read",
            "actor": self.owner if actor is None else actor,
            "asset": self.asset if asset is None else asset,
            "request_id": secrets.token_hex(8) if request_id is None else request_id,
        })

    def revoke(self, actor: str | None = None) -> Reply:
        return self.call({"op": "revoke", "actor": self.owner if actor is None else actor})

    def audit(self, request_id: str) -> Reply:
        return self.call({"op": "audit", "request_id": request_id})

    def protected_read(self, public_key: object, challenge: str = "c", actor: str | None = None) -> Reply:
        return self.call({
            "op": "protected_read", "actor": self.owner if actor is None else actor,
            "asset": self.asset, "challenge": challenge, "public_key": public_key,
        })

    def owner_reads(self) -> bool:
        reply = self.read()
        return reply.code == 0 and bool(reply.data) and reply.data.get("body") == self.body

    def audit_directory(self) -> Path | None:
        found = sorted(self.state.rglob("audit.jsonl"))
        return found[0].parent if found else None


class Suite:
    def __init__(self, entry: Path, timeout: float = 8.0) -> None:
        self.entry = entry.resolve()
        self.timeout = timeout
        self.results: list[Result] = []
        self.item = 0

    def run(self, state: Path, payload: bytes) -> Reply:
        environment = os.environ.copy()
        for name in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
            environment[name] = str(state)
        try:
            done = subprocess.run(
                [sys.executable, "-B", str(self.entry)], input=payload, capture_output=True,
                cwd=self.entry.parent, env=environment, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return Reply(None, b"", b"", None)
        try:
            data = json.loads(done.stdout)
        except (ValueError, UnicodeError, RecursionError):
            data = None
        return Reply(done.returncode, done.stdout, done.stderr, data if isinstance(data, dict) else None)

    @contextmanager
    def scenario(self, ready: bool = True) -> Iterator[Scenario]:
        with tempfile.TemporaryDirectory(prefix="t4-attack-", ignore_cleanup_errors=True) as folder:
            scene = Scenario(self, Path(folder))
            if ready:
                reply = scene.setup()
                if not (reply.code == 0 and reply.data and reply.data.get("ready") is True):
                    raise RuntimeError("setup failed; the service does not meet the basic contract")
            yield scene

    def check(self, name: str, passed: bool, severity: str, detail: str = "") -> None:
        self.results.append(Result(self.item, name, "PASS" if passed else "FAIL",
                                   "" if passed else severity, "" if passed else detail))

    def note(self, status: str, name: str, detail: str) -> None:
        self.results.append(Result(self.item, name, status, "", detail))

    # ---- item 1: malformed input ------------------------------------------------

    def item_1(self) -> None:
        with self.scenario() as s:
            base = {"op": "read", "actor": s.owner, "asset": s.asset, "request_id": "m1"}
            cases: dict[str, bytes] = {
                "empty input": b"",
                "not JSON": b"not json {",
                "JSON array": b"[1,2]",
                "JSON string": b'"read"',
                "two objects": b"{}{}",
                "invalid UTF-8": b'{"op":"read","actor":"\xff\xfe"}',
                "5 MB input": b'{"op":"read","actor":"' + b"a" * 5_000_000 + b'"}',
                "deep nesting": b'{"op":' + b"[" * 100_000 + b"]" * 100_000 + b"}",
                "NaN": b'{"op":"read","actor":NaN,"asset":"x","request_id":"n"}',
                "unknown operation": b'{"op":"delete_everything"}',
                "missing op": b'{"actor":"x"}',
                "missing fields": b'{"op":"read"}',
            }
            for field in ("actor", "asset", "request_id", "op"):
                for label, value in (("number", 7), ("null", None), ("list", [s.owner]), ("object", {"a": 1})):
                    cases[f"{field} as {label}"] = json.dumps({**base, field: value}).encode()
            for name, payload in cases.items():
                reply = s.call(payload)
                leaked = any(v.encode() in reply.stdout + reply.stderr for v in s.protected)
                # A badly typed request_id still names the real owner: weak validation, not a bypass.
                severity = "low" if name.startswith("request_id") else "critical"
                self.check(f"{name}: nothing granted", reply.refused and (severity == "low" or not leaked),
                           severity, "request was allowed, hung, or disclosed protected data")
                self.check(f"{name}: clean failure", reply.clean, "low", "traceback, oversized output or timeout")
            duplicate = (b'{"op":"read","actor":"nobody","asset":"' + s.asset.encode()
                         + b'","request_id":"d","actor":"' + s.owner.encode() + b'"}')
            reply = s.call(duplicate)
            self.note("INFO", "duplicate keys", "allowed (last value wins)" if reply.allowed else "refused")
            for name, changes in (("owners as list", {"owners": []}), ("contents as null", {"contents": None}),
                                  ("disabled as string", {"disabled": "x"}), ("body as number", {"contents": {"a": 1}})):
                reply = s.setup(**changes)
                self.check(f"setup with {name} is rejected cleanly",
                           reply.clean and not (reply.data or {}).get("ready"), "medium", "accepted or crashed")
            self.check("service still works afterwards", s.owner_reads(), "high", "owner can no longer read")

    # ---- item 2: hostile identifiers --------------------------------------------

    def item_2(self) -> None:
        hostile = {
            "newline": "a\nb", "CRLF": "a\r\nb", "U+2028": "a b", "null byte": "a\x00b",
            "path traversal": "../../escape", "backslash path": "..\\..\\escape", "absolute path": "/etc/passwd",
            "empty": "", "quotes": '"}{"', "terminal escape": "\x1b[2J", "lone surrogate": "a\ud800b",
        }
        with self.scenario() as s:
            lookalikes = {"upper case": s.owner.upper(), "trailing space": s.owner + " ",
                          "trailing null": s.owner + "\x00", "fullwidth": s.owner.replace("a", "ａ")}
            for name, text in {**hostile, **lookalikes}.items():
                request_id = f"h-{secrets.token_hex(4)}-{text}"
                reply = s.read(actor=text, request_id=request_id)
                self.check(f"actor with {name}: denied", reply.denied, "high" if reply.allowed else "medium",
                           "expected a clean deny with exit 0")
                audit = s.audit(request_id)
                self.check(f"actor with {name}: audited",
                           bool(audit.data) and audit.data.get("decision") == "deny"
                           and audit.data.get("request_id") == request_id, "medium", "audit did not return the deny")
                if name in hostile:
                    reply = s.read(asset=text)
                    self.check(f"asset with {name}: denied", reply.denied, "medium", "expected a clean deny")
            for name, text in (("long actor", "a" * 100_000), ("long request id", "r" * 100_000)):
                reply = s.read(actor=text) if name == "long actor" else s.read(request_id=text)
                self.check(f"{name}: refused or handled", reply.clean and (name != "long actor" or reply.refused),
                           "medium", "crash, timeout or grant")
            escaped = [p for p in (s.state.parent / "escape", s.state.parent.parent / "escape") if p.exists()]
            self.check("no file written outside the state directory", not escaped, "high", "traversal created a file")
            self.check("owner unaffected", s.owner_reads(), "high", "owner can no longer read")
        with self.scenario(ready=False) as s:
            s.owner, s.asset = "own\ner \x00../x", "as\nset ../y"
            reply = s.setup()
            ok = reply.code == 0 and s.owner_reads()
            self.check("opaque identifiers work as real owners", ok, "medium",
                       "unusual but valid identifiers were rejected")

    # ---- item 3: log injection ----------------------------------------------------

    def item_3(self) -> None:
        from t4.audit.log import AuditError, AuditLog

        with self.scenario() as s:
            forged = '"}\n{"actor":"admin","decision":"allow","request_id":"forged'
            sent = {"i1": forged, "i2": f"x\n{forged}", "i3": s.owner}
            for request_id, actor in sent.items():
                s.read(actor=actor, request_id=request_id)
            folder = s.audit_directory()
            if folder is None:
                return self.note("SKIP", "log injection", "no audit.jsonl found in the state directory")
            try:
                entries = AuditLog(folder, None).entries()
                ok = AuditLog(folder, None).verify().ok
            except AuditError:
                entries, ok = [], False
            self.check("log verifies after hostile text", ok, "high", "verification failed")
            decisions = [e for e in entries if e["decision"] in ("allow", "deny") and e["request_id"] in sent]
            self.check("one record per request with the original actor",
                       sorted((e["request_id"], e["actor"]) for e in decisions) == sorted(sent.items()),
                       "high", "records were split, merged or changed")
            self.check("no forged record appears",
                       not [e for e in entries if e["request_id"] == "forged" or e["actor"] == "admin"],
                       "critical", "injected text became a record")

    # ---- item 4: tampered state ----------------------------------------------------

    def item_4(self) -> None:
        with self.scenario() as s:
            s.revoke()
            names = [p.relative_to(s.state) for p in s.state.rglob("*")
                     if p.is_file() and p.stat().st_size and p.name not in AUDIT_FILES and p.suffix != ".lock"]
        if not names:
            return self.note("SKIP", "state tampering", "no state files found in the state directory")

        def flip(path: Path) -> None:
            data = bytearray(path.read_bytes())
            data[len(data) // 2] ^= 1
            path.write_bytes(bytes(data))

        def truncate(path: Path) -> None:
            path.write_bytes(path.read_bytes()[: path.stat().st_size // 2])

        changes: dict[str, Callable[[Path], None]] = {
            "flipped byte": flip, "truncated": truncate, "emptied": lambda p: p.write_bytes(b""),
            "deleted": lambda p: p.unlink(),
        }
        for index, relative in enumerate(names):
            for name, change in changes.items():
                with self.scenario() as s:
                    s.revoke()
                    matches = [p for p in s.state.rglob("*") if p.is_file() and p.relative_to(s.state) == relative]
                    if not matches:
                        continue  # file names differ between runs
                    change(matches[0])
                    label = f"state file {index + 1} {name}"
                    revoked = s.read()
                    self.check(f"{label}: revoked owner stays out", revoked.refused, "critical",
                               "revocation was lost after tampering")
                    peer = s.read(actor=s.peer, asset=s.other)
                    self.check(f"{label}: fails closed", peer.refused and peer.clean, "medium",
                               "tampering was not detected (content still served) or the service crashed")
        with self.scenario() as s, tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as backup:
            snapshot = Path(backup) / "state"
            shutil.copytree(s.state, snapshot)
            s.revoke()
            shutil.rmtree(s.state)
            shutil.copytree(snapshot, s.state)
            self.note("INFO", "full state rollback",
                      "access returned, as documented in PRD 4.1" if s.read().allowed else "rollback was refused")

    # ---- item 5: tampered audit log ---------------------------------------------

    def item_5(self) -> None:
        from t4.audit.log import AuditLog, load_signer

        with self.scenario() as s:
            for number in range(6):
                s.read(request_id=f"a{number}")
            folder = s.audit_directory()
            if folder is None:
                return self.note("SKIP", "audit tampering", "no audit.jsonl found in the state directory")
            pin = AuditLog(folder, load_signer(folder)).head()
            public_key = (folder / "audit.pub").read_bytes() if (folder / "audit.pub").exists() else None
            original = (folder / "audit.jsonl").read_bytes().splitlines(keepends=True)
            variants = {
                "edit": [*original[:2], original[2].replace(b'"decision":"', b'"decision":"x'), *original[3:]],
                "delete": original[:2] + original[3:],
                "reorder": [*original[:1], original[2], original[1], *original[3:]],
                "truncate": original[:-2],
            }
            for name, lines in variants.items():
                (folder / "audit.jsonl").write_bytes(b"".join(lines))
                report = AuditLog(folder, None).verify(pin, public_key)
                self.check(f"{name} is detected and located",
                           not report.ok and report.first_bad_seq is not None, "high", "verification passed")

    # ---- item 6: replay and repeated setup (adapter part) -----------------------

    def item_6(self) -> None:
        with self.scenario() as s:
            s.read(actor="intruder", request_id="same")
            valid = s.read(request_id="same")
            self.check("reused request id does not block a valid read", valid.allowed, "medium", "owner was refused")
            first = s.audit("same")
            self.check("first audit record is immutable",
                       bool(first.data) and first.data.get("decision") == "deny", "high", "first record was replaced")
            s.revoke()
            reply = s.setup()
            self.check("second setup starts cleanly", bool(reply.data) and s.owner_reads(), "medium",
                       "setup failed or old revocation remained")
            folder = s.audit_directory()
            if folder is None:
                self.note("SKIP", "audit chain across setups", "no audit.jsonl found")
            else:
                from t4.audit.log import AuditLog

                self.check("audit chain still verifies after second setup",
                           AuditLog(folder, None).verify().ok, "high", "chain broke")
        self.note("SKIP", "node replay, wrong node, stale or forged list", "needs the node layer commands (c3)")

    # ---- item 7: revoked and disabled actors ------------------------------------

    def item_7(self) -> None:
        with self.scenario() as s:
            reply = s.read(actor=s.disabled, asset=s.locked)
            self.check("disabled actor denied", reply.denied, "critical", "disabled actor was served")
            self.check("owner cannot read another asset", s.read(asset=s.other).denied, "critical", "cross-owner read")
            for _ in range(15):
                s.read(asset=s.other)
                s.call({"op": "read", "actor": s.owner})
            self.check("bad requests in an owner's name do not block them", s.owner_reads(), "high",
                       "owner was locked out")
            s.revoke()
            self.check("revoked actor stays denied", all(s.read().denied for _ in range(10)), "critical",
                       "revoked actor was served")
            self.check("peer unaffected", s.read(actor=s.peer, asset=s.other).allowed, "high", "peer lost access")
            reply = s.revoke("never-existed")
            self.check("revoking an unknown actor is accepted", reply.code == 0, "low", "error")

    # ---- item 8: concurrency ------------------------------------------------------

    def item_8(self) -> None:
        with self.scenario() as s:
            ids = [f"p{number}" for number in range(20)]

            def work(number: int) -> Reply:
                if number == 10:
                    return s.revoke()
                return s.read(actor=s.peer, asset=s.other, request_id=ids[number]) if number % 2 else s.read(
                    request_id=ids[number])

            with ThreadPoolExecutor(max_workers=20) as pool:
                replies = list(pool.map(work, range(20)))
            self.check("no failures or hangs under 20 parallel calls",
                       all(r.code == 0 and r.clean for r in replies), "high", "some calls failed")
            self.check("revocation not lost", s.read().denied, "critical", "owner still allowed")
            self.check("peer still served", s.read(actor=s.peer, asset=s.other).allowed, "high", "peer lost access")
            missing = [i for n, i in enumerate(ids) if n != 10 and (s.audit(i).data or {}).get("request_id") != i]
            self.check("every decision was recorded", not missing, "high", f"{len(missing)} records missing")
            folder = s.audit_directory()
            if folder is not None:
                from t4.audit.log import AuditLog

                self.check("audit chain intact", AuditLog(folder, None).verify().ok, "high", "chain broke")
            for _ in range(2):
                with ThreadPoolExecutor(max_workers=12) as pool:
                    list(pool.map(lambda n: s.revoke(f"x{n}") if n % 3 else s.setup(), range(12)))
                self.check("parallel setup and revoke leave a usable state",
                           s.read(actor=s.peer, asset=s.other).code == 0, "medium", "state unusable")

    # ---- item 11: protected_read ------------------------------------------------

    def item_11(self) -> None:
        from t4.crypto import kem, proof

        public_key, secret_key = kem.keygen()
        encoded = base64.b64encode(public_key).decode()
        with self.scenario() as s:
            challenge = "challenge-✓-" + secrets.token_hex(8)
            reply = s.protected_read(encoded, challenge)
            try:
                shared = kem.decapsulate(secret_key, base64.b64decode(reply.data["ciphertext"], validate=True))
                good = proof.verify_proof(shared, challenge.encode(), s.body.encode(), reply.data["proof"])
            except (KeyError, TypeError, ValueError):
                good = False
            self.check("owner gets a correct proof", good and reply.code == 0, "high", "interoperability failed")
            self.check("body is not sent", s.body.encode() not in reply.stdout + reply.stderr, "critical", "body leaked")
            bad_keys: dict[str, object] = {
                "short key": base64.b64encode(public_key[:-1]).decode(),
                "long key": base64.b64encode(public_key + b"x").decode(),
                "empty key": "", "not Base64": "!!!notbase64", "padded junk": encoded + "====",
                "whitespace": encoded[:10] + "\n" + encoded[10:], "number": 5, "null": None,
                "all 0xFF key": base64.b64encode(b"\xff" * 1184).decode(),
            }
            for name, value in bad_keys.items():
                reply = s.protected_read(value)
                self.check(f"{name}: refused cleanly", reply.refused and reply.clean, "medium",
                           "accepted, crashed or timed out")
            reply = s.protected_read(base64.b64encode(bytes(1184)).decode())
            self.check("all-zero key handled", reply.clean, "low", "crash or timeout")
            for name, reply in (("wrong owner", s.protected_read(encoded, actor=s.peer)),
                                ("unknown actor", s.protected_read(encoded, actor="nobody")),
                                ("disabled actor", s.protected_read(encoded, actor=s.disabled))):
                self.check(f"{name} gets no ciphertext", reply.refused, "critical", "ciphertext released")
            again = s.protected_read(encoded, challenge)
            self.note("INFO", "reused challenge", "accepted" if again.allowed else "refused")
            s.revoke()
            self.check("revoked owner gets no ciphertext", s.protected_read(encoded).refused, "critical",
                       "ciphertext released")

    # ---- item 12: secret leaks and output shape ---------------------------------

    def item_12(self) -> None:
        with self.scenario(ready=False) as s:
            public_key = base64.b64encode(bytes(1184)).decode()
            replies = [("setup", s.setup()), ("own read", s.read(request_id="own"))]
            s.revoke()
            replies += [
                ("revoked read", s.read(request_id="gone")), ("audit", s.audit("gone")),
                ("audit unknown", s.audit("never")), ("bad input", s.call(b"{" + s.marker.encode())),
                ("bad setup", s.setup(owners=5)), ("bad key", s.protected_read("!!", s.marker)),
                ("denied protected", s.protected_read(public_key)),
            ]
            for name, reply in replies:
                output = reply.stdout + reply.stderr
                self.check(f"{name}: key marker never output", s.marker.encode() not in output, "critical",
                           "key_material appeared in output")
                if name != "own read":
                    self.check(f"{name}: no protected content",
                               not any(v.encode() in output for v in s.protected[:3]), "critical", "content disclosed")
                self.check(f"{name}: output within limits", reply.clean, "low", "oversized, traceback or timeout")
            audit = dict(replies)["audit"]  # taken before any of the bad requests below it
            self.check("audit reply carries only request_id, decision and rule",
                       bool(audit.data) and set(audit.data) <= {"request_id", "decision", "rule"}
                       and {"request_id", "decision"} <= set(audit.data), "medium", "unexpected audit fields")
            self.check("audit of an unknown id invents nothing",
                       "decision" not in (s.audit("never").data or {}), "medium", "a record was invented")
            forms = (s.marker.encode(), base64.b64encode(s.marker.encode()), s.marker.encode().hex().encode())
            stored = [p for p in s.state.rglob("*") if p.is_file() and any(f in p.read_bytes() for f in forms)]
            self.check("key_material is not stored", not stored, "medium", "marker found in a state file")

    # ---- item 13: uniform denials ------------------------------------------------

    def item_13(self) -> None:
        with self.scenario() as s:
            replies = [s.read(actor="nobody"), s.read(asset="missing"), s.read(asset=s.other),
                       s.read(actor=s.disabled, asset=s.locked)]
            s.revoke()
            replies.append(s.read())
            self.check("every denial looks the same", len({r.stdout for r in replies}) == 1
                       and all(r.denied for r in replies), "low", "responses reveal why access failed")
        source = self.entry.parent / "t4" / "crypto" / "proof.py"
        if source.exists():
            self.check("proof comparison is constant time", "compare_digest" in source.read_text(encoding="utf-8"),
                       "low", "compare_digest not used")

    # ---- item 14: static scan ----------------------------------------------------

    def runtime_files(self) -> list[Path]:
        root = self.entry.parent
        names = [self.entry, root / "team_app.py", *sorted((root / "t4").rglob("*.py"))]
        return [p for p in names if p.is_file()]

    def item_14(self) -> None:
        banned_modules = {"pickle", "marshal", "shelve", "socket", "urllib", "http", "requests", "httpx",
                          "ftplib", "smtplib", "telnetlib", "xmlrpc"}
        findings: list[str] = []
        for path in self.runtime_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    modules = [node.module]
                findings += [f"{path.name}: import {m}" for m in modules if m.split(".")[0] in banned_modules]
                if isinstance(node, ast.Call):
                    function = node.func
                    if isinstance(function, ast.Name) and function.id in ("eval", "exec"):
                        findings.append(f"{path.name}:{node.lineno} {function.id}()")
                    if (isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name)
                            and function.value.id == "os" and function.attr in ("system", "popen")):
                        findings.append(f"{path.name}:{node.lineno} os.{function.attr}()")
                    if any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in node.keywords):
                        findings.append(f"{path.name}:{node.lineno} shell=True")
        self.check("no eval, exec, pickle, shell or network use", not findings, "high", "; ".join(findings[:5]))

    # ---- item 15: nothing written next to the code --------------------------------

    def item_15(self) -> None:
        skip = {".git", ".venv", "__pycache__", ".pytest_cache"}

        def snapshot() -> dict[str, str]:
            root = self.entry.parent
            return {
                str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob("*") if p.is_file() and not skip & set(p.relative_to(root).parts)
            }

        before = snapshot()
        with self.scenario() as s:
            s.read(request_id="ro")
            s.audit("ro")
            s.protected_read(base64.b64encode(bytes(1184)).decode())
            s.revoke()
        self.check("repository unchanged by service calls", snapshot() == before, "high",
                   "the service wrote next to its code")

    # ---- driver -------------------------------------------------------------------

    ITEMS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

    def execute(self, items: list[int]) -> list[Result]:
        for number in items:
            self.item = number
            method = getattr(self, f"item_{number}", None)
            if method is None:
                self.note("SKIP", "rotation kill-points" if number == 9 else "corrupted backup",
                          "needs the rotation and backup commands (c3)")
                continue
            try:
                method()
            except Exception as error:  # one broken item must not hide the others
                self.results.append(Result(number, "item could not complete", "FAIL", "high",
                                           f"{type(error).__name__}: {str(error)[:120]}"))
        return self.results


def render(results: list[Result], entry: str) -> str:
    counts = {status: sum(r.status == status for r in results) for status in ("PASS", "FAIL", "SKIP", "INFO")}
    by_severity = ", ".join(f"{level} {sum(r.severity == level for r in results)}" for level in SEVERITIES)
    lines = [
        "# Self red-team report", "",
        f"Target: `{entry}` (local only). Python {sys.version.split()[0]} on {sys.platform}.", "",
        f"Result: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped, "
        f"{counts['INFO']} informational. Failures by severity: {by_severity}.", "",
        "A pass means these probes found nothing; it is not proof of security.", "",
        "| Item | Checks passed | Failed | Skipped |", "|---|---|---|---|",
    ]
    for item in sorted({r.item for r in results}):
        group = [r for r in results if r.item == item]
        lines.append(f"| {item} | {sum(r.status == 'PASS' for r in group)} | "
                     f"{sum(r.status == 'FAIL' for r in group)} | {sum(r.status == 'SKIP' for r in group)} |")
    for title, status in (("Failures", "FAIL"), ("Skipped", "SKIP"), ("Information", "INFO")):
        lines += ["", f"## {title}", ""]
        group = [r for r in results if r.status == status]
        if status == "FAIL":
            group.sort(key=lambda r: SEVERITIES.index(r.severity))
        lines += [
            f"- Item {r.item}{f' [{r.severity}]' if r.severity else ''}: {r.name}. {r.detail}".rstrip()
            for r in group
        ] or ["None."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attack our own adapter (local only).")
    parser.add_argument("--entry", default=str(ROOT / "track4_service.py"), help="local adapter file")
    parser.add_argument("--items", help="comma-separated item numbers (default: all)")
    parser.add_argument("--report", help="write a Markdown report here")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args(argv)
    entry = Path(args.entry)
    if not entry.is_file() or entry.suffix != ".py":
        print("adapter not found: pass --entry with a local .py file", file=sys.stderr)
        return 2
    try:
        items = sorted({int(x) for x in args.items.split(",")}) if args.items else list(Suite.ITEMS)
        if not set(items) <= set(Suite.ITEMS):
            raise ValueError
    except ValueError:
        print("--items takes numbers from 1 to 15", file=sys.stderr)
        return 2
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))  # for t4.crypto and t4.audit
    results = Suite(entry, args.timeout).execute(items)
    for result in results:
        if result.status != "PASS":
            print(f"{result.status} item {result.item} {result.severity} {result.name}: {result.detail}")
    failed = sum(r.status == "FAIL" for r in results)
    print(f"{sum(r.status == 'PASS' for r in results)} passed, {failed} failed, "
          f"{sum(r.status == 'SKIP' for r in results)} skipped")
    if args.report:
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(results, entry.name), encoding="utf-8", newline="\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
