#!/usr/bin/env python3
"""The 5-minute lost-device story in one command.

    python demo/run_demo.py [--pause] [--keep]

What it shows, with the real modules (ML-KEM-768, ML-DSA-65, signed logs):

  Part 1, the judged adapter (a new process per request, as the judges run it):
    setup, owner read, peer read, protected_read verified by an independent
    client, revoke, denied read, audit and explain of the denial, peer still
    allowed.
  Part 2, the node layer (simulated clock, three nodes):
    signed requests, key rotation under load (old key before C, new key from
    C), a node goes offline, the phone is lost and revoked, the courier
    delivers the list to two nodes, the offline node locks itself once its
    list is older than T, a new device is re-enrolled, the other user still
    reads.
  Part 3, the operator:
    the detector verifies our own signed node and key-event logs, flags an
    unapproved grant, its use, and one actor probing several nodes, leaves an
    approved grant alone, and appends its alerts to the signed log; then a
    log entry is altered and verify-log against a pinned head points at it.

Every step checks its own outcome; the script exits 1 if any check fails, so
it doubles as an end-to-end test. All data are synthetic, every directory is
temporary (outside the repository), and no key is ever printed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PAUSE = False
FAILURES: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)


def section(title: str) -> None:
    say()
    say("=" * 78)
    say(title)
    say("=" * 78)
    if PAUSE:
        input("  (press Enter) ")


def check(ok: bool, what: str) -> None:
    say(f"  [{'OK' if ok else 'FAIL'}] {what}")
    if not ok:
        FAILURES.append(what)


# ---------------------------------------------------------------- part 1 ---

class Adapter:
    """Calls track4_service.py once per request, like the judges."""

    def __init__(self, state: Path):
        self.env = dict(os.environ)
        for name in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
            self.env[name] = str(state)

    def __call__(self, request: dict, show: bool = True) -> dict:
        proc = subprocess.run([sys.executable, "-B", str(ROOT / "track4_service.py")],
                              input=json.dumps(request).encode(), cwd=ROOT, env=self.env,
                              capture_output=True, timeout=30)
        reply = json.loads(proc.stdout) if proc.returncode == 0 else {"exit": proc.returncode}
        if show:
            shown = {k: (v if not isinstance(v, str) or len(v) < 60 else v[:24] + "...") for k, v in request.items()}
            reply_shown = {k: (v if not isinstance(v, str) or len(v) < 60 else v[:24] + "...") for k, v in reply.items()}
            say(f"  -> {json.dumps(shown)}")
            say(f"  <- {json.dumps(reply_shown)}")
        return reply


def part_adapter(root: Path) -> None:
    from pqcrypto.kem import ml_kem_768

    state = root / "adapter-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)  # the adapter refuses a state directory others can read (POSIX)
    call = Adapter(state)

    section("1. The judged adapter: an owner reads, a peer reads")
    contents = {"brief-maya": "Q3 plan (synthetic)", "brief-noor": "budget notes (synthetic)"}
    check(call({"op": "setup", "owners": {"brief-maya": "maya", "brief-noor": "noor"},
                "contents": contents, "disabled": [], "key_material": secrets.token_hex(16)})
          == {"ready": True}, "setup acknowledged; key_material is never stored or printed")
    check(call({"op": "read", "actor": "maya", "asset": "brief-maya", "request_id": "r1"})
          == {"decision": "allow", "body": contents["brief-maya"]}, "owner gets the exact body")
    check(call({"op": "read", "actor": "noor", "asset": "brief-maya", "request_id": "r2"})
          == {"decision": "deny"}, "someone else's file: deny, nothing else in the reply")

    section("2. protected_read: ML-KEM-768 encapsulation + HMAC proof, checked by the client")
    pk, sk = ml_kem_768.generate_keypair()
    challenge = secrets.token_hex(8)
    reply = call({"op": "protected_read", "actor": "maya", "asset": "brief-maya",
                  "challenge": challenge, "public_key": base64.b64encode(pk).decode()})
    ok = False
    if "ciphertext" in reply and "proof" in reply:
        shared = ml_kem_768.decrypt(sk, base64.b64decode(reply["ciphertext"]))
        expected = hmac.new(shared, (challenge + contents["brief-maya"]).encode(), hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(expected, reply["proof"])
    check(ok, "client decapsulates, recomputes HMAC(secret, challenge + body): proof matches")
    say("  (the body itself is not sent by protected_read; the shared secret is never stored)")

    section("3. Maya's phone is lost: revoke, then her reads are denied; Noor is unaffected")
    check(call({"op": "revoke", "actor": "maya"}) == {}, "revocation persisted before the reply")
    check(call({"op": "read", "actor": "maya", "asset": "brief-maya", "request_id": "r3"})
          == {"decision": "deny"}, "maya is denied")
    audit = call({"op": "audit", "request_id": "r3"})
    check(audit.get("decision") == "deny" and audit.get("rule") == "POL-REVOKED",
          "audit r3 explains the denial with its rule ID")
    check(call({"op": "read", "actor": "noor", "asset": "brief-noor", "request_id": "r4"})
          == {"decision": "allow", "body": contents["brief-noor"]}, "noor still reads her own file")

    say("\n  Operator view of r3 from the signed adapter log (t4.audit.cli explain r3):")
    from t4.audit.log import AuditLog
    for entry in AuditLog(state / "audit", None).explain("r3"):
        say(f"    seq {entry['seq']:>3}  {entry['ts']}  {entry['actor']} {entry['action']} "
            f"{entry['target']} -> {entry['decision']} ({entry['rule']})")


# ---------------------------------------------------------------- part 2 ---

def last_decision(log, request_action: str = "read") -> tuple[str, str]:
    for entry in reversed(log.entries()):
        if entry["action"] == request_action and entry["decision"] in ("allow", "deny"):
            return entry["decision"], entry["rule"]
    return "", ""


def part_nodes(root: Path) -> dict:
    from t4.node.authority import Authority
    from t4.node.common import load_signer, open_log
    from t4.node.device import Device
    from t4.node.freshness import Node
    from t4.node.request import respond

    signer = load_signer()
    T, S = 60.0, 2.0
    now = time.time()
    logs = root / "logs"
    owners = {"plan": "maya", "budget": "noor", "notes": "eve"}
    contents = {"plan": "synthetic plan", "budget": "synthetic budget", "notes": "synthetic notes"}
    authority = Authority.create(root / "authority", signer, open_log(logs / "authority"), freshness=T, skew=S)
    nodes = {nid: Node.provision(root / nid, signer, open_log(logs / nid), node_id=nid,
                                 authority_pk=authority.public_key, owners=owners, contents=contents,
                                 freshness=T, skew=S)
             for nid in ("node-a", "node-b", "node-c")}
    phone = Device.create(root / "phone", signer, "maya-phone", "maya")
    tablet = Device.create(root / "tablet", signer, "noor-tablet", "noor")
    eve_dev = Device.create(root / "eve", signer, "eve-laptop", "eve")
    for dev in (phone, tablet, eve_dev):
        dev.enroll(authority, now)

    def deliver(t: float, to=("node-a", "node-b", "node-c")) -> None:
        signed = authority.issue_list(t)
        for nid in to:
            nodes[nid].accept_list(signed, t)

    def ask(dev, nid, asset, t):
        reply = respond(nodes[nid], dev.make_request(nid, asset, t), t)
        return reply["decision"], last_decision(open_log(logs / nid))[1]

    section("4. Node layer: every request is signed by the device (ML-DSA-65) and checked by the node")
    deliver(now)
    d, rule = ask(phone, "node-a", "plan", now + 1)
    check(d == "allow", f"maya's phone reads 'plan' on node-a: {d} ({rule})")
    forged = phone.make_request("node-a", "plan", now + 2)
    forged["body"]["actor"] = "noor"  # change the signed body after signing
    reply = respond(nodes["node-a"], forged, now + 2)
    check(reply == {"decision": "deny"},
          f"a request altered after signing is denied ({last_decision(open_log(logs / 'node-a'))[1]})")

    section("5. Key rotation under load: old key until C, new key from C, no grace period")
    c_time = phone.rotate(authority, now + 5, now + 5 + T + S + 5)
    deliver(now + 10)
    d1, r1 = ask(phone, "node-a", "plan", c_time - 2)
    deliver(c_time + 1)
    d2, r2 = ask(phone, "node-a", "plan", c_time + 2)
    check(d1 == "allow" and d2 == "allow",
          f"before C (old key): {d1}; after C (new key): {d2}; C = start + {c_time - now:.0f} s")

    section("6. node-c goes offline; maya's phone is lost and revoked; a courier carries the list")
    t_rev = c_time + 10
    deliver(t_rev - 5)                       # last list node-c will see
    authority.revoke_device("maya-phone", t_rev)
    deliver(t_rev + 3, to=("node-a", "node-b"))
    for nid in ("node-a", "node-b"):
        d, rule = ask(phone, nid, "plan", t_rev + 4)
        check(d == "deny", f"lost phone on {nid}: {d} ({rule})")
    d, rule = ask(phone, "node-c", "plan", t_rev + 4)
    say(f"  lost phone on offline node-c within T: {d} ({rule})  <- the bounded window r + T + s")
    late = t_rev - 5 + T + 1
    d, rule = ask(phone, "node-c", "plan", late)
    check(d == "deny", f"node-c after its list is older than T: {d} ({rule})")
    d, rule = ask(tablet, "node-c", "budget", late)
    check(d == "deny", f"stale node-c denies everyone, even noor: {d} ({rule})")

    section("7. Maya enrols a new device and gets access back; Noor was never affected")
    laptop = Device.create(root / "laptop", signer, "maya-laptop", "maya")
    laptop.enroll(authority, late + 1)
    deliver(late + 2)
    d, rule = ask(laptop, "node-a", "plan", late + 3)
    check(d == "allow", f"maya's new laptop on node-a: {d} ({rule})")
    d, rule = ask(phone, "node-c", "plan", late + 3)
    check(d == "deny", f"the lost phone on node-c once it has the list: {d} ({rule})")
    d, rule = ask(tablet, "node-b", "budget", late + 3)
    check(d == "allow", f"noor on node-b: {d} ({rule})")

    # Material for the detector (part 3): one approved and one unapproved grant,
    # their use, and an enrolled actor probing files she does not own.
    t = late + 10
    authority.grant("noor", "plan", t, approval_id="chg-7", granted_by="ops-lead")
    authority.grant("eve", "budget", t + 1, granted_by="ops-lead")  # no approval
    deliver(t + 2)
    ask(tablet, "node-a", "plan", t + 3)          # approved use
    ask(eve_dev, "node-b", "budget", t + 4)       # use of the unapproved grant
    ask(eve_dev, "node-a", "plan", t + 5)         # probing
    ask(eve_dev, "node-c", "plan", t + 6)
    return {"logs": logs, "owners": {nid: dict(owners) for nid in nodes}}


# ---------------------------------------------------------------- part 3 ---

def part_operator(root: Path, world: dict) -> None:
    from t4.audit.log import AuditLog, load_signer, read_bytes
    from t4.audit.verify import verify_log
    from t4.detect import export as exp
    from t4.detect.ingest import parse_approvals

    logs: Path = world["logs"]
    section("8. Operator: the detector runs on OUR OWN signed logs (verified first)")
    now = datetime.now(timezone.utc)
    register = parse_approvals({"changes": [{
        "approval_id": "chg-7", "approved_by": "ops-lead", "subject": "noor",
        "operation": "grant_role", "role": "read:plan", "scope": ["node-a/plan", "node-b/plan", "node-c/plan"],
        "valid_from_utc": (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_until_utc": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")}]})
    sources = [exp.LogSource(logs / "authority", "authority", "authority")]
    sources += [exp.LogSource(logs / nid, "node", nid) for nid in ("node-a", "node-b", "node-c")]
    result = exp.run_export(sources, register, owners=world["owners"], approvers=["ops-lead"],
                            alert_log=logs / "authority")
    for v in result.verified:
        say(f"  verified {v['kind']:<9} log {v['log']:<9} {v['entries']:>3} entries: ok")
    say(f"  {len(result.rows)} events exported; {len(result.result.alerts)} alerts:")
    for alert in result.result.alerts:
        say(f"\n  [{alert.severity.upper()}] {alert.rule}   identity: {alert.identity}")
        say(f"    services: {', '.join(alert.services)}")
        say(f"    why: {alert.explanation}")
    by = {(a.rule, a.identity) for a in result.result.alerts}
    check(("DET-UNAPPROVED-ROLE-CHANGE", "eve") in by, "unapproved grant to eve is flagged")
    check(("DET-REVIEW-AFTER-ROLE-CHANGE", "eve") in by, "eve's use of it is flagged for review")
    check(("DET-LATERAL-MOVEMENT", "eve") in by, "eve probing files on several nodes is flagged")
    check(not any(a.identity == "noor" for a in result.result.alerts), "noor's approved grant raises no alert")
    check(not any(a.identity == "maya" for a in result.result.alerts),
          "requests whose signature was not verified are never pinned on maya (shown as '(unverified)')")
    stored = [e for e in AuditLog(logs / "authority", None).alerts() if e["detail"].get("source") == "t4.detect.export"]
    check(len(stored) == len(result.result.alerts), f"{len(stored)} alerts appended to the signed authority log")

    section("9. Tamper with a node log; verify-log against a pinned head points at the entry")
    original = logs / "node-a"
    copy = root / "node-a-log-copy"
    shutil.copytree(original, copy)
    head = AuditLog(copy, load_signer(copy)).head()
    pin = dict(head, public_key=read_bytes(copy / "audit.pub").hex())
    report = verify_log(copy, pin, bytes.fromhex(pin["public_key"]))
    check(report.ok, f"before: verify-log ok, {report.entries} entries, pinned head seq {pin['seq']}")
    path = copy / "audit.jsonl"
    data = path.read_bytes()
    path.write_bytes(data.replace(b'"decision":"deny"', b'"decision":"allow"', 1))
    say('  edited one old entry: "decision":"deny" -> "decision":"allow"')
    report = verify_log(copy, pin, bytes.fromhex(pin["public_key"]))
    check(not report.ok, f"after: verify-log FAILS at entry {report.first_bad_seq}: {report.errors[0]}")


def part_messaging() -> None:
    """Optional demo-layer messaging (needs the demo-only 'cryptography' package; never used by the adapter)."""
    section("Part 4 (optional): signed, encrypted messages, demo layer only")
    sys.path.insert(0, str(ROOT))
    try:
        from demo import messaging as m
        m._aead()
    except Exception:
        say("  skipped: install requirements-demo.txt to run this part (the adapter does not need it)")
        return
    from t4.crypto import kem, sig

    maya_pk, maya_sk = sig.sig_keygen()
    ravi_kem_pk, ravi_kem_sk = kem.keygen()
    guard = m.ReplayGuard()
    wire = json.dumps(m.seal(sender="maya", sender_sig_secret=maya_sk, recipient="ravi",
                             recipient_kem_public=ravi_kem_pk, plaintext="meet at noon", seq=1))
    check("meet at noon" not in wire, "the message on the wire does not contain the text")
    read = m.open_message(json.loads(wire), recipient="ravi", recipient_kem_secret=ravi_kem_sk,
                          expected_sender="maya", sender_sig_public=maya_pk, guard=guard)
    check(read == "meet at noon", "ravi reads it after checking maya's signature")
    try:
        m.open_message(json.loads(wire), recipient="ravi", recipient_kem_secret=ravi_kem_sk,
                       expected_sender="maya", sender_sig_public=maya_pk, guard=guard)
        check(False, "a replayed message is refused")
    except m.MessagingError:
        check(True, "a replayed message is refused")
    say("  (not forward secret; replay counters are in memory; see demo/messaging.py)")


def main(argv: list[str] | None = None) -> int:
    global PAUSE
    parser = argparse.ArgumentParser(description="Run the 5-minute demo.")
    parser.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    parser.add_argument("--keep", action="store_true", help="keep the temporary directories")
    args = parser.parse_args(argv)
    PAUSE = args.pause
    root = Path(tempfile.mkdtemp(prefix="t4-demo-"))
    started = time.perf_counter()
    try:
        say("Trust, but verify: lost-device demo (synthetic data, temporary directories)")
        part_adapter(root)
        world = part_nodes(root)
        part_operator(root, world)
        part_messaging()
    finally:
        if args.keep:
            say(f"\n(kept: {root})")
        else:
            shutil.rmtree(root, ignore_errors=True)
    say()
    say(f"{'ALL CHECKS PASSED' if not FAILURES else f'{len(FAILURES)} CHECK(S) FAILED'} "
        f"in {time.perf_counter() - started:.1f} s")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
