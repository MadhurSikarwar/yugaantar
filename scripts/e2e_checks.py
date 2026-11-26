"""End-to-end checks as a judge would run them: real processes, real adapter state, no mocks.

Usage: python scripts/e2e_checks.py [REPO_DIR]   (default: this repository)
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
PY = sys.executable
RESULTS = []


def run(*args, env=None, cwd=REPO, input_=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run([PY, *args], capture_output=True, text=True, cwd=cwd, env=e, input=input_)


def adapter(state, request):
    r = run(str(REPO / "track4_service.py"), env={"TRACK4_STATE_DIR": str(state)}, input_=json.dumps(request))
    assert r.returncode == 0, (request, r.stderr)
    return json.loads(r.stdout)


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))


def make_state(root):
    state = root / "state"
    adapter(state, {"op": "setup", "owners": {"brief": "maya", "memo": "ravi"},
                    "contents": {"brief": "B", "memo": "M"}, "disabled": [], "key_material": "synthetic"})
    for i in range(5):
        adapter(state, {"op": "read", "actor": "maya", "asset": "brief", "request_id": f"r{i}"})
    adapter(state, {"op": "revoke", "actor": "eve"})
    adapter(state, {"op": "read", "actor": "maya", "asset": "brief", "request_id": "after"})
    return state


def locate_audit(state):
    found = list(state.rglob("audit.jsonl"))
    assert found, "no audit log created by the adapter"
    return found[0].parent


def main():
    root = Path(tempfile.mkdtemp(prefix="t4-e2e-"))
    try:
        # 1. read-only audit directory: explain, verify-log and the detector export must still read it
        state = make_state(root)
        audit = locate_audit(state)
        ro = root / "ro_audit"
        shutil.copytree(audit, ro)
        for path in ro.rglob("*"):
            os.chmod(path, stat.S_IREAD)
        a = run("-m", "t4.audit.cli", "--dir", str(ro), "verify-log")
        check("read-only: verify-log", a.returncode == 0, a.stderr.strip()[:80])
        b = run("-m", "t4.audit.cli", "--dir", str(ro), "explain", "after")
        check("read-only: explain", b.returncode == 0 and "after" in b.stdout, b.stderr.strip()[:80])
        c = run("-m", "t4.audit.cli", "--dir", str(ro), "alerts")
        check("read-only: alerts", c.returncode == 0, c.stderr.strip()[:80])
        d = run("-m", "t4.detect.cli", "export", "--node", f"n1={ro}")
        check("read-only: detector export", d.returncode == 0, (d.stderr or d.stdout).strip()[:100])
        for path in ro.rglob("*"):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)

        # 2. consistency: deleted / emptied audit log with a provisioned state
        state2 = make_state(root / "c")
        ok0 = run("-m", "t4.consistency", "--state-dir", str(state2))
        check("consistency: intact state is consistent (exit 0)", ok0.returncode == 0, ok0.stdout.strip()[:100])
        shutil.rmtree(locate_audit(state2))
        gone = run("-m", "t4.consistency", "--state-dir", str(state2))
        check("consistency: deleted audit log is NOT consistent", gone.returncode == 1, gone.stdout.strip()[:120])
        state3 = make_state(root / "d")
        aud3 = locate_audit(state3)
        for name in ("audit.jsonl", "checkpoints.jsonl"):
            if (aud3 / name).exists():
                (aud3 / name).write_bytes(b"")
        emptied = run("-m", "t4.consistency", "--state-dir", str(state3))
        check("consistency: emptied audit log is NOT consistent", emptied.returncode == 1, emptied.stdout.strip()[:120])

        # 3. pin: null / missing key must not downgrade to the key inside the log directory
        state4 = make_state(root / "e")
        aud4 = locate_audit(state4)
        pin = root / "pins" / "pin.json"
        pin.parent.mkdir()
        init = run("-m", "t4.audit.cli", "--dir", str(aud4), "pin", "init", "--pin", str(pin))
        check("pin: init on the adapter's signed log works", init.returncode == 0, init.stderr.strip()[:80])
        good = run("-m", "t4.audit.cli", "--dir", str(aud4), "verify-log", "--pin", str(pin))
        check("pin: verify-log with the real pin passes", good.returncode == 0)
        data = json.loads(pin.read_text())
        for bad in (None, ""):
            data["public_key"] = bad
            pin.write_text(json.dumps(data))
            r = run("-m", "t4.audit.cli", "--dir", str(aud4), "verify-log", "--pin", str(pin))
            check(f"pin: public_key={bad!r} is refused (not silently unpinned)", r.returncode == 2)
        del data["public_key"]
        pin.write_text(json.dumps(data))
        r = run("-m", "t4.audit.cli", "--dir", str(aud4), "verify-log", "--pin", str(pin))
        check("pin: missing public_key is refused", r.returncode == 2)

        # 4. double head(), large log, tamper the newest entry, then a real append
        sys.path.insert(0, str(REPO))
        from tests.audit.synthetic import build_log
        big = root / "big"
        build_log(big, 896, pad=300)
        for _ in range(2):
            h = run("-m", "t4.audit.cli", "--dir", str(big), "head")
            assert h.returncode == 0, h.stderr
        cp_lines = (big / "checkpoints.jsonl").read_bytes().count(b"\n")
        log_path = big / "audit.jsonl"
        lines = log_path.read_bytes().split(b"\n")
        lines[-2] = lines[-2].replace(b'"actor":"actor-0"', b'"actor":"MALLORY"')
        log_path.write_bytes(b"\n".join(lines))
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from t4.audit.log import AuditLog, load_signer, AuditIntegrityError\n"
            "d = Path(%r); log = AuditLog(d, load_signer(d), checkpoint_every=16)\n"
            "try:\n"
            "    log.append(actor='a', action='read', target='t', decision='allow', rule='R', request_id='x', detail={})\n"
            "    print('APPENDED')\n"
            "except AuditIntegrityError:\n"
            "    print('REFUSED')\n" % (str(REPO), str(big)))
        r = run("-c", code)
        check("double head(): tamper of the newest entry is caught on the next real append",
              "REFUSED" in r.stdout, r.stdout.strip() + r.stderr.strip()[:80])
        check("double head(): no duplicate checkpoint was written", cp_lines <= (896 // 16) + 1, f"{cp_lines} checkpoint lines")

        # 5. messaging, two parties, JSON over the wire, fresh process for the receiver
        try:
            import cryptography  # noqa: F401  (demo-only package; see requirements-demo.txt)
            have_cipher = True
        except ImportError:
            have_cipher = False
            print("SKIP messaging: the demo-only 'cryptography' package is not installed")
        code = (
            "import json, sys; sys.path.insert(0, %r)\n"
            "from demo import messaging as m\n"
            "from t4.crypto import kem, sig\n"
            "spk, ssk = sig.sig_keygen(); kpk, ksk = kem.keygen()\n"
            "wire = json.dumps(m.seal(sender='alice', sender_sig_secret=ssk, recipient='bob', recipient_kem_public=kpk, plaintext='hi bob', seq=1))\n"
            "g = m.ReplayGuard()\n"
            "msg = json.loads(wire)\n"
            "out = m.open_message(msg, recipient='bob', recipient_kem_secret=ksk, expected_sender='alice', sender_sig_public=spk, guard=g)\n"
            "assert out == 'hi bob' and 'hi bob' not in wire\n"
            "try:\n"
            "    m.open_message(msg, recipient='bob', recipient_kem_secret=ksk, expected_sender='alice', sender_sig_public=spk, guard=g)\n"
            "    print('REPLAY-ACCEPTED')\n"
            "except m.MessagingError:\n"
            "    print('OK')\n" % str(REPO))
        if have_cipher:
            r = run("-c", code)
            check("messaging: round trip over JSON, replay refused", r.stdout.strip() == "OK", (r.stdout + r.stderr).strip()[:150])
        # the adapter must not import the demo layer or the cipher package
        r = run("-c", "import sys; sys.path.insert(0, %r); import track4_service, t4.service; "
                      "print('cryptography' in sys.modules, 'demo.messaging' in sys.modules)" % str(REPO))
        check("adapter does not import cryptography or demo.messaging", r.stdout.strip() == "False False", r.stdout.strip())
    finally:
        shutil.rmtree(root, ignore_errors=True)
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


sys.exit(main())
