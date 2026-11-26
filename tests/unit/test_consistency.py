"""State/audit consistency, and exactly which rollbacks it can and cannot see."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from t4.consistency import check
from t4.wiring import build_default_dependencies
from team_app import dispatch

try:
    from t4.crypto import sig

    sig.sig_keygen()
    HAVE_SIG = True
except Exception:  # pqcrypto missing: the real audit log needs it
    HAVE_SIG = False

ROOT = Path(__file__).resolve().parents[2]
SETUP = {"op": "setup", "owners": {"a": "maya", "b": "ravi"}, "contents": {"a": "A", "b": "B"},
         "disabled": [], "key_material": "k"}


@unittest.skipUnless(HAVE_SIG, "needs the real ML-DSA wrapper")
class Consistency(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="t4-consist-")
        self.root = Path(self._tmp.name)
        self.dir = self.root / "state"
        self.deps = build_default_dependencies(self.dir)
        dispatch(SETUP, self.deps)

    def tearDown(self):
        self._tmp.cleanup()

    def revoke(self, actor):
        dispatch({"op": "revoke", "actor": actor}, self.deps)
        dispatch({"op": "read", "actor": "maya", "asset": "a", "request_id": f"after-{actor}"}, self.deps)

    def test_a_normal_history_is_consistent(self):
        self.revoke("eve")
        self.revoke("mallory")
        result = check(self.dir)
        self.assertTrue(result["checked"] and not result["problems"], result)
        self.assertEqual(result["state"]["epoch"], 2)

    def test_a_state_file_rolled_back_on_its_own_is_detected(self):
        self.revoke("eve")
        old_state = (self.dir / "state.json").read_bytes()  # epoch 1
        self.revoke("mallory")                               # epoch 2, logged
        (self.dir / "state.json").write_bytes(old_state)     # only the state goes back
        result = check(self.dir)
        self.assertTrue(result["checked"])
        self.assertTrue(any("epoch 1" in p and "epoch 2" in p for p in result["problems"]), result)

    def test_a_whole_directory_rolled_back_together_is_not_seen_by_this_check(self):
        """Documented limit: state and log agree with each other, so only an outside pin shows it."""
        self.revoke("eve")
        shutil.copytree(self.dir, self.root / "backup")
        self.revoke("mallory")
        shutil.rmtree(self.dir)
        shutil.copytree(self.root / "backup", self.dir)
        result = check(self.dir)
        self.assertTrue(result["checked"] and not result["problems"], result)

    def test_a_pin_taken_before_the_rollback_does_expose_the_whole_directory_rollback(self):
        from t4.audit.log import AuditLog, load_signer
        from t4.audit.verify import verify_log

        self.revoke("eve")
        shutil.copytree(self.dir, self.root / "backup")
        self.revoke("mallory")
        head = AuditLog(self.dir / "audit", load_signer(self.dir / "audit")).head()
        pin = dict(head, public_key=(self.dir / "audit" / "audit.pub").read_bytes().hex())  # kept elsewhere
        shutil.rmtree(self.dir)
        shutil.copytree(self.root / "backup", self.dir)
        report = verify_log(self.dir / "audit", pin, bytes.fromhex(pin["public_key"]))
        self.assertFalse(report.ok)
        self.assertTrue(any("tail removed" in e for e in report.errors), report.errors)

    def test_a_damaged_state_or_log_is_reported_not_trusted(self):
        self.revoke("eve")
        (self.dir / "state.json").write_bytes(b"{}")
        self.assertFalse(check(self.dir)["checked"])

    def test_the_command_line_uses_exit_status(self):
        self.revoke("eve")
        run = lambda: subprocess.run([sys.executable, "-m", "t4.consistency", "--state-dir", str(self.dir)],
                                     capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(run().returncode, 0)
        old = (self.dir / "state.json").read_bytes()
        self.revoke("mallory")
        (self.dir / "state.json").write_bytes(old)
        done = run()
        self.assertEqual(done.returncode, 1)
        self.assertFalse(json.loads(done.stdout)["consistent"])


if __name__ == "__main__":
    unittest.main()
