"""Revoke, grant and ungrant events are logged once per real operation, whatever is interrupted.

Same method as test_rotation_idempotency: the real signed log, the real ML-DSA wrapper, a failure
injected at each persistence boundary, then a retry and a count of the entries.
"""
import tempfile
import unittest
from pathlib import Path

from t4.node.authority import Authority
from t4.node.common import open_log

from tests.recovery.test_rotation_idempotency import HAVE_SIG, Crash, FlakyLog, count, sig


@unittest.skipUnless(HAVE_SIG, "needs the real ML-DSA wrapper")
class AuthorityEventIdempotency(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="t4-authev-")
        self.log_dir = Path(self._tmp.name) / "alog"
        self.flaky = FlakyLog(open_log(self.log_dir))
        self.authority = Authority.create(Path(self._tmp.name) / "a", sig, self.flaky, freshness=10, skew=2)

    def tearDown(self):
        self._tmp.cleanup()

    def test_revoking_the_same_actor_twice_logs_once(self):
        first = self.authority.revoke_actor("eve", 100)
        second = self.authority.revoke_actor("eve", 150)
        self.assertEqual(first, second)
        self.assertEqual(count(self.log_dir, "KEY-REVOKE-ACTOR", "eve"), 1)

    def test_revoking_two_different_actors_logs_two(self):
        self.authority.revoke_actor("eve", 100)
        self.authority.revoke_actor("mallory", 101)
        self.assertEqual(count(self.log_dir, "KEY-REVOKE-ACTOR"), 2)

    def test_a_revocation_whose_log_entry_failed_is_logged_by_the_retry(self):
        self.flaky.arm("KEY-REVOKE-DEVICE", "oserror")
        with self.assertRaises(Exception):
            self.authority.revoke_device("phone", 100)  # enforced, but the entry is missing
        self.assertEqual(count(self.log_dir, "KEY-REVOKE-DEVICE"), 0)
        self.authority.revoke_device("phone", 105)
        self.assertEqual(count(self.log_dir, "KEY-REVOKE-DEVICE"), 1)
        self.authority.revoke_device("phone", 106)
        self.assertEqual(count(self.log_dir, "KEY-REVOKE-DEVICE"), 1)

    def test_a_grant_interrupted_after_its_entry_is_logged_once_on_retry(self):
        self.flaky.arm("PERM-GRANT", "after")
        with self.assertRaises(Crash):
            self.authority.grant("bob", "report", 100, approval_id="chg-1")
        self.assertEqual(count(self.log_dir, "PERM-GRANT"), 1)
        self.assertNotIn("bob|report", str(self.authority._record()["grants"]))  # not applied
        self.authority.grant("bob", "report", 101, approval_id="chg-1")
        self.assertEqual(count(self.log_dir, "PERM-GRANT"), 1)
        self.assertEqual(len(self.authority._record()["grants"]), 1)

    def test_a_deliberate_regrant_after_an_ungrant_is_logged_again(self):
        self.authority.grant("bob", "report", 100, approval_id="chg-1")
        self.authority.ungrant("bob", "report", 101)
        self.authority.grant("bob", "report", 102, approval_id="chg-1")
        self.assertEqual(count(self.log_dir, "PERM-GRANT"), 2)
        self.assertEqual(count(self.log_dir, "PERM-REMOVE"), 1)

    def test_an_ungrant_retried_after_success_logs_once(self):
        self.authority.grant("bob", "report", 100, approval_id="chg-1")
        self.authority.ungrant("bob", "report", 101)
        self.authority.ungrant("bob", "report", 102)
        self.assertEqual(count(self.log_dir, "PERM-REMOVE"), 1)
        self.assertTrue(open_log(self.log_dir).verify().ok)

    def test_a_crashed_grant_retried_after_another_grant_is_still_logged_once(self):
        self.flaky.arm("PERM-GRANT", "after")
        with self.assertRaises(Crash):
            self.authority.grant("bob", "report", 100, approval_id="chg-1")
        self.authority.grant("carol", "report", 101, approval_id="chg-2")  # a different grant lands first
        self.authority.grant("bob", "report", 102, approval_id="chg-1")    # the retry
        entries = [e for e in open_log(self.log_dir).entries() if e["rule"] == "PERM-GRANT"]
        self.assertEqual(sorted(e["detail"]["subject"] for e in entries), ["bob", "carol"])


if __name__ == "__main__":
    unittest.main()
