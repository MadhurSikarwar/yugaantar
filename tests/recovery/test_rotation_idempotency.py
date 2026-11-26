"""Rotation and enrolment events are logged exactly once, whatever is interrupted.

The authority writes its audit entry first and saves its state when the locked block ends, so a
process that dies between the two used to leave the entry behind; the retry then logged it a
second time. These tests inject a failure at each persistence boundary with the real ML-DSA
wrapper, the real signed audit log and temporary folders, then retry and count the entries.
"""
import base64
import tempfile
import threading
import unittest
from pathlib import Path

from t4.audit.log import AuditLog
from t4.node.authority import Authority
from t4.node.common import NodeError, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond

try:
    from t4.crypto import sig

    sig.sig_keygen()
    HAVE_SIG = True
except Exception:  # pqcrypto missing: these tests need the real wrapper
    HAVE_SIG = False

NOW, CUTOFF = 101.0, 130.0  # freshness 10, skew 2: C must be more than 12 s ahead


class Crash(Exception):
    """Stands in for the process being killed at this exact point."""


class FlakyLog:
    """The real log, with a one-shot failure around the next entry for a given rule."""

    def __init__(self, real: AuditLog):
        self.real = real
        self.rule = None
        self.mode = None  # "before": fail without writing; "after": write, then die; "oserror"

    def arm(self, rule: str, mode: str) -> None:
        self.rule, self.mode = rule, mode

    def _call(self, method, kwargs):
        armed = self.mode is not None and kwargs.get("rule") == self.rule
        mode = self.mode if armed else None
        if armed:
            self.mode = None
        if mode == "before":
            raise Crash("before the audit entry")
        if mode == "oserror":
            raise OSError("simulated write failure")
        result = method(**kwargs)
        if mode == "after":
            raise Crash("after the audit entry, before the state was saved")
        return result

    def append(self, **kwargs):
        return self._call(self.real.append, kwargs)

    def append_once(self, **kwargs):
        return self._call(self.real.append_once, kwargs)

    def __getattr__(self, name):
        return getattr(self.real, name)


def count(log_dir: Path, rule: str, target: str | None = None) -> int:
    entries = open_log(log_dir).entries()
    return sum(e["rule"] == rule and (target is None or e["target"] == target) for e in entries)


@unittest.skipUnless(HAVE_SIG, "needs the real ML-DSA wrapper")
class RotationIdempotency(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="t4-idem-")
        self.root = Path(self._tmp.name)
        self.log_dir = self.root / "alog"
        self.flaky = FlakyLog(open_log(self.log_dir))
        self.authority = Authority.create(self.root / "a", sig, self.flaky, freshness=10, skew=2)
        self.device = Device.create(self.root / "d", sig, "phone", "maya")
        self.device.enroll(self.authority, 100)

    def tearDown(self):
        self._tmp.cleanup()

    def keys_at_authority(self) -> int:
        return len(self.authority._record()["devices"]["phone"]["keys"])

    def rotate(self, now=NOW, fault=None):
        if fault is None:
            return self.device.rotate(self.authority, now, CUTOFF)
        return self.device.rotate(self.authority, now, CUTOFF, fault)

    def assert_clean(self, expect_keys=2):
        self.assertEqual(count(self.log_dir, "KEY-ROTATE"), 1)
        self.assertEqual(self.keys_at_authority(), expect_keys)
        self.assertTrue(open_log(self.log_dir).verify().ok)

    # -- every boundary -------------------------------------------------------------------

    def test_crash_after_the_audit_entry_before_the_state_is_saved(self):
        self.flaky.arm("KEY-ROTATE", "after")
        with self.assertRaises(Crash):
            self.rotate()
        self.assertEqual(count(self.log_dir, "KEY-ROTATE"), 1)  # the entry is durable
        self.assertEqual(self.keys_at_authority(), 1)           # the key is not
        self.assertEqual(self.rotate(NOW + 1), CUTOFF)          # the retry finishes it
        self.assert_clean()

    def test_crash_before_the_audit_entry(self):
        self.flaky.arm("KEY-ROTATE", "before")
        with self.assertRaises(Crash):
            self.rotate()
        self.assertEqual((count(self.log_dir, "KEY-ROTATE"), self.keys_at_authority()), (0, 1))
        self.assertEqual(self.rotate(NOW + 1), CUTOFF)
        self.assert_clean()

    def test_a_failed_audit_write_changes_nothing_and_can_be_retried(self):
        self.flaky.arm("KEY-ROTATE", "oserror")
        with self.assertRaises(OSError):
            self.rotate()
        self.assertEqual((count(self.log_dir, "KEY-ROTATE"), self.keys_at_authority()), (0, 1))
        self.assertEqual(self.rotate(NOW + 1), CUTOFF)
        self.assert_clean()

    def test_crash_after_the_state_is_saved_before_the_device_hears_back(self):
        def die_before_the_device_records_acceptance(step):
            if step == "published":
                raise Crash("device died after the authority accepted")

        with self.assertRaises(Crash):
            self.rotate(fault=die_before_the_device_records_acceptance)
        self.assertEqual(self.keys_at_authority(), 2)
        self.assertEqual(self.rotate(NOW + 1), CUTOFF)  # publication is repeated, answered from state
        self.assert_clean()

    def test_repeated_recovery_attempts_never_add_a_second_entry(self):
        for attempt in range(3):
            self.flaky.arm("KEY-ROTATE", "after")
            with self.assertRaises(Crash):
                self.rotate(NOW + attempt)
        self.assertEqual(count(self.log_dir, "KEY-ROTATE"), 1)
        self.assertEqual(self.rotate(NOW + 5), CUTOFF)
        from t4 import rotation

        for _ in range(2):  # running recovery again, as often as you like, changes nothing
            ring = rotation.recover(self.device.store)
            self.assertIsNone(ring["journal"])
            self.assertEqual(ring["current"], 2)
        self.assert_clean()

    def test_concurrent_publication_of_the_same_rotation_logs_it_once(self):
        version = self.device.info()["current"]
        from t4 import rotation

        new_version = rotation.begin_rotation(self.device.store, sig, CUTOFF, now=NOW)
        key = self.device.info()["keys"][str(new_version)]
        results, errors = [], []

        def publish():
            try:
                other = Authority(self.root / "a", sig, open_log(self.log_dir))
                results.append(other.publish_rotation("phone", new_version, key["public_key"],
                                                      key["activate_at"], NOW))
            except Exception as error:  # noqa: BLE001 - reported below
                errors.append(error)

        threads = [threading.Thread(target=publish) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(set(results), {CUTOFF})
        self.assertEqual(version, 1)
        self.assert_clean()

    # -- interactions -----------------------------------------------------------------------

    def test_a_revocation_after_an_interrupted_rotation_wins(self):
        self.flaky.arm("KEY-ROTATE", "after")
        with self.assertRaises(Crash):
            self.rotate()
        self.authority.revoke_device("phone", NOW + 1)
        with self.assertRaises(NodeError):
            self.rotate(NOW + 2)  # a revoked device cannot rotate
        record = self.authority._record()
        self.assertEqual(len(record["devices"]["phone"]["keys"]), 1)  # no new key was activated
        self.assertIn("phone", record["revoked_devices"])
        self.assertEqual(count(self.log_dir, "KEY-ROTATE"), 1)
        self.assertTrue(open_log(self.log_dir).verify().ok)

    def test_nodes_still_serve_the_old_key_until_the_cutoff_after_a_recovered_rotation(self):
        self.flaky.arm("KEY-ROTATE", "after")
        with self.assertRaises(Crash):
            self.rotate()
        self.assertEqual(self.rotate(NOW + 1), CUTOFF)
        node = Node.provision(self.root / "n", sig, open_log(self.root / "nlog"), node_id="n1",
                              authority_pk=self.authority.public_key, owners={"f": "maya"},
                              contents={"f": "synthetic"}, freshness=10, skew=2)
        self.assertTrue(node.accept_list(self.authority.issue_list(CUTOFF - 5), CUTOFF - 5))
        old = self.device.make_request("n1", "f", CUTOFF - 6)
        self.assertEqual(old["body"]["key_version"], 1)
        self.assertEqual(respond(node, old, CUTOFF - 6)["decision"], "allow")
        new = self.device.make_request("n1", "f", CUTOFF)
        self.assertEqual(new["body"]["key_version"], 2)
        self.assertTrue(node.accept_list(self.authority.issue_list(CUTOFF), CUTOFF))
        self.assertEqual(respond(node, new, CUTOFF)["decision"], "allow")

    def test_a_superseded_key_cannot_be_republished(self):
        self.assertEqual(self.rotate(), CUTOFF)
        before = self.authority._record()["devices"]["phone"]["keys"]
        old = before[0]
        # Repeating an already accepted publication is answered from state and changes nothing.
        self.assertEqual(self.authority.publish_rotation("phone", 1, old["public_key"], CUTOFF + 50, NOW + 1),
                         old["activate_at"])
        # A different key for an old version, or a skipped version, is refused.
        other = base64.b64encode(sig.sig_keygen()[0]).decode()
        with self.assertRaises(NodeError):
            self.authority.publish_rotation("phone", 1, other, CUTOFF + 50, NOW + 1)
        with self.assertRaises(NodeError):
            self.authority.publish_rotation("phone", 7, other, CUTOFF + 50, NOW + 1)
        self.assertEqual(self.authority._record()["devices"]["phone"]["keys"], before)
        self.assert_clean()

    def test_earlier_duplicates_in_existing_history_are_kept_not_rewritten(self):
        for _ in range(2):  # what the old code could leave behind: random request ids
            self.flaky.real.append(actor="authority", action="rotate", target="phone", decision="allow",
                                   rule="KEY-ROTATE", request_id="legacy-" + str(_),
                                   detail={"owner": "maya", "version": 2})
        before = open_log(self.log_dir).entries()
        self.assertEqual(self.rotate(), CUTOFF)
        after = open_log(self.log_dir).entries()
        self.assertEqual(after[: len(before)], before)  # nothing already written was touched
        self.assertEqual(count(self.log_dir, "KEY-ROTATE"), 3)  # the two legacy entries + one new
        self.assertTrue(open_log(self.log_dir).verify().ok)

    def test_enrolment_is_also_logged_once_when_interrupted(self):
        other = Device.create(self.root / "d2", sig, "tablet", "maya")
        self.flaky.arm("KEY-ENROLL", "after")
        with self.assertRaises(Crash):
            other.enroll(self.authority, 102)
        self.assertNotIn("tablet", self.authority._record()["devices"])
        other.enroll(self.authority, 103)
        self.assertIn("tablet", self.authority._record()["devices"])
        self.assertEqual(count(self.log_dir, "KEY-ENROLL", "tablet"), 1)


if __name__ == "__main__":
    unittest.main()
