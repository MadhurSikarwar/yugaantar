"""What the adapter promises when a write fails: no false acknowledgement, no false durability.

Failures are simulated (a write that raises ENOSPC, an audit sink that raises) against the real
store and the real signed audit log in a temporary folder. The host disk is never filled. These
tests prove the ordering and error semantics; they cannot show how a real full volume behaves.
"""
import dataclasses
import errno
import tempfile
import unittest
from pathlib import Path

from t4 import store as store_module
from t4.audit.log import AuditLog, load_signer
from t4.wiring import build_default_dependencies
from team_app import dispatch

try:
    from t4.crypto import sig

    sig.sig_keygen()
    HAVE_SIG = True
except Exception:  # pqcrypto missing: the real audit log needs it
    HAVE_SIG = False

SETUP = {"op": "setup", "owners": {"brief": "maya", "notes": "ravi"},
         "contents": {"brief": "maya body", "notes": "ravi body"}, "disabled": [], "key_material": "k"}


class FlakyAudit:
    """The real audit log, with a one-shot failure on the next append."""

    def __init__(self, real, fail_next=False):
        self.real, self.fail_next = real, fail_next

    def _maybe_fail(self):
        if self.fail_next:
            self.fail_next = False
            raise OSError(errno.ENOSPC, "simulated: no space left on device")

    def append(self, **kwargs):
        self._maybe_fail()
        return self.real.append(**kwargs)

    def append_once(self, **kwargs):  # a full disk fails every kind of write
        self._maybe_fail()
        return self.real.append_once(**kwargs)

    def __getattr__(self, name):
        return getattr(self.real, name)


@unittest.skipUnless(HAVE_SIG, "needs the real ML-DSA wrapper")
class StorageFailures(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="t4-store-fail-")
        self.dir = Path(self._tmp.name) / "state"
        self.deps = build_default_dependencies(self.dir)
        dispatch(SETUP, self.deps)
        self.real_write = store_module.atomic_write_bytes
        self.write_fails = 0

        def write(path, data):
            if self.write_fails:
                self.write_fails -= 1
                raise OSError(errno.ENOSPC, "simulated: no space left on device")
            return self.real_write(path, data)

        store_module.atomic_write_bytes = write

    def tearDown(self):
        store_module.atomic_write_bytes = self.real_write
        self._tmp.cleanup()

    def with_flaky_audit(self, fail_next=True):
        holder = {}

        def factory():
            holder["sink"] = FlakyAudit(self.deps.audit_factory(), fail_next)
            return holder["sink"]

        return dataclasses.replace(self.deps, audit_factory=factory)

    def read(self, actor, asset, request_id, deps=None):
        return dispatch({"op": "read", "actor": actor, "asset": asset, "request_id": request_id},
                        deps or self.deps)

    def audit_entries(self):
        return AuditLog(self.dir / "audit", load_signer(self.dir / "audit")).entries()

    # -- revocation ---------------------------------------------------------------------

    def test_a_revocation_whose_state_write_fails_is_not_acknowledged_and_changes_nothing(self):
        self.write_fails = 1
        with self.assertRaises(OSError):
            dispatch({"op": "revoke", "actor": "maya"}, self.deps)  # no {} reply: it raised
        self.assertEqual(self.read("maya", "brief", "r1"), {"decision": "allow", "body": "maya body"})
        self.assertFalse([e for e in self.audit_entries() if e["action"] == "revoke"])  # no false record

    def test_a_revocation_is_durable_even_when_its_audit_entry_cannot_be_written(self):
        deps = self.with_flaky_audit()
        # In force at once; the reply says the audit entry is still pending (no false "done").
        self.assertEqual(dispatch({"op": "revoke", "actor": "maya"}, deps), {"audit": "pending"})
        self.assertFalse([e for e in self.audit_entries() if e["action"] == "revoke"])  # the gap is real...
        self.assertEqual(self.read("maya", "brief", "r2"), {"decision": "deny"})  # enforced from now on
        # ...and closed by the next request that reaches the log, exactly once.
        self.assertEqual(len([e for e in self.audit_entries() if e["action"] == "revoke"]), 1)
        self.read("maya", "brief", "r3")
        self.assertEqual(len([e for e in self.audit_entries() if e["action"] == "revoke"]), 1)
        self.assertTrue(AuditLog(self.dir / "audit", None).verify().ok)

    def test_storage_coming_back_lets_the_next_revocation_and_its_audit_entry_through(self):
        self.write_fails = 2
        for _ in range(2):
            with self.assertRaises(OSError):
                dispatch({"op": "revoke", "actor": "maya"}, self.deps)
        self.assertEqual(dispatch({"op": "revoke", "actor": "maya"}, self.deps), {})
        self.assertEqual(self.read("maya", "brief", "r3"), {"decision": "deny"})
        self.assertEqual(len([e for e in self.audit_entries() if e["action"] == "revoke"]), 1)
        self.assertTrue(AuditLog(self.dir / "audit", None).verify().ok)

    # -- reads ----------------------------------------------------------------------------

    def test_a_read_whose_audit_entry_cannot_be_written_returns_no_body_and_changes_nothing(self):
        deps = self.with_flaky_audit()
        with self.assertRaises(OSError):
            self.read("maya", "brief", "r4", deps)
        self.assertEqual(dispatch({"op": "audit", "request_id": "r4"}, self.deps), {"error": "unknown_request"})

    def test_a_read_whose_state_write_fails_after_its_audit_entry_returns_no_body(self):
        self.write_fails = 1
        with self.assertRaises(OSError):
            self.read("maya", "brief", "r5")  # the decision was logged, but nothing was released
        self.assertEqual(dispatch({"op": "audit", "request_id": "r5"}, self.deps), {"error": "unknown_request"})
        self.assertEqual(self.read("maya", "brief", "r5"), {"decision": "allow", "body": "maya body"})

    # -- setup ----------------------------------------------------------------------------

    def test_a_setup_that_cannot_save_leaves_the_previous_state_serving(self):
        self.write_fails = 1
        with self.assertRaises(OSError):
            dispatch({**SETUP, "owners": {"brief": "eve"}, "contents": {"brief": "other"}}, self.deps)
        self.assertEqual(self.read("maya", "brief", "r6"), {"decision": "allow", "body": "maya body"})

    # -- partial writes ---------------------------------------------------------------------

    def test_an_interrupted_write_never_leaves_a_half_written_state(self):
        before = (self.dir / "state.json").read_bytes()

        def torn(path, data):
            raise KeyboardInterrupt  # the process is stopped between writing and replacing

        store_module.atomic_write_bytes = torn
        with self.assertRaises(KeyboardInterrupt):
            dispatch({"op": "revoke", "actor": "maya"}, self.deps)
        store_module.atomic_write_bytes = self.real_write
        self.assertEqual((self.dir / "state.json").read_bytes(), before)  # the old state, intact
        self.assertEqual(self.read("maya", "brief", "r7"), {"decision": "allow", "body": "maya body"})


if __name__ == "__main__":
    unittest.main()
