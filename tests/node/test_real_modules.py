"""The same tests with the REAL modules.

* Signature tests: rerun the node and recovery suites with real ML-DSA-65.
  Skipped until ``t4.crypto.sig`` and ``pqcrypto`` are present. They still use
  the in-memory test log.
* Full story: also needs the real ``t4.audit.log``.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from tests.node import test_node
from tests.recovery import test_recovery


def present(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except ImportError:
        return False


HAVE_SIG = present("t4.crypto.sig") and present("pqcrypto")
NEEDS_SIG = "real ML-DSA wrapper is not available"


def real_signer():
    from t4.node.common import load_signer

    return load_signer()


def with_real_signer(case: type) -> type:
    subclass = type(f"RealSig{case.__name__}", (case,),
                    {"signer_factory": staticmethod(real_signer), "__module__": __name__})
    return unittest.skipUnless(HAVE_SIG, NEEDS_SIG)(subclass)


RealSigRequests = with_real_signer(test_node.Requests)
RealSigRevocationAndLists = with_real_signer(test_node.RevocationAndLists)
RealSigGrantsAndLogging = with_real_signer(test_node.GrantsAndLogging)
RealSigRotationAcrossNodes = with_real_signer(test_node.RotationAcrossNodes)
RealSigRotationCrashes = with_real_signer(test_recovery.RotationCrashes)
RealSigBackups = with_real_signer(test_recovery.Backups)


@unittest.skipUnless(HAVE_SIG and present("t4.audit.log"),
                     "real crypto and audit log are not both available")
class RealModules(unittest.TestCase):
    def test_lost_device_story(self):
        from t4.node.authority import Authority
        from t4.node.common import open_log
        from t4.node.device import Device
        from t4.node.freshness import Node
        from t4.node.request import respond

        signer = real_signer()
        with tempfile.TemporaryDirectory(prefix="t4-real-") as folder:
            root = Path(folder)
            authority = Authority.create(root / "a", signer, open_log(root / "a-log"))
            device = Device.create(root / "d", signer, "phone", "maya")
            device.enroll(authority, 1000.0)
            node = Node.provision(root / "n", signer, open_log(root / "n-log"), node_id="n1",
                                  authority_pk=authority.public_key, owners={"f": "maya"},
                                  contents={"f": "synthetic"})
            self.assertTrue(node.accept_list(authority.issue_list(1000.0), 1000.0))
            self.assertEqual(respond(node, device.make_request("n1", "f", 1001.0), 1001.0),
                             {"decision": "allow", "body": "synthetic"})
            authority.revoke_device("phone", 1002.0)
            self.assertTrue(node.accept_list(authority.issue_list(1003.0), 1003.0))
            self.assertEqual(respond(node, device.make_request("n1", "f", 1004.0), 1004.0),
                             {"decision": "deny"})

            for name in ("a-log", "n-log"):
                report = open_log(root / name).verify()
                self.assertTrue(report.ok, report.errors)
                self.assertEqual(report.covered_seq, report.entries)  # all signed
            node_log = open_log(root / "n-log")
            self.assertIn("NODE-DEVICE-REVOKED", [e["rule"] for e in node_log.alerts()])
            self.assertEqual([e["rule"] for e in open_log(root / "a-log").entries()],
                             ["KEY-ENROLL", "KEY-REVOKE-DEVICE"])

            path = root / "n-log" / "audit.jsonl"
            original = path.read_bytes()
            # An edited OLD entry is found by a full verify, not by each append.
            changed = original.replace(b'"decision":"deny"', b'"decision":"allow"', 1)
            self.assertNotEqual(changed, original)
            path.write_bytes(changed)
            self.assertFalse(node_log.verify().ok)

            # An edited NEWEST entry stops the node from releasing anything.
            other = Device.create(root / "d2", signer, "tablet", "maya")
            other.enroll(authority, 1005.0)
            path.write_bytes(original)
            self.assertTrue(node.accept_list(authority.issue_list(1006.0), 1006.0))
            lines = path.read_bytes().splitlines(keepends=True)
            lines[-1] = lines[-1].replace(b'"decision":"accept"', b'"decision":"reject"')
            path.write_bytes(b"".join(lines))
            self.assertEqual(respond(node, other.make_request("n1", "f", 1007.0), 1007.0),
                             {"decision": "deny"})


if __name__ == "__main__":
    unittest.main()
