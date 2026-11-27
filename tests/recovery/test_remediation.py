"""Regression tests for backup, node-state and enrolment fixes made after the independent review.

They use the real ML-DSA-65 wrapper, the real signed audit log and temporary folders only.
"""
import base64
import tempfile
import unittest
from pathlib import Path

from t4.backup import Vault
from t4.node import request as node_request
from t4.node.authority import Authority
from t4.node.common import NodeError, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond
from t4.node.state import MAX_WRITE_BYTES, FileStore

try:
    from t4.crypto import sig

    sig.sig_keygen()
    HAVE_SIG = True
except Exception:  # pqcrypto missing: these tests need the real wrapper
    HAVE_SIG = False


def build(root: Path, vault=None):
    authority = Authority.create(root / "authority", sig, open_log(root / "authority-log"),
                                 freshness=10, skew=2, vault=vault)
    device = Device.create(root / "device", sig, "device-a", "alice")
    device.enroll(authority, 100)
    node = Node.provision(root / "node", sig, open_log(root / "node-log"), node_id="n",
                          authority_pk=authority.public_key, owners={"a": "alice"},
                          contents={"a": "synthetic"}, freshness=10, skew=2)
    assert node.accept_list(authority.issue_list(100), 100)
    return authority, device, node


@unittest.skipUnless(HAVE_SIG, "needs the real ML-DSA wrapper")
class BackupRemediation(unittest.TestCase):
    def test_restore_keeps_a_removed_grant_removed_without_an_attached_vault(self):
        """An authority created WITHOUT a vault never records removals in the ledger, but the
        readable current state still shows the grant is gone: restore must not bring it back."""
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            root = Path(folder)
            authority, _device, node = build(root)  # no vault attached
            vault = Vault.create(root / "vault-keys", root / "backups", "authority")
            authority.grant("bob", "a", 101)
            vault.backup(authority.store, "authority", 102)
            authority.ungrant("bob", "a", 103)
            vault.restore(root / "authority", "authority")
            self.assertEqual(Authority(root / "authority", sig, open_log(root / "authority-log"))
                             ._record()["grants"], {})

    def test_a_grant_added_after_the_backup_is_lost_but_nothing_is_resurrected(self):
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            root = Path(folder)
            authority, _device, _node = build(root)
            vault = Vault.create(root / "vault-keys", root / "backups", "authority")
            vault.backup(authority.store, "authority", 102)
            authority.grant("carol", "a", 103)  # added after the backup: documented loss
            vault.restore(root / "authority", "authority")
            restored = Authority(root / "authority", sig, open_log(root / "authority-log"))._record()
            self.assertEqual(restored["grants"], {})

    def test_backup_numbers_keep_working_past_eight_digits(self):
        """The file-name pattern used to stop at 8 digits, hiding every later backup."""
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            root = Path(folder)
            authority, _device, _node = build(root)
            vault = Vault.create(root / "vault-keys", root / "backups", "authority")
            with vault._ledger() as (key, ledger):
                ledger["last_backup_id"] = 99_999_998
                vault._save_ledger(key, ledger)
            self.assertEqual(vault.backup(authority.store, "authority", 102), 99_999_999)
            self.assertEqual(vault.backup(authority.store, "authority", 103), 100_000_000)
            report = vault.restore(root / "authority", "authority")
            self.assertEqual((report.used_id, report.newest_expected_id), (100_000_000, 100_000_000))
            self.assertFalse(report.fell_back)


@unittest.skipUnless(HAVE_SIG, "needs the real ML-DSA wrapper")
class NodeRemediation(unittest.TestCase):
    def test_a_public_key_of_the_wrong_size_is_not_enrolled(self):
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            root = Path(folder)
            authority, _device, _node = build(root)
            short = base64.b64encode(b"\x01" * 32).decode()
            with self.assertRaises(NodeError):
                authority.enroll("device-x", "alice", short, 101)

    def test_replay_nonces_are_capped_and_the_cap_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            root = Path(folder)
            _authority, device, node = build(root)
            original = node_request.MAX_NONCES
            node_request.MAX_NONCES = 2
            try:
                first = respond(node, device.make_request("n", "a", 101), 101)
                second = respond(node, device.make_request("n", "a", 101), 101)
                third = respond(node, device.make_request("n", "a", 101), 101)
            finally:
                node_request.MAX_NONCES = original
            self.assertEqual(first["decision"], "allow")
            self.assertEqual(second["decision"], "allow")
            self.assertEqual(third, {"decision": "deny"})  # at the cap: refused, nothing forgotten

    def test_wrong_directory_is_reported_not_crashed_on(self):
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            root = Path(folder)
            authority, device, _node = build(root)
            wrong = Authority(root / "device", sig, open_log(root / "authority-log"))  # a device dir
            with self.assertRaises(NodeError):
                wrong.revoke_device("device-a", 101)

    def test_a_state_that_would_exceed_the_size_limit_is_refused_and_the_old_one_kept(self):
        with tempfile.TemporaryDirectory(prefix="t4-rem-") as folder:
            store = FileStore.create(Path(folder) / "s", {"r": {"v": 1}})
            with self.assertRaises(NodeError):
                with store.locked() as txn:
                    txn.put("r", {"v": "x" * (MAX_WRITE_BYTES + 1)})
            with store.locked() as txn:
                self.assertEqual(txn.get("r"), {"v": 1})


if __name__ == "__main__":
    unittest.main()
