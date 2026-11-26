"""Rotation, backup and restore: M-A7, M-A8, PRD section 8 items 9 and 10."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from t4 import rotation
from t4.backup import BackupError, Vault
from t4.node.authority import Authority
from t4.node.common import NodeError
from t4.node.device import Device
from t4.node.state import FileStore
from tests.node.doubles import InsecureTestSigner, MemoryLog
from tests.recovery.crash_child import KILLED

REPO = Path(__file__).resolve().parents[2]
NOW, CUTOFF = 1_000_000.0, 1_000_100.0


class Base(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory(prefix="t4-test-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.signer = InsecureTestSigner()

    def kill_at(self, operation: str, step: str, *args) -> None:
        result = subprocess.run(
            [sys.executable, "-B", "-m", "tests.recovery.crash_child", operation, step,
             *map(str, args)], cwd=REPO, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, KILLED, result.stderr.decode(errors="replace"))


class RotationCrashes(Base):
    def make(self, name: str):
        authority = Authority.create(self.root / f"{name}-a", self.signer, MemoryLog(),
                                     freshness=60.0, skew=2.0)
        device = Device.create(self.root / f"{name}-d", self.signer, "phone", "maya")
        device.enroll(authority, NOW)
        return authority, device

    def test_kill_at_every_step(self):
        for step in ("prepared", "committed", "applied", "published", "acknowledged"):
            with self.subTest(step=step):
                authority, device = self.make(step)
                rotation.revoke_key(device.store, 99, NOW)
                self.kill_at("rotate", step, device.store.directory,
                             authority.store.directory, NOW + 1, CUTOFF)
                ring = rotation.recover(device.store)
                self.assertIsNone(ring["journal"])
                # Rolled back before the commit marker, rolled forward after it.
                self.assertEqual(ring["current"], 1 if step == "prepared" else 2)
                self.assertIn("99", ring["revoked_keys"])
                # The old key still signs before the cutoff.
                self.assertEqual(rotation.signing_key(device.store, NOW + 2)[0], 1)
                if step != "acknowledged":  # Retrying finishes the same rotation.
                    self.assertEqual(device.rotate(authority, NOW + 3, CUTOFF), CUTOFF)
                self.assertEqual(rotation.signing_key(device.store, CUTOFF)[0], 2)
                keys = authority.issue_list(NOW + 4)["body"]["devices"]["phone"]["keys"]
                self.assertEqual([k["version"] for k in keys], [1, 2])
                self.assertEqual(keys[1]["public_key"],
                                 device.info()["keys"]["2"]["public_key"])

    def test_unpublished_key_is_never_used(self):
        _, device = self.make("unpublished")
        rotation.begin_rotation(device.store, self.signer, CUTOFF)
        self.assertEqual(rotation.signing_key(device.store, CUTOFF + 50)[0], 1)

    def test_retry_with_a_new_cutoff_when_the_old_one_is_too_close(self):
        authority, device = self.make("late")
        rotation.begin_rotation(device.store, self.signer, CUTOFF)
        self.assertEqual(device.rotate(authority, CUTOFF - 5, CUTOFF + 200), CUTOFF + 200)

    def test_revoked_active_key_does_not_fall_back(self):
        authority, device = self.make("revoked")
        device.rotate(authority, NOW + 1, CUTOFF)
        rotation.revoke_key(device.store, 2, CUTOFF)
        with self.assertRaises(NodeError):
            rotation.signing_key(device.store, CUTOFF + 1)

    def test_signing_continues_while_rotating(self):
        authority, device = self.make("busy")
        seen: list[int] = []

        def sign_meanwhile(step: str) -> None:
            seen.append(rotation.signing_key(device.store, NOW + 2)[0])

        device.rotate(authority, NOW + 1, CUTOFF, sign_meanwhile)
        self.assertEqual(seen, [1] * 5)

    def test_parallel_rotation_attempts_leave_one_consistent_key(self):
        authority, device = self.make("parallel")
        errors: list[Exception] = []

        def attempt() -> None:
            try:
                device.rotate(authority, NOW + 1, CUTOFF)
            except NodeError:
                pass
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        ring = rotation.recover(device.store)
        self.assertIsNone(ring["journal"])
        keys = authority.issue_list(NOW + 2)["body"]["devices"]["phone"]["keys"]
        self.assertEqual(ring["current"], keys[-1]["version"])
        self.assertEqual(ring["keys"][str(ring["current"])]["pk"], keys[-1]["public_key"])


class Backups(Base):
    def setUp(self) -> None:
        super().setUp()
        self.vault = Vault.create(self.root / "keys", self.root / "backups", "authority")
        self.directory = self.root / "authority"
        self.authority = Authority.create(self.directory, self.signer, MemoryLog(),
                                          vault=self.vault.location())
        for name, owner in (("phone", "maya"), ("laptop", "noor")):
            Device.create(self.root / name, self.signer, name, owner).enroll(self.authority, 1.0)

    def backup(self, now: float) -> Path:
        number = self.vault.backup(self.authority.store, "authority", now)
        return self.root / "backups" / f"backup-{number:08d}.json"

    def listing(self) -> dict:
        return self.authority.issue_list(100.0)["body"]

    def test_restore_after_total_loss(self):
        self.backup(2.0)
        shutil.rmtree(self.directory)
        report = self.vault.restore(self.directory, "authority")
        self.assertFalse(report.fell_back)
        self.assertEqual(report.damaged, ())
        self.assertEqual(set(self.listing()["devices"]), {"phone", "laptop"})

    def test_restore_keeps_newer_revocations_and_grant_removals(self):
        self.authority.grant("noor", "file-a", 1.5)
        self.backup(2.0)
        self.authority.revoke_device("phone", 3.0)
        self.authority.revoke_actor("eve", 3.0)
        self.authority.ungrant("noor", "file-a", 3.0)
        shutil.rmtree(self.directory)  # Only the vault remembers what came later.
        self.vault.restore(self.directory, "authority")
        body = self.listing()
        self.assertEqual(body["revoked_devices"], ["phone"])
        self.assertEqual(body["revoked_actors"], ["eve"])
        self.assertEqual(body["grants"], [])

    def test_damaged_backup_is_reported_and_older_one_used(self):
        damage = {
            "flipped byte": lambda p: p.write_bytes(p.read_bytes().replace(b"noor", b"eve!")),
            "truncated": lambda p: p.write_bytes(p.read_bytes()[:40]),
            "empty": lambda p: p.write_bytes(b""),
            "swapped for an older file": lambda p: shutil.copyfile(
                p.with_name("backup-00000001.json"), p),
        }
        self.backup(2.0)
        for name, break_it in damage.items():
            with self.subTest(name):
                newest = self.backup(3.0)
                break_it(newest)
                report = self.vault.restore(self.root / f"target-{newest.stem}", "authority")
                self.assertTrue(report.fell_back)
                self.assertLess(report.used_id, int(newest.stem.split("-")[1]))
                self.assertTrue(any(line.startswith(newest.name) for line in report.damaged))

    def test_deleted_newest_backup_is_reported(self):
        self.backup(2.0)
        self.backup(3.0).unlink()
        report = self.vault.restore(self.root / "target", "authority")
        self.assertTrue(report.fell_back)
        self.assertIn("backup-00000002.json: missing", report.damaged)

    def test_nothing_verified_means_nothing_restored(self):
        self.backup(2.0).write_bytes(b"{}")
        with self.assertRaises(BackupError) as caught:
            self.vault.restore(self.root / "target", "authority")
        self.assertEqual(len(caught.exception.damaged), 1)
        self.assertFalse((self.root / "target" / "state.json").exists())

    def test_damaged_ledger_stops_restore(self):
        self.backup(2.0)
        (self.root / "keys" / "ledger.json").write_bytes(b"{}")
        with self.assertRaises(BackupError):
            self.vault.restore(self.root / "target", "authority")

    def test_foreign_vault_backup_is_rejected(self):
        other = Vault.create(self.root / "keys2", self.root / "backups2", "authority")
        other.backup(self.authority.store, "authority", 2.0)
        shutil.copyfile(self.root / "backups2" / "backup-00000001.json",
                        self.root / "backups" / "backup-00000001.json")
        with self.assertRaises(BackupError):
            self.vault.restore(self.root / "target", "authority")

    def test_vault_must_be_separate(self):
        with self.assertRaises(BackupError):
            Vault(self.root / "backups" / "keys", self.root / "backups")
        with self.assertRaises(BackupError):
            self.vault.restore(self.root / "keys" / "inside", "authority")

    def test_kill_at_every_restore_step(self):
        self.backup(2.0)
        self.authority.revoke_device("phone", 3.0)
        for step in ("verified", "merged", "key-ready", "state-written"):
            with self.subTest(step):
                target = self.root / f"restore-{step}"
                self.kill_at("restore", step, self.root / "keys", self.root / "backups",
                             target, "authority")
                self.vault.restore(target, "authority")  # Running it again succeeds.
                with FileStore(target).locked() as txn:
                    record = txn.get("authority")
                self.assertIn("phone", record["revoked_devices"])
                self.assertIn("laptop", record["devices"])

    def test_kill_at_every_restore_step_over_existing_state(self):
        self.backup(2.0)
        self.authority.revoke_device("phone", 3.0)
        for step in ("verified", "merged", "key-ready", "state-written"):
            with self.subTest(step):
                self.kill_at("restore", step, self.root / "keys", self.root / "backups",
                             self.directory, "authority")
                self.assertEqual(self.listing()["revoked_devices"], ["phone"])

    def test_kill_during_backup_leaves_a_usable_vault(self):
        for step in ("backup-written", "ledger-updated"):
            with self.subTest(step):
                self.kill_at("backup", step, self.directory, self.root / "keys",
                             self.root / "backups", "authority")
                self.vault.restore(self.root / f"after-{step}", "authority")
        self.assertTrue(self.backup(9.0).exists())

    def test_device_key_backup_keeps_revoked_keys(self):
        vault = Vault.create(self.root / "dk", self.root / "db", "device:phone")
        device = Device(self.root / "phone", self.signer)
        vault.backup(device.store, "keyring", 2.0)
        rotation.revoke_key(device.store, 1, 3.0, vault)
        shutil.rmtree(self.root / "phone")
        vault.restore(self.root / "phone", "keyring")
        with self.assertRaises(NodeError):
            rotation.signing_key(device.store, 4.0)


if __name__ == "__main__":
    unittest.main()
