"""Command line smoke test: wiring and arguments, run with test doubles."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import t4.cli
import t4.node.cli
from tests.node.doubles import InsecureTestSigner, MemoryLog


class CommandLine(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory(prefix="t4-cli-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        signer = InsecureTestSigner()
        for module, name, value in ((t4.node.cli, "load_signer", lambda: signer),
                                    (t4.cli, "load_signer", lambda: signer),
                                    (t4.node.cli, "open_log", MemoryLog)):
            patcher = mock.patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, main, *args, code: int = 0) -> dict:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = main([str(a) for a in args])
        self.assertEqual(result, code, err.getvalue())
        return json.loads(out.getvalue()) if out.getvalue() else {}

    def test_full_flow(self):
        node = lambda *a, **k: self.run_cli(t4.node.cli.main, *a, **k)
        ops = lambda *a, **k: self.run_cli(t4.cli.main, *a, **k)
        auth, device, edge = self.root / "a", self.root / "d", self.root / "n"
        listing, request = self.root / "list.json", self.root / "request.json"
        data = self.root / "data.json"
        data.write_text(json.dumps({"owners": {"f": "maya", "g": "noor"},
                                    "contents": {"f": "synthetic f", "g": "synthetic g"}}))
        keys, backups = self.root / "vk", self.root / "vb"
        node("init-authority", "--authority", auth, "--vault-keys", keys,
             "--vault-backups", backups)
        node("init-device", "--device", device, "--device-id", "phone", "--owner", "maya")
        node("provision-node", "--node", edge, "--authority", auth, "--node-id", "n1",
             "--data", data)
        node("enroll", "--authority", auth, "--device", device)
        owners = self.root / "owners.json"
        node("owners", "--node", edge, "--out", owners)
        self.assertEqual(json.loads(owners.read_text()), {"n1": {"f": "maya", "g": "noor"}})
        node("grant", "--authority", auth, "--actor", "maya", "--asset", "g",
             "--approval-id", "change-1")
        node("issue-list", "--authority", auth, "--out", listing)
        self.assertTrue(node("deliver", "--node", edge, "--list", listing)["accepted"])
        node("request", "--device", device, "--node-id", "n1", "--asset", "g", "--out", request)
        self.assertEqual(node("handle", "--node", edge, "--request", request),
                         {"decision": "allow", "body": "synthetic g"})
        self.assertIn("activate_at", ops("rotate", "--authority", auth, "--device", device))
        node("ungrant", "--authority", auth, "--actor", "maya", "--asset", "g")
        self.assertEqual(ops("backup", "--vault-keys", keys, "--vault-backups", backups,
                             "--source", auth, "--kind", "authority"), {"backup_id": 1})
        node("revoke-device", "--authority", auth, "--device-id", "phone")
        (auth / "state.json").write_bytes(b"damaged")
        report = ops("restore", "--vault-keys", keys, "--vault-backups", backups,
                     "--target", auth, "--kind", "authority")
        self.assertEqual(report["restored_from"], 1)
        node("issue-list", "--authority", auth, "--out", listing)
        self.assertEqual(json.loads(listing.read_text())["body"]["revoked_devices"], ["phone"])
        node("revoke-actor", "--authority", auth, "--actor", "maya")

    def test_state_inside_the_repository_is_refused(self):
        self.run_cli(t4.node.cli.main, "init-device", "--device",
                     t4.node.cli.REPO / "state-here", "--device-id", "x", "--owner", "y", code=1)
        self.assertFalse((t4.node.cli.REPO / "state-here").exists())


if __name__ == "__main__":
    unittest.main()
