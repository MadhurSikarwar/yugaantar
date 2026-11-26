"""Node layer: M-N1, M-N2, M-N3, M-N5 and PRD section 8 item 6."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from t4.node.authority import Authority
from t4.node.common import NodeError
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import handle_request, respond, sign_request
from t4.node.state import IntegrityError
from tests.node.doubles import InsecureTestSigner, MemoryLog

NOW = 1_000_000.0
T, S, W = 60.0, 2.0, 30.0
OWNERS = {"file-a": "maya", "file-b": "noor"}
CONTENTS = {"file-a": "synthetic body a", "file-b": "synthetic body b"}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory(prefix="t4-test-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.signer = InsecureTestSigner()
        self.authority_log = MemoryLog()
        self.authority = Authority.create(self.root / "authority", self.signer,
                                          self.authority_log, freshness=T, skew=S)
        self.maya = self.device("maya-phone", "maya")
        self.noor = self.device("noor-phone", "noor")
        self.node_log = MemoryLog()
        self.node = self.make_node("node-1", self.node_log)
        self.sync(NOW)

    def device(self, device_id: str, owner: str, enroll: bool = True) -> Device:
        device = Device.create(self.root / device_id, self.signer, device_id, owner)
        if enroll:
            device.enroll(self.authority, NOW)
        return device

    def make_node(self, name: str, log: MemoryLog) -> Node:
        return Node.provision(self.root / name, self.signer, log, node_id=name,
                              authority_pk=self.authority.public_key, owners=OWNERS,
                              contents=CONTENTS, freshness=T, skew=S, window=W)

    def sync(self, now: float, node: Node | None = None) -> None:
        self.assertTrue((node or self.node).accept_list(self.authority.issue_list(now), now))

    def ask(self, device: Device, asset: str, now: float, **extra):
        return handle_request(self.node, device.make_request("node-1", asset, now, **extra), now)

    def assert_rule(self, decision, rule: str) -> None:
        self.assertEqual(decision.rule, rule)
        self.assertEqual(decision.allow, rule.startswith("NODE-ALLOW-"))


class Requests(Base):
    def test_owner_reads_and_receives_body(self):
        request = self.maya.make_request("node-1", "file-a", NOW)
        self.assertEqual(respond(self.node, request, NOW),
                         {"decision": "allow", "body": "synthetic body a"})

    def test_deny_response_has_nothing_else(self):
        request = self.maya.make_request("node-1", "file-b", NOW)
        self.assertEqual(respond(self.node, request, NOW), {"decision": "deny"})

    def test_replay_is_rejected_and_survives_restart(self):
        request = self.maya.make_request("node-1", "file-a", NOW)
        self.assert_rule(handle_request(self.node, request, NOW), "NODE-ALLOW-OWNER")
        restarted = Node(self.root / "node-1", self.signer, self.node_log)
        self.assert_rule(handle_request(restarted, request, NOW + 1), "NODE-REPLAY")

    def test_request_for_another_node(self):
        request = self.maya.make_request("node-2", "file-a", NOW)
        self.assert_rule(handle_request(self.node, request, NOW), "NODE-WRONG-NODE")

    def test_edited_field_breaks_signature(self):
        request = self.maya.make_request("node-1", "file-a", NOW)
        request["body"]["asset"] = "file-b"
        self.assert_rule(handle_request(self.node, request, NOW), "NODE-BAD-SIGNATURE")

    def test_device_cannot_act_for_another_owner(self):
        self.assert_rule(self.ask(self.noor, "file-a", NOW, actor="maya"), "NODE-OWNER-MISMATCH")

    def test_unenrolled_device(self):
        stranger = self.device("stranger", "maya", enroll=False)
        self.assert_rule(self.ask(stranger, "file-a", NOW), "NODE-UNKNOWN-DEVICE")

    def test_time_window(self):
        early = self.maya.make_request("node-1", "file-a", NOW + S + 1)
        self.assert_rule(handle_request(self.node, early, NOW), "NODE-EXPIRED")
        request = self.maya.make_request("node-1", "file-a", NOW)
        self.assert_rule(handle_request(self.node, request, NOW + W + 1), "NODE-EXPIRED")

    def test_clock_set_backwards(self):
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 20), "NODE-ALLOW-OWNER")
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 5), "NODE-CLOCK-ROLLBACK")

    def test_malformed_input_denies_without_crashing(self):
        good = self.maya.make_request("node-1", "file-a", NOW)
        bad = [None, [], "x", {}, {"body": {}, "signature": ""},
               {**good, "extra": 1}, {**good, "signature": "!!!"}]
        for name, value in (("issued_at", float("nan")), ("issued_at", True),
                            ("key_version", "1"), ("asset", ["file-a"]),
                            ("actor", "x" * 5000), ("issued_at", 10 ** 400)):
            changed = copy.deepcopy(good)
            changed["body"][name] = value
            bad.append(changed)
        for request in bad:
            with self.subTest(request=str(request)[:80]):
                self.assert_rule(handle_request(self.node, request, NOW),
                                 "NODE-MALFORMED-REQUEST")

    def test_hostile_text_stays_one_value_in_the_log(self):
        asset = 'x\n{"actor":"noor","decision":"allow"} \x00'
        before = len(self.node_log.entries)
        self.assert_rule(self.ask(self.maya, asset, NOW), "NODE-NOT-PERMITTED")
        self.assertEqual(len(self.node_log.entries), before + 1)
        self.assertEqual(self.node_log.entries[-1]["target"], asset)
        self.assertEqual(self.node_log.entries[-1]["actor"], "maya")

    def test_log_failure_denies(self):
        self.node_log.fail = True
        request = self.maya.make_request("node-1", "file-a", NOW)
        self.assertEqual(respond(self.node, request, NOW), {"decision": "deny"})

    def test_tampered_node_state_denies(self):
        path = self.root / "node-1" / "state.json"
        path.write_bytes(path.read_bytes().replace(b"synthetic body a", b"synthetic body z"))
        self.assert_rule(self.ask(self.maya, "file-a", NOW), "NODE-INTERNAL-ERROR")
        with self.assertRaises(IntegrityError):
            with self.node.store.locked():
                pass


class RevocationAndLists(Base):
    def test_lost_device_story_with_reenrolment(self):
        self.assert_rule(self.ask(self.maya, "file-a", NOW), "NODE-ALLOW-OWNER")
        self.authority.revoke_device("maya-phone", NOW + 1)
        self.sync(NOW + 2)
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 3), "NODE-DEVICE-REVOKED")
        self.assert_rule(self.ask(self.noor, "file-b", NOW + 3), "NODE-ALLOW-OWNER")
        replacement = Device.create(self.root / "maya-new", self.signer, "maya-new", "maya")
        replacement.enroll(self.authority, NOW + 4)
        self.sync(NOW + 5)
        self.assert_rule(self.ask(replacement, "file-a", NOW + 6), "NODE-ALLOW-OWNER")
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 7), "NODE-DEVICE-REVOKED")

    def test_revoked_ids_and_keys_cannot_be_enrolled_again(self):
        self.authority.revoke_device("maya-phone", NOW)
        key = self.maya.info()["keys"]["1"]["public_key"]
        for device_id in ("maya-phone", "maya-again"):
            with self.assertRaises(NodeError):
                self.authority.enroll(device_id, "maya", key, NOW)

    def test_revoked_actor(self):
        self.authority.revoke_actor("maya", NOW + 1)
        self.sync(NOW + 2)
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 3), "NODE-ACTOR-REVOKED")

    def test_stale_node_denies_everyone(self):
        self.assert_rule(self.ask(self.noor, "file-b", NOW + T), "NODE-ALLOW-OWNER")
        self.assert_rule(self.ask(self.noor, "file-b", NOW + T + 0.5), "NODE-STALE-LIST")

    def test_age_counts_from_issue_not_delivery(self):
        signed = self.authority.issue_list(NOW + 1)
        late = self.make_node("node-2", MemoryLog())
        self.assertFalse(late.accept_list(signed, NOW + 1 + T))
        self.assertTrue(late.accept_list(signed, NOW + T))
        request = self.maya.make_request("node-2", "file-a", NOW + T + 2)
        self.assertEqual(handle_request(late, request, NOW + T + 2).rule, "NODE-STALE-LIST")

    def test_forged_older_repeated_and_future_lists(self):
        older = self.authority.issue_list(NOW + 1)
        self.sync(NOW + 2)
        self.assertFalse(self.node.accept_list(older, NOW + 3))
        self.assertEqual(self.node_log.rules()[-1], "NODE-LIST-NOT-NEWER")
        forged = copy.deepcopy(self.authority.issue_list(NOW + 3))
        forged["body"]["revoked_devices"] = ["noor-phone"]
        self.assertFalse(self.node.accept_list(forged, NOW + 3))
        self.assertIn("NODE-LIST-BAD-SIGNATURE", self.node_log.rules())
        future = self.authority.issue_list(NOW + 100)
        self.assertFalse(self.node.accept_list(future, NOW + 3))
        for junk in (None, {}, [], {"body": 1, "signature": 2}):
            self.assertFalse(self.node.accept_list(junk, NOW + 3))

    def test_revocation_seen_by_node_is_never_forgotten(self):
        """A newer list from a rolled-back authority omits the revocation."""
        with self.authority.store.locked() as txn:
            snapshot = txn.get("authority")
        self.authority.revoke_device("maya-phone", NOW + 1)
        self.sync(NOW + 2)
        with self.authority.store.locked() as txn:
            txn.put("authority", snapshot)
        self.sync(NOW + 3)
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 4), "NODE-DEVICE-REVOKED")

    def test_revocation_time_never_precedes_an_issued_list(self):
        self.authority.issue_list(NOW + 10)
        self.assertEqual(self.authority.revoke_device("maya-phone", NOW + 5), NOW + 10)

    def test_revocation_persists_when_log_fails(self):
        self.authority_log.fail = True
        with self.assertRaises(NodeError):
            self.authority.revoke_device("maya-phone", NOW + 1)
        self.assertIn("maya-phone",
                      self.authority.issue_list(NOW + 2)["body"]["revoked_devices"])

    def test_enrolment_fails_when_log_fails(self):
        self.authority_log.fail = True
        with self.assertRaises(OSError):
            self.device("tablet", "maya")
        self.assertNotIn("tablet", self.authority.issue_list(NOW + 1)["body"]["devices"])


class GrantsAndLogging(Base):
    def test_grant_and_removal(self):
        self.assert_rule(self.ask(self.noor, "file-a", NOW), "NODE-NOT-PERMITTED")
        self.authority.grant("noor", "file-a", NOW + 1, approval_id="change-1")
        self.sync(NOW + 2)
        self.assert_rule(self.ask(self.noor, "file-a", NOW + 3), "NODE-ALLOW-GRANT")
        self.authority.ungrant("noor", "file-a", NOW + 4)
        self.sync(NOW + 5)
        self.assert_rule(self.ask(self.noor, "file-a", NOW + 6), "NODE-NOT-PERMITTED")
        grant = next(e for e in self.authority_log.entries if e["rule"] == "PERM-GRANT")
        self.assertEqual(grant["detail"]["approval_id"], "change-1")
        self.assertEqual(grant["detail"]["subject"], "noor")

    def test_every_key_event_is_logged(self):
        self.authority.revoke_device("maya-phone", NOW)
        self.authority.revoke_actor("noor", NOW)
        self.assertEqual(self.authority_log.rules(),
                         ["KEY-ENROLL", "KEY-ENROLL", "KEY-REVOKE-DEVICE", "KEY-REVOKE-ACTOR"])

    def test_decisions_and_alerts_are_logged(self):
        self.authority.revoke_device("maya-phone", NOW + 1)
        self.sync(NOW + 2)
        decision = self.ask(self.maya, "file-a", NOW + 3)
        event, alert = self.node_log.entries[-2:]
        self.assertEqual((event["decision"], event["rule"]), ("deny", "NODE-DEVICE-REVOKED"))
        self.assertEqual(event["detail"]["device_id"], "maya-phone")
        self.assertTrue(event["detail"]["signature_verified"])
        self.assertEqual(alert["decision"], "alert")
        self.assertEqual(alert["detail"]["trigger_seq"], event["seq"])
        self.assertEqual(alert["detail"]["trigger_request_id"], decision.request_id)
        self.assertTrue(alert["detail"]["explanation"])

    def test_no_key_material_in_logs(self):
        self.ask(self.maya, "file-a", NOW)
        with self.maya.store.locked() as txn:
            secret = txn.get("keyring")["keys"]["1"]["sk"]
        text = repr(self.node_log.entries) + repr(self.authority_log.entries)
        self.assertNotIn(secret, text)


class RotationAcrossNodes(Base):
    def test_old_key_before_cutoff_new_key_from_cutoff(self):
        old_info = self.maya.info()
        cutoff = NOW + T + S + 10
        old_sk = None
        with self.maya.store.locked() as txn:
            from t4.node.common import b64d

            old_sk = b64d(txn.get("keyring")["keys"]["1"]["sk"])
        self.assertEqual(self.maya.rotate(self.authority, NOW + 1, cutoff), cutoff)
        self.sync(cutoff - 20)
        self.assert_rule(self.ask(self.maya, "file-a", cutoff - 5), "NODE-ALLOW-OWNER")
        self.assert_rule(self.ask(self.maya, "file-a", cutoff), "NODE-ALLOW-OWNER")
        stale_key = sign_request(old_sk, {
            "node_id": "node-1", "device_id": old_info["device_id"], "key_version": 1,
            "actor": "maya", "action": "read", "asset": "file-a", "nonce": "after-cutoff",
            "issued_at": cutoff + 1}, signer=self.signer)
        self.assert_rule(handle_request(self.node, stale_key, cutoff + 1), "NODE-KEY-INACTIVE")

    def test_cutoff_must_be_more_than_t_plus_s_ahead(self):
        with self.assertRaises(NodeError):
            self.maya.rotate(self.authority, NOW, NOW + T + S)
        # The device keeps working with the old key and can retry with a later C.
        self.assert_rule(self.ask(self.maya, "file-a", NOW + 1), "NODE-ALLOW-OWNER")
        later = NOW + T + S + 30
        self.assertEqual(self.maya.rotate(self.authority, NOW + 2, later), later)

    def test_revoked_device_cannot_rotate(self):
        self.authority.revoke_device("maya-phone", NOW)
        with self.assertRaises(NodeError):
            self.maya.rotate(self.authority, NOW + 1, NOW + 200)


if __name__ == "__main__":
    unittest.main()
