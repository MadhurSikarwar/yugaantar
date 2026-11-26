"""Restoring the authority must not bring back access that was taken away.

1. A key that was replaced by a rotation stays replaced after a restore.
2. Revocations survive a restore even if the vault was created separately from the authority.

Real ML-DSA signatures and the real signed log; time is passed in explicitly.
"""
import json
import shutil

import pytest

from t4.backup import BackupError, Vault
from t4.node.authority import Authority
from t4.node.common import NodeError, load_signer, open_log
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond
from t4.node.state import FileStore

T, S = 60.0, 2.0


class World:
    def __init__(self, root, *, bound=True):
        self.root = root
        self.signer = load_signer()
        self.vault = Vault.create(root / "vault-keys", root / "backups", "authority")
        self.authority = Authority.create(
            root / "authority", self.signer, open_log(root / "authority" / "log"),
            freshness=T, skew=S, vault=self.vault.location() if bound else None)
        self.device = Device.create(root / "device", self.signer, "d1", "maya")
        self.device.enroll(self.authority, 1000.0)

    def reopen(self):
        self.authority = Authority(self.root / "authority", self.signer,
                                   open_log(self.root / "authority" / "log"))

    def backup(self, now, vault=None):
        return (vault or self.vault).backup(self.authority.store, "authority", now)

    def lose_authority(self):
        shutil.rmtree(self.root / "authority")

    def restore(self, vault=None):
        report = (vault or self.vault).restore(self.root / "authority", "authority")
        self.reopen()
        return report

    def node(self, name="n1"):
        """A node that has never seen any earlier list."""
        directory = self.root / name
        return Node.provision(directory, self.signer, open_log(directory / "log"), node_id=name,
                              authority_pk=self.authority.public_key,
                              owners={"f": "maya"}, contents={"f": "secret"},
                              freshness=T, skew=S)

    def ask(self, node, device, now):
        assert node.accept_list(self.authority.issue_list(now), now)
        return respond(node, device.make_request("n1", "f", now), now)["decision"]


def copy_of(world, name):
    shutil.copytree(world.root / "device", world.root / name)
    return Device(world.root / name, world.signer)


@pytest.mark.parametrize("lost", [True, False], ids=["authority-lost", "authority-readable"])
def test_replaced_key_stays_replaced_after_restore(tmp_path, lost):
    world = World(tmp_path)
    old = copy_of(world, "old-key-copy")
    world.backup(1001.0)
    cutoff = world.device.rotate(world.authority, 1002.0, 1002.0 + T + S + 10)
    if lost:
        world.lose_authority()
    world.restore()
    node = world.node()
    assert world.ask(node, old, cutoff) == "deny"
    assert world.ask(node, world.device, cutoff + 1) == "allow"


def test_every_rotation_after_the_backup_is_kept(tmp_path):
    world = World(tmp_path)
    world.backup(1001.0)
    first = world.device.rotate(world.authority, 1002.0, 1100.0)
    middle = copy_of(world, "version-2-copy")
    second = world.device.rotate(world.authority, first + 1, first + 100)
    world.lose_authority()
    world.restore()
    node = world.node()
    assert world.ask(node, middle, second) == "deny"
    assert world.ask(node, world.device, second + 1) == "allow"


def test_rotation_made_before_linking_survives_restore_of_an_older_backup(tmp_path):
    """The vault is linked at the first backup; what happened before must be in its ledger."""
    world = World(tmp_path, bound=False)
    old = copy_of(world, "old-key-copy")
    cutoff = world.device.rotate(world.authority, 1002.0, 1100.0)
    world.backup(cutoff + 1)
    world.lose_authority()
    world.restore()
    node = world.node()
    assert world.ask(node, old, cutoff + 2) == "deny"
    assert world.ask(node, world.device, cutoff + 3) == "allow"


def test_rotation_is_refused_if_the_vault_cannot_record_it(tmp_path):
    world = World(tmp_path)
    old = copy_of(world, "old-key-copy")
    (tmp_path / "vault-keys" / "ledger.json").write_bytes(b"{}")
    with pytest.raises(NodeError):
        world.device.rotate(world.authority, 1002.0, 1100.0)
    node = world.node()
    assert world.ask(node, old, 1101.0) == "allow"  # nothing was published: version 1 is current


@pytest.mark.parametrize("what", ["device", "actor"])
def test_revocation_survives_restore_with_a_separately_created_vault(tmp_path, what):
    world = World(tmp_path, bound=False)
    world.backup(1001.0)
    world.reopen()
    if what == "device":
        world.authority.revoke_device("d1", 1002.0)
    else:
        world.authority.revoke_actor("maya", 1002.0)
    world.lose_authority()
    world.restore()
    assert world.ask(world.node(), world.device, 1003.0) == "deny"


def test_revocation_made_before_the_first_backup_survives_damaged_newer_backups(tmp_path):
    world = World(tmp_path, bound=False)
    world.authority.revoke_device("d1", 1001.0)
    world.backup(1002.0)
    world.lose_authority()
    world.restore()
    assert world.ask(world.node(), world.device, 1003.0) == "deny"


def test_a_second_vault_is_refused(tmp_path):
    world = World(tmp_path)
    other = Vault.create(tmp_path / "other-keys", tmp_path / "other-backups", "authority")
    with pytest.raises(BackupError, match="another vault"):
        world.backup(1001.0, other)
    assert not list((tmp_path / "other-backups").iterdir())


def _strip_link(world):
    """Rewrite the newest backup as one made by the earlier code: authority not linked."""
    from t4.backup import BACKUP_LABEL, _seal, _unseal

    key = (world.root / "vault-keys" / "vault.key").read_bytes()
    path = sorted((world.root / "backups").glob("backup-*.json"))[-1]
    body = _unseal(key, BACKUP_LABEL, path.read_bytes())
    body["record"]["vault"] = None
    path.write_bytes(_seal(key, BACKUP_LABEL, body))


def test_unlinked_old_backup_is_not_restored_into_a_lost_authority(tmp_path):
    """Its vault never recorded revocations, so restoring it blind could undo one."""
    world = World(tmp_path)
    world.backup(1001.0)
    _strip_link(world)
    world.lose_authority()
    with pytest.raises(BackupError, match="not linked"):
        world.vault.restore(tmp_path / "authority", "authority")
    assert not (tmp_path / "authority" / "state.json").exists()


def test_unlinked_old_backup_restores_over_a_readable_authority(tmp_path):
    world = World(tmp_path)
    world.backup(1001.0)
    _strip_link(world)
    world.authority.revoke_device("d1", 1002.0)
    world.restore()
    assert world.ask(world.node(), world.device, 1003.0) == "deny"


def test_restore_links_the_authority_to_the_vault_it_came_from(tmp_path):
    world = World(tmp_path)
    world.backup(1001.0)
    world.lose_authority()
    world.restore()
    with FileStore(tmp_path / "authority").locked() as txn:
        assert txn.get("authority")["vault"] == world.vault.location()


def test_ledger_written_by_earlier_code_still_works(tmp_path):
    from t4.backup import LEDGER_LABEL, _seal, _unseal

    world = World(tmp_path)
    key = (tmp_path / "vault-keys" / "vault.key").read_bytes()
    path = tmp_path / "vault-keys" / "ledger.json"
    ledger = _unseal(key, LEDGER_LABEL, path.read_bytes())
    ledger.pop("rotations", None)
    path.write_bytes(_seal(key, LEDGER_LABEL, ledger))
    world.backup(1001.0)
    cutoff = world.device.rotate(world.authority, 1002.0, 1100.0)
    world.lose_authority()
    world.restore()
    assert world.ask(world.node(), world.device, cutoff + 1) == "allow"
    versions = list(json.loads(path.read_bytes())["body"]["rotations"].values())
    assert [sorted(v) for v in versions] == [["1", "2"]]


def test_a_reused_device_id_does_not_inherit_a_lost_devices_keys(tmp_path):
    """An enrollment made after the backup is lost; its ID may later name a different device."""
    world = World(tmp_path)
    world.backup(1001.0)
    first = Device.create(tmp_path / "first", world.signer, "d2", "maya")
    first.enroll(world.authority, 1002.0)
    first.rotate(world.authority, 1003.0, 1100.0)
    world.lose_authority()
    world.restore()  # d2 was never in the backup
    second = Device.create(tmp_path / "second", world.signer, "d2", "maya")
    second.enroll(world.authority, 1200.0)
    world.backup(1201.0)
    world.lose_authority()
    world.restore()
    node = world.node()
    assert world.ask(node, first, 1300.0) == "deny"
    assert world.ask(node, second, 1301.0) == "allow"
