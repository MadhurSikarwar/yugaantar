"""A device: its own ML-DSA keys, rotation, and signed requests.

The private key never leaves the device directory (and its backups). After the
user loses a device, the authority revokes that device ID and the owner enrolls
a new device with a new ID and new keys.
"""
from __future__ import annotations

import secrets
from pathlib import Path

from t4 import rotation
from t4.node.authority import Authority
from t4.node.common import NodeError, Signer, check_text, check_time
from t4.node.request import sign_request
from t4.node.state import FileStore


class Device:
    def __init__(self, directory: str | Path, signer: Signer) -> None:
        self.store = FileStore(directory)
        self.signer = signer

    @classmethod
    def create(cls, directory: str | Path, signer: Signer, device_id: str,
               owner: str) -> "Device":
        check_text(device_id)
        check_text(owner)
        pk, sk = signer.sig_keygen()
        FileStore.create(directory, {rotation.RECORD: rotation.new_keyring(
            device_id, owner, pk, sk)})
        return cls(directory, signer)

    def info(self) -> dict:
        """Public facts only. No private keys."""
        ring = rotation.recover(self.store)
        return {"device_id": ring["device_id"], "owner": ring["owner"],
                "current": ring["current"],
                "keys": {version: {"public_key": key["pk"], "activate_at": key["activate_at"],
                                   "published": key["published"]}
                         for version, key in ring["keys"].items()}}

    def enroll(self, authority: Authority, now: float) -> None:
        info = self.info()
        authority.enroll(info["device_id"], info["owner"],
                         info["keys"]["1"]["public_key"], now)

    def rotate(self, authority: Authority, now: float, activate_at: float,
               fault: rotation.Fault = rotation.no_fault) -> float:
        """Rotate, or finish a rotation that was interrupted. Returns C."""
        info = self.info()
        version = info["current"]
        pending = not info["keys"][str(version)]["published"]
        if not pending:
            version = rotation.begin_rotation(self.store, self.signer, activate_at, fault,
                                              now=now)
        info = self.info()
        key = info["keys"][str(version)]
        try:
            accepted = authority.publish_rotation(
                info["device_id"], version, key["public_key"], key["activate_at"], now)
        except NodeError:
            if not pending or key["activate_at"] == activate_at:
                raise
            # The old C is too close now and the authority never accepted it.
            rotation.reschedule(self.store, version, activate_at)
            accepted = authority.publish_rotation(
                info["device_id"], version, key["public_key"], activate_at, now)
        fault("published")
        rotation.mark_published(self.store, version, accepted)
        fault("acknowledged")
        return accepted

    def make_request(self, node_id: str, asset: str, now: float, *, actor: str | None = None,
                     action: str = "read") -> dict:
        check_time(now)
        version, sk = rotation.signing_key(self.store, now)
        info = self.info()
        return sign_request(sk, {
            "node_id": node_id, "device_id": info["device_id"], "key_version": version,
            "actor": info["owner"] if actor is None else actor, "action": action,
            "asset": asset, "nonce": secrets.token_hex(16), "issued_at": now,
        }, signer=self.signer)
