"""Demo-layer sessions on top of ``demo/messaging.py``: forward secrecy, delivery and resumption.

NOT part of the adapter (``t4/`` never imports this); it needs ``requirements-demo.txt``.

Forward secrecy (one-time prekeys)
    The recipient makes a batch of one-time ML-KEM-768 key pairs ("prekeys") and publishes their
    public halves in a bundle signed with its ML-DSA-65 identity key. The sender verifies the
    bundle and encrypts each message to a different, unused prekey. When the recipient has opened
    a message it deletes that prekey's secret half for good. Someone who later steals everything
    the recipient holds (identity key and saved state included) cannot decrypt messages that were
    already delivered: the secrets they need no longer exist. Messages not yet delivered are not
    covered (their prekey secrets still exist), and a sender that runs out of prekeys must fetch a
    new bundle. There is no ratchet: each message uses its own prekey.

Delivery under loss and reordering
    The receiver accepts each sequence number once, in any order (a set of delivered numbers, not
    a strictly increasing counter), reports gaps (``missing``), and answers with a signed
    acknowledgement. The sender keeps every unacknowledged message and ``resend`` re-seals it
    (fresh prekey, fresh time) until it is acknowledged. A duplicate is refused.

Session resumption
    Both sides keep their whole session in one file, written atomically after every change.
    ``Sender.load`` and ``Receiver.load`` continue after a restart: numbering, the outbox, the
    delivered set and the remaining prekeys all survive. The file is not encrypted (it holds
    prekey secrets and unsent plaintext), like the rest of the demo's local state.
"""
from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from demo import messaging as m
from t4.crypto import kem, sig
from t4.node.state import atomic_write

BUNDLE_TYPE = "prekey-bundle-v1"
ACK_TYPE = "delivery-ack-v1"


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _save(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, _canonical(state))


def _load(path: Path) -> dict:
    try:
        return json.loads(Path(path).read_bytes())
    except (OSError, ValueError):
        raise m.MessagingError("session state is unreadable") from None


class _DeliveredGuard:
    """Replay guard for ``messaging.open_message``: each number once, in any order (persisted by the receiver)."""

    def __init__(self, delivered: set[int]) -> None:
        self.delivered = delivered

    def check(self, sender: str, seq: int) -> None:
        if seq in self.delivered:
            raise m.MessagingError("duplicate message")

    def commit(self, sender: str, seq: int) -> None:
        self.check(sender, seq)
        self.delivered.add(seq)


class Receiver:
    """One recipient's side of a session with one sender."""

    def __init__(self, path: Path, state: dict) -> None:
        self.path, self.state = Path(path), state

    @classmethod
    def create(cls, path: str | Path, *, me: str, peer: str, peer_sig_public: bytes,
               identity_secret: bytes, prekeys: int = 16) -> "Receiver":
        receiver = cls(Path(path), {"me": me, "peer": peer, "peer_sig_public": peer_sig_public.hex(),
                                    "identity_secret": identity_secret.hex(), "prekeys": {}, "delivered": []})
        receiver.add_prekeys(prekeys)
        return receiver

    @classmethod
    def load(cls, path: str | Path) -> "Receiver":
        return cls(Path(path), _load(Path(path)))

    def add_prekeys(self, count: int) -> None:
        for _ in range(count):
            public_key, secret_key = kem.keygen()
            self.state["prekeys"][secrets.token_hex(8)] = {"public": public_key.hex(), "secret": secret_key.hex()}
        _save(self.path, self.state)

    def bundle(self, now: float | None = None) -> dict:
        """The public halves of the unused prekeys, signed with the identity key."""
        body = {"type": BUNDLE_TYPE, "owner": self.state["me"], "issued_at": int(now or time.time()),
                "prekeys": {pid: key["public"] for pid, key in sorted(self.state["prekeys"].items())}}
        signature = sig.sign(bytes.fromhex(self.state["identity_secret"]), _canonical(body))
        return {"body": body, "sig": signature.hex()}

    def receive(self, envelope: dict, now: float | None = None) -> str:
        """Verify, decrypt, delete the prekey secret, remember the number. Raises ``MessagingError``."""
        prekey = self.state["prekeys"].get(envelope.get("prekey") if isinstance(envelope, dict) else None)
        if prekey is None:
            raise m.MessagingError("unknown or already used prekey")
        delivered = set(self.state["delivered"])
        guard = _DeliveredGuard(delivered)
        text = m.open_message(envelope.get("message"), recipient=self.state["me"],
                              recipient_kem_secret=bytes.fromhex(prekey["secret"]),
                              expected_sender=self.state["peer"],
                              sender_sig_public=bytes.fromhex(self.state["peer_sig_public"]),
                              guard=guard, now=now)
        # Forward secrecy: the secret half is gone before the text is handed over.
        del self.state["prekeys"][envelope["prekey"]]
        self.state["delivered"] = sorted(delivered)
        _save(self.path, self.state)
        return text

    def missing(self) -> list[int]:
        """Numbers below the highest delivered one that have not arrived (lost or still in flight)."""
        delivered = set(self.state["delivered"])
        return [n for n in range(1, max(delivered, default=0)) if n not in delivered]

    def ack(self, now: float | None = None) -> dict:
        body = {"type": ACK_TYPE, "from": self.state["me"], "to": self.state["peer"],
                "delivered": sorted(self.state["delivered"]), "at": int(now or time.time())}
        return {"body": body, "sig": sig.sign(bytes.fromhex(self.state["identity_secret"]), _canonical(body)).hex()}


class Sender:
    """One sender's side: numbering, the outbox of unacknowledged messages, the peer's prekeys."""

    def __init__(self, path: Path, state: dict) -> None:
        self.path, self.state = Path(path), state

    @classmethod
    def create(cls, path: str | Path, *, me: str, peer: str, identity_secret: bytes,
               peer_sig_public: bytes) -> "Sender":
        sender = cls(Path(path), {"me": me, "peer": peer, "identity_secret": identity_secret.hex(),
                                  "peer_sig_public": peer_sig_public.hex(), "next_seq": 1,
                                  "outbox": {}, "prekeys": {}, "used_prekeys": []})
        _save(sender.path, sender.state)
        return sender

    @classmethod
    def load(cls, path: str | Path) -> "Sender":
        return cls(Path(path), _load(Path(path)))

    def accept_bundle(self, bundle: dict) -> int:
        """Verify the recipient's signed bundle and keep the prekeys not used before. Returns how many."""
        try:
            body, signature = bundle["body"], bytes.fromhex(bundle["sig"])
            if body["type"] != BUNDLE_TYPE or body["owner"] != self.state["peer"]:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise m.MessagingError("malformed prekey bundle") from None
        if not sig.verify(bytes.fromhex(self.state["peer_sig_public"]), _canonical(body), signature):
            raise m.MessagingError("prekey bundle signature check failed")
        fresh = {pid: pk for pid, pk in body["prekeys"].items() if pid not in self.state["used_prekeys"]}
        self.state["prekeys"].update(fresh)
        _save(self.path, self.state)
        return len(fresh)

    def _seal(self, seq: int, text: str, now: float | None) -> dict:
        if not self.state["prekeys"]:
            raise m.MessagingError("no unused prekeys: fetch a new bundle")
        prekey_id = sorted(self.state["prekeys"])[0]
        public_key = bytes.fromhex(self.state["prekeys"].pop(prekey_id))
        self.state["used_prekeys"].append(prekey_id)
        message = m.seal(sender=self.state["me"], sender_sig_secret=bytes.fromhex(self.state["identity_secret"]),
                         recipient=self.state["peer"], recipient_kem_public=public_key, plaintext=text,
                         seq=seq, now=now)
        return {"prekey": prekey_id, "message": message}

    def send(self, text: str, now: float | None = None) -> dict:
        seq = self.state["next_seq"]
        envelope = self._seal(seq, text, now)
        self.state["next_seq"] = seq + 1
        self.state["outbox"][str(seq)] = text  # kept until acknowledged
        _save(self.path, self.state)
        return envelope

    def handle_ack(self, ack: dict) -> list[int]:
        """Verify a signed acknowledgement and drop what it confirms. Returns the confirmed numbers."""
        try:
            body, signature = ack["body"], bytes.fromhex(ack["sig"])
            if body["type"] != ACK_TYPE or body["from"] != self.state["peer"] or body["to"] != self.state["me"]:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise m.MessagingError("malformed acknowledgement") from None
        if not sig.verify(bytes.fromhex(self.state["peer_sig_public"]), _canonical(body), signature):
            raise m.MessagingError("acknowledgement signature check failed")
        confirmed = [n for n in body["delivered"] if str(n) in self.state["outbox"]]
        for n in confirmed:
            del self.state["outbox"][str(n)]
        _save(self.path, self.state)
        return confirmed

    def unacknowledged(self) -> list[int]:
        return sorted(int(n) for n in self.state["outbox"])

    def resend(self, now: float | None = None) -> list[dict]:
        """Re-seal every unacknowledged message (same number, fresh prekey and time)."""
        envelopes = [self._seal(int(n), self.state["outbox"][n], now) for n in sorted(self.state["outbox"], key=int)]
        _save(self.path, self.state)
        return envelopes
