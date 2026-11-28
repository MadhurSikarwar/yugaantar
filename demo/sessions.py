"""Demo-layer sessions on top of ``demo/messaging.py``: forward secrecy, delivery and resumption.

NOT part of the adapter (the adapter never imports this); it needs ``requirements-demo.txt``.
It is a prototype built from vetted primitives (ML-KEM-768, ML-DSA-65, HKDF and
ChaCha20-Poly1305 via ``demo/messaging.py``), not an established messaging protocol: no ratchet,
no post-compromise recovery, and no exactly-once guarantee for side effects outside it.

Session identity
    The receiver creates the session with a random 128-bit ID. The ID is inside the signed
    prekey bundle, inside both identities of every message (so it is covered by the message
    signature, the header used as associated data and the key derivation) and inside every
    acknowledgement. A message, bundle or ACK from another session between the same two people
    is refused.

Forward secrecy (one-time prekeys)
    Each message is encrypted to its own one-time ML-KEM prekey from the receiver's signed bundle.
    Once the receiver has authenticated a message (first delivery or a duplicate), it deletes that
    prekey's secret half. Stealing everything the receiver holds afterwards does not decrypt
    messages it already received. Messages still in flight are not covered (their prekeys exist).

Delivery
    Every message has an immutable identity: its sequence number plus the SHA-256 of the exact
    envelope. The receiver delivers each sequence number once, in any order, and its signed ACK
    lists (number, envelope digest) pairs; the sender only clears an outbox entry whose own
    envelope digest is acknowledged. A duplicate (for example a resend after a lost ACK) is
    authenticated and answered with an ACK, never delivered twice. Resends are bounded
    (``max_attempts``) with a doubling back-off; a sender without prekeys reports ``needs_bundle``
    instead of failing silently, and the receiver tops its prekeys up when they run low.

Resumption and concurrency
    Each side keeps its session in one file, written atomically. Every change happens under an
    exclusive file lock with the state re-read inside the lock, so two processes on the same file
    cannot both deliver one message. ``load`` resumes after a restart. The file is not encrypted
    (it holds prekey secrets and unsent plaintext); a crash before a delivery is saved means the
    message is delivered again later (at least once), never lost.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from contextlib import contextmanager
from pathlib import Path

from demo import messaging as m
from t4.crypto import kem, sig
from t4.node.state import atomic_write, file_lock

BUNDLE_TYPE = "prekey-bundle-v2"
ACK_TYPE = "delivery-ack-v2"
LOW_PREKEYS = 4


class Duplicate(m.MessagingError):
    """An authentic message that was already delivered (answer with ``ack``)."""


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(envelope: dict) -> str:
    """The immutable identity of one sent envelope."""
    return hashlib.sha256(_canonical(envelope)).hexdigest()


def _who(name: str, session: str) -> str:
    return f"{name}#{session}"


class _Side:
    """Shared storage: one JSON file, changed only under its lock, re-read inside the lock."""

    def __init__(self, path: Path, state: dict) -> None:
        self.path, self.state = Path(path), state

    @contextmanager
    def _transaction(self):
        with file_lock(self.path.with_name(self.path.name + ".lock")):
            self.state = self._read(self.path)
            yield self.state
            self._write()

    @staticmethod
    def _read(path: Path) -> dict:
        try:
            return json.loads(Path(path).read_bytes())
        except (OSError, ValueError):
            raise m.MessagingError("session state is unreadable") from None

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.path, _canonical(self.state))

    @property
    def session(self) -> str:
        return self.state["session"]


class Receiver(_Side):
    @classmethod
    def create(cls, path: str | Path, *, me: str, peer: str, peer_sig_public: bytes,
               identity_secret: bytes, prekeys: int = 16) -> "Receiver":
        receiver = cls(Path(path), {"session": secrets.token_hex(16), "me": me, "peer": peer,
                                    "peer_sig_public": peer_sig_public.hex(), "identity_secret": identity_secret.hex(),
                                    "prekeys": {}, "delivered": {}})
        receiver._write()
        receiver.add_prekeys(prekeys)
        return receiver

    @classmethod
    def load(cls, path: str | Path) -> "Receiver":
        return cls(Path(path), cls._read(Path(path)))

    def add_prekeys(self, count: int) -> None:
        with self._transaction() as state:
            self._add(state, count)

    @staticmethod
    def _add(state: dict, count: int) -> None:
        for _ in range(count):
            public_key, secret_key = kem.keygen()
            state["prekeys"][secrets.token_hex(8)] = {"public": public_key.hex(), "secret": secret_key.hex()}

    def bundle(self, now: float | None = None) -> dict:
        """The unused prekeys' public halves, signed with the identity key and bound to the session."""
        with self._transaction() as state:
            if len(state["prekeys"]) < LOW_PREKEYS:  # replenish before publishing
                self._add(state, LOW_PREKEYS * 2)
            body = {"type": BUNDLE_TYPE, "session": state["session"], "owner": state["me"],
                    "issued_at": int(now or time.time()),
                    "prekeys": {pid: key["public"] for pid, key in sorted(state["prekeys"].items())}}
        return {"body": body, "sig": sig.sign(bytes.fromhex(self.state["identity_secret"]), _canonical(body)).hex()}

    def receive(self, envelope: dict, now: float | None = None) -> str:
        """Deliver once. Raises ``Duplicate`` for an authentic repeat, ``MessagingError`` otherwise."""
        with self._transaction() as state:
            try:
                prekey_id = envelope["prekey"]
                session = envelope["session"]
                message = envelope["message"]
            except (TypeError, KeyError):
                raise m.MessagingError("malformed envelope") from None
            if session != state["session"]:
                raise m.MessagingError("message is for another session")
            prekey = state["prekeys"].get(prekey_id)
            if prekey is None:
                raise m.MessagingError("unknown or already used prekey")

            class _Accept:  # numbering is decided below, after authentication
                def check(self, sender, seq):
                    return None

                def commit(self, sender, seq):
                    return None

            text = m.open_message(message, recipient=_who(state["me"], session),
                                  recipient_kem_secret=bytes.fromhex(prekey["secret"]),
                                  expected_sender=_who(state["peer"], session),
                                  sender_sig_public=bytes.fromhex(state["peer_sig_public"]), guard=_Accept(), now=now)
            seq = str(json.loads(message["header"])["seq"])
            # Authentic: the prekey is used up either way (forward secrecy, no prekey left behind).
            del state["prekeys"][prekey_id]
            if len(state["prekeys"]) < LOW_PREKEYS:
                self._add(state, LOW_PREKEYS * 2)
            seen = state["delivered"].setdefault(seq, [])
            first = not seen
            seen.append(digest(envelope))
        if not first:
            raise Duplicate("already delivered: send the acknowledgement again")
        return text

    def handle(self, envelope: dict, now: float | None = None) -> tuple[str | None, dict | None]:
        """Transport step: deliver, then always answer with an ACK (also for a duplicate)."""
        try:
            text = self.receive(envelope, now)
        except Duplicate:
            text = None
        except m.MessagingError:
            return None, None
        return text, self.ack(now)

    def missing(self) -> list[int]:
        delivered = {int(n) for n in self.state["delivered"]}
        return [n for n in range(1, max(delivered, default=0)) if n not in delivered]

    def ack(self, now: float | None = None) -> dict:
        state = self._read(self.path)
        body = {"type": ACK_TYPE, "session": state["session"], "from": state["me"], "to": state["peer"],
                "delivered": sorted([int(n), d] for n, ds in state["delivered"].items() for d in ds),
                "at": int(now or time.time())}
        return {"body": body, "sig": sig.sign(bytes.fromhex(state["identity_secret"]), _canonical(body)).hex()}


class Sender(_Side):
    @classmethod
    def create(cls, path: str | Path, *, me: str, peer: str, identity_secret: bytes, peer_sig_public: bytes,
               max_attempts: int = 5, retry_after: float = 0.0) -> "Sender":
        sender = cls(Path(path), {"session": None, "me": me, "peer": peer, "identity_secret": identity_secret.hex(),
                                  "peer_sig_public": peer_sig_public.hex(), "next_seq": 1, "outbox": {},
                                  "prekeys": {}, "used_prekeys": [], "max_attempts": max_attempts,
                                  "retry_after": retry_after, "failed": []})
        sender._write()
        return sender

    @classmethod
    def load(cls, path: str | Path) -> "Sender":
        return cls(Path(path), cls._read(Path(path)))

    def accept_bundle(self, bundle: dict) -> int:
        """Verify the receiver's signed bundle (same session once set). Returns the new prekeys kept."""
        try:
            body, signature = bundle["body"], bytes.fromhex(bundle["sig"])
            if body["type"] != BUNDLE_TYPE or not isinstance(body["session"], str) or not isinstance(body["prekeys"], dict):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise m.MessagingError("malformed prekey bundle") from None
        with self._transaction() as state:
            if body["owner"] != state["peer"]:
                raise m.MessagingError("prekey bundle is from someone else")
            if not sig.verify(bytes.fromhex(state["peer_sig_public"]), _canonical(body), signature):
                raise m.MessagingError("prekey bundle signature check failed")
            if state["session"] not in (None, body["session"]):
                raise m.MessagingError("prekey bundle is for another session")
            state["session"] = body["session"]
            fresh = {pid: pk for pid, pk in body["prekeys"].items()
                     if pid not in state["used_prekeys"] and pid not in state["prekeys"]}
            state["prekeys"].update(fresh)
        return len(fresh)

    def _seal(self, state: dict, seq: int, text: str, now: float | None) -> dict:
        if state["session"] is None:
            raise m.MessagingError("no session yet: accept the receiver's bundle first")
        if not state["prekeys"]:
            raise m.MessagingError("no unused prekeys: fetch a new bundle")
        prekey_id = sorted(state["prekeys"])[0]
        public_key = bytes.fromhex(state["prekeys"].pop(prekey_id))
        state["used_prekeys"].append(prekey_id)
        session = state["session"]
        message = m.seal(sender=_who(state["me"], session), sender_sig_secret=bytes.fromhex(state["identity_secret"]),
                         recipient=_who(state["peer"], session), recipient_kem_public=public_key, plaintext=text,
                         seq=seq, now=now)
        return {"session": session, "prekey": prekey_id, "message": message}

    def send(self, text: str, now: float | None = None) -> dict:
        with self._transaction() as state:
            seq = state["next_seq"]
            envelope = self._seal(state, seq, text, now)
            state["next_seq"] = seq + 1
            state["outbox"][str(seq)] = {"text": text, "digests": [digest(envelope)], "attempts": 1,
                                         "last_sent": float(now or time.time())}
        return envelope

    def handle_ack(self, ack: dict) -> list[int]:
        """Verify a signed ACK and clear only the messages whose own envelope it names."""
        try:
            body, signature = ack["body"], bytes.fromhex(ack["sig"])
            pairs = body["delivered"]
            if (body["type"] != ACK_TYPE or not isinstance(pairs, list)
                    or not all(isinstance(p, list) and len(p) == 2 and type(p[0]) is int and isinstance(p[1], str)
                               for p in pairs)):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise m.MessagingError("malformed acknowledgement") from None
        with self._transaction() as state:
            if body["from"] != state["peer"] or body["to"] != state["me"] or body["session"] != state["session"]:
                raise m.MessagingError("acknowledgement is not for this session")
            if not sig.verify(bytes.fromhex(state["peer_sig_public"]), _canonical(body), signature):
                raise m.MessagingError("acknowledgement signature check failed")
            confirmed = sorted({seq for seq, d in pairs
                                if str(seq) in state["outbox"] and d in state["outbox"][str(seq)]["digests"]})
            for seq in confirmed:
                del state["outbox"][str(seq)]
        return confirmed

    def unacknowledged(self) -> list[int]:
        return sorted(int(n) for n in self._read(self.path)["outbox"])

    def resend(self, now: float | None = None) -> list[dict]:
        """Re-seal the messages that are due (bounded attempts, doubling back-off). Never raises for
        missing prekeys: those messages wait, and ``status()`` reports ``needs_bundle``."""
        clock = float(now or time.time())
        envelopes = []
        with self._transaction() as state:
            for key in sorted(state["outbox"], key=int):
                item = state["outbox"][key]
                if item["attempts"] >= state["max_attempts"]:
                    if int(key) not in state["failed"]:
                        state["failed"].append(int(key))
                    continue
                wait = state["retry_after"] * (2 ** (item["attempts"] - 1))
                if clock - item["last_sent"] < wait or not state["prekeys"]:
                    continue
                envelope = self._seal(state, int(key), item["text"], now)
                item["digests"].append(digest(envelope))
                item["attempts"] += 1
                item["last_sent"] = clock
                envelopes.append(envelope)
        return envelopes

    def status(self) -> dict:
        state = self._read(self.path)
        return {"session": state["session"], "unacknowledged": sorted(int(n) for n in state["outbox"]),
                "prekeys_left": len(state["prekeys"]), "needs_bundle": bool(state["outbox"]) and not state["prekeys"],
                "failed": sorted(state["failed"])}
