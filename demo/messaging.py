"""Demo-layer messaging: ML-KEM-768 key agreement, ML-DSA-65 signature, vetted AEAD, replay protection.

NOT part of the adapter. ``track4_service.py`` and everything under ``t4/`` stay pqcrypto + stdlib only.
This module needs the vetted ``cryptography`` package (see ``requirements-demo.txt``) for the cipher
and the key derivation. We do not implement a cipher: if the package is missing, sealing and opening
raise ``MessagingUnavailable`` and nothing is sent in the clear.

Construction, per message
    1. ``encapsulate`` to the recipient's ML-KEM public key gives a fresh shared secret.
    2. HKDF-SHA256 (cryptography) turns it into a 256-bit key bound to both identities.
    3. ChaCha20-Poly1305 (cryptography) encrypts the text. Associated data is the header
       (sender, recipient, sequence number, time), so none of it can be changed.
    4. The sender signs header + KEM ciphertext + nonce + ciphertext with ML-DSA-65.
The receiver verifies the signature, then the recipient and time window, then the sequence number
(strictly increasing per sender, remembered by ``ReplayGuard``), and only then decrypts.

What it does NOT give
    * Not forward secret: anyone who later obtains the recipient's long-term ML-KEM secret key can
      decrypt every message sent to it. A ratchet would be needed and is not built.
    * ``ReplayGuard`` is in memory: a restarted receiver forgets its counters. ``FileReplayGuard``
      keeps them in a file and commits each one atomically before a message is reported delivered,
      so duplicates are refused across restarts and between concurrent receivers.
    * No delivery guarantees, no session resumption, no key distribution: public keys are passed in.
    * Side-channel behaviour of the native pqcrypto code is not established.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from t4.crypto import kem, sig

VERSION = 1
MAX_AGE_S = 300.0
MAX_SKEW_S = 5.0
MAX_PLAINTEXT = 64 * 1024
_INFO = b"yugaantar-demo-message-v1"


class MessagingError(Exception):
    """A message was refused. The reason is deliberately generic."""


class MessagingUnavailable(MessagingError):
    """The vetted cipher library is not installed."""


def _aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise MessagingUnavailable("the 'cryptography' package is required for message encryption") from None
    return ChaCha20Poly1305, HKDF, hashes


def _key(shared_secret: bytes, sender: str, recipient: str) -> bytes:
    _, hkdf, hashes = _aead()
    # Length-prefixed, so no pair of identities can produce the same bytes as another pair.
    parts = [sender.encode("utf-8"), recipient.encode("utf-8")]
    info = _INFO + b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    return hkdf(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def _header(sender: str, recipient: str, seq: int, sent_at: int) -> bytes:
    return json.dumps({"v": VERSION, "from": sender, "to": recipient, "seq": seq, "at": sent_at},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _identity(value: object) -> str:
    """A sender or recipient name: non-empty text that encodes as UTF-8 (no lone surrogates)."""
    if not isinstance(value, str) or not 0 < len(value) <= 256:
        raise MessagingError("invalid identity")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise MessagingError("invalid identity") from None
    return value


def _signed_part(header: bytes, kem_ct: bytes, nonce: bytes, body: bytes) -> bytes:
    return b"|".join([header, kem_ct, nonce, body])


@dataclass
class ReplayGuard:
    """Highest accepted sequence number per sender. Strictly increasing: a repeat or an old one is refused."""
    seen: dict[str, int] = field(default_factory=dict)

    def check(self, sender: str, seq: int) -> None:
        if seq <= self.seen.get(sender, 0):
            raise MessagingError("replayed or out-of-order message")

    def accept(self, sender: str, seq: int) -> None:
        self.seen[sender] = seq

    def commit(self, sender: str, seq: int) -> None:
        """Check and accept in one step (what ``open_message`` calls after decryption)."""
        self.check(sender, seq)
        self.accept(sender, seq)

    def snapshot(self) -> dict[str, int]:
        return dict(self.seen)


class FileReplayGuard:
    """Restart-safe replay state: the receiver's counters live in one file.

    ``commit`` takes an exclusive lock, re-reads the file, re-checks the sequence number and writes
    the new counter atomically (temp file, fsync, replace, fsync of the folder) BEFORE it returns,
    so ``open_message`` only reports a delivery once it is durable. Two receivers racing on the
    same message (two processes, or a retry after a restart) cannot both deliver it: the second
    sees the first's counter under the lock. A crash before the write leaves the old counter (the
    message was not delivered and may be retried); a crash after it leaves the new one. The file is
    not authenticated: whoever can write it can roll the counters back (same trust boundary as the
    rest of the local state).
    """

    def __init__(self, path) -> None:
        from pathlib import Path

        self.path = Path(path)

    def _load(self) -> dict[str, int]:
        try:
            data = json.loads(self.path.read_bytes())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            raise MessagingError("replay state is unreadable") from None
        if not isinstance(data, dict) or not all(isinstance(k, str) and type(v) is int for k, v in data.items()):
            raise MessagingError("replay state is unreadable")
        return data

    def check(self, sender: str, seq: int) -> None:
        if seq <= self._load().get(sender, 0):
            raise MessagingError("replayed or out-of-order message")

    def commit(self, sender: str, seq: int) -> None:
        from t4.node.state import atomic_write, file_lock

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(self.path.with_name(self.path.name + ".lock")):
            seen = self._load()
            if seq <= seen.get(sender, 0):
                raise MessagingError("replayed or out-of-order message")
            seen[sender] = seq
            atomic_write(self.path, json.dumps(seen, sort_keys=True).encode("ascii"))

    def snapshot(self) -> dict[str, int]:
        return dict(self._load())


def seal(*, sender: str, sender_sig_secret: bytes, recipient: str, recipient_kem_public: bytes,
         plaintext: str, seq: int, now: float | None = None) -> dict:
    """Return a JSON-safe message. ``seq`` must be greater than every earlier ``seq`` to this recipient."""
    chacha, _, _ = _aead()
    sender, recipient = _identity(sender), _identity(recipient)
    if not isinstance(plaintext, str) or len(plaintext.encode("utf-8", "replace")) > MAX_PLAINTEXT:
        raise MessagingError("invalid message text")
    if type(seq) is not int or seq < 1:
        raise MessagingError("invalid sequence number")
    try:
        data = plaintext.encode("utf-8")
    except UnicodeEncodeError:
        raise MessagingError("invalid message text") from None
    sent_at = int(time.time() if now is None else now)
    header = _header(sender, recipient, seq, sent_at)
    kem_ct, shared = kem.encapsulate(recipient_kem_public)
    nonce = os.urandom(12)
    body = chacha(_key(shared, sender, recipient)).encrypt(nonce, data, header)
    signature = sig.sign(sender_sig_secret, _signed_part(header, kem_ct, nonce, body))
    return {"header": header.decode("ascii"), "kem_ct": kem_ct.hex(), "nonce": nonce.hex(),
            "body": body.hex(), "sig": signature.hex()}


def open_message(message: dict, *, recipient: str, recipient_kem_secret: bytes, expected_sender: str,
                 sender_sig_public: bytes, guard: ReplayGuard, now: float | None = None) -> str:
    """Verify then decrypt. Raises ``MessagingError`` (generic text) on any failure; the guard moves only on success.

    ``expected_sender`` is who the caller believes sent this and whose public key is
    ``sender_sig_public``. A message whose header names anyone else is refused, so a holder of one
    accepted signing key cannot speak as, or advance the replay counter of, another sender.
    """
    chacha, _, _ = _aead()
    expected_sender, recipient = _identity(expected_sender), _identity(recipient)
    try:
        header_bytes = message["header"].encode("ascii")
        kem_ct, nonce = bytes.fromhex(message["kem_ct"]), bytes.fromhex(message["nonce"])
        body, signature = bytes.fromhex(message["body"]), bytes.fromhex(message["sig"])
        header = json.loads(header_bytes)
        sender, to, seq, sent_at = header["from"], header["to"], header["seq"], header["at"]
        if header["v"] != VERSION or header_bytes != _header(sender, to, seq, sent_at):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeError):
        raise MessagingError("malformed message") from None
    if not sig.verify(sender_sig_public, _signed_part(header_bytes, kem_ct, nonce, body), signature):
        raise MessagingError("signature check failed")
    if sender != expected_sender:
        raise MessagingError("message is not from the expected sender")
    if to != recipient:
        raise MessagingError("message is for someone else")
    clock = time.time() if now is None else now
    if type(sent_at) is not int or not -MAX_SKEW_S <= clock - sent_at <= MAX_AGE_S:
        raise MessagingError("message outside the time window")
    if type(seq) is not int or seq < 1:
        raise MessagingError("malformed message")
    guard.check(sender, seq)
    try:
        shared = kem.decapsulate(recipient_kem_secret, kem_ct)
        text = chacha(_key(shared, sender, recipient)).decrypt(nonce, body, header_bytes).decode("utf-8")
    except Exception:
        raise MessagingError("decryption failed") from None
    guard.commit(sender, seq)  # durable before the text is handed over (FileReplayGuard)
    return text
