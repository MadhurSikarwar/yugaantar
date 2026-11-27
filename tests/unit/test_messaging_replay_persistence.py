"""Restart-safe replay protection for demo messages (FileReplayGuard)."""
import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("pqcrypto")

from demo import messaging as m  # noqa: E402
from t4.crypto import kem, sig  # noqa: E402

NOW = 1_800_000_000.0


@pytest.fixture(scope="module")
def keys():
    spk, ssk = sig.sig_keygen()
    kpk, ksk = kem.keygen()
    return spk, ssk, kpk, ksk


def send(keys, seq, text="hello"):
    _, ssk, kpk, _ = keys
    return m.seal(sender="alice", sender_sig_secret=ssk, recipient="bob", recipient_kem_public=kpk,
                  plaintext=text, seq=seq, now=NOW)


def receive(keys, msg, guard):
    spk, _, _, ksk = keys
    return m.open_message(msg, recipient="bob", recipient_kem_secret=ksk, expected_sender="alice",
                          sender_sig_public=spk, guard=guard, now=NOW)


def test_duplicate_is_refused_after_a_restart(tmp_path, keys):
    path = tmp_path / "replay.json"
    msg = send(keys, 1)
    assert receive(keys, msg, m.FileReplayGuard(path)) == "hello"
    with pytest.raises(m.MessagingError):
        receive(keys, msg, m.FileReplayGuard(path))  # a new guard object = a restarted receiver
    assert json.loads(path.read_text()) == {"alice": 1}


def test_failed_decryption_does_not_advance_the_counter(tmp_path, keys):
    path = tmp_path / "replay.json"
    msg = send(keys, 5)
    broken = dict(msg, body=msg["body"][:-2] + ("00" if msg["body"][-2:] != "00" else "11"))
    with pytest.raises(m.MessagingError):
        receive(keys, broken, m.FileReplayGuard(path))
    assert not path.exists() or json.loads(path.read_text()) == {}
    assert receive(keys, msg, m.FileReplayGuard(path)) == "hello"


def test_interrupted_persistence_does_not_deliver_and_can_be_retried(tmp_path, keys, monkeypatch):
    from t4.node import state as node_state

    path = tmp_path / "replay.json"
    msg = send(keys, 7)

    def fail(*_a, **_k):
        raise OSError("simulated crash during the write")

    monkeypatch.setattr(node_state, "atomic_write", fail)
    with pytest.raises(OSError):
        receive(keys, msg, m.FileReplayGuard(path))  # never reported as delivered
    monkeypatch.undo()
    assert receive(keys, msg, m.FileReplayGuard(path)) == "hello"  # the retry is accepted once
    with pytest.raises(m.MessagingError):
        receive(keys, msg, m.FileReplayGuard(path))


def _deliver(path: str, msg: dict, keys) -> str:
    try:
        return receive(keys, msg, m.FileReplayGuard(Path(path)))
    except m.MessagingError:
        return "refused"


def test_concurrent_duplicates_are_delivered_exactly_once(tmp_path, keys):
    path = str(tmp_path / "replay.json")
    msg = send(keys, 3)
    with ProcessPoolExecutor(6) as pool:
        results = list(pool.map(_deliver, [path] * 6, [msg] * 6, [keys] * 6))
    assert results.count("hello") == 1 and results.count("refused") == 5
