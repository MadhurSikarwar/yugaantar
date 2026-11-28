"""Demo-layer sessions: forward secrecy, loss and reordering, resumption (demo/sessions.py)."""
from __future__ import annotations

import copy

import pytest

pytest.importorskip("cryptography")

from demo import messaging as m  # noqa: E402
from demo.sessions import Receiver, Sender  # noqa: E402
from t4.crypto import sig  # noqa: E402


@pytest.fixture()
def pair(tmp_path):
    maya_pk, maya_sk = sig.sig_keygen()
    noor_pk, noor_sk = sig.sig_keygen()
    receiver = Receiver.create(tmp_path / "noor.json", me="noor", peer="maya", peer_sig_public=maya_pk,
                               identity_secret=noor_sk, prekeys=8)
    sender = Sender.create(tmp_path / "maya.json", me="maya", peer="noor", identity_secret=maya_sk,
                           peer_sig_public=noor_pk)
    assert sender.accept_bundle(receiver.bundle()) == 8
    return sender, receiver, tmp_path


def test_a_delivered_message_cannot_be_decrypted_from_the_receivers_later_state(pair):
    sender, receiver, _ = pair
    envelope = sender.send("meet at noon")
    stolen_before = copy.deepcopy(receiver.state)
    assert receiver.receive(envelope) == "meet at noon"
    # Everything the receiver holds afterwards, identity key included, lacks that prekey's secret.
    assert envelope["prekey"] not in receiver.state["prekeys"]
    assert envelope["prekey"] in stolen_before["prekeys"]  # (it existed only until delivery)
    with pytest.raises(m.MessagingError):
        Receiver(receiver.path, copy.deepcopy(receiver.state)).receive(envelope)


def test_each_message_uses_a_different_prekey(pair):
    sender, _receiver, _ = pair
    assert sender.send("a")["prekey"] != sender.send("b")["prekey"]


def test_reordered_messages_are_delivered_and_a_duplicate_is_refused(pair):
    sender, receiver, _ = pair
    one, two, three = (sender.send(t) for t in ("one", "two", "three"))
    assert [receiver.receive(e) for e in (three, one, two)] == ["three", "one", "two"]
    with pytest.raises(m.MessagingError):
        receiver.receive(two)


def test_a_lost_message_is_reported_and_resent_until_acknowledged(pair):
    sender, receiver, _ = pair
    first, _lost, third = (sender.send(t) for t in ("one", "two", "three"))
    receiver.receive(first)
    receiver.receive(third)
    assert receiver.missing() == [2]
    assert sender.handle_ack(receiver.ack()) == [1, 3]
    assert sender.unacknowledged() == [2]
    (again,) = sender.resend()
    assert receiver.receive(again) == "two" and receiver.missing() == []
    sender.handle_ack(receiver.ack())
    assert sender.unacknowledged() == []


def test_both_sides_resume_after_a_restart(pair):
    sender, receiver, _ = pair
    receiver.receive(sender.send("before restart"))
    sender, receiver = Sender.load(sender.path), Receiver.load(receiver.path)
    envelope = sender.send("after restart")
    assert envelope["message"]["header"].count('"seq":2') == 1  # numbering continued
    assert receiver.receive(envelope) == "after restart"
    assert receiver.state["delivered"] == [1, 2]


def test_forged_bundles_and_acks_are_refused(pair):
    sender, receiver, _ = pair
    bundle = receiver.bundle()
    bundle["body"]["prekeys"]["evil"] = bundle["body"]["prekeys"][next(iter(bundle["body"]["prekeys"]))]
    with pytest.raises(m.MessagingError):
        sender.accept_bundle(bundle)
    ack = receiver.ack()
    ack["body"]["delivered"] = [1, 2, 3, 4]
    with pytest.raises(m.MessagingError):
        sender.handle_ack(ack)
