"""Demo-layer sessions: binding, forward secrecy, loss and reordering, recovery, concurrency, resumption."""
from __future__ import annotations

import copy
import threading

import pytest

pytest.importorskip("cryptography")

from demo import messaging as m  # noqa: E402
from demo.sessions import Receiver, Sender, _canonical  # noqa: E402
from t4.crypto import sig  # noqa: E402


@pytest.fixture()
def keys():
    maya = sig.sig_keygen()
    noor = sig.sig_keygen()
    return maya, noor


def make_pair(tmp_path, keys, name="s1", prekeys=8):
    (maya_pk, maya_sk), (noor_pk, noor_sk) = keys
    receiver = Receiver.create(tmp_path / f"{name}-noor.json", me="noor", peer="maya", peer_sig_public=maya_pk,
                               identity_secret=noor_sk, prekeys=prekeys)
    sender = Sender.create(tmp_path / f"{name}-maya.json", me="maya", peer="noor", identity_secret=maya_sk,
                           peer_sig_public=noor_pk)
    assert sender.accept_bundle(receiver.bundle()) >= prekeys  # topped up when below the low mark
    return sender, receiver


@pytest.fixture()
def pair(tmp_path, keys):
    return make_pair(tmp_path, keys)


def test_a_delivered_message_cannot_be_decrypted_from_the_receivers_later_state(pair):
    sender, receiver = pair
    envelope = sender.send("meet at noon")
    assert receiver.receive(envelope) == "meet at noon"
    assert envelope["prekey"] not in receiver.state["prekeys"]
    with pytest.raises(m.MessagingError):
        Receiver(receiver.path, copy.deepcopy(receiver.state)).receive(envelope)


def test_reordered_messages_are_delivered_once(pair):
    sender, receiver = pair
    one, two, three = (sender.send(t) for t in ("one", "two", "three"))
    assert [receiver.receive(e) for e in (three, one, two)] == ["three", "one", "two"]


def test_an_ack_from_an_earlier_session_cannot_clear_a_new_message(tmp_path, keys):
    old_sender, old_receiver = make_pair(tmp_path, keys, "old")
    old_receiver.receive(old_sender.send("old one"))
    old_ack = old_receiver.ack()
    sender, receiver = make_pair(tmp_path, keys, "new")
    sender.send("new one")  # also sequence 1, same two people
    with pytest.raises(m.MessagingError):
        sender.handle_ack(old_ack)
    assert sender.unacknowledged() == [1]


def test_an_ack_only_confirms_the_exact_envelope_it_names(pair):
    sender, receiver = pair
    sender.send("one")
    ack = receiver.ack()
    ack_body = dict(ack["body"], delivered=[[1, "0" * 64]])
    forged = {"body": ack_body, "sig": ack["sig"]}
    with pytest.raises(m.MessagingError):  # changed after signing
        sender.handle_ack(forged)
    assert sender.unacknowledged() == [1]


def test_a_message_from_another_session_is_refused(tmp_path, keys):
    sender_a, receiver_a = make_pair(tmp_path, keys, "a")
    _sender_b, receiver_b = make_pair(tmp_path, keys, "b")
    envelope = sender_a.send("for session a")
    with pytest.raises(m.MessagingError):
        receiver_b.receive(envelope)


def test_a_lost_ack_is_recovered_without_double_delivery_or_prekey_exhaustion(tmp_path, keys):
    sender, receiver = make_pair(tmp_path, keys, prekeys=2)
    first = sender.send("only once")
    text, _lost_ack = receiver.handle(first)  # delivered; the ACK is lost
    assert text == "only once"
    (again,) = sender.resend()
    text, ack = receiver.handle(again)  # the duplicate is authenticated and answered, not delivered
    assert text is None and ack is not None
    assert sender.handle_ack(ack) == [1]
    assert sender.status()["unacknowledged"] == []
    assert len(receiver.state["delivered"]["1"]) == 2  # both envelopes are known, delivered once
    with pytest.raises(m.MessagingError):  # the original's prekey is gone: it cannot be replayed
        receiver.receive(first)


def test_a_sender_without_prekeys_reports_it_and_continues_after_a_new_bundle(tmp_path, keys):
    (maya_pk, maya_sk), (noor_pk, noor_sk) = keys
    receiver = Receiver.create(tmp_path / "r.json", me="noor", peer="maya", peer_sig_public=maya_pk,
                               identity_secret=noor_sk, prekeys=1)
    sender = Sender.create(tmp_path / "s.json", me="maya", peer="noor", identity_secret=maya_sk,
                           peer_sig_public=noor_pk)
    bundle = receiver.bundle()
    bundle_body = dict(bundle["body"], prekeys=dict(list(bundle["body"]["prekeys"].items())[:1]))
    # Accept only one prekey, as if the sender had fetched a small bundle.
    signature = sig.sign(bytes.fromhex(receiver.state["identity_secret"]), _canonical(bundle_body))
    sender.accept_bundle({"body": bundle_body, "sig": signature.hex()})
    sender.send("one")  # lost in transit
    assert sender.resend() == []  # no prekey: waits instead of failing
    assert sender.status()["needs_bundle"] is True
    sender.accept_bundle(receiver.bundle())  # the receiver topped its prekeys up
    (again,) = sender.resend()
    assert receiver.receive(again) == "one"


def test_resends_are_bounded(tmp_path, keys):
    (maya_pk, maya_sk), (noor_pk, noor_sk) = keys
    receiver = Receiver.create(tmp_path / "r.json", me="noor", peer="maya", peer_sig_public=maya_pk,
                               identity_secret=noor_sk, prekeys=16)
    sender = Sender.create(tmp_path / "s.json", me="maya", peer="noor", identity_secret=maya_sk,
                           peer_sig_public=noor_pk, max_attempts=3, retry_after=10)
    sender.accept_bundle(receiver.bundle())
    sender.send("x", now=1000)
    assert sender.resend(now=1005) == []  # back-off: not due yet
    assert len(sender.resend(now=1010)) == 1
    assert sender.resend(now=1015) == []  # back-off doubled to 20 s
    assert len(sender.resend(now=1030)) == 1
    assert sender.resend(now=5000) == [] and sender.status()["failed"] == [1]


def test_two_receiver_processes_cannot_both_deliver_one_message(pair):
    sender, receiver = pair
    envelope = sender.send("once")
    first, second = Receiver.load(receiver.path), Receiver.load(receiver.path)  # both opened before delivery
    results = []

    def deliver(side):
        try:
            results.append(side.receive(envelope))
        except m.MessagingError as error:
            results.append(type(error).__name__)

    threads = [threading.Thread(target=deliver, args=(side,)) for side in (first, second)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("once") == 1


def test_both_sides_resume_after_a_restart(pair):
    sender, receiver = pair
    receiver.receive(sender.send("before restart"))
    sender, receiver = Sender.load(sender.path), Receiver.load(receiver.path)
    envelope = sender.send("after restart")
    assert '"seq":2' in envelope["message"]["header"]
    assert receiver.receive(envelope) == "after restart"
    assert sorted(receiver.state["delivered"]) == ["1", "2"]


def test_forged_bundles_are_refused(pair):
    sender, receiver = pair
    bundle = receiver.bundle()
    bundle["body"]["prekeys"]["evil"] = next(iter(bundle["body"]["prekeys"].values()))
    with pytest.raises(m.MessagingError):
        sender.accept_bundle(bundle)
