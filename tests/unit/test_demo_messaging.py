"""Demo messaging: encryption, authentication and replay protection (needs the demo-only cryptography package)."""
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


def send(keys, text="hello", seq=1):
    _, ssk, kpk, _ = keys
    return m.seal(sender="alice", sender_sig_secret=ssk, recipient="bob", recipient_kem_public=kpk,
                  plaintext=text, seq=seq, now=NOW)


def receive(keys, msg, guard, recipient="bob", now=NOW, signer_public=None):
    spk, _, _, ksk = keys
    return m.open_message(msg, recipient=recipient, recipient_kem_secret=ksk,
                          sender_sig_public=signer_public or spk, guard=guard, now=now)


def test_round_trip_and_ciphertext_hides_the_text(keys):
    msg = send(keys, "secret plan")
    assert "secret plan" not in str(msg) and "secret plan".encode().hex() not in msg["body"]
    assert receive(keys, msg, m.ReplayGuard()) == "secret plan"


def test_replay_and_old_sequence_are_refused(keys):
    guard = m.ReplayGuard()
    first, second = send(keys, "a", 1), send(keys, "b", 2)
    assert receive(keys, second, guard) == "b"
    for msg in (second, first):
        with pytest.raises(m.MessagingError):
            receive(keys, msg, guard)


@pytest.mark.parametrize("name", ["body", "kem_ct", "nonce", "sig"])
def test_any_changed_field_is_refused_and_the_guard_does_not_move(keys, name):
    msg = send(keys)
    raw = bytearray(bytes.fromhex(msg[name]))
    raw[0] ^= 1
    msg[name] = raw.hex()
    guard = m.ReplayGuard()
    with pytest.raises(m.MessagingError):
        receive(keys, msg, guard)
    assert guard.snapshot() == {}


def test_changed_header_is_refused(keys):
    msg = send(keys)
    msg["header"] = msg["header"].replace('"seq":1', '"seq":9')
    with pytest.raises(m.MessagingError):
        receive(keys, msg, m.ReplayGuard())


def test_wrong_recipient_and_stale_message_are_refused(keys):
    msg = send(keys)
    with pytest.raises(m.MessagingError):
        receive(keys, msg, m.ReplayGuard(), recipient="carol")
    with pytest.raises(m.MessagingError):
        receive(keys, msg, m.ReplayGuard(), now=NOW + m.MAX_AGE_S + 10)


def test_a_different_signer_is_refused(keys):
    other_pk, _ = sig.sig_keygen()
    with pytest.raises(m.MessagingError):
        receive(keys, send(keys), m.ReplayGuard(), signer_public=other_pk)


def test_garbage_is_a_clean_error(keys):
    for bad in ({}, {"header": 1}, {"header": "x", "kem_ct": "zz", "nonce": "", "body": "", "sig": ""}):
        with pytest.raises(m.MessagingError):
            receive(keys, bad, m.ReplayGuard())


def test_lone_surrogate_text_is_refused(keys):
    with pytest.raises(m.MessagingError):
        send(keys, "bad\ud800")


def test_missing_cipher_library_fails_closed(keys, monkeypatch):
    def gone():
        raise m.MessagingUnavailable("x")
    monkeypatch.setattr(m, "_aead", gone)
    with pytest.raises(m.MessagingUnavailable):
        send(keys)
