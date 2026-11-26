"""ML-DSA-65 wrapper: valid signatures pass, everything else is a quiet ``False``."""

import pytest

from t4.crypto import sig

MESSAGE = b'{"type":"checkpoint","seq":7}'


@pytest.fixture(scope="module")
def signed():
    public_key, secret_key = sig.sig_keygen()
    return public_key, secret_key, sig.sign(secret_key, MESSAGE)


def test_sizes_match_the_library():
    from pqcrypto.sign import ml_dsa_65

    assert ml_dsa_65.PUBLIC_KEY_SIZE == sig.PUBLIC_KEY_SIZE
    assert ml_dsa_65.SECRET_KEY_SIZE == sig.SECRET_KEY_SIZE
    assert ml_dsa_65.SIGNATURE_SIZE == sig.SIGNATURE_SIZE


def test_valid_signature(signed):
    public_key, secret_key, signature = signed
    assert len(public_key) == sig.PUBLIC_KEY_SIZE and len(secret_key) == sig.SECRET_KEY_SIZE
    assert len(signature) == sig.SIGNATURE_SIZE
    assert sig.verify(public_key, MESSAGE, signature) is True


def test_empty_message_can_be_signed(signed):
    public_key, secret_key, _ = signed
    assert sig.verify(public_key, b"", sig.sign(secret_key, b""))


def test_altered_message_or_signature_fails(signed):
    public_key, _, signature = signed
    assert sig.verify(public_key, MESSAGE + b" ", signature) is False
    for position in (0, len(signature) // 2, len(signature) - 1):
        altered = bytearray(signature)
        altered[position] ^= 1
        assert sig.verify(public_key, MESSAGE, bytes(altered)) is False


def test_another_key_fails(signed):
    other_public, _ = sig.sig_keygen()
    assert sig.verify(other_public, MESSAGE, signed[2]) is False


@pytest.mark.parametrize("bad", [None, "text", 5, b"", b"\x00" * 10, b"\x00" * 5000])
def test_verify_never_raises(signed, bad):
    public_key, _, signature = signed
    assert sig.verify(bad, MESSAGE, signature) is False
    assert sig.verify(public_key, MESSAGE, bad) is False
    if not isinstance(bad, bytes):
        assert sig.verify(public_key, bad, signature) is False


def test_sign_rejects_bad_input(signed):
    secret_key = signed[1]
    for key, message in ((secret_key[:-1], MESSAGE), (None, MESSAGE), (secret_key, "text")):
        with pytest.raises(ValueError):
            sig.sign(key, message)
