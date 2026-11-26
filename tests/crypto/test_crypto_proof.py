"""``protected_read`` proof: contract byte order and a full client-side round trip."""

import base64
import hashlib
import hmac
import secrets

import pytest

from t4.crypto import kem, proof


def test_matches_the_contract_definition():
    key = secrets.token_bytes(32)
    challenge, body = "challenge-न".encode("utf-8"), "stored body ✓".encode("utf-8")
    expected = hmac.new(key, challenge + body, hashlib.sha256).hexdigest()
    result = proof.make_proof(key, challenge, body)
    assert result == expected and result == result.lower() and len(result) == 64


def test_order_matters():
    key = secrets.token_bytes(32)
    assert proof.make_proof(key, b"ab", b"cd") != proof.make_proof(key, b"cd", b"ab")


def test_client_side_round_trip_through_base64():
    public_key, secret_key = kem.keygen()
    challenge, body = secrets.token_hex(16).encode(), secrets.token_hex(24).encode()
    received_key = base64.b64decode(base64.b64encode(public_key), validate=True)
    ciphertext, server_secret = kem.encapsulate(received_key)
    server_proof = proof.make_proof(server_secret, challenge, body)
    client_secret = kem.decapsulate(secret_key, ciphertext)
    assert proof.verify_proof(client_secret, challenge, body, server_proof)


def test_tampered_ciphertext_fails_the_proof():
    public_key, secret_key = kem.keygen()
    ciphertext, server_secret = kem.encapsulate(public_key)
    server_proof = proof.make_proof(server_secret, b"c", b"body")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    assert not proof.verify_proof(kem.decapsulate(secret_key, tampered), b"c", b"body", server_proof)


@pytest.mark.parametrize("bad", [None, 7, b"abc", "", "zz", "é" * 64])
def test_verify_never_raises(bad):
    assert proof.verify_proof(secrets.token_bytes(32), b"c", b"b", bad) is False


def test_verify_rejects_uppercase_and_wrong_secret():
    key = secrets.token_bytes(32)
    good = proof.make_proof(key, b"c", b"b")
    assert not proof.verify_proof(key, b"c", b"b", good.upper())
    assert not proof.verify_proof(secrets.token_bytes(32), b"c", b"b", good)
    assert not proof.verify_proof(b"short", b"c", b"b", good)


@pytest.mark.parametrize(
    ("key", "challenge", "body"),
    [(b"short", b"c", b"b"), (None, b"c", b"b"), (bytes(32), "c", b"b"), (bytes(32), b"c", "b")],
)
def test_make_proof_rejects_bad_input(key, challenge, body):
    with pytest.raises(ValueError):
        proof.make_proof(key, challenge, body)
