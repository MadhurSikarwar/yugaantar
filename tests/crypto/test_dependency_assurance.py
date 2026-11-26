"""Behaviour of the pinned cryptographic dependency, checked through our wrappers.

These are correctness and fail-closed checks on pqcrypto 0.4.0's ML-KEM-768 and ML-DSA-65 as we
use them: round trips over many random keys, tampering, bad sizes, a missing library. They are NOT
known-answer tests against NIST vectors (none are available offline here) and they say nothing
about constant-time behaviour of the compiled code: no unit test can establish that.
"""
import hashlib
import hmac
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pqcrypto")

from t4.crypto import kem, proof, sig  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def test_installed_versions_and_native_files_match_the_pins():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify_dependencies.py")],
                            capture_output=True, text=True, cwd=ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


def test_wrapper_sizes_are_the_library_sizes():
    from pqcrypto.kem import ml_kem_768
    from pqcrypto.sign import ml_dsa_65

    assert (kem.PUBLIC_KEY_SIZE, kem.CIPHERTEXT_SIZE, kem.SHARED_SECRET_SIZE) == (
        ml_kem_768.PUBLIC_KEY_SIZE, ml_kem_768.CIPHERTEXT_SIZE, ml_kem_768.PLAINTEXT_SIZE)
    assert kem.SECRET_KEY_SIZE == ml_kem_768.SECRET_KEY_SIZE
    assert (sig.PUBLIC_KEY_SIZE, sig.SECRET_KEY_SIZE, sig.SIGNATURE_SIZE) == (
        ml_dsa_65.PUBLIC_KEY_SIZE, ml_dsa_65.SECRET_KEY_SIZE, ml_dsa_65.SIGNATURE_SIZE)


def test_kem_round_trips_for_many_random_keys_and_every_key_passes_our_check():
    secrets_seen = set()
    for _ in range(40):
        public_key, secret_key = kem.keygen()
        assert kem.check_public_key(public_key) == public_key  # a genuine key is never rejected
        ciphertext, shared = kem.encapsulate(public_key)
        assert kem.decapsulate(secret_key, ciphertext) == shared
        secrets_seen.add(shared)
    assert len(secrets_seen) == 40  # a fresh secret every time


def test_a_tampered_ciphertext_gives_an_unrelated_secret_not_an_error_or_the_real_one():
    public_key, secret_key = kem.keygen()
    ciphertext, shared = kem.encapsulate(public_key)
    for position in (0, 500, len(ciphertext) - 1):
        damaged = bytearray(ciphertext)
        damaged[position] ^= 0x01
        other = kem.decapsulate(secret_key, bytes(damaged))
        assert other != shared and len(other) == kem.SHARED_SECRET_SIZE
    other_secret_key = kem.keygen()[1]
    assert kem.decapsulate(other_secret_key, ciphertext) != shared


@pytest.mark.parametrize("bad", [b"", b"\x00" * 1183, b"\x00" * 1185, "text", None, 7])
def test_kem_rejects_malformed_public_keys_with_valueerror_only(bad):
    with pytest.raises(ValueError):
        kem.encapsulate(bad)


def test_kem_rejects_a_key_with_out_of_range_coefficients():
    with pytest.raises(ValueError):
        kem.encapsulate(b"\xff" * kem.PUBLIC_KEY_SIZE)


@pytest.mark.parametrize("size", [0, 1087, 1089])
def test_kem_rejects_wrong_sized_ciphertexts(size):
    with pytest.raises(ValueError):
        kem.decapsulate(kem.keygen()[1], b"\x00" * size)


def test_signatures_verify_and_every_kind_of_damage_is_rejected():
    public_key, secret_key = sig.sig_keygen()
    message = b"synthetic message"
    signature = sig.sign(secret_key, message)
    assert sig.verify(public_key, message, signature) is True
    assert sig.sign(secret_key, message) != signature  # randomized, as documented
    damaged = bytearray(signature)
    damaged[100] ^= 0x01
    assert sig.verify(public_key, message, bytes(damaged)) is False
    assert sig.verify(public_key, message + b"!", signature) is False
    assert sig.verify(sig.sig_keygen()[0], message, signature) is False
    assert sig.verify(public_key, message, signature[:-1]) is False
    assert sig.verify(public_key, message, signature + b"\x00") is False


@pytest.mark.parametrize("args", [(b"", b"m", b""), (None, b"m", b"s"), ("k", "m", "s"), (b"\x00" * 1952, b"m", b"\x00" * 3309)])
def test_signature_verification_never_raises_and_never_accepts_garbage(args):
    assert sig.verify(*args) is False


def test_signing_rejects_a_bad_key_with_valueerror_only():
    for bad in (b"", b"\x00" * 4031, None):
        with pytest.raises(ValueError):
            sig.sign(bad, b"m")


def test_the_proof_is_hmac_sha256_of_challenge_then_body_and_compares_in_constant_time_form():
    secret = hashlib.sha256(b"synthetic").digest()
    expected = hmac.new(secret, b"chal" + b"body", hashlib.sha256).hexdigest()
    assert proof.make_proof(secret, b"chal", b"body") == expected
    assert proof.verify_proof(secret, b"chal", b"body", expected) is True
    assert proof.verify_proof(secret, b"chal", b"body", expected[:-1] + ("0" if expected[-1] != "0" else "1")) is False
    assert proof.verify_proof(secret, b"chal", b"body", None) is False
    assert proof.verify_proof(secret, b"chal", b"body", "é" * 64) is False
    import inspect

    assert "compare_digest" in inspect.getsource(proof.verify_proof)  # never ==


def test_a_missing_crypto_library_fails_closed_instead_of_falling_back(monkeypatch):
    """Without pqcrypto nothing is encapsulated and nothing weaker is used in its place."""
    monkeypatch.setitem(sys.modules, "pqcrypto.kem", None)
    monkeypatch.setitem(sys.modules, "pqcrypto.sign", None)
    public_key = b"\x00" * kem.PUBLIC_KEY_SIZE  # valid for our range check, so the library is reached
    with pytest.raises(ImportError):
        kem.encapsulate(public_key)
    with pytest.raises(ImportError):
        sig.sig_keygen()
    assert sig.verify(b"\x00" * 1952, b"m", b"\x00" * 3309) is False  # verification: closed, not open


def test_no_secret_key_or_shared_secret_is_ever_written_by_the_adapter(tmp_path):
    """A protected_read round trip, then a search of everything the service wrote for the secret."""
    import base64
    import json
    import os

    public_key, secret_key = kem.keygen()
    env = dict(os.environ, TRACK4_STATE_DIR=str(tmp_path / "state"))

    def call(request):
        done = subprocess.run([sys.executable, "-B", str(ROOT / "track4_service.py")], input=json.dumps(request).encode(),
                              capture_output=True, env=env, cwd=ROOT, timeout=60)
        assert done.returncode == 0, done.stderr
        return json.loads(done.stdout), done

    call({"op": "setup", "owners": {"a": "maya"}, "contents": {"a": "synthetic body"}, "disabled": [], "key_material": "k"})
    reply, done = call({"op": "protected_read", "actor": "maya", "asset": "a", "challenge": "c1",
                        "public_key": base64.b64encode(public_key).decode()})
    shared = kem.decapsulate(secret_key, base64.b64decode(reply["ciphertext"]))
    assert proof.verify_proof(shared, b"c1", b"synthetic body", reply["proof"])
    needles = (shared, shared.hex().encode(), base64.b64encode(shared), secret_key[:64], public_key[:64].hex().encode())
    haystacks = [p.read_bytes() for p in (tmp_path / "state").rglob("*") if p.is_file()] + [done.stdout, done.stderr]
    for needle in needles:
        assert not any(needle in blob for blob in haystacks)
