"""ML-KEM-768 wrapper: round trip, sizes and hostile input."""

import subprocess
import sys
from pathlib import Path

import pytest

from t4.crypto import kem


@pytest.fixture(scope="module")
def keys():
    return kem.keygen()


def test_sizes_match_the_standard(keys):
    public_key, secret_key = keys
    ciphertext, shared_secret = kem.encapsulate(public_key)
    assert (len(public_key), len(secret_key)) == (kem.PUBLIC_KEY_SIZE, kem.SECRET_KEY_SIZE)
    assert (len(ciphertext), len(shared_secret)) == (kem.CIPHERTEXT_SIZE, kem.SHARED_SECRET_SIZE)


def test_library_constants_agree_with_ours():
    from pqcrypto.kem import ml_kem_768

    assert ml_kem_768.PUBLIC_KEY_SIZE == kem.PUBLIC_KEY_SIZE
    assert ml_kem_768.SECRET_KEY_SIZE == kem.SECRET_KEY_SIZE
    assert ml_kem_768.CIPHERTEXT_SIZE == kem.CIPHERTEXT_SIZE
    assert ml_kem_768.PLAINTEXT_SIZE == kem.SHARED_SECRET_SIZE


def test_round_trip(keys):
    public_key, secret_key = keys
    ciphertext, shared_secret = kem.encapsulate(public_key)
    assert kem.decapsulate(secret_key, ciphertext) == shared_secret


def test_each_encapsulation_is_fresh(keys):
    first = kem.encapsulate(keys[0])
    second = kem.encapsulate(keys[0])
    assert first[0] != second[0] and first[1] != second[1]


def test_tampered_ciphertext_yields_a_different_secret(keys):
    public_key, secret_key = keys
    ciphertext, shared_secret = kem.encapsulate(public_key)
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    assert kem.decapsulate(secret_key, tampered) != shared_secret


def test_generated_keys_pass_the_public_key_check():
    for _ in range(50):
        public_key, _secret = kem.keygen()
        assert kem.check_public_key(public_key) == public_key


@pytest.mark.parametrize(
    "bad_key",
    [
        b"",
        b"\x00" * (kem.PUBLIC_KEY_SIZE - 1),
        b"\x00" * (kem.PUBLIC_KEY_SIZE + 1),
        b"\xff" * kem.PUBLIC_KEY_SIZE,  # right length, coefficients out of range
        "a" * kem.PUBLIC_KEY_SIZE,
        None,
        1184,
    ],
)
def test_bad_public_key_is_a_value_error(bad_key):
    with pytest.raises(ValueError):
        kem.encapsulate(bad_key)


@pytest.mark.parametrize(("first", "second", "accepted"), [(3328, 0, True), (3329, 0, False), (0, 3328, True), (0, 3329, False)])
def test_coefficient_boundary(first, second, accepted):
    packed = bytes([first & 0xFF, (first >> 8) | ((second & 0x0F) << 4), second >> 4])
    key = packed + bytes(kem.PUBLIC_KEY_SIZE - 3)
    if accepted:
        kem.check_public_key(key)
    else:
        with pytest.raises(ValueError):
            kem.check_public_key(key)


def test_bad_secret_key_or_ciphertext_is_a_value_error(keys):
    public_key, secret_key = keys
    ciphertext, _ = kem.encapsulate(public_key)
    for bad_secret, bad_ciphertext in (
        (secret_key[:-1], ciphertext),
        (secret_key, ciphertext[:-1]),
        (None, ciphertext),
        (secret_key, None),
        (ciphertext, secret_key),
    ):
        with pytest.raises(ValueError):
            kem.decapsulate(bad_secret, bad_ciphertext)


def test_error_messages_do_not_contain_key_bytes(keys):
    secret_key = keys[1]
    with pytest.raises(ValueError) as caught:
        kem.decapsulate(secret_key, b"short")
    assert secret_key[:8].hex() not in str(caught.value)
    assert str(caught.value) == "invalid ML-KEM-768 ciphertext"


def test_importing_the_package_does_not_load_the_library():
    root = Path(__file__).resolve().parents[2]
    code = (
        "import sys, t4.crypto.kem, t4.crypto.sig, t4.crypto.proof;"
        "print(any(m.split('.')[0] == 'pqcrypto' for m in sys.modules))"
    )
    result = subprocess.run([sys.executable, "-B", "-c", code], cwd=root, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "False"
