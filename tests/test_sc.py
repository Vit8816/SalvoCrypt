import copy
import secrets

import pytest
from cryptography.exceptions import InvalidTag

from SC import (
    KeyLoader,
    decrypt_bytes,
    decrypt_for_rsa,
    decrypt_for_x25519,
    encrypt_bytes,
    encrypt_for_rsa,
    encrypt_for_x25519,
    generate_rsa_private_key,
    generate_x25519_private_key,
    indexed_sum,
)


@pytest.mark.parametrize("algorithm", ["AES-256-GCM", "CHACHA20-POLY1305"])
def test_symmetric_round_trip_and_random_nonce(algorithm):
    key = KeyLoader.random().key
    first = encrypt_bytes(b"same plaintext", key, algorithm=algorithm)
    second = encrypt_bytes(b"same plaintext", key, algorithm=algorithm)
    assert first != second
    assert decrypt_bytes(first, key) == b"same plaintext"
    assert decrypt_bytes(second, key) == b"same plaintext"


def test_ciphertext_tampering_is_rejected():
    key = KeyLoader.random().key
    envelope = encrypt_bytes(b"authenticated", key)
    damaged = copy.deepcopy(envelope)
    damaged["ciphertext"] = ("A" if damaged["ciphertext"][0] != "A" else "B") + damaged["ciphertext"][1:]
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_bytes(damaged, key)


def test_material_derivation_uses_full_input_not_only_sum():
    # These inputs have the same indexed sum: 1*(1+1)+2*(2+1) == 1*(3+1)+2*(1+1).
    left, right = bytes([1, 2]), bytes([3, 1])
    assert indexed_sum(left) == indexed_sum(right)
    salt = secrets.token_bytes(16)
    with pytest.raises(ValueError):
        KeyLoader.from_material(left, salt=salt)
    padded_left = left + b"L" * 30
    padded_right = right + b"L" * 30
    assert KeyLoader.from_material(padded_left, salt=salt).key != KeyLoader.from_material(padded_right, salt=salt).key


def test_x_1_to_2_changes_probe():
    key = KeyLoader.random()
    assert key.sensitivity_probe(1) != key.sensitivity_probe(2)
    assert 0 < key.sensitivity_delta(1, 2) <= 256


def test_password_derivation_is_stable_for_same_parameters():
    salt = secrets.token_bytes(16)
    first = KeyLoader.from_password("correct horse battery staple", salt=salt, memory_kib=8192, iterations=1, parallelism=1)
    second = KeyLoader.from_password("correct horse battery staple", salt=salt, memory_kib=8192, iterations=1, parallelism=1)
    assert first.key == second.key


def test_rsa_hybrid_round_trip():
    private_key = generate_rsa_private_key()
    envelope = encrypt_for_rsa(b"RSA protects only the data key", private_key.public_key())
    assert decrypt_for_rsa(envelope, private_key) == b"RSA protects only the data key"


def test_x25519_hybrid_round_trip():
    private_key = generate_x25519_private_key()
    envelope = encrypt_for_x25519(b"X25519 derives a wrapping key", private_key.public_key())
    assert decrypt_for_x25519(envelope, private_key) == b"X25519 derives a wrapping key"

