"""SalvoCrypt v3 experimental envelope.

The module deliberately uses established cryptographic primitives.  The
``indexed_sum`` value is diagnostic metadata only; it is never used as a key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Literal

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

Algorithm = Literal["AES-256-GCM", "CHACHA20-POLY1305"]
VERSION = 3
_DOMAIN = b"SalvoCrypt-v3"
_MODULUS = 1 << 256


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), altchars=b"-_", validate=True)


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def indexed_sum(data: bytes) -> int:
    """Order-sensitive modular sum for diagnostics, never key derivation.

    Indexing prevents a simple permutation from preserving the result, but
    collisions remain mathematically unavoidable.  Security must not depend
    on this value.
    """
    if not data:
        raise ValueError("data must not be empty")
    return sum((index + 1) * (byte + 1) for index, byte in enumerate(data)) % _MODULUS


@dataclass(frozen=True)
class KeyMaterial:
    key: bytes
    indexed_sum: int

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("SalvoCrypt v3 requires exactly 32 key bytes")

    def sensitivity_probe(self, x: int) -> bytes:
        """Return a domain-separated digest for sensitivity measurements."""
        if x < 0:
            raise ValueError("x must be non-negative")
        width = max(1, (x.bit_length() + 7) // 8)
        return hashlib.sha256(
            _DOMAIN + b"/sensitivity/" + self.key + x.to_bytes(width, "big")
        ).digest()

    def sensitivity_delta(self, first: int = 1, second: int = 2) -> int:
        """Count changed output bits when the probe value changes."""
        left = self.sensitivity_probe(first)
        right = self.sensitivity_probe(second)
        return sum((a ^ b).bit_count() for a, b in zip(left, right))


class KeyLoader:
    @staticmethod
    def random() -> KeyMaterial:
        raw = secrets.token_bytes(32)
        return KeyMaterial(raw, indexed_sum(raw))

    @staticmethod
    def from_material(material: bytes, *, salt: bytes) -> KeyMaterial:
        """Derive a key from high-entropy binary key material using HKDF."""
        if len(material) < 32:
            raise ValueError("key material must contain at least 32 bytes")
        if len(salt) < 16:
            raise ValueError("salt must contain at least 16 bytes")
        diagnostic = indexed_sum(material)
        # The complete material is the HKDF input.  The sum is merely bound
        # into the context and cannot collapse different inputs into one key.
        context = _DOMAIN + b"/raw-key/" + diagnostic.to_bytes(32, "big")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context).derive(material)
        return KeyMaterial(key, diagnostic)

    @staticmethod
    def from_password(
        password: str,
        *,
        salt: bytes,
        memory_kib: int = 65536,
        iterations: int = 3,
        parallelism: int = 4,
    ) -> KeyMaterial:
        """Derive a 256-bit key with Argon2id."""
        if not password:
            raise ValueError("password must not be empty")
        if len(salt) < 16:
            raise ValueError("salt must contain at least 16 bytes")
        raw_password = password.encode("utf-8")
        key = hash_secret_raw(
            secret=raw_password,
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
        return KeyMaterial(key, indexed_sum(raw_password))


def _aead(key: bytes, algorithm: Algorithm) -> AESGCM | ChaCha20Poly1305:
    if len(key) != 32:
        raise ValueError("key must contain exactly 32 bytes")
    if algorithm == "AES-256-GCM":
        return AESGCM(key)
    if algorithm == "CHACHA20-POLY1305":
        return ChaCha20Poly1305(key)
    raise ValueError("unsupported algorithm")


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    *,
    algorithm: Algorithm = "CHACHA20-POLY1305",
    associated_data: bytes = b"",
) -> dict[str, Any]:
    nonce = secrets.token_bytes(12)
    protected = {"version": VERSION, "algorithm": algorithm}
    aad = _DOMAIN + b"/payload/" + _canonical(protected) + associated_data
    ciphertext = _aead(key, algorithm).encrypt(nonce, plaintext, aad)
    return {
        "protected": protected,
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def decrypt_bytes(
    envelope: dict[str, Any], key: bytes, *, associated_data: bytes = b""
) -> bytes:
    protected = envelope["protected"]
    if protected.get("version") != VERSION:
        raise ValueError("unsupported SalvoCrypt version")
    algorithm = protected.get("algorithm")
    if algorithm not in ("AES-256-GCM", "CHACHA20-POLY1305"):
        raise ValueError("unsupported algorithm")
    nonce = _unb64(envelope["nonce"])
    if len(nonce) != 12:
        raise ValueError("invalid nonce length")
    aad = _DOMAIN + b"/payload/" + _canonical(protected) + associated_data
    return _aead(key, algorithm).decrypt(nonce, _unb64(envelope["ciphertext"]), aad)


def dumps(envelope: dict[str, Any]) -> str:
    return _b64(_canonical(envelope))


def loads(encoded: str) -> dict[str, Any]:
    value = json.loads(_unb64(encoded))
    if not isinstance(value, dict):
        raise ValueError("invalid envelope")
    return value


def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def encrypt_for_rsa(
    plaintext: bytes,
    public_key: rsa.RSAPublicKey,
    *,
    algorithm: Algorithm = "CHACHA20-POLY1305",
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """Hybrid encryption: AEAD payload plus RSA-OAEP key wrapping."""
    data_key = secrets.token_bytes(32)
    payload = encrypt_bytes(plaintext, data_key, algorithm=algorithm, associated_data=associated_data)
    wrapped = public_key.encrypt(
        data_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=_DOMAIN),
    )
    return {"version": VERSION, "key_wrap": "RSA-3072-OAEP-SHA256", "wrapped_key": _b64(wrapped), "payload": payload}


def decrypt_for_rsa(
    envelope: dict[str, Any],
    private_key: rsa.RSAPrivateKey,
    *,
    associated_data: bytes = b"",
) -> bytes:
    if envelope.get("version") != VERSION or envelope.get("key_wrap") != "RSA-3072-OAEP-SHA256":
        raise ValueError("invalid RSA envelope")
    data_key = private_key.decrypt(
        _unb64(envelope["wrapped_key"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=_DOMAIN),
    )
    return decrypt_bytes(envelope["payload"], data_key, associated_data=associated_data)


def generate_x25519_private_key() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def encrypt_for_x25519(
    plaintext: bytes,
    recipient_public_key: x25519.X25519PublicKey,
    *,
    algorithm: Algorithm = "CHACHA20-POLY1305",
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """Hybrid encryption using ephemeral X25519 and HKDF key agreement."""
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    salt = secrets.token_bytes(16)
    shared = ephemeral.exchange(recipient_public_key)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=_DOMAIN + b"/x25519-wrap/" + ephemeral_public,
    ).derive(shared)
    data_key = secrets.token_bytes(32)
    wrap_nonce = secrets.token_bytes(12)
    wrapped_key = ChaCha20Poly1305(wrap_key).encrypt(wrap_nonce, data_key, _DOMAIN)
    payload = encrypt_bytes(plaintext, data_key, algorithm=algorithm, associated_data=associated_data)
    return {
        "version": VERSION,
        "key_wrap": "X25519-HKDF-SHA256-CHACHA20-POLY1305",
        "ephemeral_public_key": _b64(ephemeral_public),
        "salt": _b64(salt),
        "wrap_nonce": _b64(wrap_nonce),
        "wrapped_key": _b64(wrapped_key),
        "payload": payload,
    }


def decrypt_for_x25519(
    envelope: dict[str, Any],
    recipient_private_key: x25519.X25519PrivateKey,
    *,
    associated_data: bytes = b"",
) -> bytes:
    expected = "X25519-HKDF-SHA256-CHACHA20-POLY1305"
    if envelope.get("version") != VERSION or envelope.get("key_wrap") != expected:
        raise ValueError("invalid X25519 envelope")
    ephemeral_public_bytes = _unb64(envelope["ephemeral_public_key"])
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    shared = recipient_private_key.exchange(ephemeral_public)
    wrap_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=_unb64(envelope["salt"]),
        info=_DOMAIN + b"/x25519-wrap/" + ephemeral_public_bytes,
    ).derive(shared)
    data_key = ChaCha20Poly1305(wrap_key).decrypt(
        _unb64(envelope["wrap_nonce"]), _unb64(envelope["wrapped_key"]), _DOMAIN
    )
    return decrypt_bytes(envelope["payload"], data_key, associated_data=associated_data)

