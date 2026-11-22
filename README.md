# SalvoCrypt v3 — experimental

SalvoCrypt v3 is an authenticated-encryption envelope built from established
cryptographic primitives. It is a development version and has not received an
independent security audit.

## Security design

- AES-256-GCM or ChaCha20-Poly1305 encrypts and authenticates data.
- Every encryption generates a new 96-bit nonce.
- Argon2id derives a 256-bit key from a password and a random salt.
- HKDF-SHA256 derives a key from high-entropy binary material.
- RSA-3072-OAEP-SHA256 or ephemeral X25519 can protect a random data key.
- Base64 is used only to serialize bytes. It does not add security.
- `indexed_sum` is diagnostic metadata only. It is deliberately excluded from
  the security boundary because every finite sum has collisions.

The earlier custom `const`, `pow_n`, repeated XOR and affine transformations
have been removed from the encryption path.

## Install and test

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Password example

The salt and Argon2id parameters must be stored alongside the ciphertext.

```python
import secrets
from SC import KeyLoader, encrypt_bytes, decrypt_bytes, dumps, loads

salt = secrets.token_bytes(16)
material = KeyLoader.from_password("a long passphrase", salt=salt)
encoded = dumps(encrypt_bytes(b"message", material.key))
clear = decrypt_bytes(loads(encoded), material.key)
assert clear == b"message"

changed_bits = material.sensitivity_delta(1, 2)
print(changed_bits)
```

Never reuse a stored salt as a nonce, never publish a raw key, and never return
plaintext when authenticated decryption fails.

## Public-key modes

`encrypt_for_rsa` uses RSA only to wrap a random 256-bit data key; it does not
encrypt the complete document with RSA. `encrypt_for_x25519` performs ephemeral
X25519 key agreement, derives a wrapping key through HKDF and protects the data
key with ChaCha20-Poly1305. In both modes the payload remains AEAD-encrypted.

## Compatibility

Version 3 is intentionally incompatible with the previous experimental format.
No automatic legacy decryption is provided because unauthenticated plaintext
must not be silently accepted by the new API.

