"""Разбор контейнера ENC1 и расшифрование данных с помощью AES-256-GCM."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import InvalidContainer

# Тестовый ключ из задания.
TEST_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
MAGIC = b"ENC1"
MAGIC_SIZE = 4
NONCE_SIZE = 12
TAG_SIZE = 16
MIN_CONTAINER_SIZE = MAGIC_SIZE + NONCE_SIZE + TAG_SIZE


def decrypt_enc1_body(body: bytes, key: bytes = TEST_KEY) -> bytes:
    """Расшифровать ``ENC1 | nonce(12) | ciphertext | tag(16)`` в байты."""
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")
    if not body.startswith(MAGIC):
        raise InvalidContainer("body does not start with ENC1")
    if len(body) < MIN_CONTAINER_SIZE:
        raise InvalidContainer(
            f"ENC1 container is too short: {len(body)} bytes; "
            f"at least {MIN_CONTAINER_SIZE} bytes are required"
        )

    nonce_end = MAGIC_SIZE + NONCE_SIZE
    nonce = body[MAGIC_SIZE:nonce_end]
    ciphertext_and_tag = body[nonce_end:]

    try:
        return AESGCM(key).decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag as exc:
        raise InvalidContainer("AES-GCM authentication failed") from exc
