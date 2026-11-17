from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sandbox_icap import TEST_KEY, decrypt_enc1_body
from sandbox_icap.errors import InvalidContainer


def test_decrypts_enc1_binary_plaintext() -> None:
    """Проверить расшифровку ENC1 с произвольными бинарными данными."""
    plaintext = b"\x00\xff\x80binary\r\n\x00payload"
    nonce = bytes(range(12))
    encrypted = AESGCM(TEST_KEY).encrypt(nonce, plaintext, None)
    container = b"ENC1" + nonce + encrypted

    assert decrypt_enc1_body(container) == plaintext


def test_accepts_empty_plaintext_container() -> None:
    """Проверить допустимость контейнера с пустым открытым текстом."""
    nonce = b"n" * 12
    encrypted = AESGCM(TEST_KEY).encrypt(nonce, b"", None)
    container = b"ENC1" + nonce + encrypted

    assert len(container) == 32
    assert decrypt_enc1_body(container) == b""


@pytest.mark.parametrize(
    "container",
    [b"ENC1", b"ENC1" + b"n" * 12 + b"short"],
)
def test_rejects_truncated_container(container: bytes) -> None:
    """Проверить отклонение неполного ENC1-контейнера."""
    with pytest.raises(InvalidContainer):
        decrypt_enc1_body(container)


def test_rejects_modified_tag() -> None:
    """Проверить отклонение контейнера с изменённым тегом аутентификации."""
    nonce = bytes(range(12))
    encrypted = AESGCM(TEST_KEY).encrypt(nonce, b"plaintext", None)
    container = bytearray(b"ENC1" + nonce + encrypted)
    container[-1] ^= 1

    with pytest.raises(InvalidContainer):
        decrypt_enc1_body(bytes(container))


def test_rejects_wrong_key_length() -> None:
    """Проверить отклонение ключа AES-GCM неподдерживаемой длины."""
    with pytest.raises(ValueError):
        decrypt_enc1_body(b"ENC1" + b"x" * 28, b"short")
