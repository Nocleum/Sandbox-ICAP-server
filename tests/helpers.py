from __future__ import annotations

import socket
from collections.abc import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sandbox_icap import TEST_KEY

CRLF = b"\r\n"


def encrypt_container(
    plaintext: bytes,
    nonce: bytes = bytes(range(12)),
) -> bytes:
    """Создать тестовый ENC1-контейнер с заданным открытым текстом."""
    encrypted = AESGCM(TEST_KEY).encrypt(nonce, plaintext, None)
    return b"ENC1" + nonce + encrypted


def encode_chunks(
    data: bytes,
    sizes: Iterable[int] | None = None,
) -> bytes:
    """Разбить данные на ICAP-чанки указанных размеров."""
    chunks: list[bytes] = []
    offset = 0
    if sizes is None:
        sizes = [len(data)]

    for size in sizes:
        if offset >= len(data):
            break
        part = data[offset:offset + size]
        if not part:
            continue
        chunks.extend((f"{len(part):X}".encode(), CRLF, part, CRLF))
        offset += len(part)

    if offset < len(data):
        part = data[offset:]
        chunks.extend((f"{len(part):X}".encode(), CRLF, part, CRLF))

    chunks.append(b"0\r\n\r\n")
    return b"".join(chunks)


def make_request(
    body: bytes,
    *,
    http_headers: bytes | None = None,
    chunk_sizes: Iterable[int] | None = None,
    uri: str = "icap://127.0.0.1:1344/decrypt",
    method: str = "RESPMOD",
) -> bytes:
    """Сформировать ICAP RESPMOD-запрос для интеграционного теста."""
    if http_headers is None:
        http_headers = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"X-Keep: exact-value\r\n"
            + b"Content-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
        )

    encapsulated_header = (
        b"Encapsulated: res-hdr=0, res-body="
        + str(len(http_headers)).encode()
        + b"\r\n\r\n"
    )
    head = (
        f"{method} {uri} ICAP/1.0\r\n".encode("ascii")
        + b"Host: 127.0.0.1\r\n"
        + b"Connection: close\r\n"
        + encapsulated_header
    )
    return head + http_headers + encode_chunks(body, chunk_sizes)


def transact(
    address: tuple[str, int],
    request: bytes,
    fragments: Iterable[bytes] | None = None,
) -> bytes:
    """Отправить запрос по TCP и прочитать ответ до закрытия соединения."""
    with socket.create_connection(address, timeout=3.0) as client:
        client.settimeout(3.0)
        if fragments is None:
            client.sendall(request)
        else:
            for fragment in fragments:
                if fragment:
                    client.sendall(fragment)

        response = bytearray()
        while True:
            part = client.recv(65536)
            if not part:
                break
            response.extend(part)

        return bytes(response)


def parse_icap_response(
    response: bytes,
) -> tuple[bytes, dict[bytes, bytes], bytes, bytes]:
    """Разобрать статус, заголовки и тело ICAP-ответа."""
    header_end = response.find(b"\r\n\r\n")
    assert header_end >= 0, response

    header_block = response[:header_end + 4]
    lines = header_block[:-4].split(b"\r\n")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()

    payload = response[header_end + 4:]
    return lines[0], headers, payload, header_block


def decode_chunks(data: bytes) -> bytes:
    """Собрать исходные данные из последовательности ICAP-чанков."""
    output = bytearray()
    offset = 0

    while True:
        line_end = data.find(b"\r\n", offset)
        assert line_end >= 0
        size = int(data[offset:line_end], 16)
        offset = line_end + 2

        if size == 0:
            assert data[offset:] == b"\r\n"
            return bytes(output)

        output.extend(data[offset:offset + size])
        offset += size
        assert data[offset:offset + 2] == b"\r\n"
        offset += 2
