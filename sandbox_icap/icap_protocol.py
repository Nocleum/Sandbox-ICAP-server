"""Разбор запросов ICAP RESPMOD, декодирование chunks и сборка ответов."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import ICAPError, PayloadTooLarge
from .http_message import (
    HEADER_END,
    HTTPResponseHeaders,
    parse_http_response_headers,
)
from .stream import SocketBuffer

CRLF = b"\r\n"
MAX_ICAP_HEADER_BYTES = 64 * 1024
MAX_HTTP_HEADER_BYTES = 64 * 1024
MAX_CHUNK_LINE_BYTES = 128
MAX_TRAILER_BYTES = 16 * 1024
MAX_CHUNKS = 100_000
_HEX_RE = re.compile(rb"^[0-9A-Fa-f]+$")


@dataclass(frozen=True)
class ICAPRequest:
    http_headers: HTTPResponseHeaders
    body: bytes


def _parse_header_lines(
    block: bytes,
    *,
    kind: str,
) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    if not block.endswith(HEADER_END):
        raise ICAPError(f"malformed {kind} header block")

    lines = block[:-4].split(CRLF)
    if not lines or not lines[0]:
        raise ICAPError(f"missing {kind} start-line")

    parsed: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line or b":" not in line:
            raise ICAPError(f"malformed {kind} header line")
        name, value = line.split(b":", 1)
        if not name or any(byte <= 32 or byte >= 127 for byte in name):
            raise ICAPError(f"invalid {kind} header name")
        parsed.append((name.lower(), value.strip(b" \t")))

    return lines[0], parsed


def _get_single_header(
    headers: list[tuple[bytes, bytes]],
    name: bytes,
) -> bytes:
    matches = [value for key, value in headers if key == name]
    if len(matches) != 1:
        header_name = name.decode("ascii")
        raise ICAPError(f"exactly one {header_name} header is required")
    return matches[0]


def _validate_request_line(line: bytes) -> None:
    try:
        parts = line.decode("ascii").split()
    except UnicodeDecodeError as exc:
        raise ICAPError("ICAP request-line must be ASCII") from exc

    if len(parts) != 3:
        raise ICAPError("malformed ICAP request-line")

    method, uri, version = parts
    if version != "ICAP/1.0":
        raise ICAPError("only ICAP/1.0 is supported")
    if method != "RESPMOD":
        raise ICAPError("only RESPMOD is supported", 405, "Method Not Allowed")

    try:
        parsed_uri = urlsplit(uri)
    except ValueError as exc:
        raise ICAPError("malformed ICAP service URI") from exc

    if parsed_uri.path != "/decrypt":
        raise ICAPError("unknown ICAP service", 404, "Not Found")


def _parse_encapsulated_offset(value: bytes) -> int:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ICAPError("Encapsulated header must be ASCII") from exc

    parts = [part.strip() for part in text.split(",")]
    if len(parts) != 2:
        raise ICAPError("expected Encapsulated: res-hdr=0, res-body=N")

    expected = ("res-hdr", "res-body")
    values: list[int] = []
    for part, field_name in zip(parts, expected):
        if "=" not in part:
            raise ICAPError("malformed Encapsulated header")
        name, number = (piece.strip() for piece in part.split("=", 1))
        if name != field_name or not number.isdecimal():
            raise ICAPError("expected Encapsulated: res-hdr=0, res-body=N")
        values.append(int(number))

    if values[0] != 0 or values[1] <= 0:
        raise ICAPError("res-hdr must be 0 and res-body must be positive")
    if values[1] > MAX_HTTP_HEADER_BYTES:
        raise PayloadTooLarge(
            "encapsulated HTTP headers exceed the configured limit"
        )

    return values[1]


def read_chunked_body(reader: SocketBuffer, max_body_size: int) -> bytes:
    """Собрать тело ICAP из chunks; границы chunks не несут смысла."""
    chunks: list[bytes] = []
    total = 0

    for _ in range(MAX_CHUNKS):
        line = reader.read_line(MAX_CHUNK_LINE_BYTES)
        if not line or not _HEX_RE.fullmatch(line):
            # Расширения chunks не поддерживаются в рамках задания.
            raise ICAPError(
                "invalid ICAP chunk-size line or unsupported chunk extension"
            )

        size = int(line, 16)
        if size == 0:
            # Прочитать необязательные trailer-поля до пустой строки,
            # завершающей секцию trailers. Сервис эти поля не использует.
            trailer_total = 0
            while True:
                trailer = reader.read_line(MAX_TRAILER_BYTES - trailer_total)
                trailer_total += len(trailer) + 2
                if trailer_total > MAX_TRAILER_BYTES:
                    raise PayloadTooLarge("ICAP trailer section is too large")
                if not trailer:
                    return b"".join(chunks)
                if b":" not in trailer:
                    raise ICAPError("malformed ICAP trailer field")

        if size > max_body_size - total:
            raise PayloadTooLarge(
                "ICAP body exceeds the configured size limit"
            )

        chunk = reader.read_exactly(size)
        if reader.read_exactly(2) != CRLF:
            raise ICAPError("ICAP chunk data must be followed by CRLF")

        chunks.append(chunk)
        total += size

    raise ICAPError("too many ICAP chunks")


def read_respmod_request(
    reader: SocketBuffer,
    max_body_size: int,
) -> ICAPRequest:
    """Прочитать ограниченный запрос RESPMOD из буферизованного TCP-потока."""
    icap_header_block = reader.read_until(HEADER_END, MAX_ICAP_HEADER_BYTES)
    request_line, icap_headers = _parse_header_lines(
        icap_header_block,
        kind="ICAP",
    )
    _validate_request_line(request_line)

    encapsulated = _get_single_header(icap_headers, b"encapsulated")
    http_header_length = _parse_encapsulated_offset(encapsulated)
    http_header_block = reader.read_exactly(http_header_length)
    http_headers = parse_http_response_headers(
        http_header_block,
        max_body_size,
    )

    body = read_chunked_body(reader, max_body_size)
    if len(body) != http_headers.content_length:
        raise ICAPError(
            f"HTTP Content-Length is {http_headers.content_length}, "
            f"but ICAP body contains {len(body)} bytes"
        )

    return ICAPRequest(http_headers=http_headers, body=body)


def encode_chunked_body(body: bytes, chunk_size: int = 16 * 1024) -> bytes:
    """Закодировать байты в обязательный chunked-формат ICAP body."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    encoded: list[bytes] = []
    for offset in range(0, len(body), chunk_size):
        chunk = body[offset:offset + chunk_size]
        encoded.extend(
            (f"{len(chunk):X}".encode("ascii"), CRLF, chunk, CRLF)
        )
    encoded.append(b"0\r\n\r\n")
    return b"".join(encoded)


def _validate_istag(istag: str) -> bytes:
    try:
        istag_bytes = istag.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("ISTag must be ASCII") from exc

    if not istag or len(istag_bytes) > 32 or not istag.isalnum():
        raise ValueError("ISTag must be 1..32 alphanumeric ASCII characters")

    return istag_bytes


def build_success_response(
    http_header_block: bytes,
    body: bytes,
    istag: str,
) -> bytes:
    """Собрать ответ ICAP 200 с encapsulated HTTP-ответом."""
    istag_bytes = _validate_istag(istag)
    offset = len(http_header_block)
    encapsulated_header = (
        b"Encapsulated: res-hdr=0, res-body="
        + str(offset).encode("ascii")
        + CRLF
    )
    icap_headers = (
        b"ICAP/1.0 200 OK\r\n"
        + b'ISTag: "' + istag_bytes + b'"\r\n'
        + b"Connection: close\r\n"
        + encapsulated_header
        + CRLF
    )
    return icap_headers + http_header_block + encode_chunked_body(body)


def build_error_response(
    status_code: int,
    reason: str,
    istag: str,
) -> bytes:
    """Собрать ответ ICAP с ошибкой и обязательным заголовком ISTag."""
    istag_bytes = _validate_istag(istag)
    reason_bytes = reason.encode("ascii", errors="replace")

    return (
        b"ICAP/1.0 "
        + str(status_code).encode("ascii")
        + b" "
        + reason_bytes
        + CRLF
        + b'ISTag: "'
        + istag_bytes
        + b'"\r\n'
        + b"Connection: close\r\n"
        + b"Encapsulated: null-body=0\r\n"
        + CRLF
    )
