"""Разбор и минимальное преобразование encapsulated HTTP-ответов."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import ICAPError, PayloadTooLarge

CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"
_TOKEN_RE = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


@dataclass(frozen=True)
class HTTPResponseHeaders:
    header_block: bytes
    content_length: int
    content_length_line_index: int
    lines: tuple[bytes, ...]


def parse_http_response_headers(
    header_block: bytes,
    max_body_size: int,
) -> HTTPResponseHeaders:
    """Проверить заголовки HTTP-ответа, сохранив их исходное представление."""
    if not header_block.endswith(HEADER_END):
        raise ICAPError(
            "encapsulated HTTP headers must end with CRLF CRLF"
        )

    lines = header_block[:-4].split(CRLF)
    if not lines or not lines[0]:
        raise ICAPError("missing HTTP status line")

    status_parts = lines[0].split(b" ", 2)
    supported_versions = (b"HTTP/1.0", b"HTTP/1.1")
    if len(status_parts) < 2 or status_parts[0] not in supported_versions:
        raise ICAPError("unsupported or malformed HTTP status line")
    if len(status_parts[1]) != 3 or not status_parts[1].isdigit():
        raise ICAPError("malformed HTTP status code")

    content_lengths: list[tuple[int, bytes]] = []
    for index, line in enumerate(lines[1:], start=1):
        if not line or b":" not in line:
            raise ICAPError("malformed HTTP header line")
        name, value = line.split(b":", 1)
        if not _TOKEN_RE.fullmatch(name):
            raise ICAPError("invalid HTTP header name")

        lower_name = name.lower()
        if lower_name == b"content-length":
            content_lengths.append((index, value.strip(b" \t")))
        elif lower_name == b"transfer-encoding":
            raise ICAPError(
                "HTTP Transfer-Encoding is outside this assignment's scope"
            )

    if len(content_lengths) != 1:
        raise ICAPError("exactly one HTTP Content-Length header is required")

    line_index, raw_length = content_lengths[0]
    if not raw_length or not raw_length.isdigit():
        raise ICAPError(
            "HTTP Content-Length must be a non-negative decimal integer"
        )

    content_length = int(raw_length)
    if content_length > max_body_size:
        raise PayloadTooLarge(
            "HTTP Content-Length exceeds the configured body limit"
        )

    return HTTPResponseHeaders(
        header_block=header_block,
        content_length=content_length,
        content_length_line_index=line_index,
        lines=tuple(lines),
    )


def replace_content_length(
    headers: HTTPResponseHeaders,
    new_length: int,
) -> bytes:
    """Вернуть те же HTTP-заголовки, изменив только Content-Length."""
    if new_length < 0:
        raise ValueError("new_length must be non-negative")

    lines = list(headers.lines)
    lines[headers.content_length_line_index] = (
        b"Content-Length: " + str(new_length).encode("ascii")
    )
    return CRLF.join(lines) + HEADER_END
