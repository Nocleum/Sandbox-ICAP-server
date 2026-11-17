"""Буферизованное чтение TCP."""

from __future__ import annotations

import socket

from .errors import IncompleteRead, PayloadTooLarge


class SocketBuffer:
    """Буферизованное чтение фиксированного объёма и до разделителя."""

    def __init__(self, sock: socket.socket, recv_size: int = 8192) -> None:
        self._sock = sock
        self._recv_size = recv_size
        self._buffer = bytearray()

    def _fill(self) -> None:
        chunk = self._sock.recv(self._recv_size)
        if not chunk:
            raise IncompleteRead("unexpected EOF while reading request")
        self._buffer.extend(chunk)

    def read_until(self, delimiter: bytes, max_bytes: int) -> bytes:
        """Прочитать данные до разделителя и включить его в результат."""
        if not delimiter:
            raise ValueError("delimiter must not be empty")

        while True:
            index = self._buffer.find(delimiter)
            if index >= 0:
                end = index + len(delimiter)
                if end > max_bytes:
                    raise PayloadTooLarge(
                        "protocol line or header block is too large"
                    )
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result

            if len(self._buffer) >= max_bytes:
                raise PayloadTooLarge(
                    "protocol line or header block is too large"
                )
            self._fill()

    def read_line(self, max_bytes: int = 8192) -> bytes:
        """Прочитать строку до CRLF, не включая байты разделителя."""
        return self.read_until(b"\r\n", max_bytes)[:-2]

    def read_exactly(self, count: int) -> bytes:
        """Прочитать ровно count байтов или вызвать IncompleteRead при EOF."""
        if count < 0:
            raise ValueError("count must be non-negative")

        while len(self._buffer) < count:
            self._fill()

        result = bytes(self._buffer[:count])
        del self._buffer[:count]
        return result
