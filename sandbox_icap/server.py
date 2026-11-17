"""TCP-сервер для сценария ICAP RESPMOD /decrypt из тестового задания."""

from __future__ import annotations

import logging
import socket
import threading

from .crypto import TEST_KEY, decrypt_enc1_body
from .errors import ICAPError
from .http_message import replace_content_length
from .icap_protocol import (
    build_error_response,
    build_success_response,
    read_respmod_request,
)
from .stream import SocketBuffer

LOGGER = logging.getLogger(__name__)
DEFAULT_ISTAG = "sandboxqav1"


class ICAPServer:
    """Небольшой последовательный TCP-сервер ICAP.

    Сервер обрабатывает один ICAP-запрос на соединение и затем закрывает
    его согласно требованию Connection: close. Параллельная обработка и
    постоянные соединения выходят за рамки задания.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1344,
        *,
        key: bytes = TEST_KEY,
        istag: str = DEFAULT_ISTAG,
        socket_timeout: float = 10.0,
        max_body_size: int = 64 * 1024 * 1024,
    ) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes")
        if not (0 <= port <= 65535):
            raise ValueError("port must be between 0 and 65535")
        if socket_timeout <= 0:
            raise ValueError("socket_timeout must be positive")
        if max_body_size < 0:
            raise ValueError("max_body_size must be non-negative")
        if (
            not istag.isascii()
            or not istag.isalnum()
            or not (1 <= len(istag) <= 32)
        ):
            raise ValueError(
                "ISTag must be 1..32 alphanumeric ASCII characters"
            )

        self.host = host
        self.port = port
        self.key = key
        self.istag = istag
        self.socket_timeout = socket_timeout
        self.max_body_size = max_body_size
        self._listener: socket.socket | None = None
        self._stop_event = threading.Event()

    @property
    def address(self) -> tuple[str, int]:
        """Вернуть адрес привязки; доступен после вызова start()."""
        if self._listener is None:
            raise RuntimeError("server has not been started")

        host, port = self._listener.getsockname()[:2]
        return str(host), int(port)

    def start(self) -> None:
        """Выполнить bind и listen; метод отделён для удобства тестирования."""
        if self._listener is not None:
            raise RuntimeError("server is already started")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self.port))
            listener.listen(64)
            listener.settimeout(0.2)
        except Exception:
            listener.close()
            raise

        self._listener = listener
        LOGGER.info("ICAP server listening on %s:%s", *self.address)

    def serve_forever(self) -> None:
        """Принимать и обрабатывать соединения до вызова shutdown()."""
        if self._listener is None:
            raise RuntimeError("call start() before serve_forever()")

        while not self._stop_event.is_set():
            try:
                connection, peer = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                LOGGER.exception("Error while accepting a TCP connection")
                continue

            LOGGER.debug("Accepted connection from %s:%s", *peer[:2])
            with connection:
                connection.settimeout(self.socket_timeout)
                self._handle_connection(connection)

    def shutdown(self) -> None:
        """Прекратить приём соединений и закрыть слушающий сокет."""
        self._stop_event.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                LOGGER.debug(
                    "Ignoring error while closing listening socket",
                    exc_info=True,
                )

    close = shutdown

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            request = read_respmod_request(
                SocketBuffer(connection),
                self.max_body_size,
            )
            response_body = request.body
            response_headers = request.http_headers.header_block

            if response_body.startswith(b"ENC1"):
                response_body = decrypt_enc1_body(response_body, self.key)
                response_headers = replace_content_length(
                    request.http_headers,
                    len(response_body),
                )

            response = build_success_response(
                response_headers,
                response_body,
                self.istag,
            )
            connection.sendall(response)
        except ICAPError as exc:
            LOGGER.info("Returning ICAP %s: %s", exc.status_code, exc)
            self._send_error(connection, exc.status_code, exc.reason)
        except (socket.timeout, TimeoutError):
            LOGGER.info("Client timed out while sending an ICAP request")
            self._send_error(connection, 408, "Request Timeout")
        except (BrokenPipeError, ConnectionResetError):
            LOGGER.debug("Client disconnected before response could be sent")
        except Exception:
            # Неожиданные ошибки реализации или среды — это ошибки сервера,
            # а не ошибки формата контейнера. Цикл приёма должен продолжиться.
            LOGGER.exception("Unexpected error while processing ICAP request")
            self._send_error(connection, 500, "Internal Server Error")

    def _send_error(
        self,
        connection: socket.socket,
        code: int,
        reason: str,
    ) -> None:
        try:
            connection.sendall(
                build_error_response(code, reason, self.istag)
            )
        except OSError:
            LOGGER.debug("Could not send ICAP error response", exc_info=True)
