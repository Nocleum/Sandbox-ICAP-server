from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest

from sandbox_icap import ICAPServer


@pytest.fixture
def running_server() -> Iterator[tuple[str, int]]:
    """Запустить сервер на свободном порту и остановить его после теста."""
    server = ICAPServer(host="127.0.0.1", port=0, socket_timeout=3.0)
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.address

    try:
        yield host, port
    finally:
        server.shutdown()
        thread.join(timeout=2.0)
        assert not thread.is_alive(), "ICAP server thread did not stop"
