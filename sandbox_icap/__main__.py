"""Точка входа для запуска ICAP-сервера из командной строки."""

from __future__ import annotations

import argparse
import logging

from .server import ICAPServer

LOGGER = logging.getLogger(__name__)


def build_argument_parser() -> argparse.ArgumentParser:
    """Создать парсер аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description="Run the ICAP RESPMOD /decrypt server"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="address to bind (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1344,
        help="TCP port (default: 1344)",
    )
    parser.add_argument(
        "--socket-timeout",
        type=float,
        default=10.0,
        help="per-connection socket timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--max-body-size",
        type=int,
        default=64 * 1024 * 1024,
        help="maximum HTTP body size in bytes (default: 67108864)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    return parser


def main() -> None:
    """Настроить сервер и запустить основной цикл приёма соединений."""
    args = build_argument_parser().parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    server = ICAPServer(
        host=args.host,
        port=args.port,
        socket_timeout=args.socket_timeout,
        max_body_size=args.max_body_size,
    )
    server.start()
    try:
        LOGGER.info("Ready at %s:%s", *server.address)
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Stopping ICAP server")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
