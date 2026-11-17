"""Специализированные исключения, используемые реализацией ICAP."""


class ICAPError(Exception):
    """Ошибка, о которой можно сообщить ICAP-клиенту."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        reason: str = "Bad Request",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason


class IncompleteRead(ICAPError):
    """Удалённая сторона закрыла TCP-поток до получения полного элемента."""


class InvalidContainer(ICAPError):
    """Контейнер ENC1 имеет неверный формат или не прошёл проверку AES-GCM."""


class PayloadTooLarge(ICAPError):
    """Размер запроса превышает установленное ограничение."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=413, reason="Payload Too Large")
