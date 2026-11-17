# Sandbox ICAP Server

## Описание

Простой ICAP-сервер на Python, реализующий метод RESPMOD.

Сервер принимает HTTP-ответы, проверяет наличие зашифрованного контейнера ENC1 и при необходимости расшифровывает его с помощью AES-256-GCM.

## Возможности

- Поддержка ICAP/1.0 RESPMOD.
- Обработка ICAP chunks.
- Расшифровка ENC1.
- Проверка целостности данных AES-GCM.
- Обновление Content-Length.
- Обработка ошибок.
- Автоматические тесты с pytest.
- Запуск через Docker.

## Требования

- Python 3.10+
- cryptography
- pytest

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Запуск

```bash
python -m sandbox_icap
```

По умолчанию сервер слушает порт `1344`.

## Тестирование

```bash
pytest -v
```

## Docker

Сборка:

```bash
docker build -t sandbox-icap .
```

Запуск:

```bash
docker run --rm -p 1344:1344 sandbox-icap
```

## Структура проекта

```text
sandbox_icap/
tests/
Dockerfile
README.md
README.ru.md
requirements.txt
requirements-dev.txt
pyproject.toml
```

## Документация

[ICAP RFC 3507](https://www.rfc-editor.org/rfc/rfc3507)