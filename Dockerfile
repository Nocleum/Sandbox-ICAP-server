FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sandbox_icap ./sandbox_icap
RUN pip install --no-cache-dir .

EXPOSE 1344
CMD ["python", "-m", "sandbox_icap", "--host", "0.0.0.0", "--port", "1344"]
