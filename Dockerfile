FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml .
COPY pipeline/ pipeline/
COPY tests/ tests/
RUN pip install --no-cache-dir -e ".[dev]"

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

EXPOSE 5000

ENTRYPOINT ["python", "-m", "pipeline"]
