FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml .
COPY pipeline/ pipeline/
COPY tests/ tests/
RUN pip install --no-cache-dir -e ".[dev]" pyarrow duckdb paramiko boto3

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends unixodbc && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

EXPOSE 5000

ENTRYPOINT ["python", "-m", "pipeline"]
