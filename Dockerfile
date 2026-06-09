# Stage 1: builder — install production dependencies only
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends unixodbc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY pipeline/ pipeline/
RUN pip install --no-cache-dir ".[api]" pyarrow duckdb paramiko boto3

# Stage 2: test — add dev deps + tests, run tests (used by CI via --target test)
FROM builder AS test

RUN pip install --no-cache-dir ".[dev]"
COPY tests/ tests/
RUN python -m pytest tests/ -q --tb=short \
    --ignore=tests/test_extensions \
    --ignore=tests/test_loaders/test_loader_dispatch.py

# Stage 3: runtime — minimal production image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends unixodbc \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system appuser && useradd --system --gid appuser appuser

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY pyproject.toml .
COPY pipeline/ pipeline/

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

EXPOSE 5000

ENTRYPOINT ["python", "-m", "pipeline.api"]
