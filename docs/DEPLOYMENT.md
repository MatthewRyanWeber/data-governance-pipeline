# Deployment Guide

Production deployment reference for the data-governance-pipeline REST API
and CLI.

Revision history
---
1.0   2026-06-09   Initial release.

---

## 1. Instance Sizing

The pipeline processes data in chunks of `DEFAULT_CHUNK_SIZE` (50,000 rows).
Memory usage scales linearly with chunk size and column count.

| Profile | vCPU | RAM   | Disk  | Throughput          | Use case                       |
|---------|------|-------|-------|---------------------|--------------------------------|
| Small   | 2    | 4 GB  | 20 GB | ~500K rows/hour    | Dev/staging, single-source     |
| Medium  | 4    | 16 GB | 100 GB| ~2M rows/hour      | Production, multi-source       |
| Large   | 8+   | 32 GB | 500 GB| ~5M+ rows/hour     | High-volume, parallel loaders  |

**Disk notes:**
- Compressed archives can expand 5-10x on extraction. The pipeline enforces
  `PIPELINE_MAX_DECOMPRESSED_SIZE` (default 1 GB) as a safety cap.
- Dead letter queue, checkpoints, and run ledger consume disk over time.
  Schedule periodic cleanup or mount a separate volume for `data/`.
- SQLite files (rate limiting, JWT revocation) are small (<10 MB) but
  require write access to their parent directory for WAL journals.

---

## 2. TLS Configuration

The API listens on `0.0.0.0:5000` (HTTP) by default. Always terminate TLS
at a reverse proxy in production.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name pipeline.example.com;

    ssl_certificate     /etc/ssl/certs/pipeline.pem;
    ssl_certificate_key /etc/ssl/private/pipeline.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

### Caddy

```
pipeline.example.com {
    reverse_proxy 127.0.0.1:5000
}
```

Caddy provisions TLS certificates automatically via Let's Encrypt.

---

## 3. Database Permission Matrix

Each loader requires specific minimum grants on the target database.
This table covers the 37 relational/warehouse destinations. Vector
database and file-based loaders have separate requirements noted below.

| Loader             | db_type key        | Minimum Grants                                          |
|--------------------|--------------------|---------------------------------------------------------|
| SQLLoader          | sqlite             | Read/write access to the database file                  |
| SQLLoader          | postgresql/postgres| CONNECT, CREATE, INSERT, SELECT on target schema        |
| SQLLoader          | mysql              | CREATE, INSERT, SELECT on target database               |
| SQLLoader          | mssql              | CREATE TABLE, INSERT, SELECT on target schema           |
| SnowflakeLoader    | snowflake          | USAGE on warehouse/db/schema, CREATE TABLE, INSERT      |
| BigQueryLoader     | bigquery           | bigquery.tables.create, bigquery.tables.updateData      |
| RedshiftLoader     | redshift           | CREATE, INSERT on schema; S3 read via IAM role or keys  |
| SynapseLoader      | synapse            | CREATE TABLE, INSERT, SELECT on target schema           |
| DatabricksLoader   | databricks         | USE CATALOG/SCHEMA, CREATE TABLE, INSERT                |
| ClickHouseLoader   | clickhouse         | CREATE TABLE, INSERT on target database                 |
| OracleLoader       | oracle             | CREATE TABLE, INSERT, SELECT on target schema           |
| Db2Loader          | db2                | CREATETAB, INSERT on target schema                      |
| FireboltLoader     | firebolt           | CREATE TABLE, INSERT on target database                 |
| YellowbrickLoader  | yellowbrick        | CREATE, INSERT on target schema                         |
| HanaLoader         | hana               | CREATE TABLE, INSERT, SELECT on target schema           |
| DatasphereLoader   | datasphere         | CREATE TABLE, INSERT on target space                    |
| MongoLoader        | mongodb            | readWrite role on target database                       |
| CockroachDBLoader  | cockroachdb        | CREATE, INSERT, SELECT on target database               |
| DuckDBLoader       | duckdb/motherduck  | Read/write access to the database file                  |
| ParquetLoader      | parquet            | Write access to output directory                        |
| DeltaLakeLoader    | deltalake          | Write access to table path (local or cloud storage)     |
| IcebergLoader      | iceberg            | Write access to warehouse path + catalog permissions    |
| S3Loader           | s3                 | s3:PutObject, s3:GetObject on target bucket/prefix      |
| AthenaLoader       | athena             | Athena query + S3 write on results/staging location     |
| SFTPLoader         | sftp               | Write access to target directory on remote host         |
| MicrosoftFabricLoader | fabric          | Lakehouse write permissions in target workspace         |
| PostGISLoader      | postgis            | CREATE TABLE, INSERT, SELECT + PostGIS extension        |
| KafkaLoader        | kafka              | Produce permission on target topic                      |
| QuickBooksLoader   | quickbooks         | OAuth2 token with accounting write scope                |

**Vector databases:**

| Loader                  | db_type key       | Requirements                                    |
|-------------------------|-------------------|-------------------------------------------------|
| LanceDBLoader           | lancedb           | Write access to local directory                 |
| PgvectorLoader          | pgvector          | CREATE TABLE, INSERT + pgvector extension       |
| SnowflakeVectorLoader   | snowflake_vector  | Same as Snowflake + vector type support         |
| BigQueryVectorLoader    | bigquery_vector   | Same as BigQuery                                |
| ChromaLoader            | chroma            | Collection create/write permissions             |
| MilvusLoader            | milvus            | Collection create/insert permissions            |
| PineconeLoader          | pinecone          | API key with upsert permission on target index  |
| WeaviateLoader          | weaviate          | Class create/write permissions                  |
| QdrantLoader            | qdrant            | Collection create/upsert permissions            |

---

## 4. Environment Variables

All configuration is via environment variables. None are required for CLI
usage; the API requires at least `PIPELINE_API_KEYS` to enable auth.

### Core

| Variable                        | Required | Default        | Description                                         |
|---------------------------------|----------|----------------|-----------------------------------------------------|
| `PIPELINE_API_KEYS`             | API only | (empty)        | Comma-separated static API keys for authentication  |
| `PIPELINE_JWT_SECRET`           | No       | (unset)        | 32+ char secret for JWT auth. Enables `/auth/token` |
| `PIPELINE_JWT_REVOCATION_DB`    | No       | (in-memory)    | SQLite path for persistent JWT revocation            |
| `PIPELINE_RATE_LIMIT_DB`        | No       | (in-memory)    | SQLite path for persistent API rate limiting         |
| `PIPELINE_MAX_QUEUE_SIZE`       | No       | `0`            | Max queued pipeline runs (0 = reject when busy)      |
| `PIPELINE_MAX_DECOMPRESSED_SIZE`| No       | `1073741824`   | Max decompressed archive size in bytes (1 GB)        |
| `PIPELINE_CONTAINER`            | No       | (unset)        | Set to any value for container-optimized JSON logging|

### Observability

| Variable                        | Required | Default   | Description                                       |
|---------------------------------|----------|-----------|---------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`  | No       | (unset)   | OTLP gRPC endpoint (e.g. `http://localhost:4317`) |

### Cloud Credentials (loader-specific)

| Variable              | Used by         | Description                          |
|-----------------------|-----------------|--------------------------------------|
| `REDSHIFT_IAM_ROLE`   | RedshiftLoader | IAM role ARN for COPY commands       |
| `AWS_ACCESS_KEY_ID`    | RedshiftLoader, S3Loader | AWS access key          |
| `AWS_SECRET_ACCESS_KEY`| RedshiftLoader, S3Loader | AWS secret key          |

### Auto-detected (do not set manually)

| Variable                  | Description                                      |
|---------------------------|--------------------------------------------------|
| `KUBERNETES_SERVICE_HOST` | Detected by logging setup for container mode     |

---

## 5. Docker Production Config

```yaml
# docker-compose.prod.yml
version: "3.9"

services:
  pipeline-api:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      - PIPELINE_API_KEYS=${PIPELINE_API_KEYS}
      - PIPELINE_JWT_SECRET=${PIPELINE_JWT_SECRET}
      - PIPELINE_JWT_REVOCATION_DB=/data/revocation.db
      - PIPELINE_RATE_LIMIT_DB=/data/rate_limit.db
      - PIPELINE_MAX_QUEUE_SIZE=5
      - PIPELINE_CONTAINER=1
      - OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
    volumes:
      - pipeline-data:/data
      - ./config:/app/config:ro
    deploy:
      resources:
        limits:
          cpus: "4.0"
          memory: 16G
        reservations:
          cpus: "2.0"
          memory: 4G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"

volumes:
  pipeline-data:
    driver: local
```

**Notes:**
- Mount `/data` as a persistent volume for SQLite databases and checkpoints.
- Config files are read-only mounted at `/app/config`.
- The health check hits the unauthenticated `/health` endpoint.
- Resource limits match the "Medium" sizing profile. Adjust for your workload.

---

## 6. Upgrade Procedure

1. **Back up state files:**
   ```bash
   cp -r data/ data.bak.$(date +%Y%m%d)
   ```

2. **Pull the new version:**
   ```bash
   git pull origin main
   pip install -r requirements.txt
   ```

3. **Run the test suite:**
   ```bash
   python -m pytest tests/ -q --tb=short -m "not slow and not integration"
   ```

4. **Restart the service:**
   ```bash
   # Docker
   docker compose -f docker-compose.prod.yml up -d --build

   # Systemd
   sudo systemctl restart pipeline-api
   ```

5. **Verify health:**
   ```bash
   curl -f http://localhost:5000/health
   # Expected: {"status": "healthy", "timestamp": "..."}
   ```

6. **Rollback if unhealthy:**
   ```bash
   git checkout <previous-tag>
   pip install -r requirements.txt
   docker compose -f docker-compose.prod.yml up -d --build
   # or: sudo systemctl restart pipeline-api
   ```

---

## 7. Troubleshooting

### `ConfigValidationError` on startup

The pipeline config is invalid. Check:
- Required fields: `source`, `destination`, `destination_type`
- Valid `destination_type` must match a key in the loader dispatch table
  (see section 3)
- Connection strings must be syntactically valid

### "SDK not installed" / `HAS_X is False`

The pipeline uses optional imports for destination-specific drivers.
Install the missing package:

```bash
# Examples
pip install snowflake-connector-python   # HAS_SNOWFLAKE
pip install google-cloud-bigquery        # HAS_BIGQUERY
pip install redshift-connector           # HAS_REDSHIFT
pip install pyodbc                       # HAS_SYNAPSE
pip install clickhouse-driver            # HAS_CLICKHOUSE
pip install cx_Oracle                    # HAS_ORACLE
pip install ibm_db_sa                    # HAS_DB2
pip install pyhdb                        # HAS_HANA
pip install PyJWT                        # HAS_JWT (for API auth)
```

### HTTP 429 — Rate Limited

The API enforces 100 requests per 60 seconds per API key by default.
Wait for the window to expire, or increase limits by adjusting the
`max_requests` / `window_seconds` parameters in your deployment config.

If rate limits reset unexpectedly after restart, set `PIPELINE_RATE_LIMIT_DB`
to persist them in SQLite.

### HTTP 401 — JWT Errors

| Error message              | Cause                        | Fix                                     |
|----------------------------|------------------------------|------------------------------------------|
| "Signature has expired"    | Token past its `exp` claim   | Request a new token via `/auth/token`    |
| "Token X has been revoked" | Token JTI in revocation list | Request a new token                      |
| "Invalid token"            | Malformed or wrong secret    | Check `PIPELINE_JWT_SECRET` matches      |
| 501 on `/auth/token`       | JWT not enabled              | Set `PIPELINE_JWT_SECRET` env var        |

### Ledger tamper detection

The governance logger computes SHA-256 chain hashes. If a hash mismatch
is detected, the ledger file has been modified outside the pipeline.
Restore from backup or re-run the affected pipeline segment.

### Watchdog restart storms

If the API restarts repeatedly under a process supervisor (systemd,
Docker restart policy), check:
- Port 5000 is not already in use (`lsof -i :5000` / `netstat -tlnp`)
- SQLite database files are writable (check filesystem permissions)
- Sufficient memory — OOM kills show in `dmesg` or Docker logs
- Hypercorn is installed (`pip install hypercorn`) — without it, the
  fallback dev server is not suitable for production
