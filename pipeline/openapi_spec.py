"""
OpenAPI 3.0 specification and Swagger UI for the Data Governance Pipeline API.

Provides:
  - ``get_openapi_spec()`` — returns the full OpenAPI 3.0 dict
  - ``register_docs_routes(app)`` — adds ``/docs`` and ``/openapi.json`` to Quart

Layer 6 — no pipeline logic, only metadata.

Revision history
────────────────
1.0   2026-06-09   Initial OpenAPI specification with Swagger UI.
1.1   2026-06-09   Updated error/status schemas for structured error responses and progress.
1.2   2026-06-09   Added config validation error example to /run 400 response.
1.3   2026-06-09   Added /auth/token, /auth/revoke endpoints and JWTAuth scheme.
1.4   2026-06-09   Migrated Flask imports to Quart.
1.5   2026-06-09   Fixed docstring: Flask → Quart.
"""

import logging

from pipeline.constants import VERSION

logger = logging.getLogger(__name__)


def get_openapi_spec() -> dict:
    """
    Build and return the full OpenAPI 3.0 specification as a Python dict.

    The spec documents every endpoint exposed by ``create_app``, including
    authentication requirements, request/response schemas, and error codes.
    """
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Data Governance Pipeline API",
            "description": (
                "GDPR/CCPA-compliant ETL pipeline REST API.\n\n"
                "Trigger pipeline runs, monitor execution status, collect metrics, "
                "and verify service health. Pipeline execution is asynchronous — "
                "POST /run returns immediately with a run ID, and you poll /status "
                "for completion.\n\n"
                "**Authentication:** Most endpoints require an API key passed via "
                "the `X-API-Key` header or `Authorization: Bearer <key>` header. "
                "Keys are configured through the `PIPELINE_API_KEYS` environment "
                "variable (comma-separated). If no keys are configured, "
                "authentication is disabled.\n\n"
                "**Rate limiting:** Authenticated endpoints enforce a token-bucket "
                "rate limit of 100 requests per 60-second window per API key."
            ),
            "version": VERSION,
            "contact": {
                "name": "Pipeline Maintainers",
            },
            "license": {
                "name": "Proprietary",
            },
        },
        "servers": [
            {
                "url": "/",
                "description": "Current server",
            },
        ],
        "tags": [
            {
                "name": "Pipeline",
                "description": "Trigger and monitor pipeline runs.",
            },
            {
                "name": "Observability",
                "description": "Health checks and execution metrics.",
            },
            {
                "name": "Auth",
                "description": "JWT token creation and revocation.",
            },
            {
                "name": "Documentation",
                "description": "API documentation and OpenAPI spec.",
            },
        ],
        "paths": {
            "/run": {
                "post": {
                    "tags": ["Pipeline"],
                    "summary": "Trigger a pipeline run",
                    "description": (
                        "Start an asynchronous pipeline execution. The pipeline "
                        "processes data from the given source through all governance "
                        "stages (extraction, PII detection, quality checks, "
                        "transformation) and loads into the destination.\n\n"
                        "Only one run may execute at a time. If a run is already in "
                        "progress, the request is rejected with 409 Conflict."
                    ),
                    "operationId": "triggerPipelineRun",
                    "security": [{"ApiKeyHeader": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/RunRequest"},
                                "examples": {
                                    "sqlite": {
                                        "summary": "Load CSV into SQLite",
                                        "value": {
                                            "source": "data/input.csv",
                                            "destination": "sqlite",
                                            "config": {
                                                "table": "pipeline_output",
                                            },
                                        },
                                    },
                                    "postgresql": {
                                        "summary": "Load Parquet into PostgreSQL",
                                        "value": {
                                            "source": "s3://bucket/data.parquet",
                                            "destination": "postgresql",
                                            "config": {
                                                "connection_string": "postgresql://user:pass@host/db",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "responses": {
                        "202": {
                            "description": "Pipeline run accepted and started.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/RunAccepted"},
                                },
                            },
                        },
                        "400": {
                            "description": "Invalid request — missing or malformed parameters.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "examples": {
                                        "missing_fields": {
                                            "summary": "Missing required fields",
                                            "value": {
                                                "error": {
                                                    "code": "missing_fields",
                                                    "message": "Both 'source' and 'destination' are required.",
                                                    "request_id": "req_8f3a1b2c4d5e",
                                                },
                                            },
                                        },
                                        "bad_type": {
                                            "summary": "Wrong parameter type",
                                            "value": {
                                                "error": {
                                                    "code": "invalid_type",
                                                    "message": "'source' and 'destination' must be strings.",
                                                    "request_id": "req_a1b2c3d4e5f6",
                                                },
                                            },
                                        },
                                        "unknown_destination": {
                                            "summary": "Unsupported destination",
                                            "value": {
                                                "error": {
                                                    "code": "unknown_destination",
                                                    "message": "Unknown destination 'nosql'.",
                                                    "request_id": "req_f6e5d4c3b2a1",
                                                    "valid_destinations": [
                                                        "bigquery", "clickhouse", "mongodb",
                                                        "postgresql", "sqlite", "snowflake",
                                                    ],
                                                },
                                            },
                                        },
                                        "invalid_config": {
                                            "summary": "Missing required config keys",
                                            "value": {
                                                "error": {
                                                    "code": "invalid_config",
                                                    "message": "Invalid config for 'postgresql': missing required key(s): host",
                                                    "request_id": "req_b2c3d4e5f6a1",
                                                    "db_type": "postgresql",
                                                    "missing_keys": ["host"],
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "401": {
                            "description": "Missing or invalid API key.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "unauthorized",
                                            "message": "Unauthorized. Provide a valid API key.",
                                            "request_id": "req_a1b2c3d4e5f6",
                                        },
                                    },
                                },
                            },
                        },
                        "409": {
                            "description": "A pipeline run is already in progress.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ConflictError"},
                                },
                            },
                        },
                        "429": {
                            "description": "Rate limit exceeded.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "rate_limit_exceeded",
                                            "message": "Rate limit exceeded. Try again later.",
                                            "request_id": "req_c3d4e5f6a1b2",
                                        },
                                    },
                                },
                            },
                        },
                        "501": {
                            "description": "No pipeline function configured on the server.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "not_configured",
                                            "message": "No pipeline function configured.",
                                            "request_id": "req_d4e5f6a1b2c3",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/status": {
                "get": {
                    "tags": ["Pipeline"],
                    "summary": "Get pipeline run status",
                    "description": (
                        "Returns the current state of the pipeline — whether it is "
                        "idle, running, completed, or failed. Includes timestamps "
                        "and error details if the last run failed."
                    ),
                    "operationId": "getPipelineStatus",
                    "security": [{"ApiKeyHeader": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Current pipeline status.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/StatusResponse"},
                                    "examples": {
                                        "idle": {
                                            "summary": "No run has been triggered",
                                            "value": {
                                                "run_id": None,
                                                "status": "idle",
                                                "started_at": None,
                                                "finished_at": None,
                                                "error": None,
                                            },
                                        },
                                        "running": {
                                            "summary": "Pipeline is executing with progress",
                                            "value": {
                                                "run_id": "550e8400-e29b-41d4-a716-446655440000",
                                                "status": "running",
                                                "started_at": "2026-06-09T12:00:00+00:00",
                                                "finished_at": None,
                                                "error": None,
                                                "progress": {
                                                    "last_chunk_completed": 47,
                                                    "total_rows_processed": 2350000,
                                                },
                                            },
                                        },
                                        "completed": {
                                            "summary": "Pipeline finished successfully",
                                            "value": {
                                                "run_id": "550e8400-e29b-41d4-a716-446655440000",
                                                "status": "completed",
                                                "started_at": "2026-06-09T12:00:00+00:00",
                                                "finished_at": "2026-06-09T12:05:30+00:00",
                                                "error": None,
                                            },
                                        },
                                        "failed": {
                                            "summary": "Pipeline run failed",
                                            "value": {
                                                "run_id": "550e8400-e29b-41d4-a716-446655440000",
                                                "status": "failed",
                                                "started_at": "2026-06-09T12:00:00+00:00",
                                                "finished_at": "2026-06-09T12:02:15+00:00",
                                                "error": {
                                                    "message": "Connection refused: postgresql://host:5432/db",
                                                    "type": "LoaderError",
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "401": {
                            "description": "Missing or invalid API key.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "unauthorized",
                                            "message": "Unauthorized. Provide a valid API key.",
                                            "request_id": "req_a1b2c3d4e5f6",
                                        },
                                    },
                                },
                            },
                        },
                        "429": {
                            "description": "Rate limit exceeded.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "rate_limit_exceeded",
                                            "message": "Rate limit exceeded. Try again later.",
                                            "request_id": "req_c3d4e5f6a1b2",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/health": {
                "get": {
                    "tags": ["Observability"],
                    "summary": "Health check",
                    "description": (
                        "Lightweight liveness probe. Returns 200 if the API process "
                        "is running. No authentication required — suitable for load "
                        "balancer and Kubernetes health checks."
                    ),
                    "operationId": "healthCheck",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Service is healthy.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/HealthResponse"},
                                    "example": {
                                        "status": "healthy",
                                        "timestamp": "2026-06-09T12:00:00+00:00",
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/metrics": {
                "get": {
                    "tags": ["Observability"],
                    "summary": "Get pipeline run metrics",
                    "description": (
                        "Returns performance metrics from the most recent pipeline "
                        "run, including wall-clock duration and any result summary "
                        "returned by the pipeline function."
                    ),
                    "operationId": "getPipelineMetrics",
                    "security": [{"ApiKeyHeader": []}, {"BearerAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Latest run metrics.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/MetricsResponse"},
                                    "examples": {
                                        "no_run": {
                                            "summary": "No run has executed yet",
                                            "value": {
                                                "run_id": None,
                                                "metrics": {},
                                            },
                                        },
                                        "completed": {
                                            "summary": "Metrics from a completed run",
                                            "value": {
                                                "run_id": "550e8400-e29b-41d4-a716-446655440000",
                                                "metrics": {
                                                    "duration_s": 330.45,
                                                    "result": "Loaded 12,500 rows into postgresql.",
                                                },
                                            },
                                        },
                                        "failed": {
                                            "summary": "Metrics from a failed run",
                                            "value": {
                                                "run_id": "550e8400-e29b-41d4-a716-446655440000",
                                                "metrics": {
                                                    "duration_s": 15.02,
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                        "401": {
                            "description": "Missing or invalid API key.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "unauthorized",
                                            "message": "Unauthorized. Provide a valid API key.",
                                            "request_id": "req_a1b2c3d4e5f6",
                                        },
                                    },
                                },
                            },
                        },
                        "429": {
                            "description": "Rate limit exceeded.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Error"},
                                    "example": {
                                        "error": {
                                            "code": "rate_limit_exceeded",
                                            "message": "Rate limit exceeded. Try again later.",
                                            "request_id": "req_c3d4e5f6a1b2",
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/auth/token": {
                "post": {
                    "tags": ["Auth"],
                    "summary": "Create a JWT token",
                    "description": (
                        "Exchange an existing API key for a short-lived JWT. "
                        "Requires PIPELINE_JWT_SECRET to be configured on the server."
                    ),
                    "operationId": "createAuthToken",
                    "security": [{"ApiKeyHeader": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "subject": {
                                            "type": "string",
                                            "description": "Subject claim for the JWT.",
                                            "default": "api-client",
                                        },
                                        "expiry_seconds": {
                                            "type": "integer",
                                            "description": "Token lifetime in seconds (60-86400).",
                                            "default": 3600,
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "JWT created.",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/TokenResponse"},
                                },
                            },
                        },
                        "501": {
                            "description": "JWT auth not configured on this server.",
                        },
                    },
                },
            },
            "/auth/revoke": {
                "post": {
                    "tags": ["Auth"],
                    "summary": "Revoke a JWT token",
                    "description": "Revoke a previously issued JWT by its jti claim.",
                    "operationId": "revokeAuthToken",
                    "security": [{"ApiKeyHeader": []}, {"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["jti"],
                                    "properties": {
                                        "jti": {
                                            "type": "string",
                                            "description": "The jti claim from the token to revoke.",
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Token revoked.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "jti": {"type": "string"},
                                            "status": {"type": "string", "enum": ["revoked"]},
                                        },
                                    },
                                },
                            },
                        },
                        "501": {
                            "description": "JWT auth not configured on this server.",
                        },
                    },
                },
            },
            "/openapi.json": {
                "get": {
                    "tags": ["Documentation"],
                    "summary": "OpenAPI specification",
                    "description": "Returns the full OpenAPI 3.0 specification as JSON.",
                    "operationId": "getOpenApiSpec",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "OpenAPI 3.0 specification.",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "description": "OpenAPI 3.0 specification document.",
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "/docs": {
                "get": {
                    "tags": ["Documentation"],
                    "summary": "Swagger UI",
                    "description": (
                        "Interactive API documentation rendered by Swagger UI. "
                        "Loads the OpenAPI spec from /openapi.json."
                    ),
                    "operationId": "swaggerUi",
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "HTML page with Swagger UI.",
                            "content": {
                                "text/html": {
                                    "schema": {
                                        "type": "string",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "components": {
            "securitySchemes": {
                "ApiKeyHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": (
                        "API key passed in the X-API-Key header. Keys are "
                        "configured via the PIPELINE_API_KEYS environment variable."
                    ),
                },
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": (
                        "API key passed as a Bearer token in the Authorization "
                        "header. The same keys accepted by X-API-Key work here."
                    ),
                },
                "JWTAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": (
                        "JWT token obtained from POST /auth/token. "
                        "Requires PIPELINE_JWT_SECRET to be set on the server."
                    ),
                },
            },
            "schemas": {
                "RunRequest": {
                    "type": "object",
                    "required": ["source", "destination"],
                    "properties": {
                        "source": {
                            "type": "string",
                            "description": (
                                "Data source path or URI. Can be a local file path, "
                                "S3 URI, database connection string, or any source "
                                "the Extractor supports."
                            ),
                            "example": "data/input.csv",
                        },
                        "destination": {
                            "type": "string",
                            "description": (
                                "Target database or storage type. Must be one of the "
                                "supported destination types (see /run 400 response "
                                "for the full list)."
                            ),
                            "enum": [
                                "athena", "azure_blob", "bigquery", "bigquery_vector",
                                "chroma", "clickhouse", "cockroachdb", "databricks",
                                "datasphere", "db2", "deltalake", "duckdb", "fabric",
                                "firebolt", "gcs", "hana", "iceberg", "kafka",
                                "lancedb", "milvus", "mongodb", "motherduck", "mssql",
                                "mysql", "oracle", "parquet", "pgvector", "pinecone",
                                "postgis", "postgres", "postgresql", "qdrant",
                                "quickbooks", "redshift", "s3", "sftp",
                                "snowflake", "snowflake_vector", "sqlite", "synapse",
                                "weaviate", "yellowbrick",
                            ],
                            "example": "sqlite",
                        },
                        "config": {
                            "type": "object",
                            "description": (
                                "Optional key-value configuration passed to the "
                                "pipeline function. Contents depend on the "
                                "destination type (connection strings, table names, "
                                "schema options, etc.)."
                            ),
                            "additionalProperties": True,
                            "example": {"table": "pipeline_output"},
                        },
                    },
                },
                "RunAccepted": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "format": "uuid",
                            "description": "Unique identifier for this pipeline run.",
                            "example": "550e8400-e29b-41d4-a716-446655440000",
                        },
                        "status": {
                            "type": "string",
                            "enum": ["started"],
                            "description": "Always 'started' on successful acceptance.",
                        },
                    },
                },
                "StatusResponse": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "format": "uuid",
                            "nullable": True,
                            "description": "UUID of the current or most recent run. Null if no run has been triggered.",
                        },
                        "status": {
                            "type": "string",
                            "enum": ["idle", "running", "completed", "failed"],
                            "description": "Current pipeline state.",
                        },
                        "started_at": {
                            "type": "string",
                            "format": "date-time",
                            "nullable": True,
                            "description": "ISO 8601 timestamp when the run started.",
                        },
                        "finished_at": {
                            "type": "string",
                            "format": "date-time",
                            "nullable": True,
                            "description": "ISO 8601 timestamp when the run finished. Null while running.",
                        },
                        "error": {
                            "type": "object",
                            "nullable": True,
                            "description": "Structured error details if the run failed. Null otherwise.",
                            "properties": {
                                "message": {"type": "string"},
                                "type": {"type": "string"},
                            },
                        },
                        "progress": {
                            "type": "object",
                            "nullable": True,
                            "description": "Chunk-level progress. Present only while running and when checkpoint data exists.",
                            "properties": {
                                "last_chunk_completed": {
                                    "type": "integer",
                                    "description": "Index of the last successfully processed chunk.",
                                },
                                "total_rows_processed": {
                                    "type": "integer",
                                    "description": "Cumulative row count processed so far.",
                                },
                            },
                        },
                    },
                },
                "HealthResponse": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["healthy"],
                            "description": "Always 'healthy' when the service is up.",
                        },
                        "timestamp": {
                            "type": "string",
                            "format": "date-time",
                            "description": "Current server time in ISO 8601 UTC.",
                        },
                    },
                },
                "MetricsResponse": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "format": "uuid",
                            "nullable": True,
                            "description": "UUID of the run these metrics belong to.",
                        },
                        "metrics": {
                            "type": "object",
                            "description": "Key-value metrics from the pipeline run.",
                            "properties": {
                                "duration_s": {
                                    "type": "number",
                                    "format": "float",
                                    "description": "Wall-clock duration of the run in seconds.",
                                },
                                "result": {
                                    "type": "string",
                                    "nullable": True,
                                    "description": "Summary string returned by the pipeline function, if any.",
                                },
                            },
                            "additionalProperties": True,
                        },
                    },
                },
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message", "request_id"],
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": "Machine-readable error code.",
                                    "example": "missing_fields",
                                },
                                "message": {
                                    "type": "string",
                                    "description": "Human-readable error message.",
                                    "example": "Both 'source' and 'destination' are required.",
                                },
                                "request_id": {
                                    "type": "string",
                                    "description": "Unique request identifier for tracing.",
                                    "example": "req_8f3a1b2c4d5e",
                                },
                            },
                            "additionalProperties": True,
                        },
                    },
                    "required": ["error"],
                },
                "TokenResponse": {
                    "type": "object",
                    "properties": {
                        "token": {
                            "type": "string",
                            "description": "Signed JWT token.",
                        },
                        "expires_at": {
                            "type": "string",
                            "format": "date-time",
                            "description": "ISO 8601 timestamp when the token expires.",
                        },
                        "token_type": {
                            "type": "string",
                            "enum": ["bearer"],
                        },
                    },
                },
                "ConflictError": {
                    "type": "object",
                    "description": "Returned when a pipeline run is already in progress.",
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message", "request_id"],
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "example": "already_running",
                                },
                                "message": {
                                    "type": "string",
                                    "example": "A pipeline run is already in progress.",
                                },
                                "request_id": {
                                    "type": "string",
                                    "example": "req_8f3a1b2c4d5e",
                                },
                                "active_run_id": {
                                    "type": "string",
                                    "format": "uuid",
                                    "description": "UUID of the currently-running pipeline.",
                                },
                            },
                        },
                    },
                    "required": ["error"],
                },
            },
        },
    }


_SWAGGER_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Data Governance Pipeline — API Docs</title>
  <link rel="stylesheet"
        href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *::before, *::after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none !important; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset,
      ],
      layout: "BaseLayout",
    });
  </script>
</body>
</html>
"""


def register_docs_routes(app) -> None:
    """
    Add /docs and /openapi.json routes to a Quart application.

    Parameters
    ----------
    app : Quart
        The Quart application instance returned by ``create_app()``.
    """
    from quart import jsonify as _jsonify, Response

    spec = get_openapi_spec()

    @app.route("/openapi.json", methods=["GET"])
    async def openapi_json():
        """Return the OpenAPI 3.0 spec as JSON."""
        return _jsonify(spec)

    @app.route("/docs", methods=["GET"])
    async def swagger_ui():
        """Serve the Swagger UI HTML page."""
        return Response(_SWAGGER_HTML, mimetype="text/html")

    logger.info("Registered /docs and /openapi.json routes.")
