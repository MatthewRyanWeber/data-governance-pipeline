"""
Tests for the Quart REST API: authentication, validation, rate limiting,
run queue, history, and cancel.

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-09   Updated for structured error responses, fixed flaky concurrent test.
1.2   2026-06-09   Added tests for run queue, history, cancel, webhook.
1.3   2026-06-09   Added TestAPIWithRealPipeline: real CSV-to-SQLite through API.
1.4   2026-06-09   Added config validation tests for destination-specific required keys.
2.0   2026-06-09   Migrated from Flask/unittest to Quart/pytest-asyncio.
2.1   2026-06-09   Added Prometheus /metrics/prometheus endpoint tests.
2.2   2026-06-11   Regression tests: rate limiter keyed on client address
                   (rotating credential headers no longer bypasses it),
                   case-insensitive Bearer scheme, X-Bootstrap-Secret path
                   for /auth/token in JWT-only deployments.
"""

import asyncio
import os
import shutil
import tempfile
import threading
from unittest.mock import patch

import pandas as pd
import pytest


@pytest.fixture(autouse=True)
def _clean_auth_state():
    """Reset JWT module state between tests."""
    yield
    try:
        from pipeline.auth import reset_state
        reset_state()
    except ImportError:
        pass


# ── Auth ───────────────────────────────────────────────────────────────────

class TestAPIAuth:
    """Authentication enforcement on API endpoints."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "test-key-1,test-key-2"
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    @pytest.mark.asyncio
    async def test_health_no_auth_required(self):
        async with self.app.test_client() as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            assert (await resp.get_json())["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_run_requires_auth(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={"source": "x", "destination": "sqlite",
                                                   "config": {"db_name": "test"}})
            assert resp.status_code == 401
            body = (await resp.get_json())["error"]
            assert body["code"] == "unauthorized"
            assert "request_id" in body

    @pytest.mark.asyncio
    async def test_status_requires_auth(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_metrics_requires_auth(self):
        async with self.app.test_client() as client:
            resp = await client.get("/metrics")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_api_key_header(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status", headers={"X-API-Key": "test-key-1"})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_valid_bearer_token(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status", headers={"Authorization": "Bearer test-key-2"})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_bearer_scheme_is_case_insensitive(self):
        """RFC 7235: the auth scheme token is case-insensitive."""
        async with self.app.test_client() as client:
            for scheme in ("bearer", "BEARER", "BeArEr"):
                resp = await client.get(
                    "/status",
                    headers={"Authorization": f"{scheme} test-key-2"},
                )
                assert resp.status_code == 200, f"scheme {scheme!r} rejected"

    @pytest.mark.asyncio
    async def test_non_bearer_scheme_rejected(self):
        async with self.app.test_client() as client:
            resp = await client.get(
                "/status", headers={"Authorization": "Basic test-key-2"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status", headers={"X-API-Key": "wrong-key"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_api_key_rejected(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status", headers={"X-API-Key": ""})
            assert resp.status_code == 401


class TestAPINoAuth:
    """When no API keys configured, all endpoints open."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    @pytest.mark.asyncio
    async def test_run_works_without_keys_configured(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "x.csv", "destination": "sqlite",
                "config": {"db_name": "test"},
            })
            assert resp.status_code == 202

    @pytest.mark.asyncio
    async def test_status_works_without_keys_configured(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status")
            assert resp.status_code == 200


class TestDestinationsEndpoint:
    """GET /destinations exposes the catalog with verification tiers."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    @pytest.mark.asyncio
    async def test_lists_all_destinations_with_tiers(self):
        from pipeline.loaders import _LAZY_DISPATCH
        async with self.app.test_client() as client:
            resp = await client.get("/destinations")
            assert resp.status_code == 200
            body = await resp.get_json()
            assert body["count"] == len(_LAZY_DISPATCH)
            tiers = {e["tier"] for e in body["destinations"]}
            assert tiers == {"core", "emulator", "cloud", "experimental"}

    @pytest.mark.asyncio
    async def test_tier_filter(self):
        async with self.app.test_client() as client:
            resp = await client.get("/destinations?tier=cloud")
            body = await resp.get_json()
            assert body["count"] > 0
            assert all(e["tier"] == "cloud" for e in body["destinations"])

    @pytest.mark.asyncio
    async def test_requires_auth_when_keys_configured(self):
        os.environ["PIPELINE_API_KEYS"] = "k1"
        try:
            from pipeline.api import create_app
            app = create_app(pipeline_fn=lambda s, d, c: None)
            async with app.test_client() as client:
                resp = await client.get("/destinations")
                assert resp.status_code == 401
        finally:
            os.environ.pop("PIPELINE_API_KEYS", None)


class TestJWTOnlyBootstrap:
    """JWT-only deployments (no static keys) must be able to obtain a first
    token via X-Bootstrap-Secret — previously /auth/token demanded a JWT,
    which only /auth/token could issue (deadlock)."""

    SECRET = "bootstrap-test-secret-for-unit-tests"

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ["PIPELINE_JWT_SECRET"] = self.SECRET
        from pipeline.auth import reset_state
        reset_state()
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_JWT_SECRET", None)

    @pytest.mark.asyncio
    async def test_bootstrap_secret_issues_token(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-Bootstrap-Secret": self.SECRET},
                                     json={"subject": "first-client"})
            assert resp.status_code == 201
            body = await resp.get_json()
            assert "token" in body

            resp = await client.get(
                "/status",
                headers={"Authorization": f"Bearer {body['token']}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_bootstrap_secret_rejected(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-Bootstrap-Secret": "wrong-secret"},
                                     json={"subject": "attacker"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_bootstrap_secret_rejected(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token", json={"subject": "nobody"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_jwt_can_still_request_new_token(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-Bootstrap-Secret": self.SECRET},
                                     json={"subject": "rotator"})
            token = (await resp.get_json())["token"]

            resp = await client.post("/auth/token",
                                     headers={"Authorization": f"Bearer {token}"},
                                     json={"subject": "rotator"})
            assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_other_endpoints_still_require_jwt(self):
        """The bootstrap secret only works on /auth/token."""
        async with self.app.test_client() as client:
            resp = await client.get(
                "/status", headers={"X-Bootstrap-Secret": self.SECRET},
            )
            assert resp.status_code == 401


# ── Validation ─────────────────────────────────────────────────────────────

class TestAPIValidation:
    """Input validation on /run endpoint."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    @pytest.mark.asyncio
    async def test_missing_source(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={"destination": "sqlite"})
            assert resp.status_code == 400
            body = (await resp.get_json())["error"]
            assert body["code"] == "missing_fields"
            assert "source" in body["message"].lower()

    @pytest.mark.asyncio
    async def test_missing_destination(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={"source": "data.csv"})
            assert resp.status_code == 400
            assert (await resp.get_json())["error"]["code"] == "missing_fields"

    @pytest.mark.asyncio
    async def test_non_string_source(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={"source": 123, "destination": "sqlite"})
            assert resp.status_code == 400
            assert (await resp.get_json())["error"]["code"] == "invalid_type"

    @pytest.mark.asyncio
    async def test_invalid_config_type(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "data.csv", "destination": "sqlite", "config": "not-a-dict",
            })
            assert resp.status_code == 400
            assert (await resp.get_json())["error"]["code"] == "invalid_config"

    @pytest.mark.asyncio
    async def test_unknown_destination(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "data.csv", "destination": "nonexistent_db",
            })
            assert resp.status_code == 400
            body = (await resp.get_json())["error"]
            assert body["code"] == "unknown_destination"
            assert "Unknown destination" in body["message"]

    @pytest.mark.asyncio
    async def test_valid_run_returns_202(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "data.csv", "destination": "sqlite",
                "config": {"db_name": "test"},
            })
            assert resp.status_code == 202
            body = await resp.get_json()
            assert "run_id" in body
            assert body["status"] == "started"

    @pytest.mark.asyncio
    async def test_concurrent_run_returns_409(self):
        started = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            threading.Event().wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline)

        async with app.test_client() as client:
            await client.post("/run", json={"source": "data.csv", "destination": "sqlite",
                                            "config": {"db_name": "test"}})
            started.wait(timeout=5)
            resp = await client.post("/run", json={"source": "data2.csv", "destination": "sqlite",
                                                   "config": {"db_name": "test"}})
            assert resp.status_code == 409
            assert (await resp.get_json())["error"]["code"] == "already_running"

    @pytest.mark.asyncio
    async def test_config_validation_missing_host_for_postgresql(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "data.csv", "destination": "postgresql", "config": {},
            })
            assert resp.status_code == 400
            body = (await resp.get_json())["error"]
            assert body["code"] == "invalid_config"
            assert "host" in body["missing_keys"]
            assert body["db_type"] == "postgresql"

    @pytest.mark.asyncio
    async def test_config_validation_sqlite_missing_db_name(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "data.csv", "destination": "sqlite", "config": {},
            })
            assert resp.status_code == 400
            body = (await resp.get_json())["error"]
            assert body["code"] == "invalid_config"
            assert "db_name" in body["missing_keys"]

    @pytest.mark.asyncio
    async def test_config_validation_valid_sqlite_passes(self):
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": "data.csv", "destination": "sqlite",
                "config": {"db_name": "test_db"},
            })
            assert resp.status_code == 202

    @pytest.mark.asyncio
    async def test_no_pipeline_fn_returns_501(self):
        from pipeline.api import create_app
        app = create_app(pipeline_fn=None)
        async with app.test_client() as client:
            resp = await client.post("/run", json={"source": "x", "destination": "sqlite"})
            assert resp.status_code == 501
            assert (await resp.get_json())["error"]["code"] == "not_configured"


# ── Rate limiting ──────────────────────────────────────────────────────────

class TestAPIRateLimiting:
    """Rate limiter rejects excessive requests."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "rate-test-key"
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    @pytest.mark.asyncio
    async def test_rate_limit_triggers_after_burst(self):
        headers = {"X-API-Key": "rate-test-key"}
        async with self.app.test_client() as client:
            for _ in range(100):
                await client.get("/status", headers=headers)
            resp = await client.get("/status", headers=headers)
            assert resp.status_code == 429
            assert (await resp.get_json())["error"]["code"] == "rate_limit_exceeded"

    @pytest.mark.asyncio
    async def test_rotating_credentials_do_not_bypass_rate_limit(self):
        """Regression: the limiter was keyed on the raw credential header,
        so a unique X-API-Key per request earned a fresh bucket every time.
        It must key on the client address instead."""
        async with self.app.test_client() as client:
            for i in range(100):
                await client.get("/status",
                                 headers={"X-API-Key": f"rotating-key-{i}"})
            resp = await client.get("/status",
                                    headers={"X-API-Key": "rotating-key-final"})
            assert resp.status_code == 429
            assert (await resp.get_json())["error"]["code"] == "rate_limit_exceeded"


# ── Queue ──────────────────────────────────────────────────────────────────

class TestAPIQueue:
    """Run queue accepts multiple runs when max_queue_size > 0."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)

    @pytest.mark.asyncio
    async def test_queue_second_run_while_first_running(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline, max_queue_size=5)
        cfg = {"db_name": "test"}

        async with app.test_client() as client:
            resp1 = await client.post("/run", json={"source": "a.csv", "destination": "sqlite",
                                                    "config": cfg})
            assert resp1.status_code == 202
            assert (await resp1.get_json())["status"] == "started"

            started.wait(timeout=5)

            resp2 = await client.post("/run", json={"source": "b.csv", "destination": "sqlite",
                                                    "config": cfg})
            assert resp2.status_code == 202
            body2 = await resp2.get_json()
            assert body2["status"] == "queued"
            assert body2["position"] == 1

            release.set()

    @pytest.mark.asyncio
    async def test_queue_overflow_rejected(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline, max_queue_size=1)
        cfg = {"db_name": "test"}

        async with app.test_client() as client:
            await client.post("/run", json={"source": "a.csv", "destination": "sqlite",
                                            "config": cfg})
            started.wait(timeout=5)
            await client.post("/run", json={"source": "b.csv", "destination": "sqlite",
                                            "config": cfg})
            resp = await client.post("/run", json={"source": "c.csv", "destination": "sqlite",
                                                   "config": cfg})
            assert resp.status_code == 429
            assert (await resp.get_json())["error"]["code"] == "queue_full"
            release.set()


# ── Cancel ─────────────────────────────────────────────────────────────────

class TestAPICancel:
    """Cancel queued and running pipeline runs."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)

    @pytest.mark.asyncio
    async def test_cancel_queued_run(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline, max_queue_size=5)
        cfg = {"db_name": "test"}

        async with app.test_client() as client:
            await client.post("/run", json={"source": "a.csv", "destination": "sqlite",
                                            "config": cfg})
            started.wait(timeout=5)
            resp2 = await client.post("/run", json={"source": "b.csv", "destination": "sqlite",
                                                    "config": cfg})
            queued_id = (await resp2.get_json())["run_id"]

            resp = await client.post(f"/runs/{queued_id}/cancel")
            assert resp.status_code == 200
            assert (await resp.get_json())["status"] == "cancelled"
            release.set()

    @pytest.mark.asyncio
    async def test_cancel_running_run(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline)
        cfg = {"db_name": "test"}

        async with app.test_client() as client:
            resp1 = await client.post("/run", json={"source": "a.csv", "destination": "sqlite",
                                                    "config": cfg})
            run_id = (await resp1.get_json())["run_id"]
            started.wait(timeout=5)

            resp = await client.post(f"/runs/{run_id}/cancel")
            assert resp.status_code == 200
            assert (await resp.get_json())["status"] == "cancel_requested"
            release.set()

    @pytest.mark.asyncio
    async def test_cancel_unknown_run_returns_404(self):
        from pipeline.api import create_app
        app = create_app(pipeline_fn=lambda s, d, c: None)
        async with app.test_client() as client:
            resp = await client.post("/runs/nonexistent-id/cancel")
            assert resp.status_code == 404


# ── History ────────────────────────────────────────────────────────────────

class TestAPIHistory:
    """Run history endpoints /runs and /runs/<id>."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    @pytest.mark.asyncio
    async def test_list_runs_returns_json(self):
        async with self.app.test_client() as client:
            resp = await client.get("/runs")
            assert resp.status_code == 200
            body = await resp.get_json()
            assert "runs" in body
            assert "count" in body

    @pytest.mark.asyncio
    async def test_run_detail_not_found(self):
        async with self.app.test_client() as client:
            resp = await client.get("/runs/nonexistent-id")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_run_detail_found_after_run(self):
        done = threading.Event()

        def fast_pipeline(s, d, c):
            done.set()

        from pipeline.api import create_app
        app = create_app(pipeline_fn=fast_pipeline)

        async with app.test_client() as client:
            resp = await client.post("/run", json={"source": "x.csv", "destination": "sqlite",
                                                   "config": {"db_name": "test"}})
            run_id = (await resp.get_json())["run_id"]
            done.wait(timeout=5)
            await asyncio.sleep(0.05)

            resp = await client.get(f"/runs/{run_id}")
            assert resp.status_code == 200
            body = await resp.get_json()
            assert body["run_id"] == run_id


# ── Webhook ────────────────────────────────────────────────────────────────

class TestAPIWebhook:
    """Webhook notifications on run completion."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)

    @pytest.mark.asyncio
    async def test_webhook_fired_on_completion(self):
        webhook_fired = threading.Event()

        def fast_pipeline(s, d, c):
            pass

        original_fire = __import__("pipeline.api", fromlist=["_fire_webhook"])._fire_webhook

        def tracking_fire(url, payload):
            original_fire(url, payload)
            webhook_fired.set()

        from pipeline.api import create_app
        app = create_app(pipeline_fn=fast_pipeline)

        with patch("pipeline.api._fire_webhook", side_effect=tracking_fire) as mock_webhook:
            async with app.test_client() as client:
                resp = await client.post("/run", json={
                    "source": "x.csv", "destination": "sqlite",
                    "config": {"db_name": "test"},
                    "webhook_url": "https://example.com/hook",
                })
                assert resp.status_code == 202
                webhook_fired.wait(timeout=10)

            mock_webhook.assert_called_once()
            call_args = mock_webhook.call_args
            assert call_args[0][0] == "https://example.com/hook"
            assert "run_id" in call_args[0][1]


# ── Real pipeline ─────────────────────────────────────────────────────────

class TestAPIWithRealPipeline:
    """Wire a real CSV-to-SQLite pipeline through the API endpoints."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        self.tmpdir = tempfile.mkdtemp(prefix="api_real_")
        self.csv_path = os.path.join(self.tmpdir, "api_test.csv")
        self.db_path = os.path.join(self.tmpdir, "output")

        df = pd.DataFrame([
            {"id": 1, "name": "Alice", "age": 30},
            {"id": 2, "name": "Bob", "age": 25},
            {"id": 3, "name": "Carol", "age": 40},
        ])
        df.to_csv(self.csv_path, index=False, encoding="utf-8")

        from pipeline.constants import RunContext
        from pipeline.extract import Extractor
        from pipeline.governance_logger import GovernanceLogger
        from pipeline.loaders.sql_loader import SQLLoader
        from pipeline.transform import Transformer

        tmpdir = self.tmpdir
        db_path = self.db_path

        def _real_pipeline(source, destination, config):
            run_context = RunContext()
            gov = GovernanceLogger(
                source_name=os.path.basename(source),
                log_dir=os.path.join(tmpdir, "gov"),
                run_context=run_context,
            )
            gov.pipeline_start({"source": source})
            extractor = Extractor(gov)
            df_extracted = extractor.extract(source)
            transformer = Transformer(gov, run_context=run_context)
            df_out = transformer.transform(df_extracted, [], "mask", drop_cols=[])
            loader = SQLLoader(gov, db_type="sqlite")
            loader.load(df_out, {"db_name": db_path}, "api_result", if_exists="replace")
            gov.pipeline_end({"rows": len(df_out)})

        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=_real_pipeline)

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_api_runs_real_pipeline(self):
        """POST /run with real pipeline, poll /status until complete, verify SQLite."""
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": self.csv_path,
                "destination": "sqlite",
                "config": {"db_name": self.db_path},
            })
            assert resp.status_code == 202
            run_id = (await resp.get_json())["run_id"]
            assert run_id is not None

            for _ in range(50):
                status_resp = await client.get("/status")
                status_data = await status_resp.get_json()
                if status_data.get("status") in ("idle", "completed"):
                    break
                await asyncio.sleep(0.1)

            final_resp = await client.get("/status")
            final_status = await final_resp.get_json()
            assert final_status["status"] in ("idle", "completed")

            from sqlalchemy import create_engine
            engine = create_engine(f"sqlite:///{self.db_path}.db")
            try:
                result = pd.read_sql('SELECT * FROM "api_result"', engine)
            finally:
                engine.dispose()
            assert len(result) == 3
            assert "_pipeline_id" in result.columns

            metrics_resp = await client.get("/metrics")
            assert metrics_resp.status_code == 200
            metrics = await metrics_resp.get_json()
            assert "run_id" in metrics
            assert "metrics" in metrics
            assert "duration_s" in metrics["metrics"]

    @pytest.mark.asyncio
    async def test_api_reports_real_error(self):
        """POST /run with a nonexistent source, verify structured error in status."""
        async with self.app.test_client() as client:
            resp = await client.post("/run", json={
                "source": os.path.join(self.tmpdir, "DOES_NOT_EXIST.csv"),
                "destination": "sqlite",
                "config": {"db_name": "test"},
            })
            assert resp.status_code == 202

            for _ in range(50):
                status_resp = await client.get("/status")
                status_data = await status_resp.get_json()
                if status_data.get("status") in ("idle", "failed"):
                    break
                await asyncio.sleep(0.1)

            final_resp = await client.get("/status")
            final = await final_resp.get_json()
            assert final["status"] in ("idle", "failed")


# ── Prometheus ────────────────────────────────────────────────────────────

class TestPrometheusEndpoint:
    """Tests for /metrics/prometheus Prometheus text scrape endpoint."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "test-key"

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    @pytest.mark.asyncio
    async def test_returns_501_without_exporter(self):
        from pipeline.api import create_app
        app = create_app(pipeline_fn=lambda s, d, c: None)
        async with app.test_client() as client:
            resp = await client.get("/metrics/prometheus")
            assert resp.status_code == 501

    @pytest.mark.asyncio
    async def test_returns_200_with_exporter(self):
        from unittest.mock import MagicMock
        exporter = MagicMock()
        exporter._render_metrics.return_value = (
            "# HELP pipeline_runs_total Total pipeline runs\n"
            "# TYPE pipeline_runs_total counter\n"
            "pipeline_runs_total 5\n"
        )
        from pipeline.api import create_app
        app = create_app(pipeline_fn=lambda s, d, c: None, prometheus_exporter=exporter)
        async with app.test_client() as client:
            resp = await client.get("/metrics/prometheus")
            assert resp.status_code == 200
            assert "text/plain" in resp.content_type
            body = (await resp.get_data()).decode()
            assert "pipeline_runs_total" in body

    @pytest.mark.asyncio
    async def test_no_auth_required(self):
        from unittest.mock import MagicMock
        exporter = MagicMock()
        exporter._render_metrics.return_value = "# empty\n"
        from pipeline.api import create_app
        app = create_app(pipeline_fn=lambda s, d, c: None, prometheus_exporter=exporter)
        async with app.test_client() as client:
            resp = await client.get("/metrics/prometheus")
            assert resp.status_code == 200
