"""
Tests for the Flask REST API: authentication, validation, rate limiting.

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-09   Updated for structured error responses, fixed flaky concurrent test.
"""

import os
import threading
import unittest


class TestAPIAuth(unittest.TestCase):
    """Authentication enforcement on API endpoints."""

    def setUp(self):
        os.environ["PIPELINE_API_KEYS"] = "test-key-1,test-key-2"
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    def test_health_no_auth_required(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "healthy")

    def test_run_requires_auth(self):
        resp = self.client.post("/run", json={"source": "x", "destination": "sqlite"})
        self.assertEqual(resp.status_code, 401)
        body = resp.get_json()["error"]
        self.assertEqual(body["code"], "unauthorized")
        self.assertIn("request_id", body)

    def test_status_requires_auth(self):
        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 401)

    def test_metrics_requires_auth(self):
        resp = self.client.get("/metrics")
        self.assertEqual(resp.status_code, 401)

    def test_valid_api_key_header(self):
        resp = self.client.get("/status", headers={"X-API-Key": "test-key-1"})
        self.assertEqual(resp.status_code, 200)

    def test_valid_bearer_token(self):
        resp = self.client.get("/status", headers={"Authorization": "Bearer test-key-2"})
        self.assertEqual(resp.status_code, 200)

    def test_invalid_api_key_rejected(self):
        resp = self.client.get("/status", headers={"X-API-Key": "wrong-key"})
        self.assertEqual(resp.status_code, 401)

    def test_empty_api_key_rejected(self):
        resp = self.client.get("/status", headers={"X-API-Key": ""})
        self.assertEqual(resp.status_code, 401)


class TestAPINoAuth(unittest.TestCase):
    """When no API keys configured, all endpoints open."""

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def test_run_works_without_keys_configured(self):
        resp = self.client.post("/run", json={"source": "x.csv", "destination": "sqlite"})
        self.assertEqual(resp.status_code, 202)

    def test_status_works_without_keys_configured(self):
        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)


class TestAPIValidation(unittest.TestCase):
    """Input validation on /run endpoint."""

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def test_missing_source(self):
        resp = self.client.post("/run", json={"destination": "sqlite"})
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()["error"]
        self.assertEqual(body["code"], "missing_fields")
        self.assertIn("source", body["message"].lower())
        self.assertIn("request_id", body)

    def test_missing_destination(self):
        resp = self.client.post("/run", json={"source": "data.csv"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"]["code"], "missing_fields")

    def test_non_string_source(self):
        resp = self.client.post("/run", json={"source": 123, "destination": "sqlite"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"]["code"], "invalid_type")

    def test_invalid_config_type(self):
        resp = self.client.post("/run", json={
            "source": "data.csv", "destination": "sqlite", "config": "not-a-dict"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"]["code"], "invalid_config")

    def test_unknown_destination(self):
        resp = self.client.post("/run", json={
            "source": "data.csv", "destination": "nonexistent_db"
        })
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()["error"]
        self.assertEqual(body["code"], "unknown_destination")
        self.assertIn("Unknown destination", body["message"])

    def test_valid_run_returns_202(self):
        resp = self.client.post("/run", json={
            "source": "data.csv", "destination": "sqlite"
        })
        self.assertEqual(resp.status_code, 202)
        body = resp.get_json()
        self.assertIn("run_id", body)
        self.assertEqual(body["status"], "started")

    def test_concurrent_run_returns_409(self):
        started = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            threading.Event().wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline)
        client = app.test_client()

        client.post("/run", json={"source": "data.csv", "destination": "sqlite"})
        started.wait(timeout=5)
        resp = client.post("/run", json={"source": "data2.csv", "destination": "sqlite"})
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.get_json()["error"]["code"], "already_running")

    def test_no_pipeline_fn_returns_501(self):
        from pipeline.api import create_app
        app = create_app(pipeline_fn=None)
        client = app.test_client()
        resp = client.post("/run", json={"source": "x", "destination": "sqlite"})
        self.assertEqual(resp.status_code, 501)
        self.assertEqual(resp.get_json()["error"]["code"], "not_configured")


class TestAPIRateLimiting(unittest.TestCase):
    """Rate limiter rejects excessive requests."""

    def setUp(self):
        os.environ["PIPELINE_API_KEYS"] = "rate-test-key"
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    def test_rate_limit_triggers_after_burst(self):
        headers = {"X-API-Key": "rate-test-key"}
        for _ in range(100):
            self.client.get("/status", headers=headers)
        resp = self.client.get("/status", headers=headers)
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.get_json()["error"]["code"], "rate_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
