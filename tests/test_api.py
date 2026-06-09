"""
Tests for the Flask REST API: authentication, validation, rate limiting,
run queue, history, and cancel.

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-09   Updated for structured error responses, fixed flaky concurrent test.
1.2   2026-06-09   Added tests for run queue, history, cancel, webhook.
"""

import os
import threading
import unittest
from unittest.mock import patch


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


class TestAPIQueue(unittest.TestCase):
    """Run queue accepts multiple runs when max_queue_size > 0."""

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    def test_queue_second_run_while_first_running(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline, max_queue_size=5)
        client = app.test_client()

        resp1 = client.post("/run", json={"source": "a.csv", "destination": "sqlite"})
        self.assertEqual(resp1.status_code, 202)
        self.assertEqual(resp1.get_json()["status"], "started")

        started.wait(timeout=5)

        resp2 = client.post("/run", json={"source": "b.csv", "destination": "sqlite"})
        self.assertEqual(resp2.status_code, 202)
        self.assertEqual(resp2.get_json()["status"], "queued")
        self.assertEqual(resp2.get_json()["position"], 1)

        release.set()

    def test_queue_overflow_rejected(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline, max_queue_size=1)
        client = app.test_client()

        client.post("/run", json={"source": "a.csv", "destination": "sqlite"})
        started.wait(timeout=5)
        client.post("/run", json={"source": "b.csv", "destination": "sqlite"})
        resp = client.post("/run", json={"source": "c.csv", "destination": "sqlite"})
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.get_json()["error"]["code"], "queue_full")
        release.set()


class TestAPICancel(unittest.TestCase):
    """Cancel queued and running pipeline runs."""

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    def test_cancel_queued_run(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline, max_queue_size=5)
        client = app.test_client()

        client.post("/run", json={"source": "a.csv", "destination": "sqlite"})
        started.wait(timeout=5)
        resp2 = client.post("/run", json={"source": "b.csv", "destination": "sqlite"})
        queued_id = resp2.get_json()["run_id"]

        resp = client.post(f"/runs/{queued_id}/cancel")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "cancelled")
        release.set()

    def test_cancel_running_run(self):
        started = threading.Event()
        release = threading.Event()

        def slow_pipeline(s, d, c):
            started.set()
            release.wait(timeout=5)

        from pipeline.api import create_app
        app = create_app(pipeline_fn=slow_pipeline)
        client = app.test_client()

        resp1 = client.post("/run", json={"source": "a.csv", "destination": "sqlite"})
        run_id = resp1.get_json()["run_id"]
        started.wait(timeout=5)

        resp = client.post(f"/runs/{run_id}/cancel")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "cancel_requested")
        release.set()

    def test_cancel_unknown_run_returns_404(self):
        from pipeline.api import create_app
        app = create_app(pipeline_fn=lambda s, d, c: None)
        client = app.test_client()
        resp = client.post("/runs/nonexistent-id/cancel")
        self.assertEqual(resp.status_code, 404)


class TestAPIHistory(unittest.TestCase):
    """Run history endpoints /runs and /runs/<id>."""

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def test_list_runs_returns_json(self):
        resp = self.client.get("/runs")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("runs", body)
        self.assertIn("count", body)

    def test_run_detail_not_found(self):
        resp = self.client.get("/runs/nonexistent-id")
        self.assertEqual(resp.status_code, 404)

    def test_run_detail_found_after_run(self):
        done = threading.Event()

        def fast_pipeline(s, d, c):
            done.set()

        from pipeline.api import create_app
        app = create_app(pipeline_fn=fast_pipeline)
        client = app.test_client()

        resp = client.post("/run", json={"source": "x.csv", "destination": "sqlite"})
        run_id = resp.get_json()["run_id"]
        done.wait(timeout=5)

        import time
        time.sleep(0.05)

        resp = client.get(f"/runs/{run_id}")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["run_id"], run_id)


class TestAPIWebhook(unittest.TestCase):
    """Webhook notifications on run completion."""

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    @patch("pipeline.api._fire_webhook")
    def test_webhook_fired_on_completion(self, mock_webhook):
        done = threading.Event()

        def fast_pipeline(s, d, c):
            done.set()

        from pipeline.api import create_app
        app = create_app(pipeline_fn=fast_pipeline)
        client = app.test_client()

        resp = client.post("/run", json={
            "source": "x.csv", "destination": "sqlite",
            "webhook_url": "https://example.com/hook",
        })
        self.assertEqual(resp.status_code, 202)
        done.wait(timeout=5)

        import time
        time.sleep(0.1)

        mock_webhook.assert_called_once()
        call_args = mock_webhook.call_args
        self.assertEqual(call_args[0][0], "https://example.com/hook")
        self.assertIn("run_id", call_args[0][1])


if __name__ == "__main__":
    unittest.main()
