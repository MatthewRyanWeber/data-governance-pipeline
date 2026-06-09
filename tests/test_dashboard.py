"""
Tests for the self-contained HTML dashboard.

Validates HTML rendering with various data states and the /dashboard
API route.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import unittest

from pipeline.dashboard import render_dashboard_html


class TestRenderDashboardHtml(unittest.TestCase):

    def test_returns_valid_html(self):
        html = render_dashboard_html()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<html", html)
        self.assertIn("</html>", html)
        self.assertIn("<title>Pipeline Dashboard</title>", html)

    def test_contains_status_data(self):
        html = render_dashboard_html(status={
            "run_id": "abc-123",
            "status": "running",
            "started_at": "2026-06-09T10:00:00Z",
        })
        self.assertIn("RUNNING", html)
        self.assertIn("abc-123", html)
        self.assertIn("2026-06-09T10:00:00Z", html)

    def test_contains_recent_runs(self):
        runs = [
            {"run_id": "run-001", "source": "s3://bucket", "destination": "postgres",
             "status": "completed", "duration": "12.5s"},
            {"run_id": "run-002", "source": "csv_file", "destination": "snowflake",
             "status": "failed", "duration": "3.1s"},
        ]
        html = render_dashboard_html(recent_runs=runs)
        self.assertIn("run-001", html)
        self.assertIn("run-002", html)
        self.assertIn("s3://bucket", html)
        self.assertIn("postgres", html)
        self.assertIn("failed", html)

    def test_handles_empty_data(self):
        html = render_dashboard_html(
            status={}, recent_runs=[], circuit_breakers={}, metrics={},
        )
        self.assertIn("No recent runs", html)
        self.assertIn("No circuit breakers registered", html)
        self.assertIn("IDLE", html)

    def test_circuit_breaker_details(self):
        breakers = {
            "db_loader": {"state": "closed", "failures": 0, "successes": 5},
            "api_extract": {"state": "open", "failures": 3, "successes": 1},
        }
        html = render_dashboard_html(circuit_breakers=breakers)
        self.assertIn("db_loader", html)
        self.assertIn("api_extract", html)
        self.assertIn("open", html)
        self.assertIn("closed", html)

    def test_metrics_displayed(self):
        html = render_dashboard_html(metrics={
            "total_duration_sec": 42.7,
            "rows_output": 15000,
            "error_rate": 0.023,
        })
        self.assertIn("42.7", html)
        self.assertIn("15000", html)
        self.assertIn("2.3%", html)

    def test_xss_prevention(self):
        html = render_dashboard_html(status={
            "run_id": "<script>alert(1)</script>",
            "status": "running",
        })
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_dark_mode_css_present(self):
        html = render_dashboard_html()
        self.assertIn("prefers-color-scheme:dark", html)

    def test_auto_refresh_js(self):
        html = render_dashboard_html()
        self.assertIn("setInterval", html)
        self.assertIn("/health", html)


class TestDashboardRoute(unittest.TestCase):

    def setUp(self):
        import os
        os.environ.pop("PIPELINE_API_KEYS", None)

        from pipeline.api import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def test_dashboard_returns_200(self):
        import asyncio
        async def _test():
            resp = await self.client.get("/dashboard")
            self.assertEqual(resp.status_code, 200)
            data = await resp.get_data(as_text=True)
            self.assertIn("Pipeline Dashboard", data)
            self.assertEqual(resp.content_type, "text/html; charset=utf-8")
        asyncio.run(_test())

    def test_dashboard_no_auth_required(self):
        import asyncio
        async def _test():
            resp = await self.client.get("/dashboard")
            self.assertEqual(resp.status_code, 200)
        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
