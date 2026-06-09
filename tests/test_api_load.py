"""
API concurrency and rate limiter load tests.

All tests are marked @pytest.mark.slow so they are skipped in the normal
unit test suite.  Run them explicitly with:
    pytest tests/test_api_load.py -v -m slow

Revision history
────────────────
1.0   2026-06-09   Initial release: concurrent health, status, rate limiter burst.
"""

import asyncio
import os

import pytest


@pytest.fixture(autouse=True)
def _clean_env():
    yield
    os.environ.pop("PIPELINE_API_KEYS", None)
    os.environ.pop("PIPELINE_JWT_SECRET", None)
    try:
        from pipeline.auth import reset_state
        reset_state()
    except ImportError:
        pass


@pytest.mark.slow
class TestConcurrentHealth:
    """Concurrent GET /health under load."""

    def setup_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    @pytest.mark.asyncio
    async def test_concurrent_health_checks(self):
        async with self.app.test_client() as client:
            tasks = [client.get("/health") for _ in range(50)]
            responses = await asyncio.gather(*tasks)
            status_codes = [r.status_code for r in responses]
            assert all(c == 200 for c in status_codes), f"Non-200 codes: {set(status_codes)}"


@pytest.mark.slow
class TestConcurrentStatus:
    """Concurrent GET /status under load."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "load-test-key"
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    @pytest.mark.asyncio
    async def test_concurrent_status_polling(self):
        headers = {"X-API-Key": "load-test-key"}
        async with self.app.test_client() as client:
            tasks = [client.get("/status", headers=headers) for _ in range(20)]
            responses = await asyncio.gather(*tasks)
            status_codes = [r.status_code for r in responses]
            assert all(c == 200 for c in status_codes), f"Non-200 codes: {set(status_codes)}"


@pytest.mark.slow
class TestRateLimiterBurst:
    """Rate limiter under rapid burst load."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "burst-key"
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)

    @pytest.mark.asyncio
    async def test_rate_limiter_under_burst(self):
        headers = {"X-API-Key": "burst-key"}
        async with self.app.test_client() as client:
            tasks = [client.get("/status", headers=headers) for _ in range(200)]
            responses = await asyncio.gather(*tasks)
            codes = [r.status_code for r in responses]
            ok_count = codes.count(200)
            limited_count = codes.count(429)
            assert ok_count == 100, f"Expected 100 OK, got {ok_count}"
            assert limited_count == 100, f"Expected 100 rate-limited, got {limited_count}"
