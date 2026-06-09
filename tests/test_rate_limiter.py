"""
Tests for pipeline/rate_limiter.py — in-memory and SQLite-backed rate limiting.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import os
import shutil
import tempfile
import threading
import unittest

from pipeline.rate_limiter import (
    InMemoryRateLimiter,
    PersistentRateLimiter,
    create_rate_limiter,
)


class TestInMemoryRateLimiter(unittest.TestCase):
    """In-memory rate limiter basic behavior."""

    def test_allows_under_limit(self):
        limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            self.assertTrue(limiter.allow("client_a"))

    def test_blocks_over_limit(self):
        limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.allow("client_a")
        self.assertFalse(limiter.allow("client_a"))

    def test_separate_keys(self):
        limiter = InMemoryRateLimiter(max_requests=2, window_seconds=60)
        limiter.allow("a")
        limiter.allow("a")
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))

    def test_thread_safety(self):
        limiter = InMemoryRateLimiter(max_requests=100, window_seconds=60)
        results = []

        def hit():
            results.append(limiter.allow("shared"))

        threads = [threading.Thread(target=hit) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 100)
        self.assertTrue(all(results))


class TestPersistentRateLimiter(unittest.TestCase):
    """SQLite-backed rate limiter with persistence and pruning."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="rl_")
        self.db_path = os.path.join(self.tmpdir, "rate_limit.db")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_allows_under_limit(self):
        limiter = PersistentRateLimiter(self.db_path, max_requests=5, window_seconds=60)
        for _ in range(5):
            self.assertTrue(limiter.allow("client_a"))

    def test_blocks_over_limit(self):
        limiter = PersistentRateLimiter(self.db_path, max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.allow("client_a")
        self.assertFalse(limiter.allow("client_a"))

    def test_persistent_survives_restart(self):
        limiter1 = PersistentRateLimiter(self.db_path, max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter1.allow("client_a")

        limiter2 = PersistentRateLimiter(self.db_path, max_requests=3, window_seconds=60)
        self.assertFalse(limiter2.allow("client_a"))

    def test_expired_entries_pruned(self):
        limiter = PersistentRateLimiter(self.db_path, max_requests=3, window_seconds=1)
        for _ in range(3):
            limiter.allow("client_a")
        self.assertFalse(limiter.allow("client_a"))

        import time
        time.sleep(1.1)

        pruned = limiter.prune()
        self.assertEqual(pruned, 3)
        self.assertTrue(limiter.allow("client_a"))

    def test_thread_safety(self):
        limiter = PersistentRateLimiter(self.db_path, max_requests=100, window_seconds=60)
        results = []

        def hit():
            results.append(limiter.allow("shared"))

        threads = [threading.Thread(target=hit) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 50)
        self.assertTrue(all(results))


class TestCreateRateLimiter(unittest.TestCase):
    """Factory function selects the right backend."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="rl_factory_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_in_memory_fallback_default(self):
        limiter = create_rate_limiter()
        self.assertIsInstance(limiter, InMemoryRateLimiter)

    def test_in_memory_when_none(self):
        limiter = create_rate_limiter(db_path=None)
        self.assertIsInstance(limiter, InMemoryRateLimiter)

    def test_persistent_when_path_given(self):
        db_path = os.path.join(self.tmpdir, "rl.db")
        limiter = create_rate_limiter(db_path=db_path)
        self.assertIsInstance(limiter, PersistentRateLimiter)
        self.assertTrue(limiter.allow("test"))


if __name__ == "__main__":
    unittest.main()
