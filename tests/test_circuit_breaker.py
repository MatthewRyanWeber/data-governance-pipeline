"""
Tests for the circuit breaker pattern.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-11   Tests for HALF_OPEN single-probe behaviour (no thundering
                   herd against a recovering backend).
"""

import threading
import time
import unittest

from pipeline.circuit_breaker import CircuitBreaker, get_all_breakers
from pipeline.exceptions import CircuitOpenError


class TestCircuitBreakerInit(unittest.TestCase):
    """Initial state and registration."""

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker("test-init", failure_threshold=3)
        self.assertEqual(cb.to_dict()["state"], "closed")
        cb.reset()

    def test_registered_in_global_dict(self):
        cb = CircuitBreaker("test-registered")
        breakers = get_all_breakers()
        self.assertIn("test-registered", breakers)
        cb.reset()


class TestCircuitBreakerTransitions(unittest.TestCase):
    """State transitions: CLOSED -> OPEN -> HALF_OPEN -> CLOSED."""

    def setUp(self):
        self.cb = CircuitBreaker(
            "test-transitions",
            failure_threshold=3,
            recovery_timeout=0.1,
            success_threshold=2,
        )

    def tearDown(self):
        self.cb.reset()

    def test_stays_closed_on_success(self):
        self.cb.record_success()
        self.cb.record_success()
        self.assertTrue(self.cb.allow_request())
        self.assertEqual(self.cb.to_dict()["state"], "closed")

    def test_opens_after_failure_threshold(self):
        for _ in range(3):
            self.cb.record_failure()
        self.assertFalse(self.cb.allow_request())
        self.assertEqual(self.cb.to_dict()["state"], "open")

    def test_rejects_when_open(self):
        for _ in range(3):
            self.cb.record_failure()
        self.assertFalse(self.cb.allow_request())
        self.assertFalse(self.cb.allow_request())

    def test_transitions_to_half_open_after_timeout(self):
        for _ in range(3):
            self.cb.record_failure()
        self.assertFalse(self.cb.allow_request())
        time.sleep(0.15)
        self.assertTrue(self.cb.allow_request())
        self.assertEqual(self.cb.to_dict()["state"], "half_open")

    def test_half_open_closes_after_success_threshold(self):
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(0.15)
        self.cb.allow_request()
        self.cb.record_success()
        self.cb.record_success()
        self.assertEqual(self.cb.to_dict()["state"], "closed")

    def test_half_open_reopens_on_single_failure(self):
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(0.15)
        self.cb.allow_request()
        self.cb.record_failure()
        self.assertEqual(self.cb.to_dict()["state"], "open")

    def test_reset_returns_to_closed(self):
        for _ in range(3):
            self.cb.record_failure()
        self.assertEqual(self.cb.to_dict()["state"], "open")
        self.cb.reset()
        self.assertEqual(self.cb.to_dict()["state"], "closed")
        self.assertTrue(self.cb.allow_request())

    def test_half_open_allows_exactly_one_probe(self):
        """Concurrent callers in HALF_OPEN are rejected while a probe is
        outstanding — no thundering herd against a recovering backend."""
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(0.15)
        self.assertTrue(self.cb.allow_request())   # the single probe
        self.assertFalse(self.cb.allow_request())  # rejected: probe in flight
        self.assertFalse(self.cb.allow_request())

    def test_next_probe_allowed_after_probe_success(self):
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(0.15)
        self.assertTrue(self.cb.allow_request())
        self.cb.record_success()
        # success_threshold=2: still HALF_OPEN, a new probe is now allowed
        self.assertTrue(self.cb.allow_request())
        self.assertFalse(self.cb.allow_request())

    def test_probe_failure_reopens_and_rejects(self):
        for _ in range(3):
            self.cb.record_failure()
        time.sleep(0.15)
        self.assertTrue(self.cb.allow_request())
        self.cb.record_failure()
        self.assertEqual(self.cb.to_dict()["state"], "open")
        self.assertFalse(self.cb.allow_request())


class TestCircuitBreakerCustomThresholds(unittest.TestCase):
    """Custom threshold configuration."""

    def test_custom_failure_threshold(self):
        cb = CircuitBreaker("test-custom-ft", failure_threshold=1)
        cb.record_failure()
        self.assertFalse(cb.allow_request())
        cb.reset()

    def test_custom_success_threshold(self):
        cb = CircuitBreaker(
            "test-custom-st",
            failure_threshold=1,
            recovery_timeout=0.05,
            success_threshold=1,
        )
        cb.record_failure()
        time.sleep(0.1)
        cb.allow_request()
        cb.record_success()
        self.assertEqual(cb.to_dict()["state"], "closed")
        cb.reset()


class TestCircuitBreakerSerialization(unittest.TestCase):
    """to_dict() output."""

    def test_to_dict_has_expected_keys(self):
        cb = CircuitBreaker("test-dict")
        d = cb.to_dict()
        expected_keys = {
            "name", "state", "failure_count", "success_count",
            "failure_threshold", "recovery_timeout", "success_threshold",
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["name"], "test-dict")
        self.assertEqual(d["state"], "closed")
        cb.reset()


class TestCircuitBreakerThreadSafety(unittest.TestCase):
    """Concurrent access does not corrupt state."""

    def test_concurrent_failures(self):
        cb = CircuitBreaker("test-threadsafe", failure_threshold=50)
        errors = []

        def hammer():
            try:
                for _ in range(100):
                    cb.record_failure()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        d = cb.to_dict()
        self.assertEqual(d["state"], "open")
        cb.reset()


class TestCircuitOpenError(unittest.TestCase):
    """CircuitOpenError exception."""

    def test_has_breaker_name(self):
        err = CircuitOpenError("snowflake")
        self.assertEqual(err.breaker_name, "snowflake")
        self.assertIn("snowflake", str(err))

    def test_is_exception(self):
        self.assertTrue(issubclass(CircuitOpenError, Exception))


class TestBaseLoaderCircuitBreaker(unittest.TestCase):
    """BaseLoader circuit breaker helper methods."""

    def test_check_circuit_raises_when_open(self):
        from pipeline.loaders.base import BaseLoader

        class FakeGov:
            pass

        loader = BaseLoader(FakeGov(), dry_run=True)
        loader._init_circuit_breaker("test-baseloader", failure_threshold=1)
        loader._record_circuit_failure()
        with self.assertRaises(CircuitOpenError):
            loader._check_circuit()

    def test_no_breaker_is_noop(self):
        from pipeline.loaders.base import BaseLoader

        class FakeGov:
            pass

        loader = BaseLoader(FakeGov(), dry_run=True)
        loader._check_circuit()
        loader._record_circuit_success()
        loader._record_circuit_failure()
