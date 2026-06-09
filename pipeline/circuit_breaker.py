"""
Pluggable circuit breaker for loader resilience.

Three states: CLOSED (normal) -> OPEN (fast-reject) -> HALF_OPEN (testing
recovery).  Thread-safe.  All active breakers are registered in a module-level
dict for health reporting via ``get_all_breakers()``.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-09   Added unregister() for cleanup, documented lock hierarchy.
"""

import enum
import logging
import threading
import time

logger = logging.getLogger(__name__)

# Lock hierarchy: _registry_lock (global) -> self._lock (per-breaker).
# Always acquire in this order to prevent deadlock.
_active_breakers: dict[str, "CircuitBreaker"] = {}
_registry_lock = threading.Lock()


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """
    Per-loader circuit breaker with configurable thresholds.

    Quick-start
    ───────────
        cb = CircuitBreaker("snowflake")
        if not cb.allow_request():
            raise CircuitOpenError("snowflake")
        try:
            do_work()
            cb.record_success()
        except Exception:
            cb.record_failure()
            raise
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 3,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0

        with _registry_lock:
            _active_breakers[name] = self

        logger.info("[CIRCUIT] Breaker '%s' created (threshold=%d, timeout=%.1fs)",
                    name, failure_threshold, recovery_timeout)

    def allow_request(self) -> bool:
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self._recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._success_count = 0
                    logger.info("[CIRCUIT] '%s' OPEN -> HALF_OPEN (testing recovery)",
                                self.name)
                    return True
                return False

            # HALF_OPEN — allow test requests
            return True

    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info("[CIRCUIT] '%s' HALF_OPEN -> CLOSED (recovered)",
                                self.name)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        with self._lock:
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._success_count = 0
                logger.warning("[CIRCUIT] '%s' HALF_OPEN -> OPEN (recovery failed)",
                               self.name)

            elif self._state == CircuitState.CLOSED:
                self._failure_count += 1
                if self._failure_count >= self._failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning("[CIRCUIT] '%s' CLOSED -> OPEN after %d failures",
                                   self.name, self._failure_count)

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = 0.0
        logger.info("[CIRCUIT] '%s' reset to CLOSED", self.name)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "failure_threshold": self._failure_threshold,
                "recovery_timeout": self._recovery_timeout,
                "success_threshold": self._success_threshold,
            }


def unregister(name: str) -> None:
    """Remove a breaker from the active registry."""
    with _registry_lock:
        _active_breakers.pop(name, None)


def get_all_breakers() -> dict[str, dict]:
    """Return serialised state of all registered circuit breakers."""
    with _registry_lock:
        return {name: cb.to_dict() for name, cb in _active_breakers.items()}
