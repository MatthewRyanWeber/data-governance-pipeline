"""
Pluggable rate limiter with in-memory and SQLite-backed implementations.

The in-memory limiter is the default (same behavior as the original
``_RateLimiter`` in api.py). The SQLite-backed limiter persists request
timestamps across process restarts.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-09   Initial release: InMemoryRateLimiter, PersistentRateLimiter.
1.1   2026-06-09   Added WAL mode to PersistentRateLimiter for concurrent access.
"""

import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """Token-bucket rate limiter backed by an in-process dict.

    State is lost on process restart — identical to the original api.py
    ``_RateLimiter``.
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._lock = threading.Lock()
        self._buckets: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key, [])
            bucket = [t for t in bucket if now - t < self._window]
            if len(bucket) >= self._max:
                self._buckets[key] = bucket
                return False
            bucket.append(now)
            self._buckets[key] = bucket
            return True


class PersistentRateLimiter:
    """Token-bucket rate limiter backed by SQLite.

    Persists request timestamps so rate limits survive process restarts.
    Uses ``time.time()`` (wall clock) instead of ``time.monotonic()``
    because monotonic clocks reset across restarts.

    Reuses a single connection (protected by a threading lock) to avoid
    the overhead of open/close per request.  Prunes only the current key
    on each ``allow()`` call; use ``prune()`` for a full sweep.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS rate_buckets (
            key       TEXT    NOT NULL,
            timestamp REAL    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rate_key_ts
            ON rate_buckets (key, timestamp);
    """

    def __init__(
        self,
        db_path: str | Path,
        max_requests: int = 100,
        window_seconds: int = 60,
    ) -> None:
        self._db_path = str(db_path)
        self._max = max_requests
        self._window = window_seconds
        self._lock = threading.Lock()
        self._conn = self._init_db()

    def _init_db(self) -> sqlite3.Connection:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.executescript(self._SCHEMA)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            self._conn.execute(
                "DELETE FROM rate_buckets WHERE key = ? AND timestamp < ?",
                (key, cutoff),
            )
            row = self._conn.execute(
                "SELECT COUNT(*) FROM rate_buckets WHERE key = ?", (key,)
            ).fetchone()
            count = row[0] if row else 0
            if count >= self._max:
                self._conn.commit()
                return False
            self._conn.execute(
                "INSERT INTO rate_buckets (key, timestamp) VALUES (?, ?)",
                (key, now),
            )
            self._conn.commit()
            return True

    def prune(self) -> int:
        """Remove all expired entries across all keys. Returns rows deleted."""
        cutoff = time.time() - self._window
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM rate_buckets WHERE timestamp < ?", (cutoff,)
            )
            self._conn.commit()
            return cursor.rowcount


def create_rate_limiter(
    db_path: str | Path | None = None,
    max_requests: int = 100,
    window_seconds: int = 60,
):
    """Factory: return PersistentRateLimiter if db_path is set, else in-memory."""
    if db_path:
        logger.info("[RATE-LIMIT] Using persistent SQLite backend: %s", db_path)
        return PersistentRateLimiter(db_path, max_requests, window_seconds)
    return InMemoryRateLimiter(max_requests, window_seconds)
