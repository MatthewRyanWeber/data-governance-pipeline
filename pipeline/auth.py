"""
JWT token creation, validation, and revocation for the pipeline API.

Opt-in via ``PIPELINE_JWT_SECRET`` env var. When the secret is not set,
all JWT functions raise ``RuntimeError`` — the API falls through to
static API key auth with zero behavior change.

Revocation is in-memory by default (lost on restart). Set
``PIPELINE_JWT_REVOCATION_DB`` to a file path for SQLite-backed
persistent revocation that survives process restarts.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-09   Initial release: create, validate, revoke JWT tokens.
1.1   2026-06-09   Removed stale env var caching, auto-prune on validate.
1.2   2026-06-09   Added persistent SQLite revocation store (opt-in).
1.3   2026-06-09   PRAGMA synchronous=FULL for revocation durability,
                   added close() to persistent store.
1.4   2026-06-11   Security fix: revoke_token fallback expiry now covers the
                   max issuable token lifetime (86400s) so prune_revoked can
                   never un-revoke a live token; added revoke_token_by_value
                   to extract the real exp from the token itself.
"""

import logging
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

_JWT_ALGORITHM = "HS256"
_JWT_ISSUER = "data-governance-pipeline"
_DEFAULT_EXPIRY_SECONDS = 3600
# Revocations must outlive the longest token the API can issue (86400s),
# otherwise prune_revoked() resurrects revoked-but-unexpired tokens.
MAX_TOKEN_LIFETIME_SECONDS = 86400


# ── Revocation stores ─────────────────────────────────────────────────


class _InMemoryRevocationStore:
    """In-memory JTI revocation — lost on process restart."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tokens: dict[str, float] = {}

    def add(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._tokens[jti] = expires_at

    def contains(self, jti: str) -> bool:
        with self._lock:
            return jti in self._tokens

    def prune(self) -> int:
        now = time.time()
        with self._lock:
            expired = [j for j, exp in self._tokens.items() if exp < now]
            for j in expired:
                del self._tokens[j]
        return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


class _PersistentRevocationStore:
    """SQLite-backed JTI revocation — survives process restarts."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = self._init_db()

    def _init_db(self) -> sqlite3.Connection:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti        TEXT PRIMARY KEY,
                expires_at REAL NOT NULL
            );
        """)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()

    def add(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
                (jti, expires_at),
            )
            self._conn.commit()

    def contains(self, jti: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)
            ).fetchone()
            return row is not None

    def prune(self) -> int:
        now = time.time()
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM revoked_tokens WHERE expires_at < ?", (now,)
            )
            self._conn.commit()
            return cursor.rowcount

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM revoked_tokens")
            self._conn.commit()


def _create_revocation_store():
    """Factory: return persistent store if env var is set, else in-memory."""
    db_path = os.environ.get("PIPELINE_JWT_REVOCATION_DB")
    if db_path:
        logger.info("[AUTH] Using persistent revocation store: %s", db_path)
        return _PersistentRevocationStore(db_path)
    return _InMemoryRevocationStore()


_revocation_store = _create_revocation_store()


# ── Public API ─────────────────────────────────────────────────────────


def jwt_available() -> bool:
    """Return True if PyJWT is installed and a secret is configured."""
    return HAS_JWT and bool(os.environ.get("PIPELINE_JWT_SECRET", ""))


def create_token(subject: str, expiry_seconds: int | None = None) -> dict:
    """
    Generate a signed JWT for the given subject.

    Returns a dict with ``token``, ``expires_at`` (ISO timestamp), and
    ``token_type`` ("bearer").
    """
    if not HAS_JWT:
        raise RuntimeError("PyJWT is not installed.")
    secret = os.environ.get("PIPELINE_JWT_SECRET", "")
    if not secret:
        raise RuntimeError("PIPELINE_JWT_SECRET is not set.")

    exp_seconds = expiry_seconds or _DEFAULT_EXPIRY_SECONDS
    now = time.time()
    jti = uuid.uuid4().hex

    payload = {
        "sub": subject,
        "iat": int(now),
        "exp": int(now + exp_seconds),
        "jti": jti,
        "iss": _JWT_ISSUER,
    }

    token = jwt.encode(payload, secret, algorithm=_JWT_ALGORITHM)

    from datetime import datetime, timezone
    exp_ts: float = payload["exp"]  # type: ignore[assignment]
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()

    logger.info("[AUTH] JWT issued for subject=%s, jti=%s, expires_in=%ds",
                subject, jti, exp_seconds)

    return {
        "token": token,
        "expires_at": expires_at,
        "token_type": "bearer",
    }


def validate_token(token: str) -> dict:
    """
    Decode and validate a JWT. Returns the claims dict on success.

    Raises ``jwt.ExpiredSignatureError``, ``jwt.InvalidTokenError``,
    or ``ValueError`` (if revoked).
    """
    if not HAS_JWT:
        raise RuntimeError("PyJWT is not installed.")
    secret = os.environ.get("PIPELINE_JWT_SECRET", "")
    if not secret:
        raise RuntimeError("PIPELINE_JWT_SECRET is not set.")

    prune_revoked()

    claims = jwt.decode(
        token, secret,
        algorithms=[_JWT_ALGORITHM],
        issuer=_JWT_ISSUER,
        options={"require": ["sub", "exp", "iat", "jti", "iss"]},
    )

    jti = claims.get("jti", "")
    if is_revoked(jti):
        raise ValueError(f"Token {jti} has been revoked.")

    return claims


def revoke_token(jti: str, expires_at: float | None = None) -> None:
    """
    Add a token ID to the revocation set.

    When the caller does not know the token's real expiry, the revocation
    is kept for the maximum issuable token lifetime — never shorter than
    any token that could still be in circulation.
    """
    exp = expires_at or (time.time() + MAX_TOKEN_LIFETIME_SECONDS)
    _revocation_store.add(jti, exp)
    logger.info("[AUTH] Token revoked: jti=%s", jti)


def revoke_token_by_value(token: str) -> str:
    """
    Revoke a token using the token string itself. Returns the revoked jti.

    The signature is verified but an expired ``exp`` is accepted — revoking
    an already-expired token is harmless and must not fail.
    """
    if not HAS_JWT:
        raise RuntimeError("PyJWT is not installed.")
    secret = os.environ.get("PIPELINE_JWT_SECRET", "")
    if not secret:
        raise RuntimeError("PIPELINE_JWT_SECRET is not set.")

    claims = jwt.decode(
        token, secret,
        algorithms=[_JWT_ALGORITHM],
        issuer=_JWT_ISSUER,
        options={"require": ["jti", "exp"], "verify_exp": False},
    )
    jti = str(claims["jti"])
    revoke_token(jti, expires_at=float(claims["exp"]))
    return jti


def is_revoked(jti: str) -> bool:
    """Check if a token has been revoked."""
    return bool(_revocation_store.contains(jti))


def prune_revoked() -> int:
    """Remove expired entries from the revocation set. Returns count removed."""
    return int(_revocation_store.prune())


def reset_state() -> None:
    """Reinitialize store from current env vars. For testing only."""
    global _revocation_store
    _revocation_store = _create_revocation_store()
