"""
JWT token creation, validation, and revocation for the pipeline API.

Opt-in via ``PIPELINE_JWT_SECRET`` env var. When the secret is not set,
all JWT functions raise ``RuntimeError`` — the API falls through to
static API key auth with zero behavior change.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-09   Initial release: create, validate, revoke JWT tokens.
1.1   2026-06-09   Removed stale env var caching, auto-prune on validate.
"""

import logging
import os
import threading
import time
import uuid

logger = logging.getLogger(__name__)

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

_JWT_ALGORITHM = "HS256"
_JWT_ISSUER = "data-governance-pipeline"
_DEFAULT_EXPIRY_SECONDS = 3600

_revoked_lock = threading.Lock()
_revoked_tokens: dict[str, float] = {}


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
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat()

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
    """Add a token ID to the revocation set."""
    exp = expires_at or (time.time() + _DEFAULT_EXPIRY_SECONDS)
    with _revoked_lock:
        _revoked_tokens[jti] = exp
    logger.info("[AUTH] Token revoked: jti=%s", jti)


def is_revoked(jti: str) -> bool:
    """Check if a token has been revoked."""
    with _revoked_lock:
        return jti in _revoked_tokens


def prune_revoked() -> int:
    """Remove expired entries from the revocation set. Returns count removed."""
    now = time.time()
    with _revoked_lock:
        expired = [jti for jti, exp in _revoked_tokens.items() if exp < now]
        for jti in expired:
            del _revoked_tokens[jti]
    return len(expired)


def reset_state() -> None:
    """Clear all module-level state. For testing only."""
    with _revoked_lock:
        _revoked_tokens.clear()
