"""
Tests for JWT auth token creation, validation, revocation, and API integration.

Revision history
────────────────
1.0   2026-06-09   Initial release.
1.1   2026-06-09   Migrated API tests to async for Quart.
1.2   2026-06-09   Added persistent revocation tests, fixed fixture ordering.
"""

import os
import shutil
import tempfile
import time
import unittest

import pytest


@pytest.fixture(autouse=True)
def _clean_auth_state():
    """Reset JWT module state between tests."""
    yield
    os.environ.pop("PIPELINE_JWT_REVOCATION_DB", None)
    os.environ.pop("PIPELINE_API_KEYS", None)
    os.environ.pop("PIPELINE_JWT_SECRET", None)
    from pipeline.auth import reset_state
    reset_state()


class TestJWTTokenCreation(unittest.TestCase):
    """create_token returns a valid JWT with correct claims."""

    def setUp(self):
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests-32b"
        from pipeline.auth import reset_state
        reset_state()

    def tearDown(self):
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()

    def test_create_token_returns_valid_jwt(self):
        from pipeline.auth import create_token
        result = create_token("test-user", 3600)
        self.assertIn("token", result)
        self.assertIn("expires_at", result)
        self.assertEqual(result["token_type"], "bearer")
        self.assertIn(".", result["token"])

    def test_create_token_has_correct_claims(self):
        from pipeline.auth import create_token, validate_token
        result = create_token("my-subject", 3600)
        claims = validate_token(result["token"])
        self.assertEqual(claims["sub"], "my-subject")
        self.assertEqual(claims["iss"], "data-governance-pipeline")
        self.assertIn("jti", claims)
        self.assertIn("iat", claims)
        self.assertIn("exp", claims)

    def test_create_token_without_secret_raises(self):
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state, create_token
        reset_state()
        with self.assertRaises(RuntimeError):
            create_token("test", 3600)


class TestJWTTokenExpiry(unittest.TestCase):
    """Expired tokens are rejected."""

    def setUp(self):
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests-32b"
        from pipeline.auth import reset_state
        reset_state()

    def tearDown(self):
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()

    def test_expired_token_rejected(self):
        import jwt as pyjwt
        from pipeline.auth import validate_token
        secret = os.environ["PIPELINE_JWT_SECRET"]
        expired_payload = {
            "sub": "test",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
            "jti": "expired-jti",
            "iss": "data-governance-pipeline",
        }
        token = pyjwt.encode(expired_payload, secret, algorithm="HS256")
        with self.assertRaises(pyjwt.ExpiredSignatureError):
            validate_token(token)


class TestJWTTokenRevocation(unittest.TestCase):
    """Revoked tokens are rejected."""

    def setUp(self):
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests-32b"
        from pipeline.auth import reset_state
        reset_state()

    def tearDown(self):
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()

    def test_revoked_token_rejected(self):
        from pipeline.auth import create_token, validate_token, revoke_token
        result = create_token("test-user", 3600)
        claims = validate_token(result["token"])
        jti = claims["jti"]

        revoke_token(jti)

        with self.assertRaises(ValueError):
            validate_token(result["token"])

    def test_validate_prunes_expired_revocations(self):
        from pipeline.auth import create_token, validate_token, revoke_token, is_revoked
        revoke_token("old-jti", expires_at=time.time() - 10)
        self.assertTrue(is_revoked("old-jti"))
        result = create_token("pruner", 3600)
        validate_token(result["token"])
        self.assertFalse(is_revoked("old-jti"))

    def test_prune_removes_expired_revocations(self):
        from pipeline.auth import revoke_token, is_revoked, prune_revoked
        revoke_token("old-jti", expires_at=time.time() - 10)
        self.assertTrue(is_revoked("old-jti"))
        removed = prune_revoked()
        self.assertEqual(removed, 1)
        self.assertFalse(is_revoked("old-jti"))


# ── API integration tests (async for Quart) ───────────────────────────────

class TestAPIWithJWT:
    """API endpoints work with JWT authentication."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "static-key-1"
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests-32b"
        from pipeline.auth import reset_state
        reset_state()
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()

    @pytest.mark.asyncio
    async def test_exchange_api_key_for_jwt(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-API-Key": "static-key-1"},
                                     json={"subject": "test-client"})
            assert resp.status_code == 201
            body = await resp.get_json()
            assert "token" in body
            assert body["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_jwt_authenticates_status_endpoint(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-API-Key": "static-key-1"},
                                     json={"subject": "test-client"})
            token = (await resp.get_json())["token"]

            resp = await client.get("/status",
                                    headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_expired_jwt_returns_401(self):
        import jwt as pyjwt
        secret = os.environ["PIPELINE_JWT_SECRET"]
        expired_token = pyjwt.encode({
            "sub": "test", "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
            "jti": "expired", "iss": "data-governance-pipeline",
        }, secret, algorithm="HS256")

        async with self.app.test_client() as client:
            resp = await client.get("/status",
                                    headers={"Authorization": f"Bearer {expired_token}"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_revoked_jwt_returns_401(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-API-Key": "static-key-1"},
                                     json={"subject": "test-client"})
            token = (await resp.get_json())["token"]

            from pipeline.auth import validate_token
            claims = validate_token(token)
            jti = claims["jti"]

            resp = await client.post("/auth/revoke",
                                     headers={"X-API-Key": "static-key-1"},
                                     json={"jti": jti})
            assert resp.status_code == 200

            resp = await client.get("/status",
                                    headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_static_key_still_works_alongside_jwt(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status",
                                    headers={"X-API-Key": "static-key-1"})
            assert resp.status_code == 200


class TestAPIWithoutJWT:
    """When PIPELINE_JWT_SECRET is not set, static keys work unchanged."""

    def setup_method(self):
        os.environ["PIPELINE_API_KEYS"] = "static-key-only"
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)

    def teardown_method(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        from pipeline.auth import reset_state
        reset_state()

    @pytest.mark.asyncio
    async def test_static_key_works(self):
        async with self.app.test_client() as client:
            resp = await client.get("/status",
                                    headers={"X-API-Key": "static-key-only"})
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_auth_token_endpoint_returns_501(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/token",
                                     headers={"X-API-Key": "static-key-only"})
            assert resp.status_code == 501

    @pytest.mark.asyncio
    async def test_auth_revoke_endpoint_returns_501(self):
        async with self.app.test_client() as client:
            resp = await client.post("/auth/revoke",
                                     headers={"X-API-Key": "static-key-only"},
                                     json={"jti": "some-jti"})
            assert resp.status_code == 501


# ── Persistent revocation store ──────────────────────────────────────────

class TestPersistentRevocation(unittest.TestCase):
    """SQLite-backed revocation survives re-initialization."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="auth_revoke_")
        self.db_path = os.path.join(self.tmpdir, "revoke.db")
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests-32b"
        os.environ["PIPELINE_JWT_REVOCATION_DB"] = self.db_path
        from pipeline.auth import reset_state
        reset_state()

    def tearDown(self):
        os.environ.pop("PIPELINE_JWT_REVOCATION_DB", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_revocation_persists_across_reinit(self):
        from pipeline.auth import create_token, validate_token, revoke_token, reset_state
        result = create_token("test-user", 3600)
        claims = validate_token(result["token"])
        revoke_token(claims["jti"])

        reset_state()

        with self.assertRaises(ValueError):
            validate_token(result["token"])

    def test_prune_removes_expired_from_db(self):
        from pipeline.auth import revoke_token, is_revoked, prune_revoked
        revoke_token("old-jti", expires_at=time.time() - 10)
        self.assertTrue(is_revoked("old-jti"))
        removed = prune_revoked()
        self.assertEqual(removed, 1)
        self.assertFalse(is_revoked("old-jti"))
