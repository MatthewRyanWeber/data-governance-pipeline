"""
Tests for JWT auth token creation, validation, revocation, and API integration.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import os
import time
import unittest


class TestJWTTokenCreation(unittest.TestCase):
    """create_token returns a valid JWT with correct claims."""

    def setUp(self):
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests"
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
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests"
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
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests"
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

    def test_prune_removes_expired_revocations(self):
        from pipeline.auth import revoke_token, is_revoked, prune_revoked
        revoke_token("old-jti", expires_at=time.time() - 10)
        self.assertTrue(is_revoked("old-jti"))
        removed = prune_revoked()
        self.assertEqual(removed, 1)
        self.assertFalse(is_revoked("old-jti"))


class TestAPIWithJWT(unittest.TestCase):
    """API endpoints work with JWT authentication."""

    def setUp(self):
        os.environ["PIPELINE_API_KEYS"] = "static-key-1"
        os.environ["PIPELINE_JWT_SECRET"] = "test-secret-key-for-unit-tests"
        from pipeline.auth import reset_state
        reset_state()
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()

    def test_exchange_api_key_for_jwt(self):
        resp = self.client.post("/auth/token",
                                headers={"X-API-Key": "static-key-1"},
                                json={"subject": "test-client"})
        self.assertEqual(resp.status_code, 201)
        body = resp.get_json()
        self.assertIn("token", body)
        self.assertEqual(body["token_type"], "bearer")

    def test_jwt_authenticates_status_endpoint(self):
        resp = self.client.post("/auth/token",
                                headers={"X-API-Key": "static-key-1"},
                                json={"subject": "test-client"})
        token = resp.get_json()["token"]

        resp = self.client.get("/status",
                               headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)

    def test_expired_jwt_returns_401(self):
        import jwt as pyjwt
        secret = os.environ["PIPELINE_JWT_SECRET"]
        expired_token = pyjwt.encode({
            "sub": "test", "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
            "jti": "expired", "iss": "data-governance-pipeline",
        }, secret, algorithm="HS256")

        resp = self.client.get("/status",
                               headers={"Authorization": f"Bearer {expired_token}"})
        self.assertEqual(resp.status_code, 401)

    def test_revoked_jwt_returns_401(self):
        resp = self.client.post("/auth/token",
                                headers={"X-API-Key": "static-key-1"},
                                json={"subject": "test-client"})
        token = resp.get_json()["token"]

        from pipeline.auth import validate_token
        claims = validate_token(token)
        jti = claims["jti"]

        resp = self.client.post("/auth/revoke",
                                headers={"X-API-Key": "static-key-1"},
                                json={"jti": jti})
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get("/status",
                               headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 401)

    def test_static_key_still_works_alongside_jwt(self):
        resp = self.client.get("/status",
                               headers={"X-API-Key": "static-key-1"})
        self.assertEqual(resp.status_code, 200)


class TestAPIWithoutJWT(unittest.TestCase):
    """When PIPELINE_JWT_SECRET is not set, static keys work unchanged."""

    def setUp(self):
        os.environ["PIPELINE_API_KEYS"] = "static-key-only"
        os.environ.pop("PIPELINE_JWT_SECRET", None)
        from pipeline.auth import reset_state
        reset_state()
        from pipeline.api import create_app
        self.app = create_app(pipeline_fn=lambda s, d, c: None)
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        from pipeline.auth import reset_state
        reset_state()

    def test_static_key_works(self):
        resp = self.client.get("/status",
                               headers={"X-API-Key": "static-key-only"})
        self.assertEqual(resp.status_code, 200)

    def test_auth_token_endpoint_returns_501(self):
        resp = self.client.post("/auth/token",
                                headers={"X-API-Key": "static-key-only"})
        self.assertEqual(resp.status_code, 501)

    def test_auth_revoke_endpoint_returns_501(self):
        resp = self.client.post("/auth/revoke",
                                headers={"X-API-Key": "static-key-only"},
                                json={"jti": "some-jti"})
        self.assertEqual(resp.status_code, 501)


if __name__ == "__main__":
    unittest.main()
