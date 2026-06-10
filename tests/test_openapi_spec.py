"""
Tests for the OpenAPI specification and Swagger UI.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import asyncio
import os
import unittest

from pipeline.openapi_spec import get_openapi_spec


class TestOpenAPISpec(unittest.TestCase):

    def setUp(self):
        self.spec = get_openapi_spec()

    def test_spec_is_openapi_3(self):
        self.assertTrue(self.spec["openapi"].startswith("3."))

    def test_info_present(self):
        self.assertIn("title", self.spec["info"])
        self.assertIn("version", self.spec["info"])
        self.assertIn("description", self.spec["info"])

    def test_all_routes_documented(self):
        paths = set(self.spec["paths"].keys())
        expected = {"/run", "/status", "/health", "/metrics",
                    "/auth/token", "/auth/revoke", "/openapi.json", "/docs"}
        self.assertTrue(expected.issubset(paths), f"Missing: {expected - paths}")

    def test_run_endpoint_has_methods(self):
        run = self.spec["paths"]["/run"]
        self.assertIn("post", run)
        self.assertIn("requestBody", run["post"])

    def test_security_schemes_defined(self):
        schemes = self.spec["components"]["securitySchemes"]
        self.assertIn("ApiKeyHeader", schemes)
        self.assertIn("BearerAuth", schemes)
        self.assertIn("JWTAuth", schemes)

    def test_schemas_defined(self):
        schemas = self.spec["components"]["schemas"]
        self.assertIn("RunRequest", schemas)
        self.assertIn("StatusResponse", schemas)
        self.assertIn("Error", schemas)
        self.assertIn("HealthResponse", schemas)

    def test_error_schema_structure(self):
        error = self.spec["components"]["schemas"]["Error"]
        self.assertIn("error", error["properties"])
        required = error["properties"]["error"]["required"]
        self.assertIn("code", required)
        self.assertIn("message", required)
        self.assertIn("request_id", required)

    def test_health_no_auth(self):
        health = self.spec["paths"]["/health"]["get"]
        self.assertEqual(health["security"], [])

    def test_run_requires_auth(self):
        run = self.spec["paths"]["/run"]["post"]
        self.assertTrue(len(run["security"]) > 0)


class TestDocsRoutes(unittest.TestCase):

    def setUp(self):
        os.environ.pop("PIPELINE_API_KEYS", None)
        from pipeline.api import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def test_openapi_json_returns_200(self):
        async def _test():
            resp = await self.client.get("/openapi.json")
            self.assertEqual(resp.status_code, 200)
            data = await resp.get_json()
            self.assertIn("openapi", data)
        asyncio.run(_test())

    def test_docs_returns_html(self):
        async def _test():
            resp = await self.client.get("/docs")
            self.assertEqual(resp.status_code, 200)
            body = await resp.get_data(as_text=True)
            self.assertIn("swagger-ui", body)
        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
