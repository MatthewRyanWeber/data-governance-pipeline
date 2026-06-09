"""
Tests for DatasphereLoader — SAP Datasphere OData v4 upload.

Token acquisition, endpoint building, batched PATCH upload, replace-truncate,
and validation are covered with requests mocked.

Revision history
────────────────
1.0   2026-06-09   Initial release: OData load-path coverage.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.loaders.datasphere_loader import DatasphereLoader
from pipeline.exceptions import ConfigValidationError

_DF = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})


class TestDatasphereToken(unittest.TestCase):
    def setUp(self):
        self.loader = DatasphereLoader(MagicMock())

    def test_static_token_skips_request(self):
        with patch("requests.post") as post:
            token = self.loader._get_token({"token": "T"})
        self.assertEqual(token, "T")
        post.assert_not_called()

    def test_oauth_client_credentials(self):
        resp = MagicMock()
        resp.json.return_value = {"access_token": "AT"}
        with patch("requests.post", return_value=resp):
            token = self.loader._get_token(
                {"token_url": "u", "client_id": "c", "client_secret": "s"})
        self.assertEqual(token, "AT")


class TestDatasphereEndpoint(unittest.TestCase):
    def test_endpoint_built_from_tenant_space_table(self):
        loader = DatasphereLoader(MagicMock())
        url = loader._endpoint({"tenant_url": "https://x.com/", "space": "SP",
                                "table": "T"})
        self.assertEqual(
            url, "https://x.com/api/v1/dwc/catalog/spaces/SP/assets/T/data")


class TestDatasphereLoad(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = DatasphereLoader(self.gov)
        self.cfg = {"tenant_url": "https://x.com", "token": "T",
                    "space": "SP", "table": "T", "batch_size": 1}

    def test_batched_patch_upload(self):
        with patch.object(self.loader, "_patch_batch") as patch_batch:
            self.loader.load(_DF, self.cfg)
        # batch_size=1 over 2 rows -> two PATCH calls.
        self.assertEqual(patch_batch.call_count, 2)
        self.gov.load_complete.assert_called_once_with(2, "T")

    def test_replace_truncates_first(self):
        with patch.object(self.loader, "_patch_batch"), \
             patch.object(self.loader, "_truncate") as truncate:
            self.loader.load(_DF, self.cfg, if_exists="replace")
        truncate.assert_called_once()

    def test_dry_run_skips_token(self):
        loader = DatasphereLoader(self.gov, dry_run=True)
        with patch.object(loader, "_get_token") as get_token:
            loader.load(_DF, self.cfg)
        get_token.assert_not_called()

    def test_missing_config_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(_DF, {"space": "SP"})  # no tenant_url/token

    def test_patch_batch_error_raises(self):
        resp = MagicMock()
        resp.ok = False
        resp.status_code = 400
        resp.text = "bad"
        with patch("requests.patch", return_value=resp):
            with self.assertRaises(RuntimeError):
                self.loader._patch_batch("u", {}, [{"id": 1}], 30)


if __name__ == "__main__":
    unittest.main()
