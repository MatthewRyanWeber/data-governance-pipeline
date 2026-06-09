"""
Tests for MongoLoader — DataFrame -> MongoDB collection.

The pymongo client is patched so the load path is exercised without a live
server: record conversion, insert_many invocation, URI construction, dry_run,
and config validation.

Revision history
────────────────
1.0   2026-06-09   Initial release: mocked load-path coverage for MongoLoader.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.loaders.mongo_loader import MongoLoader
from pipeline.exceptions import ConfigValidationError


class TestMongoLoader(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.loader = MongoLoader(self.gov)
        self.df = pd.DataFrame({"id": [1, 2], "name": ["a", "b"]})

    def _patched_client(self):
        """Return a (patch_context, captured) pair for a mocked MongoClient."""
        client_instance = MagicMock()
        mock_client_cls = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = client_instance
        return mock_client_cls, client_instance

    def test_insert_many_called_with_records(self):
        mock_cls, client = self._patched_client()
        with patch("pymongo.MongoClient", mock_cls):
            self.loader.load(self.df, {"db_name": "appdb"}, "users")
        collection = client.__getitem__.return_value.__getitem__.return_value
        collection.insert_many.assert_called_once()
        records = collection.insert_many.call_args[0][0]
        self.assertEqual(records, [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}])
        self.gov.load_complete.assert_called_once_with(2, "users")

    def test_uri_constructed_from_host_port(self):
        mock_cls, _ = self._patched_client()
        with patch("pymongo.MongoClient", mock_cls):
            self.loader.load(self.df, {"db_name": "d", "host": "h", "port": 1234}, "c")
        mock_cls.assert_called_once_with("mongodb://h:1234/")

    def test_explicit_uri_used(self):
        mock_cls, _ = self._patched_client()
        with patch("pymongo.MongoClient", mock_cls):
            self.loader.load(self.df, {"db_name": "d", "uri": "mongodb://custom/"}, "c")
        mock_cls.assert_called_once_with("mongodb://custom/")

    def test_dry_run_skips_insert(self):
        loader = MongoLoader(self.gov, dry_run=True)
        mock_cls, client = self._patched_client()
        with patch("pymongo.MongoClient", mock_cls):
            loader.load(self.df, {"db_name": "d"}, "c")
        mock_cls.assert_not_called()

    def test_missing_db_name_raises(self):
        with self.assertRaises(ConfigValidationError):
            self.loader.load(self.df, {}, "c")


if __name__ == "__main__":
    unittest.main()
