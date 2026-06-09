"""
Tests for QuickBooksExtractor — QBO REST API extraction.

Query building, record flattening, base-URL selection, and OAuth token refresh
are tested directly; the paginated extract() loop is driven by a mocked
requests.Session.

Revision history
────────────────
1.0   2026-06-09   Initial release: query/flatten/token/pagination coverage.
"""

import unittest
from unittest.mock import MagicMock, patch

from pipeline.loaders.quickbooks_extractor import QuickBooksExtractor


def _resp(ok=True, status=200, payload=None, text=""):
    r = MagicMock()
    r.ok = ok
    r.status_code = status
    r.json.return_value = payload or {}
    r.text = text
    return r


class TestBuildQuery(unittest.TestCase):
    def setUp(self):
        self.ext = QuickBooksExtractor(MagicMock())

    def test_no_filters(self):
        q = self.ext._build_query("Customer", {}, 1, 100)
        self.assertEqual(q, "SELECT * FROM Customer STARTPOSITION 1 MAXRESULTS 100")

    def test_date_from_uses_entity_date_field(self):
        q = self.ext._build_query("Invoice", {"date_from": "2024-01-01"}, 1, 50)
        self.assertIn("WHERE TxnDate >= '2024-01-01'", q)

    def test_unknown_entity_defaults_to_lastupdated(self):
        q = self.ext._build_query("Customer", {"date_from": "2024-01-01"}, 1, 50)
        self.assertIn("MetaData.LastUpdatedTime >= '2024-01-01'", q)

    def test_invalid_date_raises(self):
        with self.assertRaises(ValueError):
            self.ext._build_query("Invoice", {"date_from": "01/01/2024"}, 1, 50)

    def test_extra_where_appended(self):
        q = self.ext._build_query("Customer", {"extra_where": "Active = true"}, 1, 50)
        self.assertIn("WHERE Active = true", q)

    def test_date_range_both_bounds(self):
        q = self.ext._build_query(
            "Bill", {"date_from": "2024-01-01", "date_to": "2024-12-31"}, 5, 10)
        self.assertIn("TxnDate >= '2024-01-01'", q)
        self.assertIn("TxnDate <= '2024-12-31'", q)
        self.assertIn("STARTPOSITION 5 MAXRESULTS 10", q)


class TestFlatten(unittest.TestCase):
    def setUp(self):
        self.ext = QuickBooksExtractor(MagicMock())

    def test_nested_dict_flattened(self):
        rec = {"Id": "1", "BillAddr": {"City": "NYC", "Country": "US"}}
        flat = self.ext._flatten_qbo_record(rec, "Customer")
        self.assertEqual(flat["BillAddr__City"], "NYC")
        self.assertEqual(flat["BillAddr__Country"], "US")

    def test_list_serialised_to_json(self):
        rec = {"Id": "1", "Lines": [{"Amount": 5}]}
        flat = self.ext._flatten_qbo_record(rec, "Invoice")
        self.assertEqual(flat["Lines"], '[{"Amount": 5}]')


class TestBaseUrl(unittest.TestCase):
    def setUp(self):
        self.ext = QuickBooksExtractor(MagicMock())

    def test_production(self):
        url = self.ext._base_url({"realm_id": "R1"})
        self.assertTrue(url.startswith("https://quickbooks.api.intuit.com"))
        self.assertIn("/v3/company/R1", url)

    def test_sandbox(self):
        url = self.ext._base_url({"realm_id": "R1", "environment": "sandbox"})
        self.assertIn("sandbox-quickbooks", url)


class TestTokenRefresh(unittest.TestCase):
    def setUp(self):
        self.ext = QuickBooksExtractor(MagicMock())
        self.cfg = {"client_id": "id", "client_secret": "sec",
                    "refresh_token": "old"}

    def test_returns_access_token_and_rotates_refresh(self):
        with patch("requests.post", return_value=_resp(
                payload={"access_token": "AT", "refresh_token": "new"})):
            token = self.ext._refresh_access_token(self.cfg)
        self.assertEqual(token, "AT")
        self.assertEqual(self.cfg["refresh_token"], "new")  # rotated in place

    def test_failure_raises(self):
        with patch("requests.post", return_value=_resp(ok=False, status=401, text="nope")):
            with self.assertRaises(RuntimeError):
                self.ext._refresh_access_token(self.cfg)


class TestExtract(unittest.TestCase):
    def setUp(self):
        self.gov = MagicMock()
        self.ext = QuickBooksExtractor(self.gov)
        self.cfg = {"realm_id": "R1", "entity": "Customer", "page_size": 2}

    def _session_returning(self, *responses):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.side_effect = list(responses)
        return session

    def test_paginates_until_short_page(self):
        page1 = _resp(payload={"QueryResponse": {"Customer": [{"Id": "1"}, {"Id": "2"}]}})
        page2 = _resp(payload={"QueryResponse": {"Customer": [{"Id": "3"}]}})  # < page_size
        with patch.object(self.ext, "_refresh_access_token", return_value="AT"), \
             patch("requests.Session", return_value=self._session_returning(page1, page2)):
            df = self.ext.extract(self.cfg)
        self.assertEqual(len(df), 3)
        self.gov.transformation_applied.assert_called_once()

    def test_empty_result_returns_empty_df(self):
        page1 = _resp(payload={"QueryResponse": {}})
        with patch.object(self.ext, "_refresh_access_token", return_value="AT"), \
             patch("requests.Session", return_value=self._session_returning(page1)):
            df = self.ext.extract(self.cfg)
        self.assertTrue(df.empty)

    def test_api_error_raises(self):
        bad = _resp(ok=False, status=500, text="boom")
        with patch.object(self.ext, "_refresh_access_token", return_value="AT"), \
             patch("requests.Session", return_value=self._session_returning(bad)):
            with self.assertRaises(RuntimeError):
                self.ext.extract(self.cfg)


if __name__ == "__main__":
    unittest.main()
