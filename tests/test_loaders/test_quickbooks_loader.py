"""
Tests for QuickBooksLoader — QBO REST API v3 $batch writes.

The requests.Session is mocked; tests cover batch chunking (30 ops per
request), SyncToken fetch for updates, per-item fault accounting, and the
true-success count reported to governance.

Revision history
────────────────
1.0   2026-06-11   Initial release: $batch endpoint coverage for the rewrite
                   away from one-POST-per-row.
"""

import unittest
from unittest.mock import MagicMock, patch

import pandas as pd

from pipeline.loaders.quickbooks_loader import QuickBooksLoader


def _response(ok=True, status=200, payload=None, text=""):
    resp = MagicMock()
    resp.ok = ok
    resp.status_code = status
    resp.json.return_value = payload if payload is not None else {}
    resp.text = text
    return resp


def _batch_response_for(request_json):
    """Build a $batch response that succeeds every requested item."""
    items = request_json["BatchItemRequest"]
    return _response(payload={
        "BatchItemResponse": [
            {"bId": item["bId"], "Customer": {"Id": "100"}} for item in items
        ],
    })


class _SessionStub:
    """Minimal requests.Session stand-in recording every HTTP call."""

    def __init__(self, batch_responder=None, get_responder=None):
        self.posts = []
        self.gets = []
        self.headers = {}
        self._batch_responder = batch_responder or _batch_response_for
        self._get_responder = get_responder

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        return self._batch_responder(json)

    def get(self, url, timeout=None):
        self.gets.append(url)
        if self._get_responder:
            return self._get_responder(url)
        return _response(payload={"Customer": {"Id": "55", "SyncToken": "7"}})


class TestQuickBooksBatchLoad(unittest.TestCase):

    def setUp(self):
        # test_loader_dispatch.py calls logging.disable(CRITICAL) at module
        # level, which would break assertLogs here in combined runs
        import logging
        logging.disable(logging.NOTSET)
        self.gov = MagicMock()
        self.loader = QuickBooksLoader(self.gov)
        self.cfg = {
            "client_id": "id", "client_secret": "sec",
            "refresh_token": "tok", "realm_id": "R1",
            "entity": "Customer", "batch_delay": 0,
        }

    def _load(self, df, session=None):
        session = session or _SessionStub()
        with patch.object(self.loader, "_refresh_access_token", return_value="AT"), \
             patch("requests.Session", return_value=session):
            result = self.loader.load(df, self.cfg)
        return result, session

    def test_rows_sent_through_batch_endpoint(self):
        """Regression: one POST per row + sleep — rows must go through
        the $batch endpoint instead."""
        df = pd.DataFrame({"DisplayName": ["Acme", "Globex"]})
        n, session = self._load(df)
        self.assertEqual(n, 2)
        self.assertEqual(len(session.posts), 1)
        url, body = session.posts[0]
        self.assertIn("/batch", url)
        self.assertEqual(len(body["BatchItemRequest"]), 2)
        self.assertTrue(all(
            item["operation"] == "create" for item in body["BatchItemRequest"]
        ))
        self.gov.load_complete.assert_called_once_with(2, "Customer")

    def test_batches_chunked_at_thirty_operations(self):
        df = pd.DataFrame({"DisplayName": [f"c{i}" for i in range(65)]})
        n, session = self._load(df)
        self.assertEqual(n, 65)
        self.assertEqual(len(session.posts), 3)
        sizes = [len(body["BatchItemRequest"]) for _, body in session.posts]
        self.assertEqual(sizes, [30, 30, 5])

    def test_update_fetches_sync_token_and_sends_sparse(self):
        """Regression: updates without SyncToken were rejected by QBO but
        still reported as loaded."""
        df = pd.DataFrame({"Id": ["55"], "DisplayName": ["Acme"]})
        n, session = self._load(df)
        self.assertEqual(n, 1)
        self.assertEqual(len(session.gets), 1)
        self.assertIn("/customer/55", session.gets[0])
        _, body = session.posts[0]
        item = body["BatchItemRequest"][0]
        self.assertEqual(item["operation"], "update")
        self.assertEqual(item["Customer"]["SyncToken"], "7")
        self.assertTrue(item["Customer"]["sparse"])

    def test_item_faults_counted_as_errors_not_successes(self):
        """Regression: load_complete must report true successes only."""
        def respond_with_one_fault(request_json):
            items = request_json["BatchItemRequest"]
            return _response(payload={"BatchItemResponse": [
                {"bId": items[0]["bId"], "Customer": {"Id": "1"}},
                {"bId": items[1]["bId"],
                 "Fault": {"Error": [{"Message": "Duplicate Name"}]}},
            ]})

        df = pd.DataFrame({"DisplayName": ["Acme", "Acme"]})
        session = _SessionStub(batch_responder=respond_with_one_fault)
        import logging
        with self.assertLogs("pipeline.loaders.quickbooks_loader",
                             level=logging.ERROR):
            n, _ = self._load(df, session=session)
        self.assertEqual(n, 1)
        self.gov.load_complete.assert_called_once_with(1, "Customer")

    def test_failed_batch_post_counts_whole_chunk_as_errors(self):
        def reject_everything(request_json):
            return _response(ok=False, status=500, text="boom")

        df = pd.DataFrame({"DisplayName": ["Acme", "Globex"]})
        session = _SessionStub(batch_responder=reject_everything)
        import logging
        with self.assertLogs("pipeline.loaders.quickbooks_loader",
                             level=logging.ERROR):
            n, _ = self._load(df, session=session)
        self.assertEqual(n, 0)
        self.gov.load_complete.assert_called_once_with(0, "Customer")

    def test_rows_missing_required_fields_skipped(self):
        df = pd.DataFrame({"DisplayName": [None, "Acme"]})
        n, session = self._load(df)
        self.assertEqual(n, 1)
        _, body = session.posts[0]
        self.assertEqual(len(body["BatchItemRequest"]), 1)

    def test_sync_token_fetch_failure_marks_row_as_error(self):
        def failing_get(url):
            return _response(ok=False, status=404, text="not found")

        df = pd.DataFrame({"Id": ["55"], "DisplayName": ["Acme"]})
        session = _SessionStub(get_responder=failing_get)
        import logging
        with self.assertLogs("pipeline.loaders.quickbooks_loader",
                             level=logging.ERROR):
            n, _ = self._load(df, session=session)
        self.assertEqual(n, 0)
        self.assertEqual(len(session.posts), 0)

    def test_dry_run_returns_zero_without_network(self):
        loader = QuickBooksLoader(self.gov, dry_run=True)
        df = pd.DataFrame({"DisplayName": ["Acme"]})
        with patch("requests.Session") as session_cls:
            result = loader.load(df, self.cfg)
        self.assertEqual(result, 0)
        session_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
