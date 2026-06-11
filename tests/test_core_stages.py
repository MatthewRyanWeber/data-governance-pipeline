"""
Tests for four core pipeline stages: DatabaseExtractor, RESTExtractor,
TransformPipeline, and LoadVerifier.

Uses real SQLite databases for SQL tests, unittest.mock.patch for HTTP
tests, and synthetic data only (alice@example.com, 555-0101).

Revision history
────────────────
1.0   2026-06-08   Initial release — comprehensive coverage for all four modules.
1.1   2026-06-11   Tests for the referential-integrity step (now validated
                   against a cached reference frame) and rules-file caching.
"""

import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pandas as pd


class MockGov:
    """Accepts any method call without error — used as a lightweight governance stub."""

    def __getattr__(self, name):
        return lambda *a, **kw: None


# ═══════════════════════════════════════════════════════════════════════════════
# DatabaseExtractor
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatabaseExtractorBuildUrl(unittest.TestCase):
    """Tests for DatabaseExtractor._build_url."""

    def setUp(self):
        from pipeline.extractors.database_extractor import DatabaseExtractor
        self.ext = DatabaseExtractor(MockGov())

    def test_build_url_postgresql(self):
        cfg = {
            "db_type": "postgresql",
            "host": "db.example.com",
            "port": "5432",
            "user": "alice",
            "password": "s3cret",
            "db_name": "warehouse",
        }
        url = self.ext._build_url(cfg)
        self.assertIn("postgresql+psycopg2://", url)
        self.assertIn("alice", url)
        self.assertIn("db.example.com", url)
        self.assertIn(":5432/", url)
        self.assertIn("warehouse", url)

    def test_build_url_sqlite(self):
        cfg = {"db_type": "sqlite", "db_name": "/tmp/test.db"}
        url = self.ext._build_url(cfg)
        self.assertEqual(url, "sqlite:////tmp/test.db")

    def test_build_url_connection_string(self):
        cfg = {
            "connection_string": "postgresql://custom@host/db",
            "db_type": "mysql",
            "host": "ignored",
        }
        url = self.ext._build_url(cfg)
        self.assertEqual(url, "postgresql://custom@host/db")

    def test_build_url_unsupported(self):
        cfg = {"db_type": "couchdb", "db_name": "mydb"}
        with self.assertRaises(ValueError) as ctx:
            self.ext._build_url(cfg)
        self.assertIn("couchdb", str(ctx.exception).lower())


class TestDatabaseExtractorExtract(unittest.TestCase):
    """Tests for DatabaseExtractor.extract using a real SQLite database."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self._create_db()

        from pipeline.extractors.database_extractor import DatabaseExtractor
        self.ext = DatabaseExtractor(MockGov())
        self.cfg = {"db_type": "sqlite", "db_name": self.db_path}

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_db(self, row_count=5):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, phone TEXT)"
        )
        for i in range(1, row_count + 1):
            conn.execute(
                "INSERT INTO users (id, email, phone) VALUES (?, ?, ?)",
                (i, f"user{i}@example.com", f"555-010{i}"),
            )
        conn.commit()
        conn.close()

    def test_extract_from_table(self):
        df = self.ext.extract(self.cfg, table="users")
        self.assertEqual(len(df), 5)
        self.assertListEqual(sorted(df.columns.tolist()), ["email", "id", "phone"])
        self.assertIn("user1@example.com", df["email"].values)

    def test_extract_with_query(self):
        df = self.ext.extract(
            self.cfg, query="SELECT * FROM users WHERE id <= 2"
        )
        self.assertEqual(len(df), 2)
        self.assertTrue(all(df["id"] <= 2))

    def test_extract_with_columns(self):
        df = self.ext.extract(self.cfg, table="users", columns=["id", "email"])
        self.assertEqual(list(df.columns), ["id", "email"])
        self.assertNotIn("phone", df.columns)

    def test_extract_empty_table(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE empty_table (id INTEGER, name TEXT)")
        conn.commit()
        conn.close()

        df = self.ext.extract(self.cfg, table="empty_table")
        self.assertEqual(len(df), 0)

    def test_extract_requires_query_or_table(self):
        with self.assertRaises(ValueError):
            self.ext.extract(self.cfg)


class TestDatabaseExtractorChunks(unittest.TestCase):
    """Tests for DatabaseExtractor.chunks — chunked extraction."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "chunks.db")

        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, val TEXT)")
        for i in range(1, 101):
            conn.execute("INSERT INTO data (id, val) VALUES (?, ?)", (i, f"row_{i}"))
        conn.commit()
        conn.close()

        from pipeline.extractors.database_extractor import DatabaseExtractor
        self.ext = DatabaseExtractor(MockGov())
        self.cfg = {"db_type": "sqlite", "db_name": self.db_path}

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_chunks_yields_batches(self):
        chunks = list(self.ext.chunks(self.cfg, table="data", chunk_size=30))
        self.assertEqual(len(chunks), 4)
        sizes = [len(c) for c in chunks]
        self.assertEqual(sizes, [30, 30, 30, 10])
        total_rows = sum(sizes)
        self.assertEqual(total_rows, 100)


class TestDatabaseExtractorGovernance(unittest.TestCase):
    """Tests that governance events fire during extraction."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "gov.db")

        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("INSERT INTO t VALUES (1)")
        conn.commit()
        conn.close()

        self.gov = MagicMock()
        from pipeline.extractors.database_extractor import DatabaseExtractor
        self.ext = DatabaseExtractor(self.gov)
        self.cfg = {"db_type": "sqlite", "db_name": self.db_path}

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_governance_events_fired(self):
        self.ext.extract(self.cfg, table="t")
        self.gov.extract_event.assert_called()
        self.gov.source_registered.assert_called_once()

        call_args = self.gov.source_registered.call_args
        self.assertEqual(call_args[0][0], "t")


# ═══════════════════════════════════════════════════════════════════════════════
# RESTExtractor
# ═══════════════════════════════════════════════════════════════════════════════

def _mock_response(json_data, status_code=200, headers=None):
    """Build a mock requests.Response-like object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import requests
        resp.raise_for_status.side_effect = requests.HTTPError(
            response=resp
        )
    return resp


class TestRESTExtractorSinglePage(unittest.TestCase):
    """Tests for RESTExtractor with no pagination."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.ext = RESTExtractor(MockGov())

    @patch("requests.Session")
    def test_single_page_no_pagination(self, mock_session_cls):
        records = [
            {"id": 1, "email": "alice@example.com"},
            {"id": 2, "email": "bob@example.com"},
        ]
        session = MagicMock()
        session.headers = {}
        session.get.return_value = _mock_response(records)
        mock_session_cls.return_value = session

        cfg = {"url": "https://api.example.com/users"}
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 2)
        self.assertIn("email", df.columns)

    @patch("requests.Session")
    def test_empty_response(self, mock_session_cls):
        session = MagicMock()
        session.headers = {}
        session.get.return_value = _mock_response([])
        mock_session_cls.return_value = session

        cfg = {"url": "https://api.example.com/empty"}
        df = self.ext.extract(cfg)
        self.assertTrue(df.empty)


class TestRESTExtractorOffsetPagination(unittest.TestCase):
    """Tests for offset-based pagination."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.ext = RESTExtractor(MockGov())

    @patch("requests.Session")
    def test_offset_pagination(self, mock_session_cls):
        page1 = [{"id": i, "name": f"user_{i}"} for i in range(10)]
        page2 = [{"id": i, "name": f"user_{i}"} for i in range(10, 20)]
        page3 = []

        session = MagicMock()
        session.headers = {}
        session.get.side_effect = [
            _mock_response(page1),
            _mock_response(page2),
            _mock_response(page3),
        ]
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/users",
            "pagination": {
                "type": "offset",
                "page_size": 10,
                "limit_param": "limit",
                "offset_param": "offset",
            },
            "rate_limit_delay": 0,
        }
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 20)


class TestRESTExtractorCursorPagination(unittest.TestCase):
    """Tests for cursor-based pagination."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.ext = RESTExtractor(MockGov())

    @patch("requests.Session")
    def test_cursor_pagination(self, mock_session_cls):
        page1_data = {
            "results": [{"id": 1}, {"id": 2}],
            "next_cursor": "abc123",
        }
        page2_data = {
            "results": [{"id": 3}, {"id": 4}],
            "next_cursor": None,
        }

        session = MagicMock()
        session.headers = {}
        session.get.side_effect = [
            _mock_response(page1_data),
            _mock_response(page2_data),
        ]
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/items",
            "data_path": "results",
            "pagination": {
                "type": "cursor",
                "cursor_param": "cursor",
                "cursor_path": "next_cursor",
                "page_size": 10,
            },
            "rate_limit_delay": 0,
        }
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 4)


class TestRESTExtractorLinkHeaderPagination(unittest.TestCase):
    """Tests for RFC 5988 Link header pagination."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.ext = RESTExtractor(MockGov())

    @patch("requests.Session")
    def test_link_header_pagination(self, mock_session_cls):
        resp1 = _mock_response(
            [{"id": 1}, {"id": 2}],
            headers={"Link": '<https://api.example.com/users?page=2>; rel="next"'},
        )
        resp2 = _mock_response(
            [{"id": 3}],
            headers={},
        )

        session = MagicMock()
        session.headers = {}
        session.get.side_effect = [resp1, resp2]
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/users",
            "pagination": {"type": "link_header"},
            "rate_limit_delay": 0,
        }
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 3)


class TestRESTExtractorDataPath(unittest.TestCase):
    """Tests for navigating nested response JSON."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.ext = RESTExtractor(MockGov())

    @patch("requests.Session")
    def test_data_path_navigation(self, mock_session_cls):
        nested = {
            "data": {
                "results": [
                    {"id": 1, "email": "alice@example.com"},
                    {"id": 2, "email": "bob@example.com"},
                ]
            }
        }
        session = MagicMock()
        session.headers = {}
        session.get.return_value = _mock_response(nested)
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/data",
            "data_path": "data.results",
        }
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 2)
        self.assertIn("alice@example.com", df["email"].values)


class TestRESTExtractorParseLinkNext(unittest.TestCase):
    """Tests for the static _parse_link_next helper."""

    def test_parse_link_next(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        header = '<https://api.example.com/users?page=2>; rel="next", <https://api.example.com/users?page=1>; rel="prev"'
        result = RESTExtractor._parse_link_next(header)
        self.assertEqual(result, "https://api.example.com/users?page=2")

    def test_parse_link_next_no_next(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        header = '<https://api.example.com/users?page=1>; rel="prev"'
        result = RESTExtractor._parse_link_next(header)
        self.assertIsNone(result)

    def test_parse_link_next_empty(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        result = RESTExtractor._parse_link_next("")
        self.assertIsNone(result)


class TestRESTExtractorAuth(unittest.TestCase):
    """Tests for authentication configuration."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.ext = RESTExtractor(MockGov())

    @patch("requests.Session")
    def test_auth_bearer(self, mock_session_cls):
        session = MagicMock()
        session.headers = {}
        session.get.return_value = _mock_response([{"id": 1}])
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/secure",
            "auth": {"type": "bearer", "token": "sk-test-token-123"},
        }
        self.ext.extract(cfg)
        self.assertEqual(session.headers["Authorization"], "Bearer sk-test-token-123")

    @patch("requests.Session")
    def test_auth_basic(self, mock_session_cls):
        session = MagicMock()
        session.headers = {}
        session.get.return_value = _mock_response([{"id": 1}])
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/secure",
            "auth": {"type": "basic", "username": "alice", "password": "s3cret"},
        }
        self.ext.extract(cfg)
        self.assertEqual(session.auth, ("alice", "s3cret"))


class TestRESTExtractorRetry(unittest.TestCase):
    """Tests for retry and rate-limit handling."""

    def setUp(self):
        from pipeline.extractors.rest_extractor import RESTExtractor
        self.gov = MagicMock()
        self.ext = RESTExtractor(self.gov)

    @patch("pipeline.extractors.rest_extractor.time.sleep")
    @patch("requests.Session")
    def test_retry_on_failure(self, mock_session_cls, mock_sleep):
        import requests as real_requests

        fail_resp = MagicMock()
        fail_resp.status_code = 500
        fail_resp.raise_for_status.side_effect = real_requests.HTTPError(
            response=fail_resp,
        )

        ok_resp = _mock_response([{"id": 1}])

        session = MagicMock()
        session.headers = {}
        session.get.side_effect = [fail_resp, ok_resp]
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/flaky",
            "max_retries": 3,
            "rate_limit_delay": 0,
        }
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 1)
        self.assertEqual(session.get.call_count, 2)

    @patch("pipeline.extractors.rest_extractor.time.sleep")
    @patch("requests.Session")
    def test_rate_limit_429(self, mock_session_cls, mock_sleep):
        rate_resp = MagicMock()
        rate_resp.status_code = 429
        rate_resp.headers = {"Retry-After": "1"}

        ok_resp = _mock_response([{"id": 1}])

        session = MagicMock()
        session.headers = {}
        session.get.side_effect = [rate_resp, ok_resp]
        mock_session_cls.return_value = session

        cfg = {
            "url": "https://api.example.com/limited",
            "max_retries": 3,
            "rate_limit_delay": 0,
        }
        df = self.ext.extract(cfg)
        self.assertEqual(len(df), 1)
        mock_sleep.assert_any_call(1)


# ═══════════════════════════════════════════════════════════════════════════════
# TransformPipeline
# ═══════════════════════════════════════════════════════════════════════════════

class TestTransformPipelineBasic(unittest.TestCase):
    """Tests for TransformPipeline basic step execution."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.gov = MockGov()
        self.tp = TransformPipeline(self.gov)

    def _sample_df(self):
        return pd.DataFrame({
            "id": [1, 2, 3, 4, 5],
            "email": [
                "alice@example.com",
                "bob@example.com",
                "carol@example.com",
                "alice@example.com",
                "dave@example.com",
            ],
            "salary": [50000, 60000, 70000, 50000, 80000],
            "dept": ["Eng", "HR", "Sales", "Eng", "Eng"],
            "phone": ["555-0101", "555-0102", "555-0103", "555-0104", "555-0105"],
        })

    def test_empty_steps(self):
        df = self._sample_df()
        result = self.tp.run(df, {"steps": []})
        pd.testing.assert_frame_equal(result, df)

    def test_deduplicate_step(self):
        df = self._sample_df()
        config = {"steps": [{"type": "deduplicate", "subset": ["email"]}]}
        result = self.tp.run(df, config)
        self.assertEqual(len(result), 4)
        self.assertEqual(result["email"].nunique(), 4)

    def test_filter_step_eq(self):
        df = self._sample_df()
        config = {"steps": [
            {"type": "filter", "column": "dept", "op": "eq", "value": "Eng"}
        ]}
        result = self.tp.run(df, config)
        self.assertTrue(all(result["dept"] == "Eng"))
        self.assertEqual(len(result), 3)

    def test_filter_step_gt(self):
        df = self._sample_df()
        config = {"steps": [
            {"type": "filter", "column": "salary", "op": "gt", "value": 60000}
        ]}
        result = self.tp.run(df, config)
        self.assertTrue(all(result["salary"] > 60000))

    def test_filter_step_contains(self):
        df = self._sample_df()
        config = {"steps": [
            {"type": "filter", "column": "email", "op": "contains", "value": "alice"}
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(len(result), 2)
        self.assertTrue(all("alice" in e for e in result["email"]))


class TestTransformPipelineNullAndColumns(unittest.TestCase):
    """Tests for fill_nulls, drop_columns, rename_columns."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.tp = TransformPipeline(MockGov())

    def test_fill_nulls_step_value(self):
        df = pd.DataFrame({
            "city": ["NYC", None, "LA"],
            "state": ["NY", "CA", None],
        })
        config = {"steps": [
            {"type": "fill_nulls", "fill": {"city": "Unknown", "state": "N/A"}}
        ]}
        result = self.tp.run(df, config)
        self.assertNotIn(None, result["city"].values)
        self.assertEqual(result.loc[1, "city"], "Unknown")
        self.assertEqual(result.loc[2, "state"], "N/A")

    def test_fill_nulls_step_forward(self):
        df = pd.DataFrame({"val": [1.0, None, None, 4.0]})
        config = {"steps": [
            {"type": "fill_nulls", "strategy": "forward"}
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(result["val"].tolist(), [1.0, 1.0, 1.0, 4.0])

    def test_drop_columns_step(self):
        df = pd.DataFrame({
            "id": [1, 2],
            "email": ["alice@example.com", "bob@example.com"],
            "internal_code": ["X1", "X2"],
        })
        config = {"steps": [
            {"type": "drop_columns", "columns": ["internal_code"]}
        ]}
        result = self.tp.run(df, config)
        self.assertNotIn("internal_code", result.columns)
        self.assertIn("id", result.columns)

    def test_rename_columns_step(self):
        df = pd.DataFrame({"old_name": [1, 2], "keep_me": [3, 4]})
        config = {"steps": [
            {"type": "rename_columns", "mapping": {"old_name": "new_name"}}
        ]}
        result = self.tp.run(df, config)
        self.assertIn("new_name", result.columns)
        self.assertNotIn("old_name", result.columns)
        self.assertIn("keep_me", result.columns)


class TestTransformPipelineSortAndAggregate(unittest.TestCase):
    """Tests for sort and aggregate steps."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.tp = TransformPipeline(MockGov())

    def test_sort_step(self):
        df = pd.DataFrame({"name": ["carol", "alice", "bob"], "val": [3, 1, 2]})
        config = {"steps": [
            {"type": "sort", "by": ["val"], "ascending": True}
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(result["val"].tolist(), [1, 2, 3])
        self.assertEqual(result["name"].tolist(), ["alice", "bob", "carol"])

    def test_aggregate_step(self):
        df = pd.DataFrame({
            "dept": ["Eng", "Eng", "HR", "HR"],
            "salary": [50000, 70000, 60000, 80000],
        })
        config = {"steps": [
            {"type": "aggregate", "group_by": ["dept"], "aggs": {"salary": "mean"}}
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(len(result), 2)
        eng_row = result[result["dept"] == "Eng"].iloc[0]
        self.assertEqual(eng_row["salary"], 60000.0)
        hr_row = result[result["dept"] == "HR"].iloc[0]
        self.assertEqual(hr_row["salary"], 70000.0)


class TestTransformPipelineMaskPII(unittest.TestCase):
    """Tests for the mask_pii step."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.tp = TransformPipeline(MockGov())

    def test_mask_pii_step(self):
        df = pd.DataFrame({
            "id": [1, 2],
            "email": ["alice@example.com", "bob@example.com"],
            "phone": ["555-0101", "555-0102"],
        })
        config = {"steps": [
            {"type": "mask_pii", "columns": ["email", "phone"]}
        ]}
        result = self.tp.run(df, config)

        self.assertNotIn("alice@example.com", result["email"].values)
        self.assertNotIn("555-0101", result["phone"].values)

        expected_hash = hashlib.sha256("alice@example.com".encode()).hexdigest()[:8]
        self.assertEqual(result.loc[0, "email"], expected_hash)

        self.assertEqual(result.loc[0, "id"], 1)


class TestTransformPipelineChained(unittest.TestCase):
    """Tests for chaining multiple steps."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.tp = TransformPipeline(MockGov())

    def test_multiple_steps_chained(self):
        df = pd.DataFrame({
            "id": [1, 2, 3, 2, 4],
            "email": ["a@example.com", "b@example.com", "c@example.com", "b@example.com", "d@example.com"],
            "score": [80, 90, 70, 90, 85],
        })
        config = {"steps": [
            {"type": "filter", "column": "score", "op": "gte", "value": 80},
            {"type": "deduplicate", "subset": ["email"]},
            {"type": "sort", "by": ["score"], "ascending": False},
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(len(result), 3)
        self.assertEqual(result["score"].tolist(), [90, 85, 80])


class TestTransformPipelineReferentialIntegrity(unittest.TestCase):
    """Referential-integrity step — validation against a cached reference frame."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.gov = MagicMock()
        self.dlq = MagicMock()
        self.tp = TransformPipeline(self.gov, dlq=self.dlq)
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_reference(self, name="reference.csv"):
        path = os.path.join(self.tmpdir, name)
        pd.DataFrame({"dept_id": [1, 2]}).to_csv(path, index=False, encoding="utf-8")
        return path

    def _step_config(self, reference_path):
        return {"steps": [{
            "type": "referential_integrity",
            "fk_col": "dept_id",
            "ref": reference_path,
            "ref_col": "dept_id",
        }]}

    def test_invalid_fk_rows_routed_to_dlq(self):
        reference = self._write_reference()
        df = pd.DataFrame({"dept_id": [1, 2, 99]})
        self.dlq.write.side_effect = (
            lambda frame, bad_indices, reason: frame[~frame.index.isin(bad_indices)]
        )
        result = self.tp.run(df, self._step_config(reference))
        self.dlq.write.assert_called_once()
        self.assertEqual(self.dlq.write.call_args[0][1], [2])
        self.assertIn("REFERENTIAL_INTEGRITY", self.dlq.write.call_args[0][2])
        self.assertEqual(len(result), 2)
        self.gov.referential_integrity_checked.assert_called_once_with(
            "dept_id", reference, 2, 1,
        )

    def test_all_valid_rows_skip_dlq(self):
        reference = self._write_reference()
        df = pd.DataFrame({"dept_id": [1, 2, 1]})
        result = self.tp.run(df, self._step_config(reference))
        self.dlq.write.assert_not_called()
        self.assertEqual(len(result), 3)

    def test_missing_fk_column_returns_unchanged(self):
        reference = self._write_reference()
        df = pd.DataFrame({"other": [1]})
        result = self.tp.run(df, self._step_config(reference))
        pd.testing.assert_frame_equal(result, df)
        self.gov.referential_integrity_checked.assert_not_called()

    def test_no_dlq_skips_step(self):
        from pipeline.transform_pipeline import TransformPipeline
        tp_without_dlq = TransformPipeline(self.gov, dlq=None)
        reference = self._write_reference()
        df = pd.DataFrame({"dept_id": [99]})
        result = tp_without_dlq.run(df, self._step_config(reference))
        self.assertEqual(len(result), 1)

    def test_reference_parsed_once_across_chunked_runs(self):
        # Regression: the reference file was re-read from disk per chunk.
        reference = self._write_reference()
        df = pd.DataFrame({"dept_id": [1, 2]})
        with patch("pandas.read_csv", wraps=pd.read_csv) as wrapped_read:
            self.tp.run(df, self._step_config(reference))
            self.tp.run(df, self._step_config(reference))
            self.tp.run(df, self._step_config(reference))
        self.assertEqual(wrapped_read.call_count, 1)


class TestTransformPipelineRulesFileCache(unittest.TestCase):
    """Business-rules files are parsed once per (path, mtime)."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.tp = TransformPipeline(MockGov())
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_rules_file_parsed_once_across_chunked_runs(self):
        import json
        rules_path = os.path.join(self.tmpdir, "rules.json")
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump([{"type": "rename", "from": "old_name", "to": "new_name"}], f)

        from pipeline.business_rules import BusinessRuleEngine
        original_load_rules = BusinessRuleEngine.load_rules
        config = {"steps": [{"type": "business_rules", "rules_file": rules_path}]}
        df = pd.DataFrame({"old_name": [1, 2]})

        with patch.object(
            BusinessRuleEngine, "load_rules",
            autospec=True, side_effect=original_load_rules,
        ) as mock_load:
            first = self.tp.run(df.copy(), config)
            second = self.tp.run(df.copy(), config)

        self.assertEqual(mock_load.call_count, 1)
        self.assertIn("new_name", first.columns)
        self.assertIn("new_name", second.columns)


class TestTransformPipelineErrorHandling(unittest.TestCase):
    """Tests for unknown steps and error modes."""

    def setUp(self):
        from pipeline.transform_pipeline import TransformPipeline
        self.gov = MagicMock()
        self.tp = TransformPipeline(self.gov)

    def test_unknown_step_skipped(self):
        df = pd.DataFrame({"a": [1, 2, 3]})
        config = {"steps": [
            {"type": "nonexistent_step"},
            {"type": "sort", "by": ["a"]},
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(len(result), 3)
        self.assertEqual(result["a"].tolist(), [1, 2, 3])

    def test_step_failure_warn(self):
        df = pd.DataFrame({"a": [1, 2, 3]})
        config = {"steps": [
            {"type": "filter", "column": "nonexistent", "op": "eq", "value": 1},
            {"type": "sort", "by": ["a"]},
        ]}
        result = self.tp.run(df, config)
        self.assertEqual(len(result), 3)

    def test_step_failure_halt(self):
        df = pd.DataFrame({"a": [1, 2, 3]})
        config = {"steps": [
            {"type": "aggregate", "group_by": ["a"], "aggs": {"a": "sum"},
             "on_error": "halt", "name": "bad_aggregate"},
        ]}
        # Replace the handler in the dispatch dict so the error propagates
        # through the run() method's on_error=halt path.
        def _boom(df_in, step):
            raise ValueError("boom")

        original = self.tp._step_handlers["aggregate"]
        self.tp._step_handlers["aggregate"] = _boom
        try:
            with self.assertRaises(RuntimeError) as ctx:
                self.tp.run(df, config)
            self.assertIn("boom", str(ctx.exception))
        finally:
            self.tp._step_handlers["aggregate"] = original


# ═══════════════════════════════════════════════════════════════════════════════
# LoadVerifier
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoadVerifierRowCount(unittest.TestCase):
    """Tests for LoadVerifier.verify_row_count using real SQLite."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "verify.db")
        self.gov = MagicMock()

        from pipeline.load_verifier import LoadVerifier
        self.verifier = LoadVerifier(self.gov)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _insert_rows(self, table, count):
        conn = sqlite3.connect(self.db_path)
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (id INTEGER, email TEXT)")
        for i in range(count):
            conn.execute(
                f"INSERT INTO {table} (id, email) VALUES (?, ?)",
                (i, f"user{i}@example.com"),
            )
        conn.commit()
        conn.close()

    def _cfg(self):
        return {"db_type": "sqlite", "db_name": self.db_path}

    def test_row_count_match(self):
        self._insert_rows("customers", 10)
        source_df = pd.DataFrame({"id": range(10), "email": [f"u{i}@example.com" for i in range(10)]})

        result = self.verifier.verify_row_count(source_df, self._cfg(), "customers")
        self.assertTrue(result["match"])
        self.assertEqual(result["source_rows"], 10)
        self.assertEqual(result["dest_rows"], 10)
        self.assertEqual(result["difference"], 0)

    def test_row_count_mismatch(self):
        self._insert_rows("orders", 8)
        source_df = pd.DataFrame({"id": range(10)})

        result = self.verifier.verify_row_count(source_df, self._cfg(), "orders")
        self.assertFalse(result["match"])
        self.assertEqual(result["source_rows"], 10)
        self.assertEqual(result["dest_rows"], 8)
        self.assertEqual(result["difference"], -2)

    def test_row_count_within_tolerance(self):
        self._insert_rows("products", 99)
        source_df = pd.DataFrame({"id": range(100)})

        result = self.verifier.verify_row_count(
            source_df, self._cfg(), "products", tolerance=0.02,
        )
        self.assertTrue(result["match"])

    def test_row_count_exceeds_tolerance(self):
        self._insert_rows("events", 95)
        source_df = pd.DataFrame({"id": range(100)})

        result = self.verifier.verify_row_count(
            source_df, self._cfg(), "events", tolerance=0.01,
        )
        self.assertFalse(result["match"])

    def test_unsupported_destination(self):
        source_df = pd.DataFrame({"id": [1, 2, 3]})
        cfg = {"db_type": "s3"}

        result = self.verifier.verify_row_count(source_df, cfg, "my_bucket")
        self.assertIsNone(result["match"])
        self.assertIsNone(result["dest_rows"])

    def test_governance_event_fired(self):
        self._insert_rows("audit", 5)
        source_df = pd.DataFrame({"id": range(5)})

        self.verifier.verify_row_count(source_df, self._cfg(), "audit")
        self.gov.quality_event.assert_called_once()

        call_args = self.gov.quality_event.call_args
        self.assertEqual(call_args[0][0], "LOAD_VERIFICATION")
        event_data = call_args[0][1]
        self.assertEqual(event_data["table"], "audit")
        self.assertTrue(event_data["match"])


if __name__ == "__main__":
    unittest.main()
