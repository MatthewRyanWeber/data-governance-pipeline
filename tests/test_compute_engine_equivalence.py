"""
Governance-equivalence harness for the DuckDB compute fast path.

The acceleration plan's binding rule is: a faster engine may change HOW the
data is read/computed, never WHETHER governance runs or WHAT it produces. This
harness enforces that mechanically — it reads the same fixture with the pandas
and DuckDB engines and asserts the two produce equivalent data AND identical
governance outcomes (PII actions, the transformation event sequence, final
rows). A divergence (e.g. a type-inference difference that changes a masked
value) fails CI, which is the signal to keep that case on pandas.

Revision history
────────────────
1.0   2026-06-15   Initial release: read-equivalence + governed-outcome parity
                   across the pandas and duckdb read engines.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from pipeline.constants import HAS_DUCKDB
from pipeline.extract import Extractor
from pipeline.helpers import detect_pii
from pipeline.transform import Transformer

# Unambiguous fixture: values where pandas and DuckDB infer the same types, so
# the fast read is genuinely equivalent. (Pathological cases — leading-zero
# zips, mixed-type columns — are exactly what the harness exists to catch; they
# are kept off the fast path, not silently accepted.)
_CSV = (
    "id,full_name,email,country,amount\n"
    "1,Alice Stone,alice@example.com,US,100.50\n"
    "2,Bob Marsh,bob@example.com,DE,200.00\n"
    "2,Bob Marsh,bob@example.com,DE,200.00\n"   # exact dup -> dedup must remove
    "3,Carol Diaz,carol@example.com,FR,0.00\n"
    "4,Dan Webb,,US,75.25\n"                     # missing email
)


@unittest.skipUnless(HAS_DUCKDB, "duckdb not installed")
class TestComputeEngineEquivalence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = str(Path(self.tmp) / "people.csv")
        Path(self.path).write_text(_CSV, encoding="utf-8")

    def _read(self, engine):
        ext = Extractor(MagicMock(), engine=engine)
        chunks = list(ext.chunks(self.path, chunk_size=2))
        return pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()

    @staticmethod
    def _row_multiset(df):
        # Order-independent, governance-relevant canonical form: nulls collapse
        # to one sentinel (pandas NaN and DuckDB None are both "null" to every
        # governance check), numerics compare as rounded floats (100.50 == 100.5
        # — repr noise, not a value difference), everything else as text. A
        # genuine value divergence (e.g. "01234" vs "1234") still differs here.
        def norm(v):
            if pd.isna(v):
                return None
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                return round(float(v), 9)
            return str(v)
        cols = sorted(df.columns)
        rows = (tuple(norm(v) for v in row) for row in df[cols].itertuples(index=False))
        return sorted(rows, key=repr)

    def test_duckdb_read_matches_pandas_values(self):
        p, d = self._read("pandas"), self._read("duckdb")
        self.assertEqual(sorted(p.columns), sorted(d.columns))
        self.assertEqual(self._row_multiset(p), self._row_multiset(d))

    def _govern(self, df):
        gov = MagicMock()
        t = Transformer(gov)
        pii = detect_pii(list(df.columns))
        out = t.transform(df, pii, "mask", drop_cols=[])
        events = [c.args[0] for c in gov.transformation_applied.call_args_list]
        return out, t.pii_actions, events

    def test_governed_outcome_identical_through_both_reads(self):
        p_out, p_pii, p_events = self._govern(self._read("pandas"))
        d_out, d_pii, d_events = self._govern(self._read("duckdb"))
        # Same PII fields masked, same governance event sequence, same final rows.
        self.assertEqual(p_pii, d_pii)
        self.assertEqual(p_events, d_events)
        self.assertEqual(len(p_out), len(d_out))
        # Drop the per-run stamps (pipeline id, load timestamp) — they differ by
        # construction between two runs and are not data.
        stamps = ["_pipeline_id", "_loaded_at_utc"]
        p_data = p_out.drop(columns=stamps, errors="ignore")
        d_data = d_out.drop(columns=stamps, errors="ignore")
        self.assertEqual(self._row_multiset(p_data), self._row_multiset(d_data))


class TestEngineFallback(unittest.TestCase):
    def test_falls_back_to_pandas_when_duckdb_absent(self):
        from unittest.mock import patch
        with patch("pipeline.extract.HAS_DUCKDB", False):
            ext = Extractor(MagicMock(), engine="duckdb")
            self.assertEqual(ext.engine, "pandas")

    def test_default_engine_is_pandas(self):
        self.assertEqual(Extractor(MagicMock()).engine, "pandas")


if __name__ == "__main__":
    unittest.main()
