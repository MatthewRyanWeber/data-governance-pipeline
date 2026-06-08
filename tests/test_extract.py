"""
Tests for pipeline.extract — Extractor class.

Covers CSV, TSV, JSON, JSONL, XML, YAML, Excel, compressed file extraction,
chunked streaming, and internal helpers (_json_to_df, _xml_to_df).
"""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import numpy as np
import pandas as pd


class MockGov:
    """Records every governance call for assertion."""

    def __init__(self):
        self.events = []

    def __getattr__(self, name):
        def recorder(*args, **kwargs):
            self.events.append((name, args, kwargs))
        return recorder


class TestCSVExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_basic_csv_read(self):
        path = os.path.join(self.tmpdir, "data.csv")
        pd.DataFrame({
            "name": ["Alice Test", "Bob Test"],
            "phone": ["555-0101", "555-0102"],
        }).to_csv(path, index=False)

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        self.assertIn("name", df.columns)
        self.assertEqual(df["name"].iloc[0], "Alice Test")

    def test_governance_events_emitted(self):
        path = os.path.join(self.tmpdir, "data.csv")
        pd.DataFrame({"a": [1]}).to_csv(path, index=False)

        ext = self._make_extractor()
        ext.extract(path)
        event_names = [e[0] for e in self.gov.events]
        self.assertIn("extract_event", event_names)
        self.assertIn("source_registered", event_names)


class TestTSVExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_tsv_read(self):
        path = os.path.join(self.tmpdir, "data.tsv")
        pd.DataFrame({
            "id": [1, 2],
            "email": ["alice@example.com", "bob@example.com"],
        }).to_csv(path, index=False, sep="\t")

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df["email"].iloc[0], "alice@example.com")


class TestJSONExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_json_array(self):
        path = os.path.join(self.tmpdir, "data.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([
                {"name": "Alice Test", "age": 30},
                {"name": "Bob Test", "age": 25},
            ], f)

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df["name"].iloc[0], "Alice Test")

    def test_json_single_object(self):
        path = os.path.join(self.tmpdir, "data.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"name": "Alice Test", "age": 30}, f)

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df["name"].iloc[0], "Alice Test")


class TestJSONLExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_jsonl_read(self):
        path = os.path.join(self.tmpdir, "data.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"id": 1, "val": "alpha"}\n')
            f.write('{"id": 2, "val": "beta"}\n')

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df["val"].iloc[1], "beta")


class TestXMLExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_flat_xml(self):
        path = os.path.join(self.tmpdir, "data.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "<records>"
                "<record><name>Alice Test</name><phone>555-0101</phone></record>"
                "<record><name>Bob Test</name><phone>555-0102</phone></record>"
                "</records>"
            )
        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)

    def test_nested_xml(self):
        path = os.path.join(self.tmpdir, "data.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "<records>"
                "<record><name>Alice Test</name><address><city>NYC</city></address></record>"
                "<record><name>Bob Test</name><address><city>LA</city></address></record>"
                "</records>"
            )
        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        # nested city should appear somewhere in the columns
        flat_vals = df.iloc[0].to_dict()
        has_city = any("NYC" == str(v) for v in flat_vals.values())
        self.assertTrue(has_city, f"Expected NYC in flattened XML: {flat_vals}")


class TestYAMLExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    @patch("pipeline.extract.HAS_YAML", True)
    def test_yaml_list(self):
        path = os.path.join(self.tmpdir, "data.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("- name: Alice Test\n  age: 30\n- name: Bob Test\n  age: 25\n")

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df["name"].iloc[0], "Alice Test")

    @patch("pipeline.extract.HAS_YAML", True)
    def test_yaml_dict(self):
        path = os.path.join(self.tmpdir, "data.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("name: Alice Test\nage: 30\n")

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 1)

    def test_yaml_missing_dependency_raises(self):
        """When dep_flag is False the registry should raise RuntimeError."""
        from pipeline.extract import _FORMAT_REGISTRY, _FormatSpec
        path = os.path.join(self.tmpdir, "data.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("name: test\n")

        original_spec = _FORMAT_REGISTRY[".yaml"]
        fake_spec = _FormatSpec(
            file_reader=original_spec.file_reader,
            stream_reader=original_spec.stream_reader,
            dep_flag=False,
            dep_error="YAML support requires: pip install pyyaml",
        )
        ext = self._make_extractor()
        with patch.dict("pipeline.extract._FORMAT_REGISTRY", {".yaml": fake_spec}):
            with self.assertRaises(RuntimeError):
                ext.extract(path)


class TestExcelExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_xlsx_read(self):
        path = os.path.join(self.tmpdir, "data.xlsx")
        pd.DataFrame({
            "id": [1, 2],
            "email": ["alice@example.com", "bob@example.com"],
        }).to_excel(path, index=False)

        ext = self._make_extractor()
        df = ext.extract(path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df["email"].iloc[0], "alice@example.com")


class TestUnsupportedFormat(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_unsupported_raises_valueerror(self):
        path = os.path.join(self.tmpdir, "data.xyz")
        with open(path, "w", encoding="utf-8") as f:
            f.write("nope")

        ext = self._make_extractor()
        with self.assertRaises(ValueError):
            ext.extract(path)


class TestCompressedExtraction(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_compressed_csv_gz(self):
        """Compressed extraction delegates to CompressionHandler.open() stream."""
        csv_content = b"name,phone\nAlice Test,555-0101\nBob Test,555-0102\n"
        stream = io.BytesIO(csv_content)

        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = True
            instance.inner_extension.return_value = ".csv"
            instance.open.return_value.__enter__ = MagicMock(return_value=stream)
            instance.open.return_value.__exit__ = MagicMock(return_value=False)

            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            df = ext.extract("data.csv.gz")

        self.assertEqual(len(df), 2)
        self.assertEqual(df["name"].iloc[0], "Alice Test")


class TestChunks(unittest.TestCase):

    def setUp(self):
        self.gov = MockGov()
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_extractor(self):
        with patch("pipeline.extract.CompressionHandler") as MockCH:
            instance = MockCH.return_value
            instance.is_compressed.return_value = False
            instance.inner_extension.side_effect = lambda p: Path(p).suffix.lower()
            from pipeline.extract import Extractor
            ext = Extractor(self.gov)
            ext._compressor = instance
            return ext

    def test_csv_chunk_sizes(self):
        path = os.path.join(self.tmpdir, "data.csv")
        pd.DataFrame({"a": range(10)}).to_csv(path, index=False)

        ext = self._make_extractor()
        chunks = list(ext.chunks(path, chunk_size=3))
        total_rows = sum(len(c) for c in chunks)
        self.assertEqual(total_rows, 10)
        # first chunk should have 3 rows
        self.assertEqual(len(chunks[0]), 3)

    def test_chunk_governance_events(self):
        path = os.path.join(self.tmpdir, "data.csv")
        pd.DataFrame({"a": range(5)}).to_csv(path, index=False)

        ext = self._make_extractor()
        chunks = list(ext.chunks(path, chunk_size=2))
        event_names = [e[0] for e in self.gov.events]
        self.assertIn("extract_event", event_names)
        # Should have CHUNKED_EXTRACT_START + one CHUNK_EXTRACTED per chunk
        chunk_events = [e for e in self.gov.events if e[0] == "extract_event"]
        self.assertGreaterEqual(len(chunk_events), len(chunks) + 1)

    def test_fallback_chunking(self):
        """Non-CSV/TSV/JSONL formats fall back to full extract then split."""
        path = os.path.join(self.tmpdir, "data.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([{"id": i} for i in range(7)], f)

        ext = self._make_extractor()
        chunks = list(ext.chunks(path, chunk_size=3))
        total_rows = sum(len(c) for c in chunks)
        self.assertEqual(total_rows, 7)
        self.assertEqual(len(chunks[0]), 3)
        self.assertEqual(len(chunks[-1]), 1)  # 7 % 3 = 1


class TestJsonToDf(unittest.TestCase):

    def test_flat_records(self):
        from pipeline.extract import Extractor
        raw = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
        df = Extractor._json_to_df(raw, {"separator": "__"})
        self.assertEqual(len(df), 2)
        self.assertIn("a", df.columns)

    def test_nested_normalization(self):
        from pipeline.extract import Extractor
        raw = [{"id": 1, "meta": {"city": "NYC", "zip": "10001"}}]
        df = Extractor._json_to_df(raw, {"separator": "__"})
        self.assertEqual(len(df), 1)
        # should have flattened meta.city into a column
        flat_vals = df.iloc[0].to_dict()
        has_city = any("NYC" == str(v) for v in flat_vals.values())
        self.assertTrue(has_city, f"Expected NYC in normalized JSON: {flat_vals}")

    def test_single_object_wrapped(self):
        from pipeline.extract import Extractor
        raw = {"name": "Alice Test", "age": 30}
        df = Extractor._json_to_df(raw, {"separator": "__"})
        self.assertEqual(len(df), 1)
        self.assertEqual(df["name"].iloc[0], "Alice Test")


class TestXmlToDf(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_element_to_dict(self):
        from pipeline.extract import Extractor
        path = os.path.join(self.tmpdir, "data.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "<items>"
                "<item><name>Widget</name><price>9.99</price></item>"
                "<item><name>Gadget</name><price>19.99</price></item>"
                "</items>"
            )
        df = Extractor._xml_to_df(path, {"separator": "__"})
        self.assertEqual(len(df), 2)

    def test_nested_elements(self):
        from pipeline.extract import Extractor
        path = os.path.join(self.tmpdir, "data.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "<items>"
                '<item id="1"><detail><color>red</color></detail></item>'
                '<item id="2"><detail><color>blue</color></detail></item>'
                "</items>"
            )
        df = Extractor._xml_to_df(path, {"separator": "__"})
        self.assertEqual(len(df), 2)
        flat_vals = df.iloc[0].to_dict()
        has_red = any("red" == str(v) for v in flat_vals.values())
        self.assertTrue(has_red, f"Expected red in nested XML: {flat_vals}")

    def test_single_root_element(self):
        """XML with no repeated child elements wraps root into one-row df."""
        from pipeline.extract import Extractor
        path = os.path.join(self.tmpdir, "data.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("<config><name>pipeline</name><version>1</version></config>")
        df = Extractor._xml_to_df(path, {"separator": "__"})
        self.assertEqual(len(df), 1)


if __name__ == "__main__":
    unittest.main()
