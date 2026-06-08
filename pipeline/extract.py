"""
Source file extraction with compression support and chunked streaming.

Reads CSV, TSV, JSON, JSONL, XML, YAML, Parquet, Feather, ORC, Avro,
SAS, Stata, and fixed-width formats. Compressed files (.gz, .bz2, .zip,
.zst, .lz4, .tgz) are decompressed transparently.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger),
          Layer 2 (compression).
"""

import io
import json
import logging
from typing import TYPE_CHECKING, Iterator

from pipeline.compression import CompressionHandler
from pipeline.constants import (
    DEFAULT_CHUNK_SIZE, HAS_AVRO, HAS_ORC, HAS_PYARROW, HAS_YAML,
)
from pipeline.helpers import flatten_record as _flatten_record

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class Extractor:
    """
    Reads source files into DataFrames with compression and chunking support.

    Quick-start
    -----------
        from pipeline.extract import Extractor
        ext = Extractor(gov)
        df = ext.extract("data.csv.gz")
        for chunk in ext.chunks("big_file.csv", chunk_size=50_000):
            process(chunk)
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        array_strategy: str = "index",
        join_sep: str = ",",
        max_depth: int = 20,
        sep: str = "__",
    ) -> None:
        self.gov = gov
        self._compressor = CompressionHandler()
        self._array_strategy = array_strategy
        self._join_sep = join_sep
        self._max_depth = max_depth
        self._sep = sep

    def _flatten_kw(self) -> dict:
        return {"separator": self._sep}

    @staticmethod
    def _json_to_df(raw, flatten_kw: dict):
        import pandas as pd
        records = raw if isinstance(raw, list) else [raw]
        try:
            df = pd.json_normalize(records, sep=flatten_kw.get("separator", "__"))
            has_nested = any(
                df[c].dropna().apply(lambda x: isinstance(x, (dict, list))).any()
                for c in df.columns if df[c].dtype == object
            )
            if not has_nested:
                return df
        except Exception as exc:
            logger.debug("json_normalize fell back to manual flatten: %s", exc)
        flat = [_flatten_record(r, separator=flatten_kw.get("separator", "__")) for r in records]
        return pd.DataFrame(flat)

    @staticmethod
    def _xml_to_df(path: str, flatten_kw: dict):
        import pandas as pd
        import defusedxml.ElementTree as ET

        def _element_to_dict(elem, prefix=""):
            result = {}
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            node_key = f"{prefix}__{tag}" if prefix else tag
            for attr_name, attr_val in elem.attrib.items():
                result[f"{node_key}__{attr_name}"] = attr_val
            text = (elem.text or "").strip()
            if text:
                result[node_key] = text
            for child in elem:
                result.update(_element_to_dict(child, prefix=node_key))
            return result

        try:
            tree = ET.parse(path)
            root = tree.getroot()
            children = list(root)
            if children and all(c.tag == children[0].tag for c in children):
                records = [_element_to_dict(c) for c in children]
            else:
                records = [_element_to_dict(root)]
            return pd.DataFrame(records)
        except ET.ParseError:
            return pd.read_xml(path)

    def extract(self, path: str):
        """Read the full source file into a DataFrame."""
        real_ext = self._compressor.inner_extension(path)
        self.gov.extract_event("EXTRACT_START", {"source": path, "format": real_ext})

        if self._compressor.is_compressed(path):
            with self._compressor.open(path) as fh:
                df = self._read_stream(fh, real_ext)
        else:
            df = self._read_file(path, real_ext)

        self.gov.source_registered(path, real_ext, len(df), len(df.columns))
        dtype_map = {col: str(df[col].dtype) for col in df.columns}
        self.gov.extract_event("EXTRACT_COMPLETE", {
            "rows": len(df), "columns": list(df.columns), "dtypes": dtype_map,
        })
        return df

    def _read_file(self, path: str, ext: str):
        import pandas as pd

        if ext == ".csv":
            return pd.read_csv(path, encoding="utf-8")
        if ext == ".tsv":
            return pd.read_csv(path, sep="\t", encoding="utf-8")
        if ext in (".xlsx", ".xls"):
            return pd.read_excel(path)
        if ext == ".fw":
            return pd.read_fwf(path)
        if ext == ".json":
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            return self._json_to_df(raw, self._flatten_kw())
        if ext in (".jsonl", ".ndjson"):
            return pd.read_json(path, lines=True)
        if ext == ".xml":
            return self._xml_to_df(path, self._flatten_kw())
        if ext in (".yaml", ".yml"):
            if not HAS_YAML:
                raise RuntimeError("YAML support requires: pip install pyyaml")
            import yaml
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            if isinstance(raw, list):
                return pd.json_normalize(raw)
            if isinstance(raw, dict):
                return pd.json_normalize([raw])
            raise ValueError(f"Cannot convert YAML root type {type(raw)} to DataFrame")
        if ext == ".parquet":
            if not HAS_PYARROW:
                raise RuntimeError("Parquet support requires: pip install pyarrow")
            return pd.read_parquet(path)
        if ext in (".feather", ".arrow"):
            if not HAS_PYARROW:
                raise RuntimeError("Feather/Arrow support requires: pip install pyarrow")
            return pd.read_feather(path)
        if ext == ".orc":
            if not HAS_ORC:
                raise RuntimeError("ORC support requires: pip install pyorc")
            import pyorc
            with open(path, "rb") as fh:
                reader = pyorc.Reader(fh)
                rows = list(reader)
                cols = list(reader.schema.fields.keys())
            return pd.DataFrame(rows, columns=cols)
        if ext == ".avro":
            if not HAS_AVRO:
                raise RuntimeError("Avro support requires: pip install fastavro")
            import fastavro
            with open(path, "rb") as fh:
                records = list(fastavro.reader(fh))
            return pd.json_normalize(records)
        if ext == ".sas7bdat":
            return pd.read_sas(path, encoding="utf-8")
        if ext == ".dta":
            return pd.read_stata(path)
        raise ValueError(
            f"Unsupported format: {ext}\n"
            "Supported: .csv .tsv .xlsx .xls .json .jsonl .ndjson "
            ".xml .yaml .yml .parquet .feather .arrow .orc .avro "
            ".fwf .sas7bdat .dta"
        )

    def _read_stream(self, stream: io.IOBase, ext: str):
        import pandas as pd

        if ext == ".csv":
            return pd.read_csv(stream, encoding="utf-8")
        if ext == ".tsv":
            return pd.read_csv(stream, sep="\t", encoding="utf-8")
        if ext in (".jsonl", ".ndjson"):
            return pd.read_json(stream, lines=True)
        if ext == ".json":
            raw = json.load(stream)
            return self._json_to_df(raw, self._flatten_kw())
        if ext in (".yaml", ".yml"):
            if not HAS_YAML:
                raise RuntimeError("YAML support requires: pip install pyyaml")
            import yaml
            raw = yaml.safe_load(stream)
            if isinstance(raw, list):
                return pd.json_normalize(raw)
            if isinstance(raw, dict):
                return pd.json_normalize([raw])
            raise ValueError(f"Cannot convert YAML root type {type(raw)} to DataFrame")
        if ext == ".parquet":
            if not HAS_PYARROW:
                raise RuntimeError("Parquet support requires: pip install pyarrow")
            buf = io.BytesIO(stream.read())
            return pd.read_parquet(buf)
        if ext in (".feather", ".arrow"):
            if not HAS_PYARROW:
                raise RuntimeError("Feather/Arrow support requires: pip install pyarrow")
            buf = io.BytesIO(stream.read())
            return pd.read_feather(buf)
        if ext == ".avro":
            if not HAS_AVRO:
                raise RuntimeError("Avro support requires: pip install fastavro")
            import fastavro
            records = list(fastavro.reader(stream))
            return pd.json_normalize(records)
        if ext == ".orc":
            if not HAS_ORC:
                raise RuntimeError("ORC support requires: pip install pyorc")
            import pyorc
            reader = pyorc.Reader(stream)
            rows = list(reader)
            cols = list(reader.schema.fields.keys())
            return pd.DataFrame(rows, columns=cols)
        if ext == ".fw":
            buf = io.BytesIO(stream.read())
            return pd.read_fwf(buf)
        raise ValueError(f"Compressed streaming not supported for {ext}.")

    def chunks(self, path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator:
        """Yield the source file in row-count chunks."""
        import pandas as pd

        real_ext = self._compressor.inner_extension(path)
        self.gov.extract_event("CHUNKED_EXTRACT_START", {
            "source": path, "chunk_size": chunk_size,
        })

        if real_ext == ".csv" and not self._compressor.is_compressed(path):
            for i, chunk in enumerate(pd.read_csv(path, chunksize=chunk_size, encoding="utf-8")):
                self.gov.extract_event("CHUNK_EXTRACTED", {
                    "chunk_index": i, "rows": len(chunk),
                })
                yield chunk

        elif real_ext == ".tsv" and not self._compressor.is_compressed(path):
            for i, chunk in enumerate(pd.read_csv(path, sep="\t", chunksize=chunk_size, encoding="utf-8")):
                self.gov.extract_event("CHUNK_EXTRACTED", {
                    "chunk_index": i, "rows": len(chunk),
                })
                yield chunk

        elif real_ext in (".jsonl", ".ndjson") and not self._compressor.is_compressed(path):
            for i, chunk in enumerate(pd.read_json(path, lines=True, chunksize=chunk_size)):
                self.gov.extract_event("CHUNK_EXTRACTED", {
                    "chunk_index": i, "rows": len(chunk),
                })
                yield chunk

        elif real_ext == ".parquet" and not self._compressor.is_compressed(path) and HAS_PYARROW:
            import pyarrow.parquet as pq
            pf = pq.ParquetFile(path)
            i = 0
            for batch in pf.iter_batches(batch_size=chunk_size):
                chunk = batch.to_pandas()
                self.gov.extract_event("CHUNK_EXTRACTED", {
                    "chunk_index": i, "rows": len(chunk),
                })
                yield chunk
                i += 1

        else:
            df = self.extract(path)
            n = (len(df) + chunk_size - 1) // chunk_size
            for i in range(n):
                chunk = df.iloc[i * chunk_size:(i + 1) * chunk_size].copy()
                self.gov.extract_event("CHUNK_EXTRACTED", {
                    "chunk_index": i, "rows": len(chunk), "total_chunks": n,
                })
                yield chunk
