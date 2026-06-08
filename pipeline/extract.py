"""
Source file extraction with compression support and chunked streaming.

Reads CSV, TSV, JSON, JSONL, XML, YAML, Parquet, Feather, ORC, Avro,
SAS, Stata, and fixed-width formats. Compressed files (.gz, .bz2, .zip,
.zst, .lz4, .tgz) are decompressed transparently.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger),
          Layer 2 (compression).

Revision history
────────────────
1.0   2026-06-07   Initial release.
1.1   2026-06-08   Refactored if/elif dispatch into _FORMAT_REGISTRY.
"""

import io
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterator, Optional

from pipeline.compression import CompressionHandler
from pipeline.constants import (
    DEFAULT_CHUNK_SIZE, HAS_AVRO, HAS_ORC, HAS_PYARROW, HAS_YAML,
)
from pipeline.helpers import flatten_record as _flatten_record

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


# ── Format reader descriptors ───────────────────────────────────────────────
# Each entry defines how to read a single format from either a file path or a
# byte stream. The two callables share a signature:
#   (extractor_instance, source, **kw) -> pd.DataFrame
# where `source` is a file-path string (for file_reader) or an io.IOBase
# (for stream_reader). When stream_reader is None the format cannot be read
# from a compressed stream — _read_stream falls back to an explicit error.

@dataclass(frozen=True, slots=True)
class _FormatSpec:
    file_reader: Callable
    stream_reader: Optional[Callable] = None
    dep_flag: bool = True
    dep_error: str = ""


def _read_csv_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_csv(path, encoding="utf-8")


def _read_csv_stream(ext, stream, **_kw):
    import pandas as pd
    return pd.read_csv(stream, encoding="utf-8")


def _read_tsv_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_csv(path, sep="\t", encoding="utf-8")


def _read_tsv_stream(ext, stream, **_kw):
    import pandas as pd
    return pd.read_csv(stream, sep="\t", encoding="utf-8")


def _read_excel_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_excel(path)


def _read_fwf_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_fwf(path)


def _read_fwf_stream(ext, stream, **_kw):
    import pandas as pd
    buf = io.BytesIO(stream.read())
    return pd.read_fwf(buf)


def _read_json_file(ext, path, **kw):
    flatten_kw = kw.get("flatten_kw", {})
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return Extractor._json_to_df(raw, flatten_kw)


def _read_json_stream(ext, stream, **kw):
    flatten_kw = kw.get("flatten_kw", {})
    raw = json.load(stream)
    return Extractor._json_to_df(raw, flatten_kw)


def _read_jsonl_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_json(path, lines=True)


def _read_jsonl_stream(ext, stream, **_kw):
    import pandas as pd
    return pd.read_json(stream, lines=True)


def _read_xml_file(ext, path, **kw):
    flatten_kw = kw.get("flatten_kw", {})
    return Extractor._xml_to_df(path, flatten_kw)


def _read_yaml_file(ext, path, **_kw):
    import pandas as pd
    import yaml
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if isinstance(raw, list):
        return pd.json_normalize(raw)
    if isinstance(raw, dict):
        return pd.json_normalize([raw])
    raise ValueError(f"Cannot convert YAML root type {type(raw)} to DataFrame")


def _read_yaml_stream(ext, stream, **_kw):
    import pandas as pd
    import yaml
    raw = yaml.safe_load(stream)
    if isinstance(raw, list):
        return pd.json_normalize(raw)
    if isinstance(raw, dict):
        return pd.json_normalize([raw])
    raise ValueError(f"Cannot convert YAML root type {type(raw)} to DataFrame")


def _read_parquet_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_parquet(path)


def _read_parquet_stream(ext, stream, **_kw):
    import pandas as pd
    buf = io.BytesIO(stream.read())
    return pd.read_parquet(buf)


def _read_feather_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_feather(path)


def _read_feather_stream(ext, stream, **_kw):
    import pandas as pd
    buf = io.BytesIO(stream.read())
    return pd.read_feather(buf)


def _read_orc_file(ext, path, **_kw):
    import pandas as pd
    import pyorc
    with open(path, "rb") as fh:
        reader = pyorc.Reader(fh)
        rows = list(reader)
        cols = list(reader.schema.fields.keys())
    return pd.DataFrame(rows, columns=cols)


def _read_orc_stream(ext, stream, **_kw):
    import pandas as pd
    import pyorc
    reader = pyorc.Reader(stream)
    rows = list(reader)
    cols = list(reader.schema.fields.keys())
    return pd.DataFrame(rows, columns=cols)


def _read_avro_file(ext, path, **_kw):
    import pandas as pd
    import fastavro
    with open(path, "rb") as fh:
        records = list(fastavro.reader(fh))
    return pd.json_normalize(records)


def _read_avro_stream(ext, stream, **_kw):
    import pandas as pd
    import fastavro
    records = list(fastavro.reader(stream))
    return pd.json_normalize(records)


def _read_sas_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_sas(path, encoding="utf-8")


def _read_stata_file(ext, path, **_kw):
    import pandas as pd
    return pd.read_stata(path)


# Maps file extensions to their reader specifications. Dependency flags are
# evaluated at lookup time (not import time) so the registry stays static.
def _build_registry() -> dict[str, _FormatSpec]:
    return {
        ".csv": _FormatSpec(
            file_reader=_read_csv_file,
            stream_reader=_read_csv_stream,
        ),
        ".tsv": _FormatSpec(
            file_reader=_read_tsv_file,
            stream_reader=_read_tsv_stream,
        ),
        ".xlsx": _FormatSpec(
            file_reader=_read_excel_file,
        ),
        ".xls": _FormatSpec(
            file_reader=_read_excel_file,
        ),
        ".fw": _FormatSpec(
            file_reader=_read_fwf_file,
            stream_reader=_read_fwf_stream,
        ),
        ".json": _FormatSpec(
            file_reader=_read_json_file,
            stream_reader=_read_json_stream,
        ),
        ".jsonl": _FormatSpec(
            file_reader=_read_jsonl_file,
            stream_reader=_read_jsonl_stream,
        ),
        ".ndjson": _FormatSpec(
            file_reader=_read_jsonl_file,
            stream_reader=_read_jsonl_stream,
        ),
        ".xml": _FormatSpec(
            file_reader=_read_xml_file,
        ),
        ".yaml": _FormatSpec(
            file_reader=_read_yaml_file,
            stream_reader=_read_yaml_stream,
            dep_flag=HAS_YAML,
            dep_error="YAML support requires: pip install pyyaml",
        ),
        ".yml": _FormatSpec(
            file_reader=_read_yaml_file,
            stream_reader=_read_yaml_stream,
            dep_flag=HAS_YAML,
            dep_error="YAML support requires: pip install pyyaml",
        ),
        ".parquet": _FormatSpec(
            file_reader=_read_parquet_file,
            stream_reader=_read_parquet_stream,
            dep_flag=HAS_PYARROW,
            dep_error="Parquet support requires: pip install pyarrow",
        ),
        ".feather": _FormatSpec(
            file_reader=_read_feather_file,
            stream_reader=_read_feather_stream,
            dep_flag=HAS_PYARROW,
            dep_error="Feather/Arrow support requires: pip install pyarrow",
        ),
        ".arrow": _FormatSpec(
            file_reader=_read_feather_file,
            stream_reader=_read_feather_stream,
            dep_flag=HAS_PYARROW,
            dep_error="Feather/Arrow support requires: pip install pyarrow",
        ),
        ".orc": _FormatSpec(
            file_reader=_read_orc_file,
            stream_reader=_read_orc_stream,
            dep_flag=HAS_ORC,
            dep_error="ORC support requires: pip install pyorc",
        ),
        ".avro": _FormatSpec(
            file_reader=_read_avro_file,
            stream_reader=_read_avro_stream,
            dep_flag=HAS_AVRO,
            dep_error="Avro support requires: pip install fastavro",
        ),
        ".sas7bdat": _FormatSpec(
            file_reader=_read_sas_file,
        ),
        ".dta": _FormatSpec(
            file_reader=_read_stata_file,
        ),
    }


_FORMAT_REGISTRY: dict[str, _FormatSpec] = _build_registry()

_SUPPORTED_EXTENSIONS: str = " ".join(sorted(_FORMAT_REGISTRY.keys()))


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

    def _dispatch(self, ext: str, source, is_stream: bool):
        """Shared dispatch for both file-path and stream reads."""
        spec = _FORMAT_REGISTRY.get(ext)
        if spec is None:
            raise ValueError(
                f"Unsupported format: {ext}\n"
                f"Supported: {_SUPPORTED_EXTENSIONS}"
            )
        if not spec.dep_flag:
            raise RuntimeError(spec.dep_error)

        reader = spec.stream_reader if is_stream else spec.file_reader
        if reader is None:
            raise ValueError(f"Compressed streaming not supported for {ext}.")

        return reader(ext, source, flatten_kw=self._flatten_kw())

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
        return self._dispatch(ext, path, is_stream=False)

    def _read_stream(self, stream: io.IOBase, ext: str):
        return self._dispatch(ext, stream, is_stream=True)

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
