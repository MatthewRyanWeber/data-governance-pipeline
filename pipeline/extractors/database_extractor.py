"""
SQL database extractor — reads from any SQLAlchemy-supported database.

Mirrors the loader pattern in reverse: where loaders write DataFrames to
databases, this reads DataFrames from databases via SQL queries or full
table reads. Supports chunked extraction for large tables.

Layer 3 — imports from Layer 1 (governance_logger), Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import logging
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DatabaseExtractor:
    """
    Reads DataFrames from SQL databases via SQLAlchemy.

    Quick-start
    -----------
        from pipeline.extractors import DatabaseExtractor
        ext = DatabaseExtractor(gov)
        df = ext.extract(cfg, query="SELECT * FROM customers WHERE active = 1")
        # or full table:
        df = ext.extract(cfg, table="customers")
        # chunked for large tables:
        for chunk in ext.chunks(cfg, table="orders", chunk_size=50_000):
            process(chunk)
    """

    _DRIVER_MAP: dict[str, str] = {
        "postgresql": "postgresql+psycopg2",
        "postgres": "postgresql+psycopg2",
        "mysql": "mysql+pymysql",
        "mssql": "mssql+pyodbc",
        "sqlite": "sqlite",
        "oracle": "oracle+oracledb",
        "db2": "db2+ibm_db",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def _build_url(self, cfg: dict) -> str:
        """Build a SQLAlchemy connection URL from config dict."""
        if cfg.get("connection_string"):
            return cfg["connection_string"]

        db_type = cfg.get("db_type", "postgresql").lower()
        driver = self._DRIVER_MAP.get(db_type)
        if not driver:
            raise ValueError(
                f"Unsupported db_type for extraction: {db_type!r}. "
                f"Supported: {sorted(self._DRIVER_MAP)}"
            )

        host = cfg.get("host", "localhost")
        port = cfg.get("port", "")
        user = cfg.get("user", "")
        password = cfg.get("password", "")
        db_name = cfg.get("db_name", "")

        if db_type == "sqlite":
            return f"sqlite:///{db_name}"

        from urllib.parse import quote_plus
        auth = f"{quote_plus(user)}:{quote_plus(password)}@" if user else ""
        port_part = f":{port}" if port else ""
        return f"{driver}://{auth}{host}{port_part}/{db_name}"

    def _connect(self, cfg: dict):
        """Create and return a SQLAlchemy engine."""
        from sqlalchemy import create_engine

        url = self._build_url(cfg)
        connect_args = cfg.get("connect_args", {})
        return create_engine(url, connect_args=connect_args)

    @staticmethod
    def _validate_identifier(name: str) -> str:
        """Validate and quote a SQL identifier to prevent injection."""
        import re
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            raise ValueError(f"Invalid SQL identifier: {name!r}")
        return f'"{name}"'

    def extract(
        self,
        cfg: dict,
        query: str | None = None,
        table: str | None = None,
        schema: str | None = None,
        columns: list[str] | None = None,
        where: str | None = None,
    ) -> "pd.DataFrame":
        """
        Read a full result set into a DataFrame.

        Provide either ``query`` (raw SQL) or ``table`` (reads all rows).
        When using ``table``, optionally pass ``columns`` and ``where``
        to restrict what's read.
        """
        import pandas as pd
        from sqlalchemy import text

        if not query and not table:
            raise ValueError("Provide either 'query' or 'table'.")

        engine = self._connect(cfg)
        source_label = query[:80] if query else f"{schema + '.' if schema else ''}{table}"

        self.gov.extract_event("DATABASE_EXTRACT_START", {
            "source": source_label,
            "db_type": cfg.get("db_type", "unknown"),
        })

        try:
            if query:
                df = pd.read_sql(text(query), engine)
            else:
                safe_table = self._validate_identifier(table)
                col_list = ", ".join(self._validate_identifier(c) for c in columns) if columns else "*"
                schema_prefix = f"{self._validate_identifier(schema)}." if schema else ""
                sql = f"SELECT {col_list} FROM {schema_prefix}{safe_table}"
                if where:
                    sql += f" WHERE {where}"
                df = pd.read_sql(text(sql), engine)
        finally:
            engine.dispose()

        self.gov.source_registered(source_label, cfg.get("db_type", "sql"), len(df), len(df.columns))
        self.gov.extract_event("DATABASE_EXTRACT_COMPLETE", {
            "rows": len(df),
            "columns": list(df.columns),
            "source": source_label,
        })
        logger.info(
            "[DATABASE_EXTRACT] %s → %d rows, %d columns",
            source_label, len(df), len(df.columns),
        )
        return df

    def chunks(
        self,
        cfg: dict,
        query: str | None = None,
        table: str | None = None,
        schema: str | None = None,
        chunk_size: int = 50_000,
    ) -> Iterator["pd.DataFrame"]:
        """
        Yield DataFrames in chunks for memory-efficient extraction.

        Uses LIMIT/OFFSET pagination internally. For large tables, prefer
        a query with an ORDER BY on an indexed column.
        """
        import pandas as pd
        from sqlalchemy import text

        if not query and not table:
            raise ValueError("Provide either 'query' or 'table'.")

        engine = self._connect(cfg)
        source_label = query[:80] if query else f"{schema + '.' if schema else ''}{table}"

        self.gov.extract_event("DATABASE_CHUNKED_EXTRACT_START", {
            "source": source_label,
            "chunk_size": chunk_size,
        })

        try:
            if query:
                base_sql = query
            else:
                safe_table = self._validate_identifier(table)
                schema_prefix = f"{self._validate_identifier(schema)}." if schema else ""
                base_sql = f"SELECT * FROM {schema_prefix}{safe_table}"

            offset = 0
            chunk_index = 0

            while True:
                paginated = f"{base_sql} LIMIT {chunk_size} OFFSET {offset}"
                chunk = pd.read_sql(text(paginated), engine)

                if chunk.empty:
                    break

                self.gov.extract_event("DATABASE_CHUNK_EXTRACTED", {
                    "chunk_index": chunk_index,
                    "rows": len(chunk),
                    "offset": offset,
                })
                logger.info(
                    "[DATABASE_EXTRACT] Chunk %d: %d rows (offset %d)",
                    chunk_index, len(chunk), offset,
                )
                yield chunk

                if len(chunk) < chunk_size:
                    break

                offset += chunk_size
                chunk_index += 1
        finally:
            engine.dispose()
