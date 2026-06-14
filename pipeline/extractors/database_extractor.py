"""
SQL database extractor — reads from any SQLAlchemy-supported database.

Mirrors the loader pattern in reverse: where loaders write DataFrames to
databases, this reads DataFrames from databases via SQL queries or full
table reads. Supports chunked extraction for large tables.

Layer 3 — imports from Layer 1 (governance_logger), Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-14   chunks() streams a single ordered server-side cursor
                   instead of LIMIT/OFFSET: fixes O(n²) offset re-scans and,
                   critically, the unordered pagination that let a crash +
                   position-based resume drop and duplicate rows.
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
            return cfg["connection_string"]  # type: ignore[no-any-return]

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
                safe_table = self._validate_identifier(table)  # type: ignore[arg-type]
                col_list = ", ".join(self._validate_identifier(c) for c in columns) if columns else "*"
                schema_prefix = f"{self._validate_identifier(schema)}." if schema else ""  # type: ignore[arg-type]
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

        Streams the result set through a single server-side cursor in a
        deterministic order. The previous implementation paginated with
        ``LIMIT/OFFSET`` and no ``ORDER BY``; that was wrong on two counts:
        OFFSET re-scans and discards the skipped rows every chunk (O(n²) on
        large tables), and — worse — SQL gives no row-order guarantee across
        separate queries, so a crash + resume (which skips already-loaded
        chunks BY POSITION in cli.py) could silently drop some rows and
        duplicate others. A stable ORDER BY makes chunk boundaries identical
        across runs, so position-based resume is exactly-once.
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
            order_clause, is_ordered = self._resolve_order_clause(
                cfg, engine, query, table, schema
            )
            if not is_ordered:
                logger.warning(
                    "[DATABASE_EXTRACT] '%s' is being chunked without a stable "
                    "ORDER BY; chunk boundaries are not guaranteed identical "
                    "across runs, so a crash + resume may DROP or DUPLICATE "
                    "rows. Set cfg['order_by'] to a unique indexed column.",
                    source_label,
                )

            if query:
                sql = query
            else:
                safe_table = self._validate_identifier(table)  # type: ignore[arg-type]
                schema_prefix = f"{self._validate_identifier(schema)}." if schema else ""  # type: ignore[arg-type]
                sql = f"SELECT * FROM {schema_prefix}{safe_table}{order_clause}"

            chunk_index = 0
            # stream_results pushes a server-side cursor where the driver
            # supports it (psycopg2, mysqlclient, …); a no-op but still
            # correct elsewhere. read_sql(chunksize=) iterates that cursor
            # without ever materialising the whole table.
            with engine.connect().execution_options(stream_results=True) as conn:
                for chunk in pd.read_sql(text(sql), conn, chunksize=chunk_size):
                    if chunk.empty:
                        continue
                    self.gov.extract_event("DATABASE_CHUNK_EXTRACTED", {
                        "chunk_index": chunk_index,
                        "rows": len(chunk),
                    })
                    logger.info(
                        "[DATABASE_EXTRACT] Chunk %d: %d rows",
                        chunk_index, len(chunk),
                    )
                    yield chunk
                    chunk_index += 1
        finally:
            engine.dispose()

    def _resolve_order_clause(
        self, cfg: dict, engine, query: str | None,
        table: str | None, schema: str | None,
    ) -> tuple[str, bool]:
        """Return (order_by_clause, is_ordered) for stable chunked resume.

        Prefer an explicit cfg['order_by']; else the table's primary key;
        else order by every column (deterministic but slower) so resume is
        still safe. For a raw query, detect an existing ORDER BY textually —
        we cannot safely inject one into arbitrary SQL.
        """
        import re

        order_by = cfg.get("order_by")
        if order_by:
            cols = [order_by] if isinstance(order_by, str) else list(order_by)
            clause = ", ".join(self._validate_identifier(c) for c in cols)
            return f" ORDER BY {clause}", True

        if query:
            return "", bool(re.search(r"\border\s+by\b", query, re.IGNORECASE))

        from sqlalchemy import inspect as sa_inspect
        try:
            inspector = sa_inspect(engine)
            pk_cols = (
                inspector.get_pk_constraint(table, schema=schema)
                .get("constrained_columns") or []
            )
            if pk_cols:
                clause = ", ".join(self._validate_identifier(c) for c in pk_cols)
                return f" ORDER BY {clause}", True

            all_cols = [c["name"] for c in inspector.get_columns(table, schema=schema)]
        except Exception as exc:
            logger.warning(
                "[DATABASE_EXTRACT] could not introspect %r for ordering: %s",
                table, exc,
            )
            return "", False

        if all_cols:
            logger.warning(
                "[DATABASE_EXTRACT] table %r has no primary key; ordering by "
                "all columns for stable resume — set cfg['order_by'] to a "
                "unique indexed column for performance.", table,
            )
            clause = ", ".join(self._validate_identifier(c) for c in all_cols)
            return f" ORDER BY {clause}", True

        return "", False
