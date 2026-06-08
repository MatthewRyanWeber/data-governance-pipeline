"""
SQLite-backed metadata store for the data catalog.

Registers datasets, columns, tags, and owners. Auto-populates from
GovernanceLogger events and DataFrame profiling.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Hoist hashlib import, log FTS rebuild failures.
1.2   2026-06-08   Taste fixes: dry_run, per-instance lock, guard clauses, naming.
"""

import hashlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

CATALOG_DB = BASE_DIR / "config" / "catalog.db"

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS datasets (
    dataset_id   TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT DEFAULT '',
    owner        TEXT DEFAULT '',
    domain       TEXT DEFAULT '',
    source_type  TEXT DEFAULT '',
    source_path  TEXT DEFAULT '',
    row_count    INTEGER DEFAULT 0,
    col_count    INTEGER DEFAULT 0,
    tags         TEXT DEFAULT '[]',
    quality_score REAL DEFAULT NULL,
    last_updated TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS columns (
    column_id    TEXT PRIMARY KEY,
    dataset_id   TEXT NOT NULL,
    name         TEXT NOT NULL,
    dtype        TEXT DEFAULT '',
    nullable     INTEGER DEFAULT 1,
    pii          INTEGER DEFAULT 0,
    description  TEXT DEFAULT '',
    glossary_term TEXT DEFAULT '',
    tags         TEXT DEFAULT '[]',
    FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id)
);

CREATE TABLE IF NOT EXISTS dataset_tags (
    dataset_id TEXT NOT NULL,
    tag        TEXT NOT NULL,
    PRIMARY KEY (dataset_id, tag),
    FOREIGN KEY (dataset_id) REFERENCES datasets(dataset_id)
);

CREATE VIRTUAL TABLE IF NOT EXISTS catalog_fts USING fts5(
    dataset_id, name, description, owner, domain, tags,
    content='datasets', content_rowid='rowid'
);
"""


class CatalogStore:
    """
    SQLite-backed data catalog for dataset and column metadata.

    Quick-start
    -----------
        from pipeline.catalog import CatalogStore
        cat = CatalogStore(gov)
        cat.register_dataset(df, "customers", owner="data-team", domain="CRM")
        results = cat.search("customer email")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        db_path: str | Path | None = None,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.db_path = Path(db_path) if db_path else CATALOG_DB
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            try:
                conn.executescript(_SCHEMA_SQL)
                conn.commit()
            finally:
                conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def register_dataset(
        self,
        df: "pd.DataFrame",
        name: str,
        description: str = "",
        owner: str = "",
        domain: str = "",
        source_type: str = "",
        source_path: str = "",
        tags: list[str] | None = None,
        quality_score: float | None = None,
    ) -> str:
        """Register or update a dataset in the catalog. Returns dataset_id."""
        if not name or not name.strip():
            raise ValueError("Dataset name must not be empty")

        dataset_id = hashlib.sha256(name.encode()).hexdigest()[:16]
        row_count = len(df)
        column_count = len(df.columns)

        if self.dry_run:
            logger.info("[DRY RUN] Would register dataset '%s' (%d rows, %d cols)",
                        name, row_count, column_count)
            return dataset_id

        now = datetime.now(timezone.utc).isoformat()
        tag_list = tags or []

        with self._lock:
            conn = self._conn()
            try:
                conn.execute("""
                    INSERT INTO datasets
                        (dataset_id, name, description, owner, domain,
                         source_type, source_path, row_count, col_count,
                         tags, quality_score, last_updated, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(dataset_id) DO UPDATE SET
                        description=excluded.description,
                        owner=excluded.owner, domain=excluded.domain,
                        source_type=excluded.source_type,
                        source_path=excluded.source_path,
                        row_count=excluded.row_count,
                        col_count=excluded.col_count,
                        tags=excluded.tags,
                        quality_score=excluded.quality_score,
                        last_updated=excluded.last_updated
                """, (
                    dataset_id, name, description, owner, domain,
                    source_type, source_path, row_count, column_count,
                    json.dumps(tag_list), quality_score, now, now,
                ))

                conn.execute(
                    "DELETE FROM columns WHERE dataset_id = ?", (dataset_id,)
                )
                for col_name in df.columns:
                    col_id = f"{dataset_id}_{col_name}"
                    conn.execute("""
                        INSERT OR REPLACE INTO columns
                            (column_id, dataset_id, name, dtype, nullable)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        col_id, dataset_id, col_name,
                        str(df[col_name].dtype),
                        int(df[col_name].isna().any()),
                    ))

                for tag in tag_list:
                    conn.execute("""
                        INSERT OR IGNORE INTO dataset_tags (dataset_id, tag)
                        VALUES (?, ?)
                    """, (dataset_id, tag))

                try:
                    conn.execute(
                        "INSERT INTO catalog_fts(catalog_fts) VALUES('rebuild')"
                    )
                except sqlite3.OperationalError as exc:
                    logger.warning("[CATALOG] FTS rebuild failed: %s", exc)

                conn.commit()
            finally:
                conn.close()

        self.gov.transformation_applied("CATALOG_DATASET_REGISTERED", {
            "dataset_id": dataset_id, "name": name,
            "rows": row_count, "columns": column_count,
            "owner": owner, "domain": domain,
        })
        logger.info("[CATALOG] Registered dataset '%s' (%d rows, %d cols)",
                     name, row_count, column_count)
        return dataset_id

    def get_dataset(self, name: str) -> dict | None:
        """Look up a dataset by name."""
        dataset_id = hashlib.sha256(name.encode()).hexdigest()[:16]
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM datasets WHERE dataset_id = ?", (dataset_id,)
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            result["tags"] = json.loads(result["tags"])
            cols = conn.execute(
                "SELECT * FROM columns WHERE dataset_id = ?", (dataset_id,)
            ).fetchall()
            result["columns"] = [dict(c) for c in cols]
            return result
        finally:
            conn.close()

    def list_datasets(self, domain: str | None = None) -> list[dict]:
        """List all datasets, optionally filtered by domain."""
        conn = self._conn()
        try:
            if domain:
                rows = conn.execute(
                    "SELECT * FROM datasets WHERE domain = ? ORDER BY name",
                    (domain,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM datasets ORDER BY name"
                ).fetchall()
            results = []
            for row in rows:
                dataset_record = dict(row)
                dataset_record["tags"] = json.loads(dataset_record["tags"])
                results.append(dataset_record)
            return results
        finally:
            conn.close()

    def tag_column(
        self, dataset_name: str, column_name: str,
        pii: bool = False, description: str = "",
        glossary_term: str = "", tags: list[str] | None = None,
    ) -> None:
        """Update metadata for a specific column."""
        if self.dry_run:
            logger.info("[DRY RUN] Would tag column '%s.%s'",
                        dataset_name, column_name)
            return

        dataset_id = hashlib.sha256(dataset_name.encode()).hexdigest()[:16]
        col_id = f"{dataset_id}_{column_name}"
        with self._lock:
            conn = self._conn()
            try:
                cur = conn.execute("""
                    UPDATE columns SET
                        pii = ?, description = ?,
                        glossary_term = ?, tags = ?
                    WHERE column_id = ?
                """, (
                    int(pii), description, glossary_term,
                    json.dumps(tags or []), col_id,
                ))
                if cur.rowcount == 0:
                    logger.warning("[CATALOG] Column '%s' not found in dataset '%s'",
                                   column_name, dataset_name)
                conn.commit()
            finally:
                conn.close()

    def update_quality_score(self, dataset_name: str, score: float) -> None:
        """Update the quality score for a dataset."""
        if self.dry_run:
            logger.info("[DRY RUN] Would update quality score for '%s' to %.2f",
                        dataset_name, score)
            return

        dataset_id = hashlib.sha256(dataset_name.encode()).hexdigest()[:16]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._conn()
            try:
                cur = conn.execute(
                    "UPDATE datasets SET quality_score = ?, last_updated = ? "
                    "WHERE dataset_id = ?",
                    (score, now, dataset_id),
                )
                if cur.rowcount == 0:
                    logger.warning("[CATALOG] Dataset '%s' not found for quality update",
                                   dataset_name)
                conn.commit()
            finally:
                conn.close()

    def delete_dataset(self, name: str) -> bool:
        """Remove a dataset and its columns from the catalog."""
        if self.dry_run:
            logger.info("[DRY RUN] Would delete dataset '%s'", name)
            return False

        dataset_id = hashlib.sha256(name.encode()).hexdigest()[:16]
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("DELETE FROM columns WHERE dataset_id = ?", (dataset_id,))
                conn.execute("DELETE FROM dataset_tags WHERE dataset_id = ?", (dataset_id,))
                cur = conn.execute("DELETE FROM datasets WHERE dataset_id = ?", (dataset_id,))
                conn.commit()
                deleted = cur.rowcount > 0
            finally:
                conn.close()
        if deleted:
            logger.info("[CATALOG] Deleted dataset '%s'", name)
        return deleted
