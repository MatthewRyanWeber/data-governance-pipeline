"""
Full-text search across the data catalog.

Searches datasets, columns, tags, owners, and domains using SQLite FTS5.

Layer 3 — imports from catalog_store.

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_CATALOG_DB = BASE_DIR / "config" / "catalog.db"


class CatalogSearch:
    """
    Full-text search across the data catalog.

    Quick-start
    -----------
        from pipeline.catalog import CatalogSearch
        search = CatalogSearch(gov)
        results = search.search("customer email PII")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        db_path: str | Path | None = None,
    ) -> None:
        self.gov = gov
        self.db_path = Path(db_path) if db_path else _CATALOG_DB

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """
        Search datasets by name, description, owner, domain, or tags.

        Uses FTS5 for ranked full-text search with fallback to LIKE
        if FTS table is unavailable.
        """
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            try:
                rows = conn.execute("""
                    SELECT d.*, fts.rank
                    FROM catalog_fts fts
                    JOIN datasets d ON d.dataset_id = fts.dataset_id
                    WHERE catalog_fts MATCH ?
                    ORDER BY fts.rank
                    LIMIT ?
                """, (query, limit)).fetchall()
            except sqlite3.OperationalError:
                like_q = f"%{query}%"
                rows = conn.execute("""
                    SELECT *, 0 as rank FROM datasets
                    WHERE name LIKE ? OR description LIKE ?
                       OR owner LIKE ? OR domain LIKE ? OR tags LIKE ?
                    ORDER BY name LIMIT ?
                """, (like_q, like_q, like_q, like_q, like_q, limit)).fetchall()

            results = []
            for row in rows:
                d = dict(row)
                d["tags"] = json.loads(d.get("tags", "[]"))
                results.append(d)

            self.gov.transformation_applied("CATALOG_SEARCH", {
                "query": query, "results": len(results),
            })
            return results
        finally:
            conn.close()

    def search_columns(self, query: str, limit: int = 100) -> list[dict]:
        """Search columns by name, description, or glossary term."""
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            like_q = f"%{query}%"
            rows = conn.execute("""
                SELECT c.*, d.name as dataset_name
                FROM columns c
                JOIN datasets d ON d.dataset_id = c.dataset_id
                WHERE c.name LIKE ? OR c.description LIKE ?
                   OR c.glossary_term LIKE ?
                ORDER BY d.name, c.name
                LIMIT ?
            """, (like_q, like_q, like_q, limit)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def find_pii_columns(self) -> list[dict]:
        """Return all columns flagged as PII across all datasets."""
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            rows = conn.execute("""
                SELECT c.*, d.name as dataset_name
                FROM columns c
                JOIN datasets d ON d.dataset_id = c.dataset_id
                WHERE c.pii = 1
                ORDER BY d.name, c.name
            """).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def datasets_by_owner(self, owner: str) -> list[dict]:
        """Return all datasets owned by a specific owner."""
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM datasets WHERE owner = ? ORDER BY name",
                (owner,),
            ).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["tags"] = json.loads(d.get("tags", "[]"))
                results.append(d)
            return results
        finally:
            conn.close()
