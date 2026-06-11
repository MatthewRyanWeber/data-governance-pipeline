"""
Full-text search across the data catalog.

Searches datasets, columns, tags, owners, and domains using SQLite FTS5.

Layer 3 — imports from catalog_store.

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Taste fixes: renamed import to CATALOG_DB, added dry_run,
                   guard clauses on search/search_columns, FTS fallback warning,
                   renamed d -> dataset_record.
1.2   2026-06-11   Security fix: all query paths are tenant-scoped (tenant_id
                   parameter matching CatalogStore) — previously every tenant
                   could read every other tenant's catalog rows.
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.catalog.catalog_store import CATALOG_DB

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


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
        dry_run: bool = False,
        tenant_id: str = "default",
    ) -> None:
        self.gov = gov
        self.dry_run = dry_run
        self.db_path = Path(db_path) if db_path else CATALOG_DB
        # Must match CatalogStore's tenant convention so search never
        # returns rows the calling tenant did not register.
        self.tenant_id = tenant_id

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
        if not query or not query.strip():
            return []
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            try:
                rows = conn.execute("""
                    SELECT d.*, fts.rank
                    FROM catalog_fts fts
                    JOIN datasets d ON d.dataset_id = fts.dataset_id
                    WHERE catalog_fts MATCH ? AND d.tenant_id = ?
                    ORDER BY fts.rank
                    LIMIT ?
                """, (query, self.tenant_id, limit)).fetchall()
            except sqlite3.OperationalError as exc:
                logger.warning("[CATALOG] FTS search failed, falling back to LIKE: %s", exc)
                like_q = f"%{query}%"
                rows = conn.execute("""
                    SELECT *, 0 as rank FROM datasets
                    WHERE tenant_id = ?
                      AND (name LIKE ? OR description LIKE ?
                       OR owner LIKE ? OR domain LIKE ? OR tags LIKE ?)
                    ORDER BY name LIMIT ?
                """, (self.tenant_id, like_q, like_q, like_q, like_q, like_q,
                      limit)).fetchall()

            results = []
            for row in rows:
                dataset_record = dict(row)
                dataset_record["tags"] = json.loads(dataset_record.get("tags", "[]"))
                results.append(dataset_record)

            self.gov.transformation_applied("CATALOG_SEARCH", {
                "query": query, "results": len(results),
            })
            return results
        finally:
            conn.close()

    def search_columns(self, query: str, limit: int = 100) -> list[dict]:
        """Search columns by name, description, or glossary term."""
        if not query or not query.strip():
            return []
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            like_q = f"%{query}%"
            rows = conn.execute("""
                SELECT c.*, d.name as dataset_name
                FROM columns c
                JOIN datasets d ON d.dataset_id = c.dataset_id
                              AND d.tenant_id = c.tenant_id
                WHERE c.tenant_id = ?
                  AND (c.name LIKE ? OR c.description LIKE ?
                   OR c.glossary_term LIKE ?)
                ORDER BY d.name, c.name
                LIMIT ?
            """, (self.tenant_id, like_q, like_q, like_q, limit)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def find_pii_columns(self) -> list[dict]:
        """Return all PII-flagged columns across the current tenant's datasets."""
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            rows = conn.execute("""
                SELECT c.*, d.name as dataset_name
                FROM columns c
                JOIN datasets d ON d.dataset_id = c.dataset_id
                              AND d.tenant_id = c.tenant_id
                WHERE c.pii = 1 AND c.tenant_id = ?
                ORDER BY d.name, c.name
            """, (self.tenant_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def datasets_by_owner(self, owner: str) -> list[dict]:
        """Return the current tenant's datasets owned by a specific owner."""
        if not self.db_path.exists():
            return []

        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM datasets WHERE owner = ? AND tenant_id = ? "
                "ORDER BY name",
                (owner, self.tenant_id),
            ).fetchall()
            results = []
            for row in rows:
                dataset_record = dict(row)
                dataset_record["tags"] = json.loads(dataset_record.get("tags", "[]"))
                results.append(dataset_record)
            return results
        finally:
            conn.close()
