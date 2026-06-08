"""
Business glossary — maps business terms to physical columns.

Bridges technical metadata and business meaning so PII tags and
quality scores have domain context.

Layer 3 — imports from Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import json
import logging
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_GLOSSARY_FILE = BASE_DIR / "config" / "business_glossary.json"
_LOCK = threading.Lock()


class BusinessGlossary:
    """
    Business glossary with term-to-column mapping.

    Quick-start
    -----------
        from pipeline.catalog import BusinessGlossary
        glossary = BusinessGlossary(gov)
        glossary.add_term("Customer LTV", "Lifetime value in USD",
                          domain="Finance", columns=["customers.ltv_usd"])
        matches = glossary.search("lifetime value")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        glossary_file: str | Path | None = None,
    ) -> None:
        self.gov = gov
        self.glossary_file = Path(glossary_file) if glossary_file else _GLOSSARY_FILE
        self.glossary_file.parent.mkdir(parents=True, exist_ok=True)
        self._glossary: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if not self.glossary_file.exists():
            return {}
        try:
            data = json.loads(self.glossary_file.read_text(encoding="utf-8"))
            return data.get("terms", {})
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load glossary: %s", exc)
            return {}

    def _save(self) -> None:
        with _LOCK:
            payload = {
                "version": "1.0",
                "updated_utc": datetime.now(timezone.utc).isoformat(),
                "terms": self._glossary,
            }
            data = json.dumps(payload, indent=2)
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=str(self.glossary_file.parent), suffix=".tmp",
            )
            try:
                with open(tmp_fd, "w", encoding="utf-8") as fh:
                    fh.write(data)
                Path(tmp_path).replace(self.glossary_file)
            except BaseException:
                Path(tmp_path).unlink(missing_ok=True)
                raise

    def add_term(
        self,
        term: str,
        definition: str,
        domain: str = "",
        owner: str = "",
        columns: list[str] | None = None,
        synonyms: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Add or update a business term."""
        key = term.lower().strip()
        self._glossary[key] = {
            "term": term,
            "definition": definition,
            "domain": domain,
            "owner": owner,
            "columns": columns or [],
            "synonyms": synonyms or [],
            "tags": tags or [],
            "updated_utc": datetime.now(timezone.utc).isoformat(),
        }
        self._save()
        self.gov.transformation_applied("GLOSSARY_TERM_ADDED", {
            "term": term, "domain": domain,
            "column_count": len(columns or []),
        })
        logger.info("[GLOSSARY] Added term '%s' (domain=%s)", term, domain)

    def get_term(self, term: str) -> dict | None:
        """Look up a term by exact name."""
        return self._glossary.get(term.lower().strip())

    def search(self, query: str) -> list[dict]:
        """Search terms by name, definition, synonyms, or column mapping."""
        q = query.lower()
        results = []
        for entry in self._glossary.values():
            if (q in entry["term"].lower()
                    or q in entry["definition"].lower()
                    or any(q in s.lower() for s in entry.get("synonyms", []))
                    or any(q in c.lower() for c in entry.get("columns", []))):
                results.append(entry)
        return results

    def terms_for_column(self, column_name: str) -> list[dict]:
        """Find all business terms mapped to a physical column."""
        col = column_name.lower()
        return [
            entry for entry in self._glossary.values()
            if any(col in c.lower() for c in entry.get("columns", []))
        ]

    def list_terms(self, domain: str | None = None) -> list[dict]:
        """List all terms, optionally filtered by domain."""
        if domain:
            return [
                e for e in self._glossary.values()
                if e.get("domain", "").lower() == domain.lower()
            ]
        return list(self._glossary.values())

    def remove_term(self, term: str) -> bool:
        """Remove a term from the glossary."""
        key = term.lower().strip()
        if key in self._glossary:
            del self._glossary[key]
            self._save()
            logger.info("[GLOSSARY] Removed term '%s'", term)
            return True
        return False

    def export(self) -> dict:
        """Export the full glossary as a dict."""
        return {
            "version": "1.0",
            "term_count": len(self._glossary),
            "terms": self._glossary,
        }
