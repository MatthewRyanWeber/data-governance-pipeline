"""
Business glossary — maps business terms to physical columns.

Bridges technical metadata and business meaning so PII tags and
quality scores have domain context.

Layer 3 — imports from Layer 0 (constants, helpers).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Taste fixes: dry_run support, instance-level lock,
                   atomic_json_write from helpers, input guard clauses,
                   extracted _term_matches helper.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR
from pipeline.helpers import atomic_json_write

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_GLOSSARY_FILE = BASE_DIR / "config" / "business_glossary.json"


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
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self.glossary_file = Path(glossary_file) if glossary_file else _GLOSSARY_FILE
        self.glossary_file.parent.mkdir(parents=True, exist_ok=True)
        self._glossary: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if not self.glossary_file.exists():
            return {}
        try:
            data = json.loads(self.glossary_file.read_text(encoding="utf-8"))
            return data.get("terms", {})  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load glossary: %s", exc)
            return {}

    def _save(self) -> None:
        with self._lock:
            payload = {
                "version": "1.0",
                "updated_utc": datetime.now(timezone.utc).isoformat(),
                "terms": self._glossary,
            }
            atomic_json_write(self.glossary_file, json.dumps(payload, indent=2))

    def _term_matches(self, entry: dict, query: str) -> bool:
        """Check whether *entry* matches *query* on any searchable field."""
        return (
            query in entry["term"].lower()
            or query in entry["definition"].lower()
            or any(query in s.lower() for s in entry.get("synonyms", []))
            or any(query in c.lower() for c in entry.get("columns", []))
        )

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
        if not term or not term.strip():
            raise ValueError("Term must not be empty")
        term = term.strip()

        if self.dry_run:
            logger.info("[GLOSSARY] DRY RUN — would add term '%s' (domain=%s)", term, domain)
            return

        key = term.lower()
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
        if not query or not query.strip():
            return []
        q = query.lower()
        return [
            entry for entry in self._glossary.values()
            if self._term_matches(entry, q)
        ]

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
        if self.dry_run:
            logger.info("[GLOSSARY] DRY RUN — would remove term '%s'", term)
            return False

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
