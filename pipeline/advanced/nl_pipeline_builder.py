"""
Natural-language pipeline builder — generates pipeline configs from plain English.

Layer 5 — imports from Layer 0-4.

Revision history
────────────────
1.0   2026-06-07   Initial release: LLM and keyword-fallback config generation.
"""

import json
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class NLPipelineBuilder:
    """
    Generates pipeline configuration dicts from natural language descriptions.

    Uses an LLM API (OpenAI-compatible) when available, falling back to
    regex-based keyword extraction when no API key is configured.

    Quick-start
    -----------
        from pipeline.advanced import NLPipelineBuilder
        builder = NLPipelineBuilder(gov, api_key="sk-...")
        config = builder.build("Load customers.csv, mask PII, write to Postgres")

    Parameters
    ----------
    gov      : GovernanceLogger
    api_key  : str | None   OpenAI API key. None = keyword fallback only.
    model    : str          Model identifier for the chat completions API.
    """

    # ── Source type keywords ──────────────────────────────────────────────

    _SOURCE_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"\.csv\b", re.IGNORECASE), "csv"),
        (re.compile(r"\.json\b", re.IGNORECASE), "json"),
        (re.compile(r"\.parquet\b", re.IGNORECASE), "parquet"),
        (re.compile(r"\.xlsx?\b", re.IGNORECASE), "excel"),
        (re.compile(r"\bapi\b|\brest\b|\bendpoint\b", re.IGNORECASE), "api"),
        (re.compile(r"\bsql\b|\bdatabase\b|\btable\b", re.IGNORECASE), "database"),
    ]

    # ── Destination type keywords ────────────────────────────────────────

    _DEST_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"\bpostgres(?:ql)?\b", re.IGNORECASE), "postgresql"),
        (re.compile(r"\bmysql\b", re.IGNORECASE), "mysql"),
        (re.compile(r"\bsqlite\b", re.IGNORECASE), "sqlite"),
        (re.compile(r"\bsnowflake\b", re.IGNORECASE), "snowflake"),
        (re.compile(r"\bbigquery\b", re.IGNORECASE), "bigquery"),
        (re.compile(r"\bredshift\b", re.IGNORECASE), "redshift"),
        (re.compile(r"\bmssql\b|\bsql\s*server\b", re.IGNORECASE), "mssql"),
        (re.compile(r"\bparquet\b", re.IGNORECASE), "parquet"),
        (re.compile(r"\bcsv\b", re.IGNORECASE), "csv"),
    ]

    # ── Transform keywords ───────────────────────────────────────────────

    _TRANSFORM_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"\bmask\b|\bpseudonym", re.IGNORECASE), "mask_pii"),
        (re.compile(r"\bencrypt\b", re.IGNORECASE), "encrypt_pii"),
        (re.compile(r"\bdrop.*(column|field|pii)", re.IGNORECASE), "drop_pii"),
        (re.compile(r"\bdedup\b|\bduplicate", re.IGNORECASE), "deduplicate"),
        (re.compile(r"\bstandardi[sz]e\b|\bnormali[sz]e\b", re.IGNORECASE), "standardise"),
        (re.compile(r"\bflatten\b|\bnested\b", re.IGNORECASE), "flatten"),
        (re.compile(r"\bfilter\b|\bwhere\b", re.IGNORECASE), "filter"),
        (re.compile(r"\brename\b", re.IGNORECASE), "rename_columns"),
        (re.compile(r"\bcast\b|\bconvert\b|\btype\b", re.IGNORECASE), "type_coerce"),
        (re.compile(r"\benrich\b|\bjoin\b|\blookup\b", re.IGNORECASE), "enrich"),
    ]

    # ── Quality check keywords ───────────────────────────────────────────

    _QUALITY_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"\bnull\b|\bmissing\b|\bcompleteness\b", re.IGNORECASE), "null_check"),
        (re.compile(r"\bunique\b|\bduplicat", re.IGNORECASE), "uniqueness_check"),
        (re.compile(r"\bschema\b|\bcontract\b", re.IGNORECASE), "schema_validation"),
        (re.compile(r"\bfreshness\b|\bstale\b|\bage\b", re.IGNORECASE), "freshness_check"),
        (re.compile(r"\brange\b|\bbound", re.IGNORECASE), "range_check"),
        (re.compile(r"\bpii\b|\bpersonal\b|\bgdpr\b", re.IGNORECASE), "pii_scan"),
    ]

    def __init__(
        self,
        gov: "GovernanceLogger",
        api_key: str | None = None,
        model: str = "gpt-4",
    ) -> None:
        self.gov = gov
        self.api_key = api_key
        self.model = model

    # ── Public API ───────────────────────────────────────────────────────

    def build(self, description: str) -> dict:
        """
        Parse a natural language description into a pipeline config dict.

        Tries the LLM first (if api_key is set), falls back to keyword
        extraction on failure or when no key is available.

        Returns
        -------
        dict  Keys: source_type, source_path, destination_type,
              destination_cfg, transforms, quality_checks.
        """
        if not description or not description.strip():
            raise ValueError("Pipeline description must not be empty.")

        config: dict | None = None

        if self.api_key:
            try:
                config = self._call_llm(description)
                logger.info("Pipeline config generated via LLM (%s).", self.model)
            except Exception as exc:
                logger.warning(
                    "LLM call failed, falling back to keyword extraction: %s", exc,
                )

        if config is None:
            config = self._keyword_fallback(description)
            logger.info("Pipeline config generated via keyword fallback.")

        # Ensure all expected keys are present
        config.setdefault("source_type", "csv")
        config.setdefault("source_path", "")
        config.setdefault("destination_type", "sqlite")
        config.setdefault("destination_cfg", {})
        config.setdefault("transforms", [])
        config.setdefault("quality_checks", [])

        self.gov.transformation_applied("NL_PIPELINE_CONFIG_GENERATED", {
            "description_length": len(description),
            "source_type": config["source_type"],
            "destination_type": config["destination_type"],
            "transform_count": len(config["transforms"]),
            "quality_check_count": len(config["quality_checks"]),
            "method": "llm" if self.api_key and config.get("_method") != "keyword" else "keyword",
        })

        # Strip internal tracking key before returning
        config.pop("_method", None)
        return config

    # ── Keyword fallback ─────────────────────────────────────────────────

    def _keyword_fallback(self, description: str) -> dict:
        """Regex-based keyword extraction from a pipeline description."""
        config: dict = {"_method": "keyword"}

        # Source type
        for pattern, source_type in self._SOURCE_PATTERNS:
            if pattern.search(description):
                config["source_type"] = source_type
                break

        # Source path — look for quoted strings or file-like tokens
        path_match = re.search(r'["\']([^"\']+)["\']', description)
        if path_match:
            config["source_path"] = path_match.group(1)
        else:
            file_match = re.search(r'\b([\w./\\-]+\.\w{2,5})\b', description)
            if file_match:
                config["source_path"] = file_match.group(1)

        # Destination type
        for pattern, dest_type in self._DEST_PATTERNS:
            if pattern.search(description):
                config["destination_type"] = dest_type
                break

        # Transforms
        transforms = []
        for pattern, transform_name in self._TRANSFORM_PATTERNS:
            if pattern.search(description):
                transforms.append(transform_name)
        config["transforms"] = transforms

        # Quality checks
        quality_checks = []
        for pattern, check_name in self._QUALITY_PATTERNS:
            if pattern.search(description):
                quality_checks.append(check_name)
        config["quality_checks"] = quality_checks

        # Destination config — extract table name if mentioned
        table_match = re.search(
            r"\b(?:into|to|table)\s+[\"']?(\w+)[\"']?", description, re.IGNORECASE,
        )
        if table_match:
            config["destination_cfg"] = {"table": table_match.group(1)}

        return config

    # ── LLM-based parsing ────────────────────────────────────────────────

    def _call_llm(self, description: str) -> dict:
        """Call an OpenAI-compatible chat completions API to parse the description."""
        import requests

        system_prompt = (
            "You are a data pipeline configuration generator. "
            "Given a natural language description of a data pipeline, "
            "return a JSON object with exactly these keys:\n"
            "- source_type: one of csv, json, parquet, excel, api, database\n"
            "- source_path: file path or connection string (empty string if unknown)\n"
            "- destination_type: one of sqlite, postgresql, mysql, mssql, snowflake, "
            "bigquery, redshift, parquet, csv\n"
            "- destination_cfg: dict with connection details (table name at minimum)\n"
            "- transforms: list of transform names from: mask_pii, encrypt_pii, "
            "drop_pii, deduplicate, standardise, flatten, filter, rename_columns, "
            "type_coerce, enrich\n"
            "- quality_checks: list of check names from: null_check, uniqueness_check, "
            "schema_validation, freshness_check, range_check, pii_scan\n\n"
            "Return ONLY valid JSON, no markdown, no explanation."
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": description},
            ],
            "temperature": 0.1,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()

        result = response.json()
        content = result["choices"][0]["message"]["content"].strip()

        # Strip markdown code fences if the model wrapped its response
        if content.startswith("```"):
            lines = content.splitlines()
            lines = [l for l in lines if not l.strip().startswith("```")]
            content = "\n".join(lines)

        config = json.loads(content)
        if not isinstance(config, dict):
            raise ValueError(f"LLM returned non-dict: {type(config).__name__}")

        return config
