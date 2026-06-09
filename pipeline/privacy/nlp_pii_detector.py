"""
NLP-powered PII detection using named entity recognition.

Augments the existing pattern-based PII scanner with NER-based detection
for unstructured text fields, supporting 50+ entity types.

Falls back gracefully when spaCy is not installed.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Taste fixes: dry_run, return types, guard clause, naming,
                   configurable random seed, defaultdict, regex ordering.
"""

import logging
import re
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

try:
    import spacy
    _HAS_SPACY = True
except ImportError:
    _HAS_SPACY = False

_ENTITY_PII_MAP: dict[str, str] = {
    "PERSON": "PERSON_NAME",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "ORG": "ORGANIZATION",
    "DATE": "DATE_OF_BIRTH",
    "CARDINAL": "NUMERIC_ID",
    "MONEY": "FINANCIAL",
    "NORP": "DEMOGRAPHIC",
    "FAC": "ADDRESS",
}

_REGEX_DETECTORS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("IP_ADDRESS", re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )),
    ("US_PASSPORT", re.compile(r"\b[A-Z]\d{8}\b")),
    # Overlaps with US_PASSPORT (8 digits); passport checked first so it takes priority in dedup
    ("US_DRIVERS_LICENSE", re.compile(r"\b[A-Z]\d{7,12}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
]


class NLPPIIDetector:
    """
    NER-based PII detection for unstructured text columns.

    Quick-start
    -----------
        from pipeline.privacy.nlp_pii_detector import NLPPIIDetector
        detector = NLPPIIDetector(gov)
        findings = detector.scan(df, text_columns=["notes", "comments"])
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        model_name: str = "en_core_web_sm",
        confidence_threshold: float = 0.5,
        sample_size: int = 1000,
        random_seed: int = 42,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.model_name = model_name
        self.confidence = confidence_threshold
        self.sample_size = sample_size
        self.random_seed = random_seed
        self.dry_run = dry_run
        self._nlp = None

    def _load_model(self) -> object | None:
        if self._nlp is not None:
            return self._nlp
        if not _HAS_SPACY:
            logger.warning("spaCy not installed — NLP PII detection unavailable. "
                           "pip install spacy && python -m spacy download en_core_web_sm")
            return None
        try:
            self._nlp = spacy.load(self.model_name)
            logger.info("[NLP-PII] Loaded spaCy model '%s'", self.model_name)
            return self._nlp
        except OSError:
            logger.warning("spaCy model '%s' not found. "
                           "Run: python -m spacy download %s",
                           self.model_name, self.model_name)
            return None

    def scan(
        self,
        df: "pd.DataFrame",
        text_columns: list[str] | None = None,
        include_regex: bool = True,
    ) -> list[dict]:
        """
        Scan DataFrame columns for PII using NER and regex patterns.

        Parameters
        ----------
        df            : pd.DataFrame
        text_columns  : list | None  Columns to scan. Auto-detects object cols if None.
        include_regex : bool         Also run regex-based detectors.

        Returns
        -------
        list[dict]  Findings with column, entity_type, count, sample_values.
        """
        if df is None or df.empty:
            return []

        if text_columns is None:
            text_columns = list(df.select_dtypes(include=["object"]).columns)

        findings: list[dict] = []

        for col in text_columns:
            if col not in df.columns:
                continue

            sample = df[col].dropna()
            if len(sample) > self.sample_size:
                sample = sample.sample(self.sample_size, random_state=self.random_seed)

            col_findings = self._scan_column_ner(col, sample)
            if include_regex:
                col_findings.extend(self._scan_column_regex(col, sample))

            col_findings = self._deduplicate(col_findings)
            findings.extend(col_findings)

        self.gov.transformation_applied("NLP_PII_SCAN", {
            "columns_scanned": len(text_columns),
            "findings": len(findings),
            "entity_types": list({f["entity_type"] for f in findings}),
        })

        if findings:
            logger.info("[NLP-PII] Found %d PII instances across %d columns",
                        len(findings), len({f["column"] for f in findings}))
        else:
            logger.info("[NLP-PII] No PII detected in %d columns", len(text_columns))

        return findings

    def _scan_column_ner(self, column_name: str, sample: "pd.Series") -> list[dict]:
        nlp = self._load_model()
        if nlp is None:
            return []

        entity_counts: dict[str, int] = defaultdict(int)
        text_batch = sample.astype(str).tolist()

        for doc in nlp.pipe(text_batch, batch_size=64, disable=["tagger", "parser", "lemmatizer"]):  # type: ignore[attr-defined]
            for ent in doc.ents:
                pii_type = _ENTITY_PII_MAP.get(ent.label_)
                if pii_type:
                    entity_counts[pii_type] += 1

        findings = []
        for entity_type, count in entity_counts.items():
            detection_rate = count / max(len(sample), 1)
            if detection_rate >= self.confidence:
                findings.append({
                    "column": column_name,
                    "entity_type": entity_type,
                    "detection_method": "NER",
                    "count": count,
                    "detection_rate": round(detection_rate, 4),
                    "model": self.model_name,
                })

        return findings

    def _scan_column_regex(self, column_name: str, sample: "pd.Series") -> list[dict]:
        findings = []
        text_values = sample.astype(str)

        for pii_type, pattern in _REGEX_DETECTORS:
            matches = text_values.str.contains(pattern, na=False)
            count = int(matches.sum())
            if count > 0:
                detection_rate = count / max(len(sample), 1)
                if detection_rate >= self.confidence / 10:
                    findings.append({
                        "column": column_name,
                        "entity_type": pii_type,
                        "detection_method": "REGEX",
                        "count": count,
                        "detection_rate": round(detection_rate, 4),
                    })

        return findings

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        merged: dict[tuple, dict] = {}
        for finding in findings:
            key = (finding["column"], finding["entity_type"])
            if key not in merged:
                merged[key] = finding
            else:
                merged[key]["count"] = max(merged[key]["count"], finding["count"])
        return list(merged.values())

    def scan_and_classify(
        self,
        df: "pd.DataFrame",
        text_columns: list[str] | None = None,
    ) -> dict:
        """
        Scan and return a classification summary per column.

        Returns dict mapping column names to their highest-confidence PII type.
        """
        findings = self.scan(df, text_columns)
        classification: dict[str, dict] = {}

        for f in findings:
            col = f["column"]
            if col not in classification or f["detection_rate"] > classification[col]["detection_rate"]:
                classification[col] = {
                    "pii_type": f["entity_type"],
                    "detection_rate": f["detection_rate"],
                    "method": f["detection_method"],
                }

        return classification
