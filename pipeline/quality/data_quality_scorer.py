"""
Data quality scorer — computes a 0-100 composite quality score across five dimensions.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataQualityScorer:
    """
    Computes a 0-100 composite data quality score for a DataFrame,
    broken down across five standard dimensions:

        Completeness   — non-null cells as a fraction of total cells
        Uniqueness     — fraction of rows that are not exact duplicates
        Validity       — fraction of rows that passed Great Expectations
        Consistency    — fraction of numeric columns within expected range
        Timeliness     — fraction of date columns within the past N days

    The composite score is the weighted mean of each dimension.

    Scores are logged to the governance ledger and appended to a
    persistent JSONL history file so quality trends can be tracked.

    Quick-start
    -----------
        from pipeline.quality import DataQualityScorer
        scorer = DataQualityScorer(gov)
        result = scorer.score(df, validation_report=report)
        logger.info("Score: %s", result["score"])

    Parameters
    ----------
    gov           : GovernanceLogger
    history_file  : str | Path   Defaults to "quality_score_history.jsonl"
    weights       : dict | None  Custom dimension weights (must sum to 1.0).
    """

    DEFAULT_WEIGHTS = {
        "completeness": 0.30,
        "uniqueness":   0.20,
        "validity":     0.25,
        "consistency":  0.15,
        "timeliness":   0.10,
    }

    def __init__(
        self,
        gov: "GovernanceLogger",
        history_file: str | Path | None = None,
        weights: dict | None = None,
    ) -> None:
        self.gov          = gov
        self.history_file = Path(history_file) if history_file else gov.log_dir / "quality_history.jsonl"
        self.weights      = weights or self.DEFAULT_WEIGHTS

    # ── Dimension calculators ─────────────────────────────────────────────

    def _completeness(self, df: "pd.DataFrame") -> float:
        total = df.size
        if total == 0:
            return 100.0
        return round((1 - df.isna().sum().sum() / total) * 100, 2)

    def _uniqueness(self, df: "pd.DataFrame") -> float:
        if len(df) == 0:
            return 100.0
        return round((1 - df.duplicated().sum() / len(df)) * 100, 2)

    def _validity(self, validation_report: dict | None) -> float:
        if not validation_report:
            return 100.0
        passed = validation_report.get("expectations_passed", 0)
        total  = validation_report.get("expectations_total",  0)
        if total == 0:
            return 100.0
        return round(passed / total * 100, 2)

    def _consistency(self, df: "pd.DataFrame") -> float:
        num_cols = df.select_dtypes(include="number")
        if num_cols.empty:
            return 100.0
        scores = []
        for col in num_cols.columns:
            s   = num_cols[col].dropna()
            if len(s) < 2:
                continue
            mean = s.mean()
            std  = s.std()
            if std == 0:
                scores.append(100.0)
                continue
            # Fraction of values within 3 sigma of mean
            in_range = ((s >= mean - 3 * std) & (s <= mean + 3 * std)).mean()
            scores.append(in_range * 100)
        return round(sum(scores) / len(scores), 2) if scores else 100.0

    def _timeliness(self, df: "pd.DataFrame", max_days: int = 365) -> float:
        date_cols = df.select_dtypes(include=["datetime64[ns]", "datetimetz"])
        if date_cols.empty:
            return 100.0
        now    = datetime.now(timezone.utc).replace(tzinfo=None)
        scores = []
        for col in date_cols.columns:
            s   = date_cols[col].dropna()
            if len(s) == 0:
                continue
            days_old = (now - s.dt.tz_localize(None)).dt.days
            fresh    = (days_old <= max_days).mean()
            scores.append(fresh * 100)
        return round(sum(scores) / len(scores), 2) if scores else 100.0

    # ── Main scorer ───────────────────────────────────────────────────────

    def score(
        self,
        df: "pd.DataFrame",
        validation_report: dict | None = None,
        timeliness_max_days: int = 365,
        run_label: str | None = None,
    ) -> dict:
        """
        Compute the composite quality score.

        Parameters
        ----------
        df                  : pd.DataFrame
        validation_report   : dict | None   From SchemaValidator.validate()
        timeliness_max_days : int           Days threshold for timeliness check
        run_label           : str | None    Tag for history file (e.g. "2026-01")

        Returns
        -------
        dict  {score, dimensions, rows, columns, generated_utc, ...}
        """
        dims = {
            "completeness": self._completeness(df),
            "uniqueness":   self._uniqueness(df),
            "validity":     self._validity(validation_report),
            "consistency":  self._consistency(df),
            "timeliness":   self._timeliness(df, timeliness_max_days),
        }
        composite = round(
            sum(dims[d] * self.weights[d] for d in dims), 2
        )

        report = {
            "score":         composite,
            "grade":         "A" if composite >= 90 else "B" if composite >= 80
                             else "C" if composite >= 70 else "D" if composite >= 60 else "F",
            "dimensions":    dims,
            "rows":          len(df),
            "columns":       len(df.columns),
            "run_label":     run_label,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
        }

        # Persist to history
        with open(self.history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(report, default=str) + "\n")

        self.gov.transformation_applied("QUALITY_SCORE_COMPUTED", {
            "score": composite, "grade": report["grade"],
            "dimensions": dims,
        })
        logger.info("[Quality] Composite score: %.1f (grade %s)", composite, report["grade"])
        return report

    def trend(self, n: int = 30) -> list[dict]:
        """
        Return the last ``n`` quality score records for trend analysis.

        Parameters
        ----------
        n : int   Maximum records to return (most recent first).
        """
        if not self.history_file.exists():
            return []
        lines = self.history_file.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines[-n:]):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records
