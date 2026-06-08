"""
Data observability — freshness, volume trends, and distribution drift.

Goes beyond quality alerts to continuously monitor when data was last
updated, detect volume anomalies, and flag distribution shifts.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
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


class DataObserver:
    """
    Monitors freshness, volume, and distribution drift across pipeline runs.

    Quick-start
    -----------
        from pipeline.monitoring.observability import DataObserver
        obs = DataObserver(gov)
        report = obs.observe(df, dataset="customers")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        history_file: str | Path | None = None,
        freshness_threshold_hours: float = 24.0,
        volume_change_threshold: float = 0.5,
        drift_threshold: float = 0.1,
    ) -> None:
        self.gov = gov
        self.history_file = (
            Path(history_file) if history_file
            else gov.log_dir / "observability_history.jsonl"
        )
        self.freshness_hours = freshness_threshold_hours
        self.volume_threshold = volume_change_threshold
        self.drift_threshold = drift_threshold

    def observe(
        self,
        df: "pd.DataFrame",
        dataset: str = "",
        timestamp_col: str | None = None,
    ) -> dict:
        """
        Run all observability checks on a DataFrame.

        Returns dict with freshness, volume, and drift alerts.
        """
        alerts: list[dict] = []

        freshness = self._check_freshness(df, timestamp_col)
        if freshness:
            alerts.append(freshness)

        volume_alert = self._check_volume(df, dataset)
        if volume_alert:
            alerts.append(volume_alert)

        drift_alerts = self._check_drift(df, dataset)
        alerts.extend(drift_alerts)

        report = {
            "dataset": dataset,
            "row_count": len(df),
            "column_count": len(df.columns),
            "alerts": alerts,
            "alert_count": len(alerts),
            "observed_utc": datetime.now(timezone.utc).isoformat(),
        }

        self._save_observation(report)

        if alerts:
            self.gov.transformation_applied("OBSERVABILITY_ALERTS", {
                "dataset": dataset, "alert_count": len(alerts),
                "alert_types": [a["type"] for a in alerts],
            })
            for alert in alerts:
                logger.warning("[OBSERVE] %s: %s", alert["type"], alert["message"])
        else:
            logger.info("[OBSERVE] '%s': all checks passed", dataset)

        return report

    def _check_freshness(
        self, df: "pd.DataFrame", timestamp_col: str | None,
    ) -> dict | None:
        """Check if data is stale based on the most recent timestamp."""
        import pandas as pd

        if timestamp_col and timestamp_col in df.columns:
            date_cols = [timestamp_col]
        else:
            date_cols = list(df.select_dtypes(
                include=["datetime64[ns]", "datetimetz"]
            ).columns)

        if not date_cols:
            return None

        now = datetime.now(timezone.utc)
        for col in date_cols:
            series = pd.to_datetime(df[col], errors="coerce").dropna()
            if series.empty:
                continue
            latest = series.max()
            if hasattr(latest, "tzinfo") and latest.tzinfo is None:
                latest = latest.tz_localize("UTC")
            age_hours = (now - latest).total_seconds() / 3600

            if age_hours > self.freshness_hours:
                return {
                    "type": "FRESHNESS",
                    "severity": "HIGH" if age_hours > self.freshness_hours * 3 else "MEDIUM",
                    "message": (
                        f"Data in '{col}' is {age_hours:.1f}h old "
                        f"(threshold: {self.freshness_hours}h)"
                    ),
                    "column": col,
                    "age_hours": round(age_hours, 1),
                    "threshold_hours": self.freshness_hours,
                }
        return None

    def _check_volume(self, df: "pd.DataFrame", dataset: str) -> dict | None:
        """Check for abnormal row count changes vs historical baseline."""
        history = self._load_history(dataset, n=5)
        if not history:
            return None

        historical_counts = [h["row_count"] for h in history]
        avg_count = sum(historical_counts) / len(historical_counts)

        if avg_count == 0:
            return None

        change_rate = abs(len(df) - avg_count) / avg_count

        if change_rate > self.volume_threshold:
            direction = "increased" if len(df) > avg_count else "decreased"
            return {
                "type": "VOLUME",
                "severity": "HIGH" if change_rate > self.volume_threshold * 2 else "MEDIUM",
                "message": (
                    f"Row count {direction} by {change_rate:.0%} "
                    f"(current: {len(df):,}, avg: {avg_count:,.0f})"
                ),
                "current_count": len(df),
                "average_count": round(avg_count),
                "change_rate": round(change_rate, 3),
            }
        return None

    def _check_drift(self, df: "pd.DataFrame", dataset: str) -> list[dict]:
        """Detect distribution drift on numeric columns vs last observation."""
        history = self._load_history(dataset, n=1)
        if not history or "column_stats" not in history[0]:
            return []

        prev_stats = {s["name"]: s for s in history[0].get("column_stats", [])}
        alerts = []

        for col in df.select_dtypes(include="number").columns:
            prev = prev_stats.get(col)
            if not prev or prev.get("mean") is None:
                continue

            series = df[col].dropna()
            if series.empty:
                continue

            curr_mean = float(series.mean())
            curr_std = float(series.std()) if len(series) > 1 else 0.0
            prev_mean = prev["mean"]
            prev_std = prev.get("std", 0.0)

            if prev_std == 0 and curr_std == 0:
                continue

            denom = max(prev_std, curr_std, 1e-10)
            mean_shift = abs(curr_mean - prev_mean) / denom

            if mean_shift > self.drift_threshold * 10:
                alerts.append({
                    "type": "DRIFT",
                    "severity": "HIGH" if mean_shift > self.drift_threshold * 20 else "MEDIUM",
                    "message": (
                        f"Column '{col}' mean shifted from {prev_mean:.2f} "
                        f"to {curr_mean:.2f} (normalized shift: {mean_shift:.2f})"
                    ),
                    "column": col,
                    "prev_mean": prev_mean,
                    "curr_mean": round(curr_mean, 4),
                    "normalized_shift": round(mean_shift, 4),
                })

        return alerts

    def _save_observation(self, report: dict) -> None:
        """Persist observation with column stats for future drift detection."""
        entry = dict(report)
        with open(self.history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")

    def _load_history(self, dataset: str, n: int = 5) -> list[dict]:
        """Load last n observations for a dataset."""
        if not self.history_file.exists():
            return []
        lines = self.history_file.read_text(encoding="utf-8").strip().splitlines()
        records = []
        for line in reversed(lines):
            try:
                rec = json.loads(line)
                if rec.get("dataset") == dataset:
                    records.append(rec)
                    if len(records) >= n:
                        break
            except json.JSONDecodeError:
                pass
        return records

    def freshness_report(self, datasets: list[str] | None = None) -> list[dict]:
        """Generate a freshness report across all observed datasets."""
        if not self.history_file.exists():
            return []

        lines = self.history_file.read_text(encoding="utf-8").strip().splitlines()
        latest: dict[str, dict] = {}
        for line in reversed(lines):
            try:
                rec = json.loads(line)
                ds = rec.get("dataset", "")
                if ds and ds not in latest:
                    if datasets is None or ds in datasets:
                        latest[ds] = rec
            except json.JSONDecodeError:
                pass

        return [
            {
                "dataset": ds,
                "last_observed": rec["observed_utc"],
                "row_count": rec["row_count"],
                "alert_count": rec["alert_count"],
            }
            for ds, rec in sorted(latest.items())
        ]
