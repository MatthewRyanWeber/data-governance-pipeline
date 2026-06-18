"""
Data observability — freshness, volume trends, and distribution drift.

Goes beyond quality alerts to continuously monitor when data was last
updated, detect volume anomalies, and flag distribution shifts.

Layer 3 — imports from Layer 0 (helpers); GovernanceLogger is type-only.

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Fix drift detection: persist column_stats in observations.
1.2   2026-06-08   Taste fixes: dry_run, thread lock, column_stats moved to
                   observe(), guard empty df, use read_jsonl_tail, rename
                   rec→observation_record / ds→dataset_name.
1.3   2026-06-14   Add per-column null-rate tracking + null-spike detection:
                   a critical field going silently mostly-null passes schema,
                   row-count and drift checks — this closes that gap.
1.4   2026-06-14   observe() reads history once and computes each column's
                   null rate once, sharing both across all detectors (was
                   three file reads + a duplicate null-rate pass per call).
1.5   2026-06-14   Export OBSERVER_CONFIG_KEYS (pinned to the constructor by
                   a test) so the CLI forwards config keys from one home.
1.6   2026-06-14   Audit fixes: drop duplicate columns instead of crashing
                   observe() (df[col] -> DataFrame); tolerate history records
                   without row_count in volume check; a critical field that
                   both spikes and breaches the floor now reports HIGH.
1.7   2026-06-15   Add business-key duplicate detection: a declared key that
                   repeats (same key, differing timestamps) is flagged even
                   though row counts and full-row dedup miss it; a rising
                   duplicate rate vs the previous run escalates to HIGH.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.helpers import read_jsonl_tail

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


# The DataObserver.__init__ keyword arguments that may be supplied from a
# config "observability" block. Kept here, next to the class, so the CLI can
# forward exactly these without re-declaring the threshold defaults — the set
# has one home. test_monitoring pins it to the actual constructor signature,
# so renaming a parameter fails CI instead of silently dropping config.
OBSERVER_CONFIG_KEYS = (
    "critical_fields",
    "null_spike_threshold",
    "null_absolute_floor",
    "freshness_threshold_hours",
    "volume_change_threshold",
    "drift_threshold",
    "business_keys",
    "duplicate_key_spike",
)


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
        critical_fields: list[str] | None = None,
        null_spike_threshold: float = 0.2,
        null_absolute_floor: float = 0.5,
        business_keys: list[str] | None = None,
        duplicate_key_spike: float = 0.01,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.history_file = (
            Path(history_file) if history_file
            else gov.log_dir / "observability_history.jsonl"
        )
        self.freshness_hours = freshness_threshold_hours
        self.volume_threshold = volume_change_threshold
        self.drift_threshold = drift_threshold
        # Fields that must stay populated. When set, null-spike detection is
        # scoped to these (and only these get the absolute-floor check); when
        # empty, the baseline-spike check still watches every column.
        self.critical_fields = list(critical_fields or [])
        self.null_spike_threshold = null_spike_threshold
        self.null_absolute_floor = null_absolute_floor
        # Columns forming a business/natural key that MUST be unique. Catches
        # same-key duplicates (e.g. a source resending events with a fresh
        # timestamp) that row-count reconciliation and full-row dedup miss.
        self.business_keys = list(business_keys or [])
        # A rise in the duplicate-key rate beyond this vs the previous run is
        # flagged HIGH — catches a source that *starts* duplicating.
        self.duplicate_key_spike = duplicate_key_spike
        self.dry_run = dry_run
        self._lock = threading.Lock()

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
        if df.empty:
            logger.info(
                "[OBSERVE] '%s': empty DataFrame — skipping volume/drift checks",
                dataset,
            )
            return {
                "dataset": dataset,
                "row_count": 0,
                "column_count": len(df.columns),
                "alerts": [],
                "alert_count": 0,
                "observed_utc": datetime.now(timezone.utc).isoformat(),
            }

        # Duplicate column labels make df[col] return a DataFrame rather than
        # a Series, which breaks every per-column statistic below (and would
        # abort the whole load, since observe() runs per chunk). Drop the
        # duplicates loudly instead of crashing.
        if df.columns.duplicated().any():
            dupes = sorted(set(df.columns[df.columns.duplicated()]))
            logger.warning(
                "[OBSERVE] '%s': duplicate column(s) %s — keeping the first of "
                "each for observation.", dataset, dupes,
            )
            df = df.loc[:, ~df.columns.duplicated()]

        alerts: list[dict] = []

        # One history read per observe() for every detector that needs the
        # prior run(s): volume averages the last few, drift and null-spike
        # compare against the most recent (history is newest-first). Reading
        # the file once keeps this off the per-record I/O path.
        history = self._load_history(dataset, n=5)
        previous = history[0] if history else None

        # Per-column null rate: computed once here, consumed by both the
        # null-spike detector and the persisted column_stats below.
        null_rates = {
            col: round(float(df[col].isna().mean()), 6) for col in df.columns
        }

        freshness = self._check_freshness(df, timestamp_col)
        if freshness:
            alerts.append(freshness)

        volume_alert = self._check_volume(df, history)
        if volume_alert:
            alerts.append(volume_alert)

        drift_alerts = self._check_drift(df, previous)
        alerts.extend(drift_alerts)

        null_alerts = self._check_null_spikes(df, previous, null_rates)
        alerts.extend(null_alerts)

        dup_alerts, duplicate_key_rate = self._check_duplicate_keys(df, previous)
        alerts.extend(dup_alerts)

        report = {
            "dataset": dataset,
            "row_count": len(df),
            "column_count": len(df.columns),
            "alerts": alerts,
            "alert_count": len(alerts),
            "observed_utc": datetime.now(timezone.utc).isoformat(),
        }
        if duplicate_key_rate is not None:
            # Persisted so next run can detect a *rising* duplicate rate.
            report["duplicate_key_rate"] = duplicate_key_rate

        # Compute column stats here so _save_observation stays I/O-only.
        # null_rate is tracked for EVERY column (it drives null-spike
        # detection on the next run); mean/std only for numeric columns
        # (they drive drift). Non-numeric columns carry null_rate alone.
        numeric_cols = set(df.select_dtypes(include="number").columns)
        column_stats = []
        for col in df.columns:
            entry = {
                "name": col,
                "null_rate": null_rates[col],
            }
            non_null = df[col].dropna()
            if col in numeric_cols and not non_null.empty:
                entry["mean"] = round(float(non_null.mean()), 6)
                entry["std"] = (
                    round(float(non_null.std()), 6) if len(non_null) > 1 else 0.0
                )
            column_stats.append(entry)
        report["column_stats"] = column_stats

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

    def export_metrics(self, metrics_path, summary_path=None) -> dict:
        """Export the latest per-dataset observations as monitoring output.

        Reads the persisted observation history (end-of-run, off the
        per-record path) and writes a Prometheus textfile for node_exporter;
        optionally a run-summary JSON. Returns the run summary dict.
        """
        from pipeline.monitoring.metrics_exporter import DataQualityMetricsExporter

        exporter = DataQualityMetricsExporter(dry_run=self.dry_run)
        reports = exporter.latest_reports_from_history(self)
        exporter.write_textfile(metrics_path, reports)
        if summary_path is not None:
            exporter.write_summary_json(summary_path, reports)
        return exporter.summarize(reports)

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

    def _check_volume(self, df: "pd.DataFrame", history: list[dict]) -> dict | None:
        """Check for abnormal row count changes vs historical baseline."""
        if not history:
            return None

        # Tolerate old/hand-edited records that predate row_count, the way
        # drift and null-spike tolerate records without column_stats.
        historical_counts = [h["row_count"] for h in history if "row_count" in h]
        if not historical_counts:
            return None
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

    def _check_drift(self, df: "pd.DataFrame", previous: dict | None) -> list[dict]:
        """Detect distribution drift on numeric columns vs last observation."""
        if not previous or "column_stats" not in previous:
            return []

        prev_stats = {s["name"]: s for s in previous.get("column_stats", [])}
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

    def _check_null_spikes(
        self,
        df: "pd.DataFrame",
        previous: dict | None,
        null_rates: dict[str, float],
    ) -> list[dict]:
        """Detect spikes in per-column null rate vs the last observation.

        This is the degraded-but-valid failure the other checks miss: a
        field going silently mostly-null passes schema validation (nulls
        are usually allowed), passes row-count reconciliation (the rows are
        all present), and passes drift (null cells don't move the mean). It
        also gets averaged away in the aggregate completeness score.

        ``null_rates`` is the current per-column null rate, computed once by
        the caller and shared with the persisted column_stats.
        """
        fields = self.critical_fields or list(df.columns)

        prev_rates: dict[str, float] = {}
        if previous and "column_stats" in previous:
            prev_rates = {
                stat["name"]: stat["null_rate"]
                for stat in previous["column_stats"]
                if "null_rate" in stat
            }

        alerts = []
        for col in fields:
            if col not in df.columns:
                # A declared-critical field that vanished is itself a problem.
                if col in self.critical_fields:
                    alerts.append({
                        "type": "NULL_FLOOR",
                        "severity": "HIGH",
                        "message": f"Critical field '{col}' is absent from the data",
                        "column": col,
                        "curr_null_rate": 1.0,
                    })
                continue

            curr_rate = null_rates[col]
            prev_rate = prev_rates.get(col)

            # Baseline spike: null rate jumped vs the previous run. A critical
            # field that both spiked AND breached the floor is HIGH — the
            # single spike alert must not under-report it to MEDIUM.
            if prev_rate is not None and curr_rate - prev_rate > self.null_spike_threshold:
                jump = curr_rate - prev_rate
                spike_is_high = jump > self.null_spike_threshold * 2 or (
                    col in self.critical_fields and curr_rate > self.null_absolute_floor
                )
                alerts.append({
                    "type": "NULL_SPIKE",
                    "severity": "HIGH" if spike_is_high else "MEDIUM",
                    "message": (
                        f"Null rate for '{col}' jumped from {prev_rate:.0%} "
                        f"to {curr_rate:.0%} (+{jump:.0%})"
                    ),
                    "column": col,
                    "prev_null_rate": round(prev_rate, 4),
                    "curr_null_rate": round(curr_rate, 4),
                    "jump": round(jump, 4),
                })
                continue

            # Absolute floor: a declared-critical field that is mostly null
            # even on the first run, where there is no baseline to spike against.
            if col in self.critical_fields and curr_rate > self.null_absolute_floor:
                alerts.append({
                    "type": "NULL_FLOOR",
                    "severity": "HIGH",
                    "message": (
                        f"Critical field '{col}' is {curr_rate:.0%} null "
                        f"(floor: {self.null_absolute_floor:.0%})"
                    ),
                    "column": col,
                    "curr_null_rate": round(curr_rate, 4),
                    "floor": self.null_absolute_floor,
                })

        return alerts

    def _check_duplicate_keys(
        self, df: "pd.DataFrame", previous: dict | None,
    ) -> tuple[list[dict], float | None]:
        """Detect duplicate business keys — the failure row counts can't see.

        A declared business/natural key must be unique. A source that resends
        events with the same key but a *different* timestamp produces rows that
        are NOT full-row duplicates and do NOT change the source row count, so
        full-row dedup, the uniqueness quality score, and source↔dest
        reconciliation all pass while wrong data flows to gold. This checks the
        key directly. Returns (alerts, duplicate_key_rate) — the rate is
        persisted so the next run can detect a *rising* duplicate rate (a
        source that just started duplicating).
        """
        if not self.business_keys:
            return [], None

        missing = [k for k in self.business_keys if k not in df.columns]
        if missing:
            return [{
                "type": "DUPLICATE_KEYS",
                "severity": "HIGH",
                "message": f"Business key column(s) {missing} absent from the data",
                "business_keys": self.business_keys,
                "missing": missing,
            }], None

        distinct = len(df.drop_duplicates(subset=self.business_keys))
        dup_count = len(df) - distinct
        dup_rate = round(dup_count / len(df), 6) if len(df) else 0.0
        prev_rate = previous.get("duplicate_key_rate") if previous else None

        if dup_count == 0:
            return [], dup_rate

        # A business key is duplicated at all — a real violation. Escalate to
        # HIGH when the rate also rose sharply vs the last run (a source that
        # *started* duplicating), so a slow-creeping break still stands out.
        jumped = prev_rate is not None and dup_rate - prev_rate > self.duplicate_key_spike
        message = (
            f"{dup_count} duplicate row(s) on business key {self.business_keys} "
            f"({dup_rate:.1%} of rows) — same key, likely differing timestamps"
        )
        if jumped:
            message += f"; duplicate rate rose from {prev_rate:.1%} to {dup_rate:.1%}"
        return [{
            "type": "DUPLICATE_KEYS",
            "severity": "HIGH" if (jumped or dup_rate > 0.05) else "MEDIUM",
            "message": message,
            "business_keys": self.business_keys,
            "duplicate_count": dup_count,
            "duplicate_rate": dup_rate,
            "prev_duplicate_rate": prev_rate,
        }], dup_rate

    def _save_observation(self, report: dict) -> None:
        """Persist observation to JSONL history. Skipped when dry_run."""
        if self.dry_run:
            logger.info("[OBSERVE] dry_run — would save observation for '%s'",
                        report.get("dataset", ""))
            return
        with self._lock:
            with open(self.history_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(report, default=str) + "\n")

    def _load_history(self, dataset: str, n: int = 5) -> list[dict]:
        """Load last n observations for a dataset."""
        return read_jsonl_tail(
            self.history_file,
            count=n,
            filter_fn=lambda observation_record: observation_record.get("dataset") == dataset,
        )

    def freshness_report(self, datasets: list[str] | None = None) -> list[dict]:
        """Generate a freshness report across all observed datasets."""
        all_records = read_jsonl_tail(self.history_file, count=500)

        latest: dict[str, dict] = {}
        for observation_record in all_records:
            dataset_name = observation_record.get("dataset", "")
            if dataset_name and dataset_name not in latest:
                if datasets is None or dataset_name in datasets:
                    latest[dataset_name] = observation_record

        return [
            {
                "dataset": dataset_name,
                "last_observed": observation_record["observed_utc"],
                "row_count": observation_record["row_count"],
                "alert_count": observation_record["alert_count"],
            }
            for dataset_name, observation_record in sorted(latest.items())
        ]
