"""
Pipeline throughput and per-stage timing metrics.

Tracks total duration, per-stage durations, rows/sec, error rates.

Layer 3 — imports from Layer 1 (governance_logger).
"""

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Collects pipeline throughput and timing metrics.

    Quick-start
    -----------
        from pipeline.monitoring import MetricsCollector
        mc = MetricsCollector(gov)
        mc.start_stage("extract")
        # ... extract ...
        mc.end_stage("extract", rows=len(df))
        mc.write_report()
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        self._run_start = time.monotonic()
        self._stages: dict[str, dict] = {}
        self._current: str | None = None
        self._stage_start: float = 0.0
        self.rows_in: int = 0
        self.rows_out: int = 0

    def record_extract(self, rows: int, elapsed: float) -> None:
        self.start_stage("extract")
        self._stages["extract"]["rows"] = rows
        self._stages["extract"]["elapsed"] = elapsed
        self.gov.stage_metrics("extract", rows, elapsed)

    def record_transform(self, rows: int, elapsed: float) -> None:
        self.start_stage("transform")
        self._stages["transform"]["rows"] = rows
        self._stages["transform"]["elapsed"] = elapsed
        self.gov.stage_metrics("transform", rows, elapsed)

    def record_load(self, rows: int, elapsed: float) -> None:
        self.start_stage("load")
        self._stages["load"]["rows"] = rows
        self._stages["load"]["elapsed"] = elapsed
        self.gov.stage_metrics("load", rows, elapsed)

    def record_validate(self, rows_total: int, rows_failed: int, elapsed: float) -> None:
        self.start_stage("validate")
        self._stages["validate"]["rows"] = rows_total
        self._stages["validate"]["elapsed"] = elapsed
        self.gov.stage_metrics("validate", rows_total, elapsed)

    def record(self, metric: str, value, stage: str | None = None) -> None:
        _stage = stage or "custom"
        if _stage not in self._stages:
            self._stages[_stage] = {}
        self._stages[_stage][metric] = value
        self.gov.transformation_applied("METRIC_RECORDED", {
            "stage": _stage, "metric": metric, "value": value,
        })

    def report(self) -> dict:
        self.write_report()
        return dict(self._stages)

    def start_stage(self, name: str) -> None:
        self._current = name
        self._stage_start = time.monotonic()
        self._stages[name] = {"start": self._stage_start, "duration_sec": None, "rows": 0}

    def end_stage(self, name: str, rows: int = 0) -> float:
        duration = time.monotonic() - self._stages.get(name, {}).get("start", time.monotonic())
        self._stages[name]["duration_sec"] = round(duration, 3)
        self._stages[name]["rows"] = rows
        self._stages[name]["rows_per_sec"] = round(rows / duration, 1) if duration > 0 else 0
        self._current = None
        return duration

    def write_report(self, dlq_rows: int = 0) -> None:
        total_duration = time.monotonic() - self._run_start
        total_rps = round(self.rows_out / total_duration, 1) if total_duration > 0 else 0
        error_rate = round(dlq_rows / max(self.rows_in, 1), 4)

        metrics = {
            "total_duration_sec": round(total_duration, 2),
            "rows_input": self.rows_in,
            "rows_output": self.rows_out,
            "rows_dlq": dlq_rows,
            "error_rate": error_rate,
            "overall_rows_per_sec": total_rps,
            "stages": self._stages,
        }
        self.gov.metrics_recorded(metrics)
        self.gov.write_metrics_report(metrics)
        logger.info(
            "[METRICS] %.1fs | %s rows | %.0f rows/s | DLQ=%d | error_rate=%.1f%%",
            total_duration, f"{self.rows_out:,}", total_rps, dlq_rows, error_rate * 100,
        )
