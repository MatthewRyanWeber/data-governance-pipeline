"""
Data-quality metrics exporter.

Turns DataObserver observation reports into machine-readable monitoring output:
the Prometheus text-exposition format (written to a ``.prom`` textfile for the
node_exporter textfile collector — the standard way to ship batch-job metrics)
and a compact run-summary JSON. Both are dependency-free: the Prometheus text
format is generated directly, so no prometheus_client install is required and
the optional-deps-blocked CI job still exercises it.

The exporter reads the observations the DataObserver already persisted, so it
runs once at end-of-run — never on the per-record path.

Layer 2 — imports from Layer 0 (helpers) and reads DataObserver output.

Revision history
────────────────
1.0   2026-06-18   Initial release: Prometheus text exposition + run summary,
                   driven from observability history.
"""

import json
import logging
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.helpers import read_jsonl_tail

if TYPE_CHECKING:
    from pipeline.monitoring.observability import DataObserver

logger = logging.getLogger(__name__)

_METRIC_PREFIX = "dgp"


def _escape_label(value: str) -> str:
    """Escape a Prometheus label value (backslash, quote, newline)."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _format_number(value) -> str:
    """Render a metric value: ints plain, floats via repr (no sci-notation surprises)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


class DataQualityMetricsExporter:
    """
    Render DataObserver reports as Prometheus metrics and a run-summary JSON.

    Quick-start
    -----------
        from pipeline.monitoring.metrics_exporter import DataQualityMetricsExporter
        exporter = DataQualityMetricsExporter()
        text = exporter.render_prometheus(reports)        # exposition string
        exporter.write_textfile("dgp.prom", reports)      # for node_exporter
        summary = exporter.summarize(reports)             # dict / JSON
    """

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    # ── Prometheus text exposition ───────────────────────────────────────

    def render_prometheus(self, reports: list[dict]) -> str:
        """Render observation reports as Prometheus text-exposition format.

        One gauge family per quality signal, labelled by dataset (and column or
        alert type where relevant). HELP/TYPE are emitted once per family.
        """
        # name -> (help, type, [ (labels_dict, value) ])
        families: dict[str, tuple[str, str, list]] = {
            "observed_rows": ("Rows in the most recent observed run.", "gauge", []),
            "observed_columns": ("Columns in the most recent observed run.", "gauge", []),
            "alerts": ("Total data-quality alerts in the most recent run.", "gauge", []),
            "alerts_by_type": ("Data-quality alerts by type.", "gauge", []),
            "duplicate_key_rate": ("Business-key duplicate rate (0-1).", "gauge", []),
            "column_null_rate": ("Per-column null rate (0-1).", "gauge", []),
        }

        for report in reports:
            dataset = report.get("dataset", "")
            labels = {"dataset": dataset}
            families["observed_rows"][2].append((labels, report.get("row_count", 0)))
            families["observed_columns"][2].append((labels, report.get("column_count", 0)))
            families["alerts"][2].append((labels, report.get("alert_count", 0)))

            # Count alerts per type so a dashboard can break them out.
            type_counts: dict[str, int] = {}
            for alert in report.get("alerts", []):
                alert_type = str(alert.get("type", "UNKNOWN"))
                type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            for alert_type, count in type_counts.items():
                families["alerts_by_type"][2].append(
                    ({"dataset": dataset, "type": alert_type}, count))

            if report.get("duplicate_key_rate") is not None:
                families["duplicate_key_rate"][2].append(
                    (labels, report["duplicate_key_rate"]))

            for stat in report.get("column_stats", []):
                if "null_rate" in stat:
                    families["column_null_rate"][2].append(
                        ({"dataset": dataset, "column": str(stat["name"])},
                         stat["null_rate"]))

        lines: list[str] = []
        for name, (help_text, metric_type, series) in families.items():
            if not series:
                continue
            metric = f"{_METRIC_PREFIX}_{name}"
            lines.append(f"# HELP {metric} {help_text}")
            lines.append(f"# TYPE {metric} {metric_type}")
            for label_dict, value in series:
                label_str = ",".join(
                    f'{key}="{_escape_label(val)}"' for key, val in label_dict.items())
                lines.append(f"{metric}{{{label_str}}} {_format_number(value)}")
        return "\n".join(lines) + "\n" if lines else ""

    def write_textfile(self, path: str | Path, reports: list[dict]) -> Path:
        """Atomically write the Prometheus exposition to a ``.prom`` file.

        Atomic temp-then-rename so node_exporter never scrapes a half-written
        file. Honors dry_run (logs, writes nothing).
        """
        target = Path(path)
        content = self.render_prometheus(reports)
        if self.dry_run:
            logger.info("[METRICS] DRY RUN — would write %d bytes to %s",
                        len(content), target)
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
        try:
            with open(tmp_fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            Path(tmp_path).replace(target)
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise
        logger.info("[METRICS] Wrote %d data-quality metric line(s) to %s",
                    content.count("\n"), target)
        return target

    # ── Run-summary JSON ─────────────────────────────────────────────────

    def summarize(self, reports: list[dict]) -> dict:
        """Aggregate reports into a compact run summary."""
        alert_type_totals: dict[str, int] = {}
        datasets_with_alerts = []
        total_rows = 0
        for report in reports:
            total_rows += int(report.get("row_count", 0))
            if report.get("alert_count", 0):
                datasets_with_alerts.append(report.get("dataset", ""))
            for alert in report.get("alerts", []):
                alert_type = str(alert.get("type", "UNKNOWN"))
                alert_type_totals[alert_type] = alert_type_totals.get(alert_type, 0) + 1
        return {
            "datasets_observed": len(reports),
            "total_rows": total_rows,
            "total_alerts": sum(alert_type_totals.values()),
            "alerts_by_type": alert_type_totals,
            "datasets_with_alerts": sorted(set(datasets_with_alerts)),
        }

    def write_summary_json(self, path: str | Path, reports: list[dict]) -> Path:
        """Write the run summary as indented JSON (honors dry_run)."""
        target = Path(path)
        summary = self.summarize(reports)
        if self.dry_run:
            logger.info("[METRICS] DRY RUN — would write run summary to %s", target)
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return target

    # ── Convenience: drive from a DataObserver's history ─────────────────

    def latest_reports_from_history(self, observer: "DataObserver") -> list[dict]:
        """Read the most recent observation per dataset from an observer's history.

        History is newest-first, so the first time a dataset is seen is its
        latest observation.
        """
        history_file = observer.history_file
        if not Path(history_file).exists():
            return []
        records = read_jsonl_tail(Path(history_file), count=500)
        latest: dict[str, dict] = {}
        for record in records:
            dataset = record.get("dataset", "")
            if dataset not in latest:
                latest[dataset] = record
        return list(latest.values())
