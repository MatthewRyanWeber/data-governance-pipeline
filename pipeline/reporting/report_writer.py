"""
Structured JSON report writer for governance data.

Writes PII, validation, profiling, metrics, classification, and cross-border
transfer reports as JSON files.  Extracted from GovernanceLogger to keep the
logger focused on event capture and the writer focused on report generation.

Layer 3 — imports from pipeline.governance_logger (Layer 1).

Revision history
────────────────
1.0   2026-06-08   Extracted 7 report-writing methods from GovernanceLogger.
"""

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class ReportWriter:
    """
    Writes structured JSON governance reports using data collected by a
    GovernanceLogger instance.

    All report methods are read-only consumers of GovernanceLogger state —
    they never mutate the logger's data, only read it.  The writer respects
    dry_run mode: when active, reports are logged but not written to disk.

    Quick-start
    -----------
        from pipeline.governance_logger import GovernanceLogger
        from pipeline.reporting import ReportWriter

        gov    = GovernanceLogger("customers.csv")
        writer = ReportWriter(gov)
        writer.write_pii_report()
        writer.summary()
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    # ── Convenience accessors ───────────────────────────────────────────

    @property
    def dry_run(self) -> bool:
        return self.gov.dry_run

    @property
    def _logger(self) -> logging.Logger:
        return self.gov.logger

    # ── Report writers ──────────────────────────────────────────────────

    def write_pii_report(self) -> None:
        """Write PII findings to JSON (GDPR Art. 4, 9, 17, 25, 32; CCPA §1798)."""
        gov = self.gov
        report = {
            "pipeline_id": gov.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "regulation_references": {
                "GDPR": "Articles 4,9,17,25,32",
                "CCPA": "§1798.100,§1798.140,§1798.150",
            },
            "pii_findings": gov.pii_findings,
            "summary": {
                "total_pii_fields": len(gov.pii_findings),
                "special_category_fields": sum(
                    1 for f in gov.pii_findings if f.get("special_category")
                ),
            },
        }
        if not self.dry_run:
            with open(gov.pii_report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self._logger.info("PII report          → %s", gov.pii_report_file)

    def write_validation_report(self) -> None:
        """Write validation expectation results to JSON."""
        gov = self.gov
        report = {
            "pipeline_id": gov.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "expectation_results": gov.validation_results,
            "summary": {
                "total": len(gov.validation_results),
                "passed": sum(1 for r in gov.validation_results if r["success"]),
                "failed": sum(1 for r in gov.validation_results if not r["success"]),
                "dlq_rows": gov.dlq_rows_total,
            },
        }
        if not self.dry_run:
            with open(gov.validation_rpt_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self._logger.info("Validation report   → %s", gov.validation_rpt_file)

    def write_profile_report(self, profile: dict) -> None:
        """Write data profiling summary to JSON."""
        gov = self.gov
        profile["pipeline_id"] = gov.run_context.pipeline_id
        profile["generated_utc"] = datetime.now(timezone.utc).isoformat()
        if not self.dry_run:
            with open(gov.profile_rpt_file, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2, default=str)
        self._logger.info("Profile report      → %s", gov.profile_rpt_file)

    def write_metrics_report(self, metrics: dict) -> None:
        """Write pipeline metrics to JSON."""
        gov = self.gov
        metrics["pipeline_id"] = gov.run_context.pipeline_id
        metrics["generated_utc"] = datetime.now(timezone.utc).isoformat()
        if not self.dry_run:
            with open(gov.metrics_rpt_file, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2)
        self._logger.info("Metrics report      → %s", gov.metrics_rpt_file)

    def write_classification_report(self) -> None:
        """Write data classification tags to JSON."""
        gov = self.gov
        report = {
            "pipeline_id": gov.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "classification_events": gov.classification_tags,
        }
        if not self.dry_run:
            with open(gov.classification_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self._logger.info("Classification rpt  → %s", gov.classification_file)

    def write_transfer_log(self) -> None:
        """Write GDPR Chapter V cross-border transfer log to JSON."""
        gov = self.gov
        report = {
            "pipeline_id": gov.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "gdpr_chapter_v_transfers": gov.transfer_events,
        }
        if not self.dry_run:
            with open(gov.transfer_log_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self._logger.info("Transfer log        → %s", gov.transfer_log_file)

    # ── Summary ─────────────────────────────────────────────────────────

    def pipeline_summary(self) -> None:
        """Alias for summary()."""
        self.summary()

    def summary(self) -> None:
        """Log a human-readable governance summary to the pipeline logger."""
        gov = self.gov
        self._logger.info("=" * 64)
        self._logger.info("  GOVERNANCE SUMMARY  v4.0")
        self._logger.info("=" * 64)
        self._logger.info("  Pipeline ID        : %s", gov.run_context.pipeline_id)
        self._logger.info("  Run started        : %s", gov.run_context.run_start)
        self._logger.info("  Audit ledger       : %s", gov.ledger_file)
        self._logger.info("  PII report         : %s", gov.pii_report_file)
        self._logger.info("  Validation report  : %s", gov.validation_rpt_file)
        self._logger.info("  Profile report     : %s", gov.profile_rpt_file)
        self._logger.info("  Metrics report     : %s", gov.metrics_rpt_file)
        self._logger.info("  Classification rpt : %s", gov.classification_file)
        self._logger.info("  Transfer log       : %s", gov.transfer_log_file)
        self._logger.info("  Dead letter queue  : %s  (%s rows)", gov.dlq_file, gov.dlq_rows_total)
        self._logger.info("  Log file           : %s", gov.log_file)
        self._logger.info("  Total events       : %s", len(gov.ledger_entries))
        self._logger.info("=" * 64)
