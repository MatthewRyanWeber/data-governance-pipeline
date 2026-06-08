"""
Central audit and governance logging facility.

Chained-hash tamper detection (GDPR Art. 32): each JSONL ledger event
includes a SHA-256 hash of the previous event, creating a cryptographic
chain that makes any historical modification detectable.

Layer 1 — imports from Layer 0 only (constants, helpers).
"""

import getpass
import hashlib
import json
import logging
import platform
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.constants import DEFAULT_RUN_CONTEXT, RunContext
from pipeline.helpers import file_hash

logger = logging.getLogger(__name__)

_REGION_PREFIX_TO_COUNTRY: dict[str, str] = {
    "us": "US", "eu": "EU", "ap": "SG", "ca": "CA",
    "sa": "BR", "me": "AE", "a": "ZA", "au": "AU",
}


def _infer_cross_border_transfer(db: str, name: str) -> dict | None:
    """Infer a GDPR Chapter V cross-border transfer from cloud provider endpoint format."""
    if db == "snowflake" and "/" in name:
        account = name.split("/")[0]
        parts = account.split(".")
        if len(parts) >= 2:
            region = parts[1]
            dest_cc = _REGION_PREFIX_TO_COUNTRY.get(region.split("-")[0].lower(), "US")
            return dict(
                source_country="US", dest_country=dest_cc,
                transfer_type="SNOWFLAKE_CLOUD_REGION", safeguard="SCC",
            )

    elif db == "redshift" and "/" in name:
        host = name.split("/")[0]
        for part in host.split("."):
            pfx = part.split("-")[0].lower()
            if pfx in _REGION_PREFIX_TO_COUNTRY:
                return dict(
                    source_country="US", dest_country=_REGION_PREFIX_TO_COUNTRY[pfx],
                    transfer_type="REDSHIFT_CLOUD_REGION", safeguard="SCC",
                )

    elif db == "bigquery" and "@" in name:
        location = name.split("@")[-1].upper()
        if "EU" in location or "EUROPE" in location:
            return dict(
                source_country="EU", dest_country="EU",
                transfer_type="INTRA_EU",
                safeguard="EU/EEA intra-zone — no restrictions",
            )
        bq_region_map = {"US": "US", "ASIA": "SG", "AUSTRALIA-SOUTHEAST1": "AU"}
        return dict(
            source_country="US", dest_country=bq_region_map.get(location, "US"),
            transfer_type="BIGQUERY_REGION", safeguard="SCC",
        )

    return None


class GovernanceLogger:
    """
    Central audit and governance logging facility.

    Writes structured JSONL audit events with chained-hash tamper detection,
    30+ event-type wrappers, and 7 report writers covering PII, validation,
    profiling, metrics, classification, and cross-border transfers.

    Quick-start
    -----------
        from pipeline.governance_logger import GovernanceLogger
        gov = GovernanceLogger("customers.csv")
        gov.pipeline_start({"source": "customers.csv"})
    """

    def __init__(
        self,
        source_name: str = "pipeline",
        log_dir: str | None = None,
        run_context: RunContext | None = None,
        dry_run: bool = False,
    ) -> None:
        self.run_context = run_context or DEFAULT_RUN_CONTEXT
        self.dry_run = dry_run

        stem = Path(source_name).stem if source_name else "pipeline"
        for ch in ('/', '\\', ':', '*', '?', '"', '<', '>', '|'):
            stem = stem.replace(ch, '_')
        stem = stem.strip() or "pipeline"

        self.source_name = stem
        self.log_dir = (Path(log_dir) if log_dir else Path(f"{stem} LOGS")).resolve()
        self.log_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.log_file = self.log_dir / f"pipeline_{ts}.log"
        self.ledger_file = self.log_dir / f"audit_ledger_{ts}.jsonl"
        self.pii_report_file = self.log_dir / f"pii_report_{ts}.json"
        self.validation_rpt_file = self.log_dir / f"validation_report_{ts}.json"
        self.profile_rpt_file = self.log_dir / f"profile_report_{ts}.json"
        self.dlq_file = self.log_dir / f"dlq_{ts}.csv"
        self.metrics_rpt_file = self.log_dir / f"metrics_report_{ts}.json"
        self.classification_file = self.log_dir / f"classification_report_{ts}.json"
        self.transfer_log_file = self.log_dir / f"transfer_log_{ts}.json"

        self.cost_log_file = self.log_dir / "cost_history.jsonl"
        self.quality_log_file = self.log_dir / "quality_history.jsonl"

        self.snapshot_dir = self.log_dir / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("DataPipeline")

        self.pii_findings: list[dict] = []
        self.ledger_entries: list[dict] = []
        self.validation_results: list[dict] = []
        self.classification_tags: list[dict] = []
        self.transfer_events: list[dict] = []
        self.dlq_rows_total: int = 0
        self._prev_hash: str = "GENESIS"
        self._event_lock = threading.RLock()

    # ── Core event writer with chained hash ──────────────────────────────

    def _event(
        self,
        category: str,
        action: str,
        detail: dict | None = None,
        level: str = "INFO",
    ) -> None:
        """Write a structured audit event to the JSONL ledger with chained hash."""
        base_entry = {
            "pipeline_id": self.run_context.pipeline_id,
            "event_id": str(uuid.uuid4()),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "os_user": getpass.getuser(),
            "category": category,
            "action": action,
            "detail": detail or {},
        }

        with self._event_lock:
            base_entry["prev_hash"] = self._prev_hash
            raw_json = json.dumps(base_entry, sort_keys=True)
            self._prev_hash = hashlib.sha256(raw_json.encode()).hexdigest()
            base_entry["self_hash"] = self._prev_hash

            if not self.dry_run:
                with open(self.ledger_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(base_entry, sort_keys=True) + "\n")

            self.ledger_entries.append(base_entry)

        msg = f"[{category}] {action}"
        if detail:
            msg += f" | {json.dumps(detail)}"
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def verify_ledger(self) -> bool:
        """
        Walk the JSONL ledger and verify the chained-hash integrity.

        Returns True if the entire ledger is intact; False if tampering detected.
        """
        if not self.ledger_file.exists():
            return True

        with open(self.ledger_file, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            return True

        prev_hash = "GENESIS"
        for i, line in enumerate(lines):
            event = json.loads(line)
            stored_prev = event.get("prev_hash", "")
            if stored_prev != prev_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Event #%s (id=%s) "
                    "expected prev_hash=%r but found %r",
                    i + 1, event.get("event_id"), prev_hash, stored_prev,
                )
                return False

            entry_for_hash = {k: v for k, v in event.items() if k != "self_hash"}
            computed_hash = hashlib.sha256(
                json.dumps(entry_for_hash, sort_keys=True).encode()
            ).hexdigest()
            stored_self = event.get("self_hash")
            if stored_self and stored_self != computed_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Event #%s (id=%s) "
                    "self_hash mismatch — event content has been altered",
                    i + 1, event.get("event_id"),
                )
                return False
            prev_hash = computed_hash

        self.logger.info(
            "[TAMPER CHECK] Ledger integrity verified — %s events OK.", len(lines)
        )
        return True

    # ── Lifecycle events ─────────────────────────────────────────────────

    def pipeline_start(self, metadata: dict) -> None:
        self._event("LIFECYCLE", "PIPELINE_STARTED", metadata)

    def pipeline_end(self, summary: dict) -> None:
        self._event("LIFECYCLE", "PIPELINE_COMPLETED", summary)

    def pipeline_complete(self, summary: dict) -> None:
        self.pipeline_end(summary)

    def transformation_applied(self, name: str, detail: dict | None = None) -> None:
        self._event("TRANSFORMATION", name, detail)

    # ── Lineage events ───────────────────────────────────────────────────

    def source_registered(self, path: str, file_type: str, rows: int, cols: int) -> None:
        try:
            sha = file_hash(path)
        except (FileNotFoundError, OSError):
            sha = "N/A"
        self._event("LINEAGE", "SOURCE_REGISTERED", {
            "source_path": path, "file_type": file_type,
            "row_count": rows, "col_count": cols, "sha256": sha,
        })

    def destination_registered(self, db: str, name: str, table: str) -> None:
        self._event("LINEAGE", "DESTINATION_REGISTERED", {
            "db_type": db, "db_name": name, "table_or_collection": table,
        })
        transfer = _infer_cross_border_transfer(db, name)
        if transfer:
            self.transfer_logged(**transfer)

    def load_complete(self, rows: int, table: str) -> None:
        self._event("LINEAGE", "LOAD_COMPLETE", {
            "rows_written": rows, "destination_table": table,
        })

    # ── Privacy events ───────────────────────────────────────────────────

    def pii_detected(self, findings: list[dict]) -> None:
        self.pii_findings.extend(findings)
        self._event("PRIVACY", "PII_DETECTED", {
            "findings_count": len(findings),
            "fields": [f["field"] for f in findings],
        }, level="WARNING")

    def pii_action(self, field: str, action: str) -> None:
        self._event("PRIVACY", f"PII_{action}", {"field": field})

    def data_minimization(self, orig: list, retained: list, dropped: list) -> None:
        self._event("PRIVACY", "DATA_MINIMIZATION_APPLIED", {
            "original_column_count": len(orig),
            "retained_column_count": len(retained),
            "dropped_columns": dropped,
        })

    def consent_recorded(self, purpose: str, basis: str, confirmed: bool) -> None:
        self._event("CONSENT", "LAWFUL_BASIS_RECORDED", {
            "processing_purpose": purpose, "lawful_basis": basis,
            "user_confirmed": confirmed,
        })

    def retention_policy(self, policy: str, days: int | None) -> None:
        self._event("RETENTION", "POLICY_RECORDED", {
            "policy": policy, "retention_days": days,
        })

    # ── Validation events ────────────────────────────────────────────────

    def validation_result(self, suite: str, ok: bool, passed: int, failed: int, total: int) -> None:
        self._event("VALIDATION", "SUITE_RESULT", {
            "suite_name": suite, "overall_success": ok,
            "expectations_passed": passed, "expectations_failed": failed,
            "expectations_total": total,
        }, level="INFO" if ok else "WARNING")

    def validation_expectation(self, exp: str, col: str | None,
                               ok: bool, unexpected: int = 0) -> None:
        self.validation_results.append({
            "expectation": exp, "column": col,
            "success": ok, "unexpected_count": unexpected,
        })
        self._event("VALIDATION", "EXPECTATION_RESULT", {
            "expectation": exp, "column": col,
            "success": ok, "unexpected_count": unexpected,
        }, level="INFO" if ok else "WARNING")

    def profile_recorded(self, summary: dict) -> None:
        self._event("PROFILING", "PROFILE_GENERATED", summary)

    def dlq_written(self, count: int, reason: str) -> None:
        self.dlq_rows_total += count
        self._event("DLQ", "ROWS_REJECTED", {
            "rejected_row_count": count, "reason": reason,
            "dlq_file": str(self.dlq_file),
        }, level="WARNING")

    def watermark_event(self, action: str, col: str, val: Any, filtered: int = 0) -> None:
        self._event("INCREMENTAL", f"WATERMARK_{action}", {
            "watermark_column": col, "watermark_value": str(val),
            "rows_filtered": filtered,
        })

    def retry_attempt(self, attempt: int, max_attempts: int, wait: float, exc: Exception) -> None:
        self._event("RETRY", "RETRY_ATTEMPT", {
            "attempt": attempt, "max_attempts": max_attempts,
            "wait_seconds": wait, "exception": str(exc),
        }, level="WARNING")

    def notification_sent(self, channel: str, status: str, detail: str = "") -> None:
        self._event("NOTIFICATION", f"{channel.upper()}_{status}", {"detail": detail})

    def error(self, msg: str, exc: Exception | None = None) -> None:
        self._event("ERROR", msg,
                    {"exception": str(exc)} if exc else None, level="ERROR")

    # ── v3.0 event wrappers ──────────────────────────────────────────────

    def sla_event(self, status: str, elapsed_sec: float, threshold_sec: float) -> None:
        level = "WARNING" if status in ("BREACH", "WARNING") else "INFO"
        self._event("SLA", f"SLA_{status}", {
            "elapsed_seconds": round(elapsed_sec, 1),
            "threshold_seconds": threshold_sec,
            "over_by_seconds": max(0, round(elapsed_sec - threshold_sec, 1)),
        }, level=level)

    def metrics_recorded(self, metrics: dict) -> None:
        self._event("METRICS", "METRICS_RECORDED", metrics)

    def encryption_applied(self, field: str, algorithm: str) -> None:
        self._event("ENCRYPTION", "COLUMN_ENCRYPTED", {
            "field": field, "algorithm": algorithm,
        })

    def enrichment_applied(self, join_col: str, lookup_table: str,
                           rows_matched: int, rows_total: int) -> None:
        self._event("ENRICHMENT", "LOOKUP_JOIN_APPLIED", {
            "join_column": join_col,
            "lookup_table": lookup_table,
            "rows_matched": rows_matched,
            "rows_total": rows_total,
            "match_rate": round(rows_matched / rows_total, 4) if rows_total else 0,
        })

    def referential_integrity_checked(self, fk_col: str, ref_table: str,
                                      valid: int, invalid: int) -> None:
        level = "INFO" if invalid == 0 else "WARNING"
        self._event("REFERENTIAL", "FK_CHECK_RESULT", {
            "foreign_key_column": fk_col,
            "reference_table": ref_table,
            "valid_rows": valid,
            "invalid_rows": invalid,
        }, level=level)

    def erasure_executed(self, subject_id: str, table: str,
                         rows_deleted: int, method: str = "DELETE") -> None:
        # GDPR Art. 17 — hash subject ID before logging (never store raw PII in audit trail)
        subject_hash = hashlib.sha256(str(subject_id).encode()).hexdigest()[:16]
        self._event("ERASURE", "GDPR_ERASURE_EXECUTED", {
            "subject_id_hash": subject_hash,
            "target_table": table,
            "rows_deleted": rows_deleted,
            "method": method,
            "gdpr_reference": "Article 17 — Right to Erasure",
        }, level="WARNING")

    def classification_tagged(self, level: str, pii_count: int,
                              special_count: int) -> None:
        entry = {
            "classification_level": level, "pii_fields": pii_count,
            "special_category_fields": special_count,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        self.classification_tags.append(entry)
        self._event("CLASSIFICATION", "DATA_CLASSIFIED", entry)

    def transfer_logged(self, source_country: str, dest_country: str,
                        safeguard: str, transfer_type: str) -> None:
        # GDPR Chapter V — cross-border transfer logging
        entry = {
            "source_country": source_country,
            "dest_country": dest_country,
            "safeguard": safeguard,
            "transfer_type": transfer_type,
            "gdpr_reference": "Chapter V — Transfers to Third Countries",
        }
        self.transfer_events.append(entry)
        level = "INFO" if transfer_type in ("INTRA_EU", "DOMESTIC", "ADEQUACY_DECISION") \
                       else "WARNING"
        self._event("TRANSFER", "CROSS_BORDER_TRANSFER_LOGGED", entry, level=level)

    def checkpoint_event(self, action: str, chunk_idx: int, rows: int) -> None:
        self._event("CHECKPOINT", f"CHECKPOINT_{action}", {
            "chunk_index": chunk_idx, "rows_processed": rows,
        })

    def standardisation_applied(self, column: str, rule: str, changed: int) -> None:
        self._event("STANDARDISE", "COLUMN_STANDARDISED", {
            "column": column, "rule": rule, "values_changed": changed,
        })

    def rule_applied(self, rule_name: str, rule_type: str, rows_affected: int) -> None:
        self._event("RULES", "BUSINESS_RULE_APPLIED", {
            "rule_name": rule_name, "rule_type": rule_type,
            "rows_affected": rows_affected,
        })

    # ── Report writers ───────────────────────────────────────────────────

    def write_pii_report(self) -> None:
        report = {
            "pipeline_id": self.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "regulation_references": {
                "GDPR": "Articles 4,9,17,25,32",
                "CCPA": "§1798.100,§1798.140,§1798.150",
            },
            "pii_findings": self.pii_findings,
            "summary": {
                "total_pii_fields": len(self.pii_findings),
                "special_category_fields": sum(
                    1 for f in self.pii_findings if f.get("special_category")
                ),
            },
        }
        if not self.dry_run:
            with open(self.pii_report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self.logger.info("PII report          → %s", self.pii_report_file)

    def write_validation_report(self) -> None:
        report = {
            "pipeline_id": self.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "expectation_results": self.validation_results,
            "summary": {
                "total": len(self.validation_results),
                "passed": sum(1 for r in self.validation_results if r["success"]),
                "failed": sum(1 for r in self.validation_results if not r["success"]),
                "dlq_rows": self.dlq_rows_total,
            },
        }
        if not self.dry_run:
            with open(self.validation_rpt_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self.logger.info("Validation report   → %s", self.validation_rpt_file)

    def write_profile_report(self, profile: dict) -> None:
        profile["pipeline_id"] = self.run_context.pipeline_id
        profile["generated_utc"] = datetime.now(timezone.utc).isoformat()
        if not self.dry_run:
            with open(self.profile_rpt_file, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2, default=str)
        self.logger.info("Profile report      → %s", self.profile_rpt_file)

    def write_metrics_report(self, metrics: dict) -> None:
        metrics["pipeline_id"] = self.run_context.pipeline_id
        metrics["generated_utc"] = datetime.now(timezone.utc).isoformat()
        if not self.dry_run:
            with open(self.metrics_rpt_file, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2)
        self.logger.info("Metrics report      → %s", self.metrics_rpt_file)

    def write_classification_report(self) -> None:
        report = {
            "pipeline_id": self.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "classification_events": self.classification_tags,
        }
        if not self.dry_run:
            with open(self.classification_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self.logger.info("Classification rpt  → %s", self.classification_file)

    def write_transfer_log(self) -> None:
        report = {
            "pipeline_id": self.run_context.pipeline_id,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "gdpr_chapter_v_transfers": self.transfer_events,
        }
        if not self.dry_run:
            with open(self.transfer_log_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        self.logger.info("Transfer log        → %s", self.transfer_log_file)

    def pipeline_summary(self) -> None:
        self.summary()

    def summary(self) -> None:
        self.logger.info("=" * 64)
        self.logger.info("  GOVERNANCE SUMMARY  v4.0")
        self.logger.info("=" * 64)
        self.logger.info("  Pipeline ID        : %s", self.run_context.pipeline_id)
        self.logger.info("  Run started        : %s", self.run_context.run_start)
        self.logger.info("  Audit ledger       : %s", self.ledger_file)
        self.logger.info("  PII report         : %s", self.pii_report_file)
        self.logger.info("  Validation report  : %s", self.validation_rpt_file)
        self.logger.info("  Profile report     : %s", self.profile_rpt_file)
        self.logger.info("  Metrics report     : %s", self.metrics_rpt_file)
        self.logger.info("  Classification rpt : %s", self.classification_file)
        self.logger.info("  Transfer log       : %s", self.transfer_log_file)
        self.logger.info("  Dead letter queue  : %s  (%s rows)", self.dlq_file, self.dlq_rows_total)
        self.logger.info("  Log file           : %s", self.log_file)
        self.logger.info("  Total events       : %s", len(self.ledger_entries))
        self.logger.info("=" * 64)
