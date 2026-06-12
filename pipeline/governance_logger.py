"""
Central audit and governance logging facility.

Chained-hash tamper detection (GDPR Art. 32): each JSONL ledger event
includes a SHA-256 hash of the previous event, creating a cryptographic
chain that makes any historical modification detectable.

Layer 1 — imports from Layer 0 only (constants, helpers).

Revision history
────────────────
4.0   2026-06-07   Stable release with 30+ event types and 7 report writers.
4.1   2026-06-08   Extracted report writers into pipeline.reporting.ReportWriter;
                   GovernanceLogger delegates to ReportWriter for backward compat.
4.2   2026-06-09   Audit ledger writes via AppendOnlyWriter (seek/truncate blocked).
4.3   2026-06-11   Integrity fixes: hash chain advances only after a successful
                   write (a failed write no longer poisons every later event);
                   sidecar anchor file (last hash + entry count) makes tail
                   truncation and whole-ledger deletion detectable; fixed
                   af-south-1 region mapping (dead "a" prefix never matched).
4.4   2026-06-12   Report-path layout extracted to pipeline.run_artifacts
                   (RunArtifacts dataclass); attributes kept as aliases.
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
from typing import TYPE_CHECKING, Any

from pipeline.constants import default_run_context, EventCategory, RunContext
from pipeline.helpers import atomic_json_write, file_hash
from pipeline.run_artifacts import RunArtifacts

if TYPE_CHECKING:
    from pipeline.append_only_writer import AppendOnlyWriter
    from pipeline.reporting.report_writer import ReportWriter

logger = logging.getLogger(__name__)

# Keys must be the full hyphen-delimited prefix: af-south-1 splits to "af",
# so a single-letter "a" entry can never match anything.
_REGION_PREFIX_TO_COUNTRY: dict[str, str] = {
    "us": "US", "eu": "EU", "ap": "SG", "ca": "CA",
    "sa": "BR", "me": "AE", "af": "ZA", "au": "AU",
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
        verify_integrity: bool = False,
    ) -> None:
        self.run_context = run_context or default_run_context()
        self.dry_run = dry_run

        stem = Path(source_name).stem if source_name else "pipeline"
        for ch in ('/', '\\', ':', '*', '?', '"', '<', '>', '|'):
            stem = stem.replace(ch, '_')
        stem = stem.strip() or "pipeline"

        self.source_name = stem
        self.log_dir = (Path(log_dir) if log_dir else Path(f"{stem} LOGS")).resolve()
        self.log_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Path layout lives in RunArtifacts; the attributes below are
        # back-compat aliases for the original inline names.
        self.artifacts = RunArtifacts(log_dir=self.log_dir, timestamp=ts)
        self.artifacts.ensure_directories()

        self.log_file = self.artifacts.log_file
        self.ledger_file = self.artifacts.ledger_file
        self.ledger_anchor_file = self.artifacts.ledger_anchor_file
        self.pii_report_file = self.artifacts.pii_report_file
        self.validation_rpt_file = self.artifacts.validation_report_file
        self.profile_rpt_file = self.artifacts.profile_report_file
        self.dlq_file = self.artifacts.dlq_file
        self.metrics_rpt_file = self.artifacts.metrics_report_file
        self.classification_file = self.artifacts.classification_file
        self.transfer_log_file = self.artifacts.transfer_log_file
        self.cost_log_file = self.artifacts.cost_log_file
        self.quality_log_file = self.artifacts.quality_log_file
        self.snapshot_dir = self.artifacts.snapshot_dir

        self.logger = logging.getLogger("DataPipeline")

        self.pii_findings: list[dict] = []
        self.ledger_entries: list[dict] = []
        self.validation_results: list[dict] = []
        self.classification_tags: list[dict] = []
        self.transfer_events: list[dict] = []
        self.dlq_rows_total: int = 0
        self._prev_hash: str = "GENESIS"
        self._written_event_count: int = 0
        self._event_lock = threading.RLock()
        self._verify_integrity = verify_integrity
        self._writer: "AppendOnlyWriter | None" = None

    # ── Core event writer with chained hash ──────────────────────────────
    # Performance: each _event() call serialises JSON + computes SHA-256 +
    # writes to disk.  For high-volume pipelines (>100k chunks), consider
    # buffering events in self.ledger_entries and flushing once per
    # checkpoint interval instead of per-event.  Current design prioritises
    # durability (no events lost on crash) over throughput.

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
            event_hash = hashlib.sha256(raw_json.encode()).hexdigest()
            base_entry["self_hash"] = event_hash
            final_json = json.dumps(base_entry, sort_keys=True)

            if not self.dry_run:
                if self._writer is None:
                    from pipeline.append_only_writer import AppendOnlyWriter
                    self._writer = AppendOnlyWriter(
                        self.ledger_file,
                        verify_integrity=self._verify_integrity,
                    )
                    self._writer.open()
                self._writer.write(final_json + "\n")
                self._written_event_count += 1
                self._write_anchor(event_hash)

            # Advance the chain only after the write lands: if the write
            # raises, the next event reuses this prev_hash and the on-disk
            # chain stays contiguous instead of permanently broken.
            self._prev_hash = event_hash
            self.ledger_entries.append(base_entry)

        msg = f"[{category}] {action}"
        if detail:
            msg += f" | {json.dumps(detail)}"
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def _write_anchor(self, last_hash: str) -> None:
        """Persist the chain anchor atomically alongside the ledger.

        The chained hashes alone cannot prove the ledger's *tail* exists:
        truncating the last N lines (or deleting the file) leaves a chain
        that still verifies. The anchor pins the expected final hash and
        entry count outside the ledger file itself.
        """
        anchor = {
            "last_hash": last_hash,
            "entry_count": self._written_event_count,
            "ledger_file": self.ledger_file.name,
        }
        atomic_json_write(self.ledger_anchor_file, json.dumps(anchor, indent=2))

    def _read_anchor(self) -> dict | None:
        """Load the anchor sidecar. Returns None when no anchor exists."""
        if not self.ledger_anchor_file.exists():
            return None
        try:
            anchor = json.loads(
                self.ledger_anchor_file.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, OSError) as exc:
            # An unreadable anchor is itself a tamper signal — never treat
            # it as "no anchor", which would let truncation pass unnoticed.
            self.logger.error("[TAMPER CHECK] Anchor file unreadable: %s", exc)
            return {"last_hash": "UNREADABLE", "entry_count": -1}
        if not isinstance(anchor, dict):
            self.logger.error("[TAMPER CHECK] Anchor file malformed (not a dict)")
            return {"last_hash": "UNREADABLE", "entry_count": -1}
        return anchor

    def verify_ledger(self) -> bool:
        """
        Walk the JSONL ledger and verify the chained-hash integrity,
        then check the tail against the persisted anchor.

        Returns True if the entire ledger is intact; False if tampering detected.
        """
        anchor = self._read_anchor()

        if not self.ledger_file.exists():
            if anchor is not None:
                self.logger.error(
                    "[TAMPER DETECTED] Ledger file is missing but anchor "
                    "records %s written events.", anchor.get("entry_count"),
                )
                return False
            return True

        with open(self.ledger_file, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            if anchor is not None:
                self.logger.error(
                    "[TAMPER DETECTED] Ledger file is empty but anchor "
                    "records %s written events.", anchor.get("entry_count"),
                )
                return False
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

        if anchor is not None:
            if anchor.get("entry_count") != len(lines):
                self.logger.error(
                    "[TAMPER DETECTED] Ledger has %s events but anchor "
                    "records %s — tail truncation suspected.",
                    len(lines), anchor.get("entry_count"),
                )
                return False
            if anchor.get("last_hash") != prev_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Final ledger hash %r does not match "
                    "anchored hash %r.", prev_hash, anchor.get("last_hash"),
                )
                return False

        self.logger.info(
            "[TAMPER CHECK] Ledger integrity verified — %s events OK.", len(lines)
        )
        return True

    # ── Lifecycle events ─────────────────────────────────────────────────

    def pipeline_start(self, metadata: dict) -> None:
        self._event(EventCategory.LIFECYCLE, "PIPELINE_STARTED", metadata)

    def pipeline_end(self, summary: dict) -> None:
        self._event(EventCategory.LIFECYCLE, "PIPELINE_COMPLETED", summary)

    def pipeline_complete(self, summary: dict) -> None:
        self.pipeline_end(summary)

    def transformation_applied(self, name: str, detail: dict | None = None) -> None:
        self._event(EventCategory.TRANSFORMATION, name, detail)

    def extract_event(self, action: str, detail: dict | None = None) -> None:
        self._event(EventCategory.EXTRACT, action, detail)

    def load_event(self, action: str, detail: dict | None = None) -> None:
        self._event(EventCategory.LOAD, action, detail)

    def quality_event(self, action: str, detail: dict | None = None) -> None:
        self._event(EventCategory.QUALITY, action, detail)

    def schema_event(self, action: str, detail: dict | None = None) -> None:
        self._event(EventCategory.SCHEMA, action, detail)

    def stage_metrics(self, stage: str, rows: int, elapsed: float) -> None:
        self._event(EventCategory.METRICS, f"{stage.upper()}_METRICS", {
            "rows": rows, "elapsed_s": elapsed,
        })

    # ── Lineage events ───────────────────────────────────────────────────

    def source_registered(self, path: str, file_type: str, rows: int, cols: int) -> None:
        try:
            sha = file_hash(path)
        except (FileNotFoundError, OSError):
            sha = "N/A"
        self._event(EventCategory.LINEAGE, "SOURCE_REGISTERED", {
            "source_path": path, "file_type": file_type,
            "row_count": rows, "col_count": cols, "sha256": sha,
        })

    def destination_registered(self, db: str, name: str, table: str) -> None:
        self._event(EventCategory.LINEAGE, "DESTINATION_REGISTERED", {
            "db_type": db, "db_name": name, "table_or_collection": table,
        })
        transfer = _infer_cross_border_transfer(db, name)
        if transfer:
            self.transfer_logged(**transfer)

    def load_complete(self, rows: int, table: str) -> None:
        self._event(EventCategory.LINEAGE, "LOAD_COMPLETE", {
            "rows_written": rows, "destination_table": table,
        })

    # ── Privacy events ───────────────────────────────────────────────────

    def pii_detected(self, findings: list[dict]) -> None:
        self.pii_findings.extend(findings)
        self._event(EventCategory.PRIVACY, "PII_DETECTED", {
            "findings_count": len(findings),
            "fields": [f["field"] for f in findings],
        }, level="WARNING")

    def pii_action(self, field: str, action: str) -> None:
        self._event(EventCategory.PRIVACY, f"PII_{action}", {"field": field})

    def data_minimization(self, orig: list, retained: list, dropped: list) -> None:
        self._event(EventCategory.PRIVACY, "DATA_MINIMIZATION_APPLIED", {
            "original_column_count": len(orig),
            "retained_column_count": len(retained),
            "dropped_columns": dropped,
        })

    def consent_recorded(self, purpose: str, basis: str, confirmed: bool) -> None:
        self._event(EventCategory.CONSENT, "LAWFUL_BASIS_RECORDED", {
            "processing_purpose": purpose, "lawful_basis": basis,
            "user_confirmed": confirmed,
        })

    def consent_event(self, action: str, detail: dict | None = None) -> None:
        self._event(EventCategory.CONSENT, action, detail)

    def retention_policy(self, policy: str, days: int | None) -> None:
        self._event(EventCategory.RETENTION, "POLICY_RECORDED", {
            "policy": policy, "retention_days": days,
        })

    # ── Validation events ────────────────────────────────────────────────

    def validation_result(self, suite: str, ok: bool, passed: int, failed: int, total: int) -> None:
        self._event(EventCategory.VALIDATION, "SUITE_RESULT", {
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
        self._event(EventCategory.VALIDATION, "EXPECTATION_RESULT", {
            "expectation": exp, "column": col,
            "success": ok, "unexpected_count": unexpected,
        }, level="INFO" if ok else "WARNING")

    def profile_recorded(self, summary: dict) -> None:
        self._event(EventCategory.PROFILING, "PROFILE_GENERATED", summary)

    def dlq_written(self, count: int, reason: str) -> None:
        self.dlq_rows_total += count
        self._event(EventCategory.DLQ, "ROWS_REJECTED", {
            "rejected_row_count": count, "reason": reason,
            "dlq_file": str(self.dlq_file),
        }, level="WARNING")

    def watermark_event(self, action: str, col: str, val: Any, filtered: int = 0) -> None:
        self._event(EventCategory.INCREMENTAL, f"WATERMARK_{action}", {
            "watermark_column": col, "watermark_value": str(val),
            "rows_filtered": filtered,
        })

    def retry_attempt(self, attempt: int, max_attempts: int, wait: float, exc: Exception) -> None:
        self._event(EventCategory.RETRY, "RETRY_ATTEMPT", {
            "attempt": attempt, "max_attempts": max_attempts,
            "wait_seconds": wait, "exception": str(exc),
        }, level="WARNING")

    def notification_sent(self, channel: str, status: str, detail: str = "") -> None:
        self._event(EventCategory.NOTIFICATION, f"{channel.upper()}_{status}", {"detail": detail})

    def error(self, msg: str, exc: Exception | None = None) -> None:
        self._event(EventCategory.ERROR, msg,
                    {"exception": str(exc)} if exc else None, level="ERROR")

    # ── v3.0 event wrappers ──────────────────────────────────────────────

    def sla_event(self, status: str, elapsed_sec: float, threshold_sec: float) -> None:
        level = "WARNING" if status in ("BREACH", "WARNING") else "INFO"
        self._event(EventCategory.SLA, f"SLA_{status}", {
            "elapsed_seconds": round(elapsed_sec, 1),
            "threshold_seconds": threshold_sec,
            "over_by_seconds": max(0, round(elapsed_sec - threshold_sec, 1)),
        }, level=level)

    def metrics_recorded(self, metrics: dict) -> None:
        self._event(EventCategory.METRICS, "METRICS_RECORDED", metrics)

    def encryption_applied(self, field: str, algorithm: str) -> None:
        self._event(EventCategory.ENCRYPTION, "COLUMN_ENCRYPTED", {
            "field": field, "algorithm": algorithm,
        })

    def enrichment_applied(self, join_col: str, lookup_table: str,
                           rows_matched: int, rows_total: int) -> None:
        self._event(EventCategory.ENRICHMENT, "LOOKUP_JOIN_APPLIED", {
            "join_column": join_col,
            "lookup_table": lookup_table,
            "rows_matched": rows_matched,
            "rows_total": rows_total,
            "match_rate": round(rows_matched / rows_total, 4) if rows_total else 0,
        })

    def referential_integrity_checked(self, fk_col: str, ref_table: str,
                                      valid: int, invalid: int) -> None:
        level = "INFO" if invalid == 0 else "WARNING"
        self._event(EventCategory.REFERENTIAL, "FK_CHECK_RESULT", {
            "foreign_key_column": fk_col,
            "reference_table": ref_table,
            "valid_rows": valid,
            "invalid_rows": invalid,
        }, level=level)

    def erasure_executed(self, subject_id: str, table: str,
                         rows_deleted: int, method: str = "DELETE") -> None:
        # GDPR Art. 17 — hash subject ID before logging (never store raw PII in audit trail)
        subject_hash = hashlib.sha256(str(subject_id).encode()).hexdigest()[:16]
        self._event(EventCategory.ERASURE, "GDPR_ERASURE_EXECUTED", {
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
        self._event(EventCategory.CLASSIFICATION, "DATA_CLASSIFIED", entry)

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
        self._event(EventCategory.TRANSFER, "CROSS_BORDER_TRANSFER_LOGGED", entry, level=level)

    def checkpoint_event(self, action: str, chunk_idx: int, rows: int) -> None:
        self._event(EventCategory.CHECKPOINT, f"CHECKPOINT_{action}", {
            "chunk_index": chunk_idx, "rows_processed": rows,
        })

    def standardisation_applied(self, column: str, rule: str, changed: int) -> None:
        self._event(EventCategory.STANDARDISE, "COLUMN_STANDARDISED", {
            "column": column, "rule": rule, "values_changed": changed,
        })

    def rule_applied(self, rule_name: str, rule_type: str, rows_affected: int) -> None:
        self._event(EventCategory.RULES, "BUSINESS_RULE_APPLIED", {
            "rule_name": rule_name, "rule_type": rule_type,
            "rows_affected": rows_affected,
        })

    # ── Report writer (lazy, avoids circular import at module level) ────

    @property
    def report_writer(self) -> "ReportWriter":
        """Return a ReportWriter bound to this logger, created on first access."""
        try:
            return self._report_writer  # type: ignore[no-any-return, has-type]
        except AttributeError:
            from pipeline.reporting.report_writer import ReportWriter
            self._report_writer = ReportWriter(self)
            return self._report_writer

    # ── Backward-compatible delegation to ReportWriter ──────────────────

    def write_pii_report(self) -> None:
        self.report_writer.write_pii_report()

    def write_validation_report(self) -> None:
        self.report_writer.write_validation_report()

    def write_profile_report(self, profile: dict) -> None:
        self.report_writer.write_profile_report(profile)

    def write_metrics_report(self, metrics: dict) -> None:
        self.report_writer.write_metrics_report(metrics)

    def write_classification_report(self) -> None:
        self.report_writer.write_classification_report()

    def write_transfer_log(self) -> None:
        self.report_writer.write_transfer_log()

    def pipeline_summary(self) -> None:
        self.report_writer.pipeline_summary()

    def summary(self) -> None:
        self.report_writer.summary()
