"""
=============================================================
  METADATA EXTENSIONS  v1.0.0
  12 additional metadata capabilities for pipeline_v3.py
=============================================================

FEATURES
--------
  ①  SchemaDriftDetector       — Persists schema between runs; raises on
                                  column additions, removals, or type changes.

  ②  OpenLineageEmitter        — Emits industry-standard OpenLineage
                                  RunEvent / DatasetEvent JSON to a file
                                  or Marquez-compatible HTTP endpoint.

  ③  ColumnLineageTracker      — Records source-col → dest-col mappings
                                  through every transformation step.

  ④  DSARIndex                 — Maps hashed subject IDs to the pipeline
                                  runs and tables that contain their data;
                                  satisfies GDPR Art. 15 (access) and
                                  Art. 17 (erasure) lookup requirements.

  ⑤  DataContractValidator     — Loads a YAML data contract (Data Contract
                                  Specification format) and validates the
                                  source DataFrame against it before load.

  ⑥  QualityHistoryTracker     — Appends per-run quality scores to a
                                  rolling JSONL log; detects pass-rate
                                  regression across consecutive runs.

  ⑦  AnomalyDetector          — Compares current profile stats against a
                                  rolling baseline; flags Z-score outliers
                                  in column distributions.

  ⑧  ColumnQualityScorer      — Computes a per-column quality score (0–100)
                                  from GX results, null rates, and unique
                                  counts; writes to governance_logs/.

  ⑨  DataFreshnessChecker     — Checks source-file modification time against
                                  a configurable max-age threshold; aborts
                                  or warns on stale data.

  ⑩  ColumnPurposeRegistry    — Stores a GDPR Art. 5(1)(b) processing
                                  purpose for each PII column individually,
                                  not just one purpose per run.

  ⑪  RecordProvenanceHasher   — Appends a _source_row_hash column (SHA-256
                                  of the original raw field values) to every
                                  loaded record, enabling post-load audit
                                  of what the source data actually was.

  ⑫  DbtResultsIntegrator     — Reads dbt's run_results.json and
                                  sources.json; appends dbt test results to
                                  the governance audit ledger and quality
                                  history so both tools share one quality view.

PERSISTENT STATE FILES
----------------------
  schema_registry.json      — Schema snapshots (one entry per source path)
  quality_history.jsonl     — Appended quality summary after each run
  anomaly_baseline.json     — Rolling column-stat baselines for Z-score
  dsar_index.jsonl          — Subject-ID → run → table index
  column_purpose.json       — Per-column processing purpose registry
  openlineage_events.jsonl  — Local sink for OpenLineage events

DEPENDENCIES
------------
  scipy>=1.10   — Z-score calculation (AnomalyDetector)
  pyyaml>=6.0   — Data contract YAML parsing (DataContractValidator)
  openlineage-python>=1.0  — OpenLineage SDK (OpenLineageEmitter)
  All standard library modules
=============================================================
"""

# ─────────────────────────────────────────────────────────────────────────────
#  IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import hashlib
import json
import logging
import os
# import re
# import stat
# import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Anchor all state files to the script's own directory ──────────────────
_BASE_DIR = Path(__file__).resolve().parent
log = logging.getLogger("MetadataExtensions")

# ── Optional dependencies ─────────────────────────────────────────────────────
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    from scipy import stats as scipy_stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from openlineage.client import OpenLineageClient
    from openlineage.client.run import (
        RunEvent, RunState, Run, Job,
        InputDataset, OutputDataset,
    )
    from openlineage.client.facet import (
        SchemaDatasetFacet, SchemaField,
        DataQualityMetricsInputDatasetFacet, ColumnMetric,
        DocumentationJobFacet,
        NominalTimeRunFacet, ParentRunFacet,
    )
    HAS_OPENLINEAGE = True
except ImportError:
    HAS_OPENLINEAGE = False


# ═════════════════════════════════════════════════════════════════════════════
#  ① SCHEMA DRIFT DETECTOR
# ═════════════════════════════════════════════════════════════════════════════
class SchemaDriftDetector:
    """
    Persists a schema snapshot after each successful run and compares
    the incoming DataFrame's schema against it on the next run.

    What counts as drift
    --------------------
    ADDED      — A column present now that wasn't in the last snapshot.
                 Usually benign but may indicate an upstream change.
    REMOVED    — A column from the last snapshot is missing now.
                 High severity: downstream queries may break.
    TYPE_CHANGE — A column exists in both but its dtype changed.
                 High severity: silent data corruption risk.
    RENAMED    — Heuristic only (flagged when count stays the same but
                 names change); requires human review.

    on_drift modes
    --------------
    "warn"  — Log a WARNING and continue.  Default for ADDED.
    "abort" — Raise SchemaDriftError and halt the pipeline.  Default
              for REMOVED and TYPE_CHANGE.
    "ignore"— Silently continue regardless.

    State file
    ----------
    schema_registry.json  — keyed by source_path, stores:
        { "source_path": { "columns": {"col": "dtype", ...},
                           "run_id": "...", "timestamp": "..." } }
    """

    REGISTRY_FILE = _BASE_DIR / "schema_registry.json"

    def __init__(self, gov) -> None:
        self.gov = gov

    # ── Public API ────────────────────────────────────────────────────────

    def check(
        self,
        df: "pd.DataFrame",
        source_path: str,
        on_added:       str = "warn",
        on_removed:     str = "abort",
        on_type_change: str = "abort",
    ) -> list[dict]:
        """
        Compare df's schema against the last saved snapshot for source_path.

        Parameters
        ----------
        df           : pd.DataFrame  Incoming DataFrame.
        source_path  : str           Source file path (registry key).
        on_added     : str           Action on new columns.
        on_removed   : str           Action on missing columns.
        on_type_change: str          Action on dtype changes.

        Returns
        -------
        list[dict]  List of drift events (empty if no drift).

        Raises
        ------
        SchemaDriftError  If on_* == "abort" and drift is detected.
        """
        current  = {c: str(df[c].dtype) for c in df.columns}
        previous = self._load(source_path)

        if previous is None:
            # First run — nothing to compare against.
            log.info("[SCHEMA] No prior snapshot for %s — baseline saved.", Path(source_path).name)
            self._save(source_path, current)
            self.gov._event("SCHEMA", "BASELINE_SAVED",
                            {"source": source_path, "columns": len(current)})
            return []

        drift_events = []
        prev_cols    = set(previous.keys())
        curr_cols    = set(current.keys())

        # Removed columns.
        for col in sorted(prev_cols - curr_cols):
            evt = {"drift_type": "REMOVED", "column": col,
                   "previous_dtype": previous[col], "current_dtype": None}
            drift_events.append(evt)
            self._handle(evt, on_removed,
                         f"Column '{col}' ({previous[col]}) was REMOVED from {source_path}")

        # Added columns.
        for col in sorted(curr_cols - prev_cols):
            evt = {"drift_type": "ADDED", "column": col,
                   "previous_dtype": None, "current_dtype": current[col]}
            drift_events.append(evt)
            self._handle(evt, on_added,
                         f"Column '{col}' ({current[col]}) was ADDED to {source_path}")

        # Type changes on common columns.
        for col in sorted(prev_cols & curr_cols):
            if previous[col] != current[col]:
                evt = {"drift_type": "TYPE_CHANGE", "column": col,
                       "previous_dtype": previous[col], "current_dtype": current[col]}
                drift_events.append(evt)
                self._handle(
                    evt, on_type_change,
                    f"Column '{col}' type changed: {previous[col]} → {current[col]}"
                )

        if drift_events:
            self.gov._event("SCHEMA", "DRIFT_DETECTED",
                            {"source": source_path, "drift_events": drift_events},
                            level="WARNING")
            print(f"  ⚠  [SCHEMA DRIFT] {len(drift_events)} change(s) detected:")
            for e in drift_events:
                symbol = {"REMOVED": "✗", "ADDED": "+", "TYPE_CHANGE": "~"}.get(
                    e["drift_type"], "?"
                )
                print(f"      {symbol}  {e['drift_type']:12}  {e['column']}"
                      f"  ({e['previous_dtype']} → {e['current_dtype']})")
        else:
            self.gov._event("SCHEMA", "NO_DRIFT",
                            {"source": source_path, "columns_checked": len(current)})
            print(f"  ✓  [SCHEMA] No drift detected ({len(current)} columns match).")

        # Always update the snapshot after a successful check.
        self._save(source_path, current)
        return drift_events

    def get_snapshot(self, source_path: str) -> dict | None:
        """Return the stored schema snapshot for source_path, or None."""
        return self._load(source_path)

    # ── Internals ─────────────────────────────────────────────────────────

    def _handle(self, _evt: dict, action: str, message: str) -> None:
        if action == "abort":
            log.error("[SCHEMA DRIFT] %s", message)
            raise SchemaDriftError(message)
        elif action == "warn":
            log.warning("[SCHEMA DRIFT] %s", message)

    def _load(self, source_path: str) -> dict | None:
        if not self.REGISTRY_FILE.exists():
            return None
        with open(self.REGISTRY_FILE, encoding="utf-8") as f:
            registry = json.load(f)
        entry = registry.get(source_path)
        return entry["columns"] if entry else None

    def _save(self, source_path: str, columns: dict) -> None:
        registry: dict = {}
        if self.REGISTRY_FILE.exists():
            with open(self.REGISTRY_FILE, encoding="utf-8") as f:
                registry = json.load(f)
        registry[source_path] = {
            "columns"  : columns,
            "run_id"   : self.gov.ledger_entries[0]["pipeline_id"]
                         if self.gov.ledger_entries else str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "col_count": len(columns),
        }
        with open(self.REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)


class SchemaDriftError(RuntimeError):
    """Raised by SchemaDriftDetector when drift is detected in abort mode."""


# ═════════════════════════════════════════════════════════════════════════════
#  ② OPENLINEAGE EMITTER
# ═════════════════════════════════════════════════════════════════════════════
class OpenLineageEmitter:
    """
    Emits industry-standard OpenLineage events for every pipeline run.

    OpenLineage (https://openlineage.io) is the open standard for data
    lineage interchange.  Events emitted here can be consumed by:
      • Marquez  (open-source lineage server)
      • Apache Atlas
      • Atlan, Collibra, DataHub (all support OpenLineage ingestion)
      • Any tool implementing the OpenLineage spec

    Events emitted
    --------------
    START    — Emitted when the pipeline begins extraction.
    COMPLETE — Emitted after load completes with full input/output
               dataset facets (schema, row count, quality metrics).
    FAIL     — Emitted if the pipeline aborts with an exception.

    Output modes
    ------------
    "file"   — Append events to openlineage_events.jsonl (default).
               Always available; no server required.
    "http"   — POST events to a Marquez or OpenLineage-compatible
               HTTP endpoint (set transport_url in config).

    Dataset naming
    --------------
    Input  dataset namespace: "file://"  name: source file path
    Output dataset namespace: "{db_type}://{db_name}"  name: table name
    """

    EVENTS_FILE   = _BASE_DIR / "openlineage_events.jsonl"

    def __init__(self, gov, config: dict | None = None) -> None:
        self.gov    = gov
        self.config = config or {}
        self._run_id        = str(uuid.uuid4())
        self._parent_run_id = (config or {}).get("parent_run_id")  # ⑧ multi-hop lineage
        self._job_namespace = self.config.get("job_namespace", "data-governance-pipeline")
        self._job_name      = self.config.get("job_name", "pipeline_v3")
        self._transport     = self.config.get("transport", "file")
        self._url           = self.config.get("transport_url", "")
        self._client        = None

        if HAS_OPENLINEAGE and self._transport == "http" and self._url:
            try:
                self._client = OpenLineageClient(url=self._url)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log.warning("[OL] HTTP client init failed (%s) — falling back to file.", exc)
                self._transport = "file"

    def emit_start(self, source_path: str) -> None:
        """Emit a START RunEvent when extraction begins."""
        if not HAS_OPENLINEAGE:
            self._emit_fallback("START", source_path, {})
            return
        event = RunEvent(
            eventType = RunState.START,
            eventTime = datetime.now(timezone.utc).isoformat(),
            run       = Run(runId=self._run_id,
                            facets={
                                "nominalTime": NominalTimeRunFacet(
                                    nominalStartTime=datetime.now(timezone.utc).isoformat()
                                ),
                                # ⑧ Multi-hop lineage: link to upstream pipeline run.
                                **( {"parent": ParentRunFacet(
                                        run={"runId": self._parent_run_id},
                                        job={"namespace": self._job_namespace,
                                             "name": self._job_name}
                                    )} if self._parent_run_id else {}
                                ),
                            }),
            job       = Job(namespace=self._job_namespace, name=self._job_name,
                            facets={"documentation": DocumentationJobFacet(
                                description="Data Governance Pipeline v3 ETL run"
                            )}),
            inputs    = [InputDataset(namespace="file://",
                                       name=str(Path(source_path).resolve()))],
            outputs   = [],
            producer  = "data-governance-pipeline/v3",
        )
        self._emit(event)
        log.info("[OL] START event emitted (run_id=%s)", self._run_id[:8])

    def emit_complete(
        self,
        source_path: str,
        db_type:     str,
        db_name:     str,
        table:       str,
        df_in:       "pd.DataFrame",
        df_out:      "pd.DataFrame",
        quality:     dict | None = None,
    ) -> None:
        """
        Emit a COMPLETE RunEvent with full schema and quality facets.

        Parameters
        ----------
        source_path : str           Source file path.
        db_type     : str           Destination database type.
        db_name     : str           Destination database name.
        table       : str           Destination table name.
        df_in       : pd.DataFrame  Raw input DataFrame (for schema facet).
        df_out      : pd.DataFrame  Transformed output DataFrame.
        quality     : dict | None   Quality summary dict.
        """
        if not HAS_OPENLINEAGE:
            self._emit_fallback("COMPLETE", source_path,
                                {"table": table, "rows": len(df_out)})
            return

        # Input schema facet — raw source columns.
        in_schema = SchemaDatasetFacet(fields=[
            SchemaField(name=c, type=str(df_in[c].dtype))
            for c in df_in.columns
        ])

        # Output schema facet — transformed columns.
        out_schema = SchemaDatasetFacet(fields=[
            SchemaField(name=c, type=str(df_out[c].dtype))
            for c in df_out.columns
        ])

        # Quality metrics facet — merge pipeline quality summary if provided.
        _q = quality or {}
        quality_facet = DataQualityMetricsInputDatasetFacet(
            rowCount    = _q.get("row_count", len(df_in)),
            bytes       = None,
            columnMetrics = {
                col: ColumnMetric(
                    nullCount    = int(df_in[col].isnull().sum()),
                    distinctCount= int(df_in[col].nunique()),
                )
                for col in df_in.columns
                if df_in[col].dtype in ("object", "float64", "int64")
            },
        )

        event = RunEvent(
            eventType = RunState.COMPLETE,
            eventTime = datetime.now(timezone.utc).isoformat(),
            run       = Run(runId=self._run_id,
                            facets={"nominalTime": NominalTimeRunFacet(
                                nominalStartTime=datetime.now(timezone.utc).isoformat(),
                                nominalEndTime  =datetime.now(timezone.utc).isoformat(),
                            )}),
            job       = Job(namespace=self._job_namespace, name=self._job_name),
            inputs    = [InputDataset(
                namespace = "file://",
                name      = str(Path(source_path).resolve()),
                facets    = {"schema": in_schema, "dataQuality": quality_facet},
            )],
            outputs   = [OutputDataset(
                namespace = f"{db_type}://{db_name}",
                name      = table,
                facets    = {"schema": out_schema},
            )],
            producer  = "data-governance-pipeline/v3",
        )
        self._emit(event)
        log.info("[OL] COMPLETE event emitted → %s://%s/%s", db_type, db_name, table)

    def emit_fail(self, source_path: str, error: str) -> None:
        """Emit a FAIL RunEvent when the pipeline aborts."""
        if not HAS_OPENLINEAGE:
            self._emit_fallback("FAIL", source_path, {"error": error})
            return
        event = RunEvent(
            eventType = RunState.FAIL,
            eventTime = datetime.now(timezone.utc).isoformat(),
            run       = Run(runId=self._run_id),
            job       = Job(namespace=self._job_namespace, name=self._job_name),
            inputs    = [InputDataset(namespace="file://",
                                       name=str(Path(source_path).resolve()))],
            outputs   = [],
            producer  = "data-governance-pipeline/v3",
        )
        self._emit(event)
        log.warning("[OL] FAIL event emitted: %s", error[:80])

    # ── Internals ─────────────────────────────────────────────────────────

    def _emit(self, event) -> None:
        """Write to file sink and optionally POST to HTTP endpoint."""
        # Use attr.asdict() when available (openlineage 1.x uses attrs dataclasses).
        # This correctly serializes nested Run/Job/Facet objects as plain dicts,
        # enabling proper downstream parsing of run.facets (e.g. parent run ID).
        # Falls back to __dict__ + str coercion for non-attrs objects.
        try:
            import attr as _attr
            raw = json.dumps(_attr.asdict(event), default=str)
        except Exception:  # pylint: disable=broad-exception-caught
            raw = event.json() if hasattr(event, "json") else json.dumps(
                event.__dict__, default=str
            )
        # Always write to local file.
        with open(self.EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(raw + "\n")
        self.gov._event("LINEAGE", "OPENLINEAGE_EVENT_EMITTED",
                        {"event_type": str(getattr(event, "eventType", "?")),
                         "run_id": self._run_id})
        # Optionally POST to HTTP.
        if self._client:
            try:
                self._client.emit(event)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log.warning("[OL] HTTP emit failed: %s", exc)

    def _emit_fallback(self, event_type: str, source: str, detail: dict) -> None:
        """Write a minimal JSON event when openlineage-python is absent."""
        entry = {
            "eventType"  : event_type,
            "eventTime"  : datetime.now(timezone.utc).isoformat(),
            "runId"      : self._run_id,
            "jobNamespace": self._job_namespace,
            "jobName"    : self._job_name,
            "source"     : source,
            **detail,
        }
        with open(self.EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self.gov._event("LINEAGE", "OPENLINEAGE_EVENT_EMITTED",
                        {"event_type": event_type, "run_id": self._run_id,
                         "note": "openlineage-python not installed; minimal format used"})


# ═════════════════════════════════════════════════════════════════════════════
#  ③ COLUMN LINEAGE TRACKER
# ═════════════════════════════════════════════════════════════════════════════
class ColumnLineageTracker:
    """
    Records source-column → destination-column mappings through every
    transformation step the pipeline applies.

    Why this matters
    ----------------
    Table-level lineage says "file X was loaded into table Y".  Column-
    level lineage says "source field address.city became dest column
    address__city after JSON flattening, then was sanitised to
    address__city".  Without this, catalog lineage graphs show a black
    box at the column level — analysts can't trace a value back to its
    origin field.

    Mappings tracked
    ----------------
    identity    — Column carried through unchanged (most columns).
    flatten     — Nested path (e.g. "address.city") → flat column
                  (e.g. "address__city").
    rename      — Business rule renamed it.
    mask        — PII field pseudonymised (value changed, name kept).
    encrypt     — Column AES-256 encrypted.
    drop        — Column removed during minimisation.
    derive      — New column derived from source column(s).
    coerce      — Dtype changed by TypeCoercer.
    sanitise    — Column name cleaned (special chars replaced).
    enrich      — Column added from a lookup join (no source column).
    metadata    — Pipeline-injected metadata column (_pipeline_id etc).
    standardise — Value normalised (e.g. phone → E.164).

    Output
    ------
    Written to governance_logs/column_lineage_<ts>.json after the run.
    Each entry:
        { "source_col": "address.city",
          "dest_col":   "address__city",
          "mapping_type": "flatten",
          "transformation": "JSON nested key flattening",
          "pii": false }
    """

    def __init__(self, gov) -> None:
        self.gov      = gov
        self._mappings: list[dict] = []

    def record(
        self,
        source_col:      str | None,
        dest_col:        str | None,
        mapping_type:    str,
        transformation:  str = "",
        is_pii:          bool = False,
    ) -> None:
        """
        Record a single column lineage mapping.

        Parameters
        ----------
        source_col     : str | None  Original column name (None for enriched/metadata cols).
        dest_col       : str | None  Final column name (None for dropped cols).
        mapping_type   : str         One of the mapping types listed in the class docstring.
        transformation : str         Human-readable description of what happened.
        is_pii         : bool        Whether the column contains PII.
        """
        entry = {
            "source_col"    : source_col,
            "dest_col"      : dest_col,
            "mapping_type"  : mapping_type,
            "transformation": transformation,
            "is_pii"        : is_pii,
        }
        self._mappings.append(entry)

    def infer_from_dataframes(
        self,
        df_before:   "pd.DataFrame",
        df_after:    "pd.DataFrame",
        pii_fields:  list[str]       = (),
        masked_cols: list[str]       = (),
        dropped_cols:list[str]       = (),
        renamed:     dict[str, str]  = None,
    ) -> None:
        """
        Automatically infer column lineage by diffing two DataFrames.

        Call this after the full transformation step to capture the
        bulk of column-level mappings without manual instrumentation.

        Parameters
        ----------
        df_before    : pd.DataFrame  DataFrame before transformation.
        df_after     : pd.DataFrame  DataFrame after transformation.
        pii_fields   : list[str]     PII column names.
        masked_cols  : list[str]     Columns that were SHA-256 masked.
        dropped_cols : list[str]     Columns intentionally dropped.
        renamed      : dict          {old_name: new_name} rename map.
        """
        before_cols = set(df_before.columns)
        after_cols  = set(df_after.columns)
        rename_map  = renamed or {}
        pii_set     = set(pii_fields)
        masked_set  = set(masked_cols)

        # Columns present in both — identity or masked/encrypted.
        for col in sorted(before_cols & after_cols):
            if col in masked_set:
                self.record(col, col, "mask",
                            "SHA-256 pseudonymisation applied", is_pii=True)
            elif df_before[col].dtype != df_after[col].dtype:
                self.record(col, col, "coerce",
                            f"dtype {df_before[col].dtype} → {df_after[col].dtype}",
                            is_pii=col in pii_set)
            else:
                self.record(col, col, "identity", "", is_pii=col in pii_set)

        # Dropped columns: union of set-difference and explicitly-listed drops.
        explicit_drops = set(dropped_cols)
        for col in sorted((before_cols - after_cols) | explicit_drops):
            if col not in rename_map and col in before_cols:
                self.record(col, None, "drop",
                            "Removed during data minimisation or PII drop",
                            is_pii=col in pii_set)

        # New columns (enrichment or metadata).
        for col in sorted(after_cols - before_cols):
            if col.startswith("_"):
                self.record(None, col, "metadata",
                            "Pipeline-injected metadata column")
            else:
                self.record(None, col, "enrich",
                            "Added by data enrichment join")

        # Renames from business rules.
        for old, new in rename_map.items():
            self.record(old, new, "rename",
                        f"Business rule renamed '{old}' to '{new}'",
                        is_pii=old in pii_set)

    def record_flatten(self, nested_path: str, flat_col: str) -> None:
        """Convenience method for JSON flattening mappings."""
        self.record(nested_path, flat_col, "flatten",
                    f"Nested JSON key '{nested_path}' flattened to '{flat_col}'")

    def write_report(self, log_dir: str = "governance_logs") -> Path:
        """Serialise all mappings to column_lineage_<ts>.json."""
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(log_dir) / f"column_lineage_{ts}.json"
        report = {
            "pipeline_id"  : self.gov.ledger_entries[0]["pipeline_id"]
                             if self.gov.ledger_entries else "",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "total_mappings": len(self._mappings),
            "summary": {
                t: sum(1 for m in self._mappings if m["mapping_type"] == t)
                for t in ("identity","flatten","mask","drop","enrich",
                          "metadata","coerce","rename","derive","encrypt",
                          "sanitise","standardise")
            },
            "mappings": self._mappings,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self.gov._event("LINEAGE", "COLUMN_LINEAGE_WRITTEN",
                        {"mappings": len(self._mappings), "file": str(path)})
        log.info("[COL LINEAGE] %s mappings → %s", len(self._mappings), path)
        return path

    @property
    def mappings(self) -> list[dict]:
        return list(self._mappings)


# ═════════════════════════════════════════════════════════════════════════════
#  ④ DSAR INDEX
# ═════════════════════════════════════════════════════════════════════════════
class DSARIndex:
    """
    Data Subject Access Request index.

    Maintains a persistent log mapping data subjects to every pipeline
    run and database table that contains their data.  This satisfies:

    GDPR Art. 15  — Right of access: "where are all the records about me?"
    GDPR Art. 17  — Right to erasure: "delete all records about me" requires
                    knowing where they are first.
    GDPR Art. 20  — Right to portability: export all data about a subject.

    Privacy
    -------
    Subject identifiers (e.g. email addresses) are SHA-256 hashed before
    being written to the index.  The index never stores raw PII.  A lookup
    takes the raw ID, hashes it, and finds matching entries.

    Index file
    ----------
    dsar_index.jsonl  — One JSON line per index entry:
        { "subject_hash": "abc123...",
          "subject_col":  "email",
          "pipeline_id":  "...",
          "run_timestamp": "...",
          "source_path":  "employees.csv",
          "dest_db_type": "postgresql",
          "dest_db_name": "analytics",
          "dest_table":   "employees",
          "row_count":    4 }

    Usage
    -----
    # After load, index all subjects in the loaded DataFrame:
        dsar = DSARIndex(gov)
        dsar.index_dataset(df, subject_col="email", source_path="...",
                           dest_db_type="sqlite", dest_db_name="output",
                           dest_table="employees")

    # Respond to an access request:
        records = dsar.lookup("alice@example.com", subject_col="email")

    # Respond to an erasure request:
        tables = dsar.find_tables_for_subject("alice@example.com", "email")
    """

    INDEX_FILE    = _BASE_DIR / "dsar_index.jsonl"

    def __init__(self, gov) -> None:
        self.gov = gov

    def _hash(self, subject_id: str) -> str:
        """SHA-256 hash of the subject identifier (never store raw PII)."""
        return hashlib.sha256(str(subject_id).encode("utf-8")).hexdigest()

    def index_dataset(
        self,
        df:           "pd.DataFrame",
        subject_col:  str,
        source_path:  str,
        dest_db_type: str,
        dest_db_name: str,
        dest_table:   str,
    ) -> int:
        """
        Index all unique subject IDs found in subject_col.

        One index entry is written per unique subject value.  Duplicate
        entries for the same subject + run are de-duplicated by checking
        for an existing matching entry before writing.

        Parameters
        ----------
        df           : pd.DataFrame  The loaded (post-transform) DataFrame.
        subject_col  : str           Column containing subject identifiers.
        source_path  : str           Source file path.
        dest_db_type : str           Destination DB type.
        dest_db_name : str           Destination DB name.
        dest_table   : str           Destination table name.

        Returns
        -------
        int  Number of unique subjects indexed.
        """
        if subject_col not in df.columns:
            log.warning("[DSAR] subject_col '%s' not in DataFrame — skipping index.", subject_col)
            return 0

        pipeline_id = (self.gov.ledger_entries[0]["pipeline_id"]
                       if self.gov.ledger_entries else str(uuid.uuid4()))
        run_ts      = datetime.now(timezone.utc).isoformat()

        # Load existing index to avoid duplicate entries.
        existing = self._load_all()
        existing_keys = {
            (e["subject_hash"], e["pipeline_id"], e["dest_table"])
            for e in existing
        }

        subjects   = df[subject_col].dropna().unique()
        new_count  = 0
        with open(self.INDEX_FILE, "a", encoding="utf-8") as f:
            for subject in subjects:
                subject_hash = self._hash(str(subject))
                key = (subject_hash, pipeline_id, dest_table)
                if key in existing_keys:
                    continue
                entry = {
                    "subject_hash" : subject_hash,
                    "subject_col"  : subject_col,
                    "pipeline_id"  : pipeline_id,
                    "run_timestamp": run_ts,
                    "source_path"  : source_path,
                    "dest_db_type" : dest_db_type,
                    "dest_db_name" : dest_db_name,
                    "dest_table"   : dest_table,
                    "row_count"    : int((df[subject_col] == subject).sum()),
                }
                f.write(json.dumps(entry) + "\n")
                new_count += 1

        self.gov._event("PRIVACY", "DSAR_INDEX_UPDATED",
                        {"subjects_indexed": new_count,
                         "subject_col": subject_col,
                         "dest_table": dest_table,
                         "gdpr_reference": "Articles 15, 17, 20"})
        log.info("[DSAR] %s subject(s) indexed in %s", new_count, self.INDEX_FILE)
        return new_count

    def lookup(self, subject_id: str, subject_col: str | None = None) -> list[dict]:
        """
        Find all index entries for a given subject identifier.

        Parameters
        ----------
        subject_id  : str        Raw subject value (will be hashed for lookup).
        subject_col : str | None Filter by column name (optional).

        Returns
        -------
        list[dict]  All index entries matching this subject.
        """
        target_hash = self._hash(str(subject_id))
        results     = [
            e for e in self._load_all()
            if e["subject_hash"] == target_hash
            and (subject_col is None or e["subject_col"] == subject_col)
        ]
        log.info("[DSAR] Lookup returned %s entry/entries.", len(results))
        return results

    def find_tables_for_subject(
        self, subject_id: str, subject_col: str | None = None
    ) -> list[dict]:
        """
        Return a deduplicated list of db/table locations containing the subject.

        Used by ErasureHandler to know where to delete before executing.
        Each result: {"dest_db_type": ..., "dest_db_name": ..., "dest_table": ...}
        """
        seen   = set()
        tables = []
        for entry in self.lookup(subject_id, subject_col):
            key = (entry["dest_db_type"], entry["dest_db_name"], entry["dest_table"])
            if key not in seen:
                tables.append({k: entry[k] for k in
                               ("dest_db_type", "dest_db_name", "dest_table")})
                seen.add(key)
        return tables

    def _load_all(self) -> list[dict]:
        if not self.INDEX_FILE.exists():
            return []
        with open(self.INDEX_FILE, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


# ═════════════════════════════════════════════════════════════════════════════
#  ⑤ DATA CONTRACT VALIDATOR
# ═════════════════════════════════════════════════════════════════════════════
class DataContractValidator:
    """
    Validates the source DataFrame against a machine-readable data contract.

    Uses a subset of the Data Contract Specification (datacontract.com),
    the emerging open standard for producer–consumer agreements.

    Contract format (YAML)
    ----------------------
    dataContractSpecification: "0.9.3"
    id: "employees-v1"
    info:
      title: "Employee Data Contract"
      version: "1.0.0"
      description: "HR employee records from HRIS"
      owner: "HR Engineering"
      contact:
        name: "Data Platform Team"

    models:
      employees:
        description: "Employee records"
        fields:
          id:
            type: integer
            required: true
            unique: true
          email:
            type: string
            required: true
            pii: true
            classification: confidential
          salary:
            type: number
            required: false
            minimum: 0
            maximum: 500000
          department_id:
            type: integer
            required: true
          hired_date:
            type: date
            required: true

    quality:
      type: "great-expectations"
      specifications:
        - name: "row_count_check"
          expectation: "expect_table_row_count_to_be_between"
          kwargs: {min_value: 1, max_value: 1000000}

    Checks performed
    ----------------
    1. Required fields present.
    2. No undeclared fields (warn on unexpected columns).
    3. Numeric range constraints (minimum / maximum).
    4. PII field consistency with pipeline's own PII detection.
    5. Data type compatibility (broad type families).
    """

    TYPE_MAP = {
        "string"  : ("object",),
        "integer" : ("int64", "Int64", "int32", "Int32"),
        "number"  : ("float64", "float32", "int64", "Int64"),
        "boolean" : ("bool", "boolean"),
        "date"    : ("object", "datetime64[ns]", "datetime64[ns, UTC]"),
        "timestamp":("datetime64[ns]", "datetime64[ns, UTC]"),
        "object"  : ("object",),
    }

    def __init__(self, gov) -> None:
        self.gov = gov

    def load_contract(self, contract_path: str) -> dict:
        """Load a YAML data contract file."""
        if not HAS_YAML:
            raise RuntimeError("pyyaml not installed. Run: pip install pyyaml")
        with open(contract_path, encoding="utf-8") as f:
            contract = yaml.safe_load(f)
        log.info("[CONTRACT] Loaded: %s", contract.get("info", {}).get("title", contract_path))
        return contract

    def validate(
        self,
        df:          "pd.DataFrame",
        contract:    dict,
        model_name:  str | None = None,
        pii_findings: list[dict] = (),
        on_failure:  str = "warn",
    ) -> list[dict]:
        """
        Validate df against the contract and return a list of violations.

        Parameters
        ----------
        df           : pd.DataFrame   DataFrame to validate.
        contract     : dict           Loaded contract dict.
        model_name   : str | None     Which model in the contract to use.
                                      Defaults to the first model.
        pii_findings : list[dict]     Pipeline PII findings for cross-check.
        on_failure   : str            "warn" | "abort".

        Returns
        -------
        list[dict]  Violation records (empty if all checks pass).
        """
        models = contract.get("models", {})
        if not models:
            log.warning("[CONTRACT] No models defined in contract.")
            return []

        name   = model_name or next(iter(models))
        model  = models[name]
        fields = model.get("fields", {})

        violations = []
        pii_set    = {f["field"] for f in pii_findings}

        for field_name, field_spec in fields.items():
            # 1. Required field present?
            if field_spec.get("required", False) and field_name not in df.columns:
                violations.append({
                    "check"  : "REQUIRED_FIELD_MISSING",
                    "field"  : field_name,
                    "detail" : f"Required field '{field_name}' not found in data.",
                })

            if field_name not in df.columns:
                continue

            col   = df[field_name]
            dtype = str(col.dtype)

            # 2. Type compatibility.
            expected_type = field_spec.get("type", "")
            if expected_type and expected_type in self.TYPE_MAP:
                if dtype not in self.TYPE_MAP[expected_type]:
                    violations.append({
                        "check"  : "TYPE_MISMATCH",
                        "field"  : field_name,
                        "detail" : (f"Expected type '{expected_type}' "
                                    f"(compatible dtypes: {self.TYPE_MAP[expected_type]}), "
                                    f"got '{dtype}'."),
                    })

            # 3. Numeric range constraints.
            if "minimum" in field_spec and pd.api.types.is_numeric_dtype(col):
                violations_min = int((col.dropna() < field_spec["minimum"]).sum())
                if violations_min:
                    violations.append({
                        "check"  : "BELOW_MINIMUM",
                        "field"  : field_name,
                        "detail" : (f"{violations_min} value(s) below minimum "
                                    f"{field_spec['minimum']}."),
                    })
            if "maximum" in field_spec and pd.api.types.is_numeric_dtype(col):
                violations_max = int((col.dropna() > field_spec["maximum"]).sum())
                if violations_max:
                    violations.append({
                        "check"  : "ABOVE_MAXIMUM",
                        "field"  : field_name,
                        "detail" : (f"{violations_max} value(s) above maximum "
                                    f"{field_spec['maximum']}."),
                    })

            # 4. PII consistency check.
            if field_spec.get("pii", False) and field_name not in pii_set:
                violations.append({
                    "check"  : "PII_NOT_DETECTED",
                    "field"  : field_name,
                    "detail" : (f"Contract marks '{field_name}' as PII but pipeline "
                                f"did not detect it.  Review PII patterns."),
                })

        # 5. Undeclared columns (warn only).
        declared = set(fields.keys())
        for col_name in df.columns:
            if col_name not in declared and not col_name.startswith("_"):
                violations.append({
                    "check"  : "UNDECLARED_COLUMN",
                    "field"  : col_name,
                    "detail" : f"Column '{col_name}' not declared in contract.",
                })

        status = "PASSED" if not violations else "FAILED"
        self.gov._event("CONTRACT", f"CONTRACT_{status}",
                        {"model": name, "violations": len(violations),
                         "contract_id": contract.get("id", ""),
                         "contract_version": contract.get("info", {}).get("version", "")},
                        level="INFO" if status == "PASSED" else "WARNING")

        if violations and on_failure == "abort":
            raise DataContractViolationError(
                f"Data contract '{name}' failed: {len(violations)} violation(s)."
            )

        v_count = len([v for v in violations if v["check"] != "UNDECLARED_COLUMN"])
        print(f"  {'✓' if status == 'PASSED' else '⚠'}  "
              f"[CONTRACT] '{name}': {status}  "
              f"({v_count} violation(s), "
              f"{len([v for v in violations if v['check'] == 'UNDECLARED_COLUMN'])} undeclared columns)")
        return violations


class DataContractViolationError(RuntimeError):
    """Raised by DataContractValidator in abort mode."""


def generate_contract_template(
    df:          "pd.DataFrame",
    model_name:  str = "my_dataset",
    pii_findings: list[dict] = (),
    output_path: str = "data_contract.yaml",
) -> str:
    """
    Auto-generate a data contract YAML template from an existing DataFrame.

    The generated contract is a starting point — field owners should
    review it, add business descriptions, and set appropriate constraints
    before treating it as a production contract.

    Parameters
    ----------
    df           : pd.DataFrame   Sample DataFrame.
    model_name   : str            Name for the model in the contract.
    pii_findings : list[dict]     PII findings to annotate PII fields.
    output_path  : str            Where to write the YAML file.

    Returns
    -------
    str  Path to the written file.
    """
    if not HAS_YAML:
        raise RuntimeError("pyyaml not installed. Run: pip install pyyaml")

    pii_set = {f["field"] for f in pii_findings}
    spec_fields = {}
    type_map_reverse = {
        "int64": "integer", "Int64": "integer", "int32": "integer",
        "float64": "number", "float32": "number",
        "bool": "boolean", "boolean": "boolean",
        "object": "string",
        "datetime64[ns]": "timestamp", "datetime64[ns, UTC]": "timestamp",
    }
    for col in df.columns:
        dtype     = str(df[col].dtype)
        col_type  = type_map_reverse.get(dtype, "string")
        field_def: dict = {
            "type"       : col_type,
            "required"   : bool(df[col].isnull().mean() == 0),
            "description": f"TODO: describe {col}",
        }
        if col in pii_set:
            field_def["pii"]            = True
            field_def["classification"] = "confidential"
        if pd.api.types.is_numeric_dtype(df[col]):
            non_null = df[col].dropna()
            if len(non_null):
                field_def["minimum"] = float(non_null.min())
                field_def["maximum"] = float(non_null.max())
        spec_fields[col] = field_def

    contract = {
        "dataContractSpecification": "0.9.3",
        "id": f"{model_name}-v1",
        "info": {
            "title"      : f"{model_name.title()} Data Contract",
            "version"    : "1.0.0",
            "description": "Auto-generated from pipeline run — review before production use.",
            "owner"      : "TODO: set owner",
        },
        "models": {
            model_name: {
                "description": f"TODO: describe {model_name}",
                "fields"     : spec_fields,
            }
        },
    }
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(contract, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    log.info("[CONTRACT] Template generated → %s", output_path)
    return output_path


# ═════════════════════════════════════════════════════════════════════════════
#  ⑥ QUALITY HISTORY TRACKER
# ═════════════════════════════════════════════════════════════════════════════
class QualityHistoryTracker:
    """
    Appends a quality summary to a rolling JSONL log after each run and
    detects pass-rate regression across consecutive runs.

    Why this matters
    ----------------
    A single run's validation report says "pass rate was 94% today".
    Quality history says "pass rate has been declining for 5 consecutive
    runs: 100% → 99% → 97% → 95% → 94%".  Only the history catches
    the trend before it becomes a production incident.

    History file
    ------------
    quality_history.jsonl  — One entry per run:
        { "run_id": "...",
          "timestamp_utc": "...",
          "source": "employees.csv",
          "table": "employees",
          "row_count": 1000,
          "pass_rate": 0.94,
          "expectations_total": 22,
          "expectations_passed": 21,
          "dlq_rows": 6,
          "error_rate": 0.006,
          "pii_field_count": 5,
          "classification": "CONFIDENTIAL" }

    Regression detection
    --------------------
    After appending, compares the last N runs (default 5).  Fires a
    WARNING if:
      • Pass rate has declined in every consecutive run (monotonic drop).
      • Current pass rate is more than `threshold` points below the
        rolling mean (default 0.05 = 5 percentage points).
    """

    HISTORY_FILE  = _BASE_DIR / "quality_history.jsonl"

    def __init__(self, gov) -> None:
        self.gov = gov

    def append(
        self,
        source_path:    str,
        table:          str,
        row_count:      int,
        pass_rate:      float,
        exp_total:      int,
        exp_passed:     int,
        dlq_rows:       int,
        classification: str,
        pii_count:      int,
    ) -> dict:
        """
        Append a quality record for the current run and return it.

        Parameters
        ----------
        See class-level docstring for field descriptions.

        Returns
        -------
        dict  The written history entry.
        """
        pipeline_id = (self.gov.ledger_entries[0]["pipeline_id"]
                       if self.gov.ledger_entries else str(uuid.uuid4()))
        entry = {
            "run_id"           : pipeline_id,
            "timestamp_utc"    : datetime.now(timezone.utc).isoformat(),
            "source"           : str(Path(source_path).name),
            "table"            : table,
            "row_count"        : row_count,
            "pass_rate"        : round(pass_rate, 4),
            "expectations_total": exp_total,
            "expectations_passed": exp_passed,
            "dlq_rows"         : dlq_rows,
            "error_rate"       : round(dlq_rows / max(row_count, 1), 4),
            "pii_field_count"  : pii_count,
            "classification"   : classification,
        }
        with open(self.HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        self.gov._event("QUALITY", "HISTORY_APPENDED",
                        {"table": table, "pass_rate": pass_rate,
                         "run_number": len(self._load_history(table))})
        return entry

    def check_regression(
        self,
        table:         str,
        window:        int   = 5,
        threshold:     float = 0.05,
    ) -> dict:
        """
        Check for quality regression over the last `window` runs.

        Parameters
        ----------
        table     : str    Table name to filter history.
        window    : int    Number of recent runs to examine.
        threshold : float  Alert if current rate is this far below rolling mean.

        Returns
        -------
        dict  { "regression": bool, "trend": list[float], "message": str }
        """
        history = self._load_history(table)
        if len(history) < 2:
            return {"regression": False, "trend": [], "message": "Insufficient history."}

        recent = history[-window:]
        rates  = [e["pass_rate"] for e in recent]
        mean   = sum(rates) / len(rates)
        current= rates[-1]

        # Monotonic decline: every rate is lower than the previous.
        monotonic_decline = all(rates[i] >= rates[i+1] for i in range(len(rates)-1))
        below_threshold   = (mean - current) > threshold

        regression = monotonic_decline or below_threshold
        if regression:
            message = (
                f"Quality regression on '{table}': "
                f"pass_rate trend = {[f'{r:.1%}' for r in rates]}  "
                f"(mean={mean:.1%}, current={current:.1%})"
            )
            self.gov._event("QUALITY", "REGRESSION_DETECTED",
                            {"table": table, "trend": rates, "mean": mean,
                             "current": current}, level="WARNING")
            print(f"  ⚠  [QUALITY TREND] {message}")
        else:
            message = (
                f"No regression on '{table}'.  "
                f"Recent pass rates: {[f'{r:.1%}' for r in rates]}"
            )
            print(f"  ✓  [QUALITY TREND] {message}")

        return {"regression": regression, "trend": rates, "mean": mean,
                "current": current, "message": message}

    def _load_history(self, table: str | None = None) -> list[dict]:
        if not self.HISTORY_FILE.exists():
            return []
        with open(self.HISTORY_FILE, encoding="utf-8") as f:
            all_entries = [json.loads(line) for line in f if line.strip()]
        if table:
            return [e for e in all_entries if e["table"] == table]
        return all_entries


# ═════════════════════════════════════════════════════════════════════════════
#  ⑦ ANOMALY DETECTOR
# ═════════════════════════════════════════════════════════════════════════════
class AnomalyDetector:
    """
    Detects statistical anomalies in column distributions by comparing
    the current run's profile against a rolling baseline.

    Method
    ------
    After each run, per-column statistics (mean, std, null_pct, unique_count)
    are appended to a baseline file.  On the next run, Z-scores are computed:

        z = (current_value - baseline_mean) / baseline_std

    A |z| > threshold (default 3.0) flags the column as anomalous.

    Checks applied per numeric column
    ----------------------------------
    • mean_zscore       — Is the column mean significantly shifted?
    • null_pct_zscore   — Has the null rate spiked or dropped?
    • unique_count_zscore — Has the cardinality changed unexpectedly?

    State file
    ----------
    anomaly_baseline.json  — Rolling stats per source × column:
        { "employees.csv::salary": [
            {"mean": 85000, "std": 7000, "null_pct": 0.0, "unique_count": 3},
            ...
          ]
        }
    """

    BASELINE_FILE = _BASE_DIR / "anomaly_baseline.json"
    DEFAULT_WINDOW    = 10   # Number of past runs to include in baseline
    DEFAULT_THRESHOLD = 3.0  # Z-score threshold for flagging anomalies

    def __init__(self, gov) -> None:
        self.gov = gov

    def check(
        self,
        profile:     dict,
        source_path: str,
        threshold:   float = DEFAULT_THRESHOLD,
        window:      int   = DEFAULT_WINDOW,
    ) -> list[dict]:
        """
        Compare current profile stats against the rolling baseline.

        Parameters
        ----------
        profile     : dict   Profile dict from DataProfiler.profile().
        source_path : str    Source file identifier (registry key prefix).
        threshold   : float  Z-score threshold for anomaly flag.
        window      : int    Max number of past runs to include in baseline.

        Returns
        -------
        list[dict]  Anomaly events (empty if nothing flagged).
        """
        baseline  = self._load_baseline()
        anomalies = []
        source_key= str(Path(source_path).name)

        for col, stats in profile.get("columns", {}).items():
            key = f"{source_key}::{col}"
            history = baseline.get(key, [])

            if len(history) < 3:
                # Not enough history for meaningful Z-scores.
                continue

            recent = history[-window:]
            checks = []
            if "mean" in stats:
                checks.append(("mean",        stats["mean"]))
            checks.append(("null_pct",         stats.get("null_pct", 0)))
            checks.append(("unique_count",     stats.get("unique_count", 0)))

            for metric, current_val in checks:
                past_vals = [r.get(metric, 0) for r in recent
                             if r.get(metric) is not None]
                if len(past_vals) < 3:
                    continue

                if HAS_SCIPY:
                    z = float(scipy_stats.zscore(past_vals + [current_val])[-1])
                else:
                    # Manual Z-score if scipy absent.
                    mean = sum(past_vals) / len(past_vals)
                    std  = (sum((v - mean) ** 2 for v in past_vals) / len(past_vals)) ** 0.5
                    z    = (current_val - mean) / std if std > 0 else 0.0

                if abs(z) > threshold:
                    baseline_mean = sum(past_vals) / len(past_vals)
                    anomaly = {
                        "column"       : col,
                        "metric"       : metric,
                        "current_value": round(current_val, 4),
                        "baseline_mean": round(baseline_mean, 4),
                        "z_score"      : round(z, 2),
                        "threshold"    : threshold,
                    }
                    anomalies.append(anomaly)
                    self.gov._event("ANOMALY", "COLUMN_ANOMALY_DETECTED", anomaly,
                                    level="WARNING")
                    print(f"  ⚠  [ANOMALY] '{col}' {metric}: "
                          f"current={current_val:.3f}  "
                          f"baseline_mean={baseline_mean:.3f}  "
                          f"z={z:.1f}")

        if not anomalies:
            print(f"  ✓  [ANOMALY] No statistical anomalies detected "
                  f"({len(profile.get('columns', {}))} columns checked).")
        else:
            self.gov._event("ANOMALY", "ANOMALY_SUMMARY",
                            {"anomaly_count": len(anomalies),
                             "columns": [a["column"] for a in anomalies]},
                            level="WARNING")

        # Update the baseline with current run's stats.
        self._update_baseline(baseline, profile, source_key)
        return anomalies

    # ── Internals ─────────────────────────────────────────────────────────

    def _load_baseline(self) -> dict:
        if not self.BASELINE_FILE.exists():
            return {}
        with open(self.BASELINE_FILE, encoding="utf-8") as f:
            return json.load(f)

    def _update_baseline(self, baseline: dict, profile: dict, source_key: str) -> None:
        for col, stats in profile.get("columns", {}).items():
            key = f"{source_key}::{col}"
            record = {
                "mean"        : stats.get("mean"),
                "std"         : stats.get("std"),
                "null_pct"    : stats.get("null_pct", 0),
                "unique_count": stats.get("unique_count", 0),
                "timestamp"   : datetime.now(timezone.utc).isoformat(),
            }
            baseline.setdefault(key, []).append(record)
            # Keep only the last DEFAULT_WINDOW entries.
            baseline[key] = baseline[key][-self.DEFAULT_WINDOW:]
        with open(self.BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, default=str)


# ═════════════════════════════════════════════════════════════════════════════
#  ⑧ COLUMN QUALITY SCORER
# ═════════════════════════════════════════════════════════════════════════════
class ColumnQualityScorer:
    """
    Computes a per-column quality score (0–100) and writes a structured report.

    Score components (weighted average)
    ------------------------------------
    completeness  (40%)  — 1 - null_pct.  A column with 0% nulls scores 100.
    validity      (35%)  — GX pass rate for expectations targeting this column.
                           Columns with no GX expectations default to 100.
    uniqueness    (15%)  — Unique value ratio (unique_count / row_count).
                           Capped at 1.0 for high-cardinality columns.
    consistency   (10%)  — 1 if dtype matches expected type family;
                           0 if GX ExpectColumnValuesToBeOfType failed.

    Overall table score is the mean of all column scores.

    Output
    ------
    governance_logs/column_quality_<ts>.json:
        { "table_score": 94.2,
          "columns": {
            "email": { "score": 100.0,
                       "completeness": 1.0, "validity": 1.0,
                       "uniqueness": 1.0, "consistency": 1.0 },
            "salary": { "score": 75.0, ...}, ...
          }
        }
    """

    WEIGHTS = {"completeness": 0.40, "validity": 0.35,
               "uniqueness": 0.15, "consistency": 0.10}

    def __init__(self, gov) -> None:
        self.gov = gov

    def score(
        self,
        profile:          dict,
        val_results:      list[dict] = (),
        log_dir:          str        = "governance_logs",
    ) -> dict:
        """
        Compute per-column quality scores.

        Parameters
        ----------
        profile      : dict         From DataProfiler.profile().
        val_results  : list[dict]   From GovernanceLogger.validation_results.
        log_dir      : str          Output directory.

        Returns
        -------
        dict  { "table_score": float, "columns": { col: { "score": float, ... } } }
        """
        row_count  = profile.get("table", {}).get("row_count", 1)
        col_stats  = profile.get("columns", {})

        # Build a per-column GX result map.
        gx_col_results: dict[str, list[bool]] = {}
        for r in val_results:
            col = r.get("column")
            if col:
                gx_col_results.setdefault(col, []).append(r.get("success", True))

        col_scores: dict = {}
        for col, stats in col_stats.items():
            null_pct    = stats.get("null_pct", 0)
            unique_count= stats.get("unique_count", 0)

            completeness = 1.0 - null_pct
            uniqueness   = min(unique_count / max(row_count, 1), 1.0)
            validity     = (sum(gx_col_results[col]) / len(gx_col_results[col])
                            if col in gx_col_results else 1.0)
            consistency  = 1.0  # Degrades if type expectation failed.
            for r in val_results:
                if r.get("column") == col and "Type" in r.get("expectation", ""):
                    consistency = 1.0 if r.get("success") else 0.0

            score = round(
                100 * (
                    self.WEIGHTS["completeness"] * completeness
                    + self.WEIGHTS["validity"]    * validity
                    + self.WEIGHTS["uniqueness"]  * uniqueness
                    + self.WEIGHTS["consistency"] * consistency
                ),
                1,
            )
            col_scores[col] = {
                "score"        : score,
                "completeness" : round(completeness, 4),
                "validity"     : round(validity, 4),
                "uniqueness"   : round(uniqueness, 4),
                "consistency"  : round(consistency, 4),
            }

        table_score = round(
            sum(v["score"] for v in col_scores.values()) / max(len(col_scores), 1), 1
        )
        report = {
            "pipeline_id"  : self.gov.ledger_entries[0]["pipeline_id"]
                             if self.gov.ledger_entries else "",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "table_score"  : table_score,
            "row_count"    : row_count,
            "columns"      : col_scores,
        }

        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(log_dir) / f"column_quality_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        self.gov._event("QUALITY", "COLUMN_QUALITY_SCORED",
                        {"table_score": table_score, "columns_scored": len(col_scores)})
        log.info("[COL QUALITY] Table score=%s  → %s", format(table_score, ".1f"), path)
        print(f"  ✓  [COL QUALITY] Table score: {table_score:.1f}/100  "
              f"({len(col_scores)} columns scored)")
        return report


# ═════════════════════════════════════════════════════════════════════════════
#  ⑨ DATA FRESHNESS CHECKER
# ═════════════════════════════════════════════════════════════════════════════
class DataFreshnessChecker:
    """
    Checks how old the source file is and warns or aborts if it exceeds
    a configurable maximum age.

    Why this matters
    ----------------
    A daily ETL that runs at midnight should always receive a file from
    the same day.  If the upstream system failed to deliver an updated
    file, the pipeline would silently reload yesterday's data, causing
    dashboards to show stale numbers without any alert.

    Checks
    ------
    FILE_MTIME   — File system last-modified timestamp (always available).
    CONTENT_DATE — Parses a date/timestamp column in the data itself and
                   checks the maximum value against now.  More reliable
                   than mtime for files copied between systems.

    on_stale modes
    --------------
    "warn"   — Log a WARNING and continue.
    "abort"  — Raise DataFreshnessError and halt the pipeline.
    """

    def __init__(self, gov) -> None:
        self.gov = gov

    def check_file_mtime(
        self,
        source_path:      str,
        max_age_hours:    float,
        on_stale:         str = "warn",
    ) -> dict:
        """
        Check the file's filesystem modification time.

        Parameters
        ----------
        source_path   : str    Path to the source file.
        max_age_hours : float  Maximum acceptable age in hours.
        on_stale      : str    "warn" | "abort".

        Returns
        -------
        dict  { "fresh": bool, "age_hours": float, "mtime": str }
        """
        try:
            mtime_epoch = os.path.getmtime(source_path)
            mtime       = datetime.fromtimestamp(mtime_epoch, tz=timezone.utc)
            age_hours   = (datetime.now(timezone.utc) - mtime).total_seconds() / 3600
        except OSError as exc:
            log.warning("[FRESHNESS] Could not stat %s: %s", source_path, exc)
            return {"fresh": None, "age_hours": None, "mtime": None}

        fresh   = age_hours <= max_age_hours
        result  = {
            "fresh"      : fresh,
            "age_hours"  : round(age_hours, 2),
            "max_age_hours": max_age_hours,
            "mtime"      : mtime.isoformat(),
            "check_type" : "FILE_MTIME",
        }
        level = "INFO" if fresh else "WARNING"
        self.gov._event("FRESHNESS", "FRESHNESS_CHECK", result, level=level)

        symbol = "✓" if fresh else "⚠"
        status = "fresh" if fresh else f"STALE — {age_hours:.1f}h old (max: {max_age_hours}h)"
        print(f"  {symbol}  [FRESHNESS] {Path(source_path).name}: {status}")

        if not fresh and on_stale == "abort":
            raise DataFreshnessError(
                f"Source file '{source_path}' is {age_hours:.1f}h old "
                f"(max allowed: {max_age_hours}h)."
            )
        return result

    def check_content_date(
        self,
        df:               "pd.DataFrame",
        date_col:         str,
        max_age_hours:    float,
        on_stale:         str = "warn",
    ) -> dict:
        """
        Check freshness based on the maximum value of a date/timestamp column.

        More reliable than mtime because it reflects the actual data date
        rather than when the file was copied or touched.

        Parameters
        ----------
        df            : pd.DataFrame  The loaded DataFrame.
        date_col      : str           Column containing dates/timestamps.
        max_age_hours : float         Maximum acceptable age in hours.
        on_stale      : str           "warn" | "abort".

        Returns
        -------
        dict  { "fresh": bool, "age_hours": float, "max_date": str }
        """
        if date_col not in df.columns:
            log.warning("[FRESHNESS] Date column '%s' not found.", date_col)
            return {"fresh": None, "age_hours": None}

        try:
            parsed    = pd.to_datetime(df[date_col], errors="coerce")
            max_date  = parsed.max()
            if pd.isna(max_date):
                log.warning("[FRESHNESS] No parseable dates in '%s'.", date_col)
                return {"fresh": None, "age_hours": None}
            max_date_utc = max_date.tz_localize("UTC") if max_date.tzinfo is None else max_date
            age_hours    = (datetime.now(timezone.utc) - max_date_utc).total_seconds() / 3600
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.warning("[FRESHNESS] Content date check failed: %s", exc)
            return {"fresh": None, "age_hours": None}

        fresh  = age_hours <= max_age_hours
        result = {
            "fresh"        : fresh,
            "age_hours"    : round(age_hours, 2),
            "max_age_hours": max_age_hours,
            "max_date"     : max_date_utc.isoformat(),
            "date_col"     : date_col,
            "check_type"   : "CONTENT_DATE",
        }
        self.gov._event("FRESHNESS", "CONTENT_FRESHNESS_CHECK", result,
                        level="INFO" if fresh else "WARNING")

        symbol = "✓" if fresh else "⚠"
        status = "fresh" if fresh else f"STALE — newest record is {age_hours:.1f}h old"
        print(f"  {symbol}  [FRESHNESS] '{date_col}' content: {status}")

        if not fresh and on_stale == "abort":
            raise DataFreshnessError(
                f"Data in '{date_col}' is {age_hours:.1f}h old "
                f"(max allowed: {max_age_hours}h)."
            )
        return result


class DataFreshnessError(RuntimeError):
    """Raised by DataFreshnessChecker in abort mode."""


# ═════════════════════════════════════════════════════════════════════════════
#  ⑩ COLUMN PURPOSE REGISTRY
# ═════════════════════════════════════════════════════════════════════════════
class ColumnPurposeRegistry:
    """
    Records a specific GDPR Art. 5(1)(b) processing purpose for each PII
    column individually, rather than one purpose covering the whole table.

    GDPR Art. 5(1)(b) — Purpose Limitation
    "Personal data shall be collected for specified, explicit and legitimate
    purposes and not further processed in a manner that is incompatible with
    those purposes."

    Why column-level purposes matter
    ---------------------------------
    A table may contain:
      email   → used for transactional notifications
      salary  → used only for payroll processing
      phone   → used only for 2FA / emergency contact
      dob     → used only for age-gating and regulatory reporting

    These are four separate lawful purposes under Art. 5(1)(b).  Storing
    a single purpose ("HR data analysis") for all of them is technically
    non-compliant.  A DPA audit may ask to see the purpose recorded per
    data element.

    State file
    ----------
    column_purpose.json  — Keyed by "{source}::{column}":
        { "employees.csv::email": {
            "purpose": "Transactional notifications",
            "lawful_basis": "Contract",
            "retention_days": 365,
            "data_controller": "HR Department",
            "registered_at": "...",
            "registered_by": "..." } }
    """

    REGISTRY_FILE = _BASE_DIR / "column_purpose.json"

    def __init__(self, gov) -> None:
        self.gov = gov

    def register(
        self,
        source_path:    str,
        column:         str,
        purpose:        str,
        lawful_basis:   str,
        retention_days: int | None = None,
        data_controller:str        = "",
    ) -> None:
        """
        Register a processing purpose for a single PII column.

        Parameters
        ----------
        source_path     : str        Source file identifier.
        column          : str        Column name.
        purpose         : str        Processing purpose (e.g. "Payroll processing").
        lawful_basis    : str        GDPR Art. 6 lawful basis.
        retention_days  : int | None Retention period specific to this column.
        data_controller : str        Data controller for this column.
        """
        import getpass
        registry = self._load()
        key = f"{Path(source_path).name}::{column}"
        registry[key] = {
            "source_path"   : str(Path(source_path).name),
            "column"        : column,
            "purpose"       : purpose,
            "lawful_basis"  : lawful_basis,
            "retention_days": retention_days,
            "data_controller": data_controller,
            "gdpr_reference": "Art. 5(1)(b) — Purpose Limitation",
            "registered_at" : datetime.now(timezone.utc).isoformat(),
            "registered_by" : getpass.getuser(),
        }
        self._save(registry)
        self.gov._event("PRIVACY", "COLUMN_PURPOSE_REGISTERED",
                        {"column": column, "purpose": purpose,
                         "lawful_basis": lawful_basis,
                         "gdpr_reference": "Art. 5(1)(b)"})

    def register_bulk(
        self,
        source_path:  str,
        pii_findings: list[dict],
        default_purpose:    str = "",
        default_basis:      str = "Legitimate Interests",
        interactive:        bool= True,
    ) -> None:
        """
        Register processing purposes for all PII columns at once.

        In interactive mode, prompts the user for each column.
        In non-interactive mode, uses the defaults for all columns.

        Parameters
        ----------
        source_path     : str         Source file identifier.
        pii_findings    : list[dict]  PII findings from _detect_pii().
        default_purpose : str         Default purpose string.
        default_basis   : str         Default lawful basis.
        interactive     : bool        Prompt per-column in interactive mode.
        """
        if not pii_findings:
            return

        bases = {
            "1":"Consent","2":"Contract","3":"Legal Obligation",
            "4":"Vital Interests","5":"Public Task","6":"Legitimate Interests",
        }

        if interactive:
            print("\n" + "═" * 64)
            print("  COLUMN PURPOSE REGISTRY  (GDPR Art. 5(1)(b))")
            print("═" * 64)
            print("  Register a specific processing purpose for each PII column.")
            print("  This satisfies purpose-limitation requirements per data element.\n")

        for finding in pii_findings:
            col = finding["field"]
            if interactive:
                print(f"  Column: {col}"
                      f"{'  ⚠ SPECIAL CATEGORY' if finding.get('special_category') else ''}")
                purpose = input(f"    Purpose (or Enter for '{default_purpose}'): ").strip()
                purpose = purpose or default_purpose or f"Processing of {col}"
                print("    Lawful basis: " + "  ".join(f"{k}.{v}" for k, v in bases.items()))
                choice = input("    Basis [6]: ").strip()
                basis  = bases.get(choice, default_basis)
                ret    = input("    Retention days (Enter to inherit run default): ").strip()
                try:
                    retention = int(ret)
                except ValueError:
                    retention = None
                ctrl = input("    Data controller (Enter to skip): ").strip()
            else:
                purpose   = default_purpose or f"Processing of {col}"
                basis     = default_basis
                retention = None
                ctrl      = ""

            self.register(source_path, col, purpose, basis, retention, ctrl)

        count = len(pii_findings)
        log.info("[PURPOSE] %s PII column purpose(s) registered.", count)
        print(f"  ✓  [PURPOSE] {count} column purpose(s) recorded.")

    def get(self, source_path: str, column: str) -> dict | None:
        """Return the registered purpose for a column, or None."""
        key = f"{Path(source_path).name}::{column}"
        return self._load().get(key)

    def export_art30_records(self, output_path: str = "art30_processing_records.json") -> str:
        """
        Export all registered column purposes in GDPR Art. 30 record format.

        Art. 30 requires controllers to maintain records of processing
        activities including: purposes, categories of data, recipients,
        transfers, and retention.  This export provides per-column detail.
        """
        registry = self._load()
        records  = {
            "gdpr_article"          : "Article 30 — Records of Processing Activities",
            "generated_utc"         : datetime.now(timezone.utc).isoformat(),
            "processing_activities" : list(registry.values()),
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        log.info("[PURPOSE] Art. 30 records exported → %s", output_path)
        return output_path

    def _load(self) -> dict:
        if not self.REGISTRY_FILE.exists():
            return {}
        with open(self.REGISTRY_FILE, encoding="utf-8") as f:
            return json.load(f)

    def _save(self, registry: dict) -> None:
        with open(self.REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(registry, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  ⑪ RECORD PROVENANCE HASHER
# ═════════════════════════════════════════════════════════════════════════════
class RecordProvenanceHasher:
    """
    Appends a _source_row_hash column to every loaded record.

    The hash is a SHA-256 of the original raw field values (before any
    transformation — masking, type coercion, enrichment, etc.) so that
    post-load auditors can prove what the source data was for any given
    record, independently of the source file still existing.

    How it works
    ------------
    Before transformation: compute a deterministic SHA-256 over every
    source column's value, concatenated with a separator.  Store it in
    _source_row_hash.  After transformation, this column survives into
    the loaded table.

    Given the same source row, _source_row_hash will always be the same
    value regardless of which run loaded it.  This lets you:
      • Detect if a "re-loaded" record was actually different at source.
      • Prove to an auditor what the original email/salary/etc. was
        (by re-hashing the alleged original values and comparing).
      • Identify if two records in different tables came from the same
        source row (hash collision implies identity).

    Security note
    -------------
    For datasets with low-cardinality PII (e.g. a small employee table),
    a hash alone may be reversible by brute force.  In those cases,
    consider adding a pipeline-specific salt via the salt parameter.

    Usage
    -----
        hasher  = RecordProvenanceHasher(gov)
        df_raw  = hasher.attach(df_raw)    # call BEFORE transform
        # ...transform, load...
        # df loaded will contain _source_row_hash column
    """

    def __init__(self, gov, salt: str = "") -> None:
        """
        Parameters
        ----------
        gov  : GovernanceLogger
        salt : str  Optional pipeline-specific salt prepended to each row's
                    value string before hashing.  Prevents brute-force reversal
                    on small datasets.  Store the salt alongside the pipeline
                    config — it must be the same on every run for hashes to match.
        """
        self.gov  = gov
        self._salt= salt

    def attach(
        self,
        df:            "pd.DataFrame",
        exclude_cols:  list[str] = (),
    ) -> "pd.DataFrame":
        """
        Compute and attach _source_row_hash to each row.

        Parameters
        ----------
        df           : pd.DataFrame  Raw source DataFrame (call BEFORE transform).
        exclude_cols : list[str]     Columns to exclude from hashing
                                     (e.g. auto-generated IDs that vary per run).

        Returns
        -------
        pd.DataFrame  Same DataFrame with _source_row_hash column added.
        """
        hash_cols = [c for c in df.columns if c not in set(exclude_cols)]

        def _row_hash(row) -> str:
            # Sort columns for determinism regardless of DataFrame column order.
            values = [f"{c}={row[c]}" for c in sorted(hash_cols)]
            raw    = (self._salt + "|").join(values) if self._salt else "|".join(values)
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()

        df = df.copy()
        df["_source_row_hash"] = df.apply(_row_hash, axis=1)

        self.gov._event("LINEAGE", "RECORD_PROVENANCE_ATTACHED",
                        {"rows": len(df), "hashed_columns": len(hash_cols),
                         "salted": bool(self._salt)})
        log.info("[PROVENANCE] _source_row_hash attached to %s rows.", len(df))
        return df

    def verify(
        self,
        original_values: dict,
        stored_hash:     str,
        hash_cols:       list[str],
    ) -> bool:
        """
        Verify a stored hash against re-computed values.

        Use this in an audit to confirm what a record's original values were.

        Parameters
        ----------
        original_values : dict       { col: value } for all hashed columns.
        stored_hash     : str        The _source_row_hash value from the DB.
        hash_cols       : list[str]  The columns that were hashed (must match).

        Returns
        -------
        bool  True if original_values reproduce the stored_hash.
        """
        values = [f"{c}={original_values.get(c)}" for c in sorted(hash_cols)]
        raw    = (self._salt + "|").join(values) if self._salt else "|".join(values)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest() == stored_hash


# ═════════════════════════════════════════════════════════════════════════════
#  ⑫ DBT RESULTS INTEGRATOR
# ═════════════════════════════════════════════════════════════════════════════
class DbtResultsIntegrator:
    """
    Reads dbt's run_results.json and sources.json and appends dbt test
    results to the governance audit ledger and quality history.

    Why this matters
    ----------------
    This pipeline uses Great Expectations for pre-load validation.
    Downstream dbt projects use dbt tests for post-load validation.
    Without integration, a data consumer sees:
      • GX results in governance_logs/  (pre-load)
      • dbt test results in dbt's target/ directory  (post-load)
    ...as two separate, unlinked quality pictures.

    With this integrator, both are merged into the same audit ledger
    and quality history, giving a unified end-to-end quality view.

    dbt files consumed
    ------------------
    target/run_results.json  — Test pass/fail for the last `dbt test` run.
    target/sources.json      — Source freshness check results.
    manifest.json            — Model/test metadata (column descriptions, tags).

    What gets imported
    ------------------
    • Per-test pass/fail status and failure messages.
    • Model-level row counts (if `store_failures` is enabled in dbt).
    • Source freshness status (max_loaded_at vs warn_after / error_after).
    • Test metadata: model name, column name, test type, severity.

    These are appended to:
      • The governance audit ledger (category: DBT_TEST).
      • quality_history.jsonl (so quality trending includes dbt results).
    """

    def __init__(self, gov) -> None:
        self.gov = gov

    def ingest(
        self,
        dbt_project_dir: str,
        table:           str,
        quality_history: "QualityHistoryTracker | None" = None,
    ) -> dict:
        """
        Ingest the latest dbt test results for a given table/model.

        Parameters
        ----------
        dbt_project_dir : str                  Path to the dbt project root.
        table           : str                  Model / table name to filter for.
        quality_history : QualityHistoryTracker | None
                          If provided, appends dbt results to quality history.

        Returns
        -------
        dict  Summary: { "tests_total": int, "tests_passed": int,
                          "tests_failed": int, "pass_rate": float,
                          "failures": list[dict] }
        """
        run_results_path = Path(dbt_project_dir) / "target" / "run_results.json"
        manifest_path    = Path(dbt_project_dir) / "target" / "manifest.json"

        if not run_results_path.exists():
            log.warning("[DBT] run_results.json not found at %s", run_results_path)
            return {"tests_total": 0, "tests_passed": 0,
                    "tests_failed": 0, "pass_rate": 1.0, "failures": []}

        with open(run_results_path, encoding="utf-8") as f:
            run_results = json.load(f)

        # Load manifest for test metadata (optional).
        manifest: dict = {}
        if manifest_path.exists():
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)

        dbt_metadata = run_results.get("metadata", {})
        results      = run_results.get("results", [])

        # Filter to tests related to this table/model.
        table_tests = [
            r for r in results
            if table.lower() in r.get("unique_id", "").lower()
            and r.get("unique_id", "").startswith("test.")
        ]

        if not table_tests:
            log.info("[DBT] No tests found for model '%s' in run_results.json", table)

        total   = len(table_tests)
        passed  = sum(1 for r in table_tests if r.get("status") == "pass")
        failed  = total - passed
        failures: list[dict] = []

        for result in table_tests:
            uid      = result.get("unique_id", "")
            status   = result.get("status", "unknown")
            failures_val = result.get("failures", 0) or 0

            # Pull test metadata from manifest.
            node_meta = manifest.get("nodes", {}).get(uid, {})
            test_meta = {
                "unique_id"  : uid,
                "test_name"  : node_meta.get("name", uid.split(".")[-1]),
                "model"      : node_meta.get("attached_node", "").split(".")[-1],
                "column"     : node_meta.get("column_name", ""),
                "test_type"  : node_meta.get("test_metadata", {}).get("name", ""),
                "severity"   : node_meta.get("config", {}).get("severity", "error"),
                "status"     : status,
                "failures"   : failures_val,
                "message"    : result.get("message", ""),
                "execution_time": result.get("execution_time", 0),
            }

            # Emit one audit event per test.
            level = "INFO" if status == "pass" else "WARNING"
            self.gov._event("DBT_TEST", f"DBT_TEST_{status.upper()}", test_meta,
                            level=level)

            if status != "pass":
                failures.append(test_meta)

        pass_rate = passed / total if total else 1.0
        summary   = {
            "dbt_version"   : dbt_metadata.get("dbt_version", "unknown"),
            "generated_at"  : dbt_metadata.get("generated_at", ""),
            "model"         : table,
            "tests_total"   : total,
            "tests_passed"  : passed,
            "tests_failed"  : failed,
            "pass_rate"     : round(pass_rate, 4),
            "failures"      : failures,
        }
        self.gov._event("DBT_TEST", "DBT_RESULTS_INGESTED",
                        {k: v for k, v in summary.items() if k != "failures"})

        print(f"  {'✓' if failed == 0 else '⚠'}  "
              f"[DBT] {table}: {passed}/{total} tests passed  "
              f"(pass_rate={pass_rate:.0%})")

        if quality_history and total > 0:
            quality_history.append(
                source_path    = f"dbt::{table}",
                table          = table,
                row_count      = 0,
                pass_rate      = pass_rate,
                exp_total      = total,
                exp_passed     = passed,
                dlq_rows       = 0,
                classification = "INTERNAL",
                pii_count      = 0,
            )

        # Ingest source freshness if available.
        self._ingest_source_freshness(dbt_project_dir, table)
        return summary

    def _ingest_source_freshness(self, dbt_project_dir: str, table: str) -> None:
        """Read sources.json and log freshness results for this table."""
        sources_path = Path(dbt_project_dir) / "target" / "sources.json"
        if not sources_path.exists():
            return
        with open(sources_path, encoding="utf-8") as f:
            sources = json.load(f)
        for result in sources.get("results", []):
            if table.lower() not in result.get("unique_id", "").lower():
                continue
            status   = result.get("status", "unknown")
            criteria = result.get("criteria", {})
            self.gov._event("DBT_TEST", "DBT_SOURCE_FRESHNESS",
                            {"unique_id"   : result.get("unique_id"),
                             "status"      : status,
                             "warn_after"  : criteria.get("warn_after"),
                             "error_after" : criteria.get("error_after"),
                             "max_loaded_at": result.get("max_loaded_at", "")},
                            level="INFO" if status in ("pass","warn") else "WARNING")


# ═════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATOR  — runs all extensions in one call from main()
# ═════════════════════════════════════════════════════════════════════════════
class MetadataExtensionOrchestrator:
    """
    Convenience class that wires all 12 extensions into the pipeline.

    Instantiate once in main() and call the appropriate hook methods at
    each stage of the pipeline.  Keeps pipeline_v3.py main() clean — all
    extension logic stays in this module.

    Hooks
    -----
    on_extract(df, source_path)
        → DataFreshnessChecker  (file mtime check)
        → SchemaDriftDetector   (schema comparison)
        → RecordProvenanceHasher.attach(df)
        → OpenLineageEmitter.emit_start()

    on_profile(profile, source_path)
        → AnomalyDetector.check()

    on_pii(df, pii_findings, source_path)
        → ColumnPurposeRegistry.register_bulk()

    on_post_transform(df_before, df_after, pii_findings, compliance)
        → ColumnLineageTracker.infer_from_dataframes()

    on_post_validation(profile, val_results)
        → ColumnQualityScorer.score()

    on_pre_load(df, contract_path, pii_findings)
        → DataContractValidator.validate()

    on_post_load(df, subject_col, source_path, db_type, db_name, table,
                 df_in, df_out, quality)
        → DSARIndex.index_dataset()
        → QualityHistoryTracker.append() + check_regression()
        → OpenLineageEmitter.emit_complete()

    on_complete(log_dir, dbt_project_dir, table)
        → ColumnLineageTracker.write_report()
        → DbtResultsIntegrator.ingest()

    on_fail(source_path, error)
        → OpenLineageEmitter.emit_fail()
    """

    def __init__(self, gov, config: dict | None = None) -> None:
        cfg = config or {}
        self.gov    = gov
        self.cfg    = cfg

        self.schema_drift   = SchemaDriftDetector(gov)
        # ⑧ Multi-hop lineage: merge parent_run_id into OL config if provided
        _ol_cfg = cfg.get("openlineage", {})
        if cfg.get("parent_run_id") and "parent_run_id" not in _ol_cfg:
            _ol_cfg = {**_ol_cfg, "parent_run_id": cfg["parent_run_id"]}
        self.ol_emitter     = OpenLineageEmitter(gov, _ol_cfg)
        self.col_lineage    = ColumnLineageTracker(gov)
        self.dsar           = DSARIndex(gov)
        self.contract_val   = DataContractValidator(gov)
        self.quality_hist   = QualityHistoryTracker(gov)
        self.anomaly        = AnomalyDetector(gov)
        self.col_quality    = ColumnQualityScorer(gov)
        self.freshness      = DataFreshnessChecker(gov)
        self.purpose_reg    = ColumnPurposeRegistry(gov)
        self.provenance     = RecordProvenanceHasher(gov, salt=cfg.get("provenance_salt", ""))
        self.dbt            = DbtResultsIntegrator(gov)

        # Stash df_before for column lineage diffing.
        self._df_before:    "pd.DataFrame | None" = None
        self._source_path:  str = ""
        self._df_in:        "pd.DataFrame | None" = None

    # ── Pipeline hooks ─────────────────────────────────────────────────────

    def on_extract(
        self,
        df:          "pd.DataFrame",
        source_path: str,
    ) -> "pd.DataFrame":
        """Call immediately after extraction, before any transformation."""
        self._source_path = source_path
        self._df_in       = df.copy()

        # Freshness check.
        fc = self.cfg.get("freshness", {})
        if fc.get("max_age_hours"):
            self.freshness.check_file_mtime(
                source_path,
                max_age_hours = fc["max_age_hours"],
                on_stale      = fc.get("on_stale", "warn"),
            )
        if fc.get("content_date_col"):
            self.freshness.check_content_date(
                df, fc["content_date_col"],
                max_age_hours = fc.get("max_age_hours", 48),
                on_stale      = fc.get("on_stale", "warn"),
            )

        # Schema drift.
        sd = self.cfg.get("schema_drift", {})
        self.schema_drift.check(
            df, source_path,
            on_added       = sd.get("on_added",       "warn"),
            on_removed     = sd.get("on_removed",     "abort"),
            on_type_change = sd.get("on_type_change", "abort"),
        )

        # Provenance hashing (before any transformation).
        if self.cfg.get("record_provenance", True):
            df = self.provenance.attach(df,
                exclude_cols=self.cfg.get("provenance_exclude_cols", []))

        # OpenLineage START.
        if self.cfg.get("openlineage", {}).get("enabled", True):
            self.ol_emitter.emit_start(source_path)

        # Save pre-transform snapshot for column lineage diffing.
        self._df_before = df.copy()
        return df

    def on_profile(self, profile: dict, source_path: str) -> list[dict]:
        """Call after DataProfiler.profile()."""
        return self.anomaly.check(
            profile, source_path,
            threshold = self.cfg.get("anomaly_threshold", 3.0),
            window    = self.cfg.get("anomaly_window", 10),
        )

    def on_pii(
        self,
        _df:          "pd.DataFrame",
        pii_findings: list[dict],
        source_path:  str,
        interactive:  bool = True,
    ) -> None:
        """Call after PII detection and classification."""
        if self.cfg.get("column_purpose", {}).get("enabled", False):
            self.purpose_reg.register_bulk(
                source_path,
                pii_findings,
                default_purpose = self.cfg["column_purpose"].get("default_purpose", ""),
                default_basis   = self.cfg["column_purpose"].get("default_basis",
                                                                    "Legitimate Interests"),
                interactive     = interactive,
            )

    def on_post_transform(
        self,
        df_after:    "pd.DataFrame",
        pii_findings: list[dict],
        compliance:  dict,
        renamed_cols: dict | None = None,
    ) -> None:
        """Call after Transformer.transform()."""
        if self._df_before is not None:
            pii_set     = {f["field"] for f in pii_findings}
            masked_cols = list(pii_set) if compliance.get("pii_strategy") == "mask" else []
            dropped_cols= compliance.get("drop_cols", [])
            self.col_lineage.infer_from_dataframes(
                self._df_before, df_after,
                pii_fields  = list(pii_set),
                masked_cols = masked_cols,
                dropped_cols= dropped_cols,
                renamed     = renamed_cols or {},
            )

    def on_post_validation(
        self,
        profile:     dict,
        val_results: list[dict],
        log_dir:     str = "governance_logs",
    ) -> dict:
        """Call after SchemaValidator.validate(). Returns column quality report."""
        return self.col_quality.score(profile, val_results, log_dir)

    def on_pre_load(
        self,
        df:            "pd.DataFrame",
        pii_findings:  list[dict],
    ) -> list[dict]:
        """Call after validation, before load. Returns contract violations (may be empty)."""
        contract_path = self.cfg.get("data_contract_path")
        if not contract_path or not Path(contract_path).exists():
            return []
        try:
            contract   = self.contract_val.load_contract(contract_path)
            violations = self.contract_val.validate(
                df, contract,
                pii_findings = pii_findings,
                on_failure   = self.cfg.get("contract_on_failure", "warn"),
            )
            return violations
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.error("[CONTRACT] Validation failed: %s", exc)
            return []

    def on_post_load(
        self,
        df:           "pd.DataFrame",
        source_path:  str,
        db_type:      str,
        db_name:      str,
        table:        str,
        pii_findings: list[dict],
        quality_meta: dict,
        classification: str,
    ) -> None:
        """Call after successful load."""
        # DSAR index — use pre-transform _df_in so subject hashes match raw
        # values (real emails), not SHA-256 masked ones in the output df.
        dsar_df = self._df_in if self._df_in is not None else df
        subject_col = self.cfg.get("dsar_subject_col")
        if subject_col and subject_col in dsar_df.columns:
            self.dsar.index_dataset(
                dsar_df, subject_col, source_path, db_type, db_name, table
            )
        elif pii_findings:
            candidates = [f["field"] for f in pii_findings
                          if "email" in f["field"].lower() and f["field"] in dsar_df.columns]
            if not candidates:
                candidates = [f["field"] for f in pii_findings if f["field"] in dsar_df.columns]
            if candidates:
                self.dsar.index_dataset(
                    dsar_df, candidates[0], source_path, db_type, db_name, table
                )

        # Quality history + regression check.
        q = quality_meta
        self.quality_hist.append(
            source_path    = source_path,
            table          = table,
            row_count      = len(df),
            pass_rate      = q.get("pass_rate", 1.0),
            exp_total      = q.get("expectations_total", 0),
            exp_passed     = q.get("expectations_passed", 0),
            dlq_rows       = q.get("dlq_rows", 0),
            classification = classification,
            pii_count      = len(pii_findings),
        )
        self.quality_hist.check_regression(
            table  = table,
            window = self.cfg.get("regression_window", 5),
        )

        # OpenLineage COMPLETE.
        if self.cfg.get("openlineage", {}).get("enabled", True) and self._df_in is not None:
            self.ol_emitter.emit_complete(
                source_path = source_path,
                db_type     = db_type,
                db_name     = db_name,
                table       = table,
                df_in       = self._df_in,
                df_out      = df,
                quality     = quality_meta,
            )

    def on_complete(
        self,
        log_dir:         str = "governance_logs",
        dbt_project_dir: str | None = None,
        table:           str = "",
    ) -> None:
        """Call at the very end of a successful pipeline run."""
        # Column lineage report.
        if self.col_lineage.mappings:
            self.col_lineage.write_report(log_dir)

        # dbt results.
        if dbt_project_dir and table:
            self.dbt.ingest(dbt_project_dir, table, self.quality_hist)

    def on_fail(self, source_path: str, error: str) -> None:
        """Call if the pipeline exits with an exception."""
        if self.cfg.get("openlineage", {}).get("enabled", True):
            self.ol_emitter.emit_fail(source_path, error)


# ═════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE CONFIG WIZARD  (called from prompt_v3_features in pipeline_v3)
# ═════════════════════════════════════════════════════════════════════════════
def prompt_metadata_extensions_config(columns: list[str]) -> dict:
    """
    Interactive wizard for all 12 metadata extension features.
    Returns a config dict for MetadataExtensionOrchestrator.
    """
    def yn(msg, default=False):
        suffix = "[Y/n]" if default else "[y/N]"
        r = input(f"{msg} {suffix}: ").strip().lower()
        return default if not r else r in ("y","yes")
    def prompt(msg, default=""):
        r = input(f"{msg} [{default}]: " if default else f"{msg}: ").strip()
        return r or default

    cfg: dict = {}

    print("\n" + "═" * 64)
    print("  METADATA EXTENSIONS  (12 additional features)")
    print("═" * 64)

    # ① Schema drift
    if yn("\n[①] Enable schema drift detection?", True):
        cfg["schema_drift"] = {
            "on_added"      : prompt("  on_added (warn/ignore)", "warn"),
            "on_removed"    : prompt("  on_removed (warn/abort)", "abort"),
            "on_type_change": prompt("  on_type_change (warn/abort)", "abort"),
        }

    # ② OpenLineage
    if yn("\n[②] Enable OpenLineage event emission?", True):
        transport = prompt("  Transport (file/http)", "file")
        ol_cfg: dict = {"enabled": True, "transport": transport}
        if transport == "http":
            ol_cfg["transport_url"] = prompt("  Marquez/OpenLineage URL")
            ol_cfg["job_namespace"] = prompt("  Job namespace", "data-governance-pipeline")
        cfg["openlineage"] = ol_cfg

    # ③ Column lineage — always on if schema drift is on
    # (inferred automatically — no separate config needed)

    # ④ DSAR index
    if yn("\n[④] Enable DSAR index (GDPR Art.15/17)?", True):
        print(f"  Columns: {', '.join(columns[:12])}")
        cfg["dsar_subject_col"] = prompt("  Subject identifier column (e.g. email)", "email")

    # ⑤ Data contract
    if yn("\n[⑤] Validate against a data contract?", False):
        cp = prompt("  Path to contract YAML file")
        if Path(cp).exists():
            cfg["data_contract_path"]   = cp
            cfg["contract_on_failure"]  = prompt("  on_failure (warn/abort)", "warn")
        else:
            print(f"  File not found: {cp}  (skipping)")

    # ⑥ Quality history — always enabled
    cfg["regression_window"] = int(prompt("\n[⑥] Quality regression window (runs)", "5"))

    # ⑦ Anomaly detection
    if yn("\n[⑦] Enable statistical anomaly detection?", True):
        cfg["anomaly_threshold"] = float(prompt("  Z-score threshold", "3.0"))
        cfg["anomaly_window"]    = int(prompt("  Baseline window (runs)", "10"))

    # ⑧ Column quality scoring — always enabled (no config needed)

    # ⑨ Data freshness
    if yn("\n[⑨] Enable data freshness check?", False):
        cfg["freshness"] = {
            "max_age_hours": float(prompt("  Max source age (hours)", "48")),
            "on_stale"     : prompt("  on_stale (warn/abort)", "warn"),
        }
        print(f"  Columns: {', '.join(columns[:12])}")
        date_col = prompt("  Content date column (Enter to use file mtime only)", "")
        if date_col and date_col in columns:
            cfg["freshness"]["content_date_col"] = date_col

    # ⑩ Column purpose registry
    if yn("\n[⑩] Register per-column processing purposes (GDPR Art.5)?", False):
        cfg["column_purpose"] = {
            "enabled"        : True,
            "default_purpose": prompt("  Default purpose", "Data processing"),
            "default_basis"  : prompt("  Default lawful basis", "Legitimate Interests"),
        }

    # ⑪ Record provenance hashing — always enabled
    cfg["record_provenance"] = True
    if yn("\n[⑪] Add salt to provenance hashes (recommended)?", False):
        cfg["provenance_salt"] = prompt("  Salt string (store this securely)")

    # ⑫ dbt integration
    if yn("\n[⑫] Integrate dbt test results?", False):
        dbt_dir = prompt("  dbt project directory")
        if Path(dbt_dir).exists():
            cfg["dbt_project_dir"] = dbt_dir
        else:
            print(f"  Directory not found: {dbt_dir}  (skipping)")

    return cfg
