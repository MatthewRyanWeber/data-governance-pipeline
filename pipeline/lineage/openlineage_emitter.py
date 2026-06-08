"""
OpenLineage-compatible event emitter.

Emits lineage events in the OpenLineage JSON spec so this pipeline
can integrate with Marquez, DataHub, or OpenMetadata as consumers.

Spec: https://openlineage.io/spec/2-0-2/OpenLineage.json

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Add dry_run, thread lock, quality_threshold ctor param,
                   ImportError guard in _post_event, extract _persist_event.
"""

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import VERSION

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_OL_SCHEMA = "https://openlineage.io/spec/2-0-2/OpenLineage.json"
_PRODUCER = f"data-governance-pipeline/{VERSION}"


class OpenLineageEmitter:
    """
    Emits OpenLineage-compatible JSON events for pipeline runs.

    Quick-start
    -----------
        from pipeline.lineage import OpenLineageEmitter
        emitter = OpenLineageEmitter(gov, namespace="production")
        emitter.emit_start("extract", inputs=["s3://bucket/raw.csv"])
        emitter.emit_complete("extract", outputs=["postgres://db/staging"])
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        namespace: str = "data-governance-pipeline",
        output_file: str | Path | None = None,
        http_endpoint: str | None = None,
        quality_threshold: float = 70.0,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.namespace = namespace
        self.output_file = (
            Path(output_file) if output_file
            else gov.log_dir / "openlineage_events.jsonl"
        )
        self.http_endpoint = http_endpoint
        self.quality_threshold = quality_threshold
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self._run_id = str(uuid.uuid4())

    def emit_start(
        self,
        job_name: str,
        inputs: list[str | dict] | None = None,
        outputs: list[str | dict] | None = None,
        facets: dict | None = None,
    ) -> dict:
        """Emit a START event for a job."""
        return self._emit("START", job_name, inputs, outputs, facets)

    def emit_complete(
        self,
        job_name: str,
        inputs: list[str | dict] | None = None,
        outputs: list[str | dict] | None = None,
        facets: dict | None = None,
    ) -> dict:
        """Emit a COMPLETE event for a job."""
        return self._emit("COMPLETE", job_name, inputs, outputs, facets)

    def emit_fail(
        self,
        job_name: str,
        error_message: str = "",
        inputs: list[str | dict] | None = None,
        outputs: list[str | dict] | None = None,
    ) -> dict:
        """Emit a FAIL event for a job."""
        facets = {}
        if error_message:
            facets["errorMessage"] = {
                "_producer": _PRODUCER,
                "_schemaURL": _OL_SCHEMA,
                "message": error_message,
                "programmingLanguage": "python",
            }
        return self._emit("FAIL", job_name, inputs, outputs, facets)

    def emit_dataset_facets(
        self,
        job_name: str,
        dataset_name: str,
        schema_fields: list[dict] | None = None,
        row_count: int | None = None,
        quality_score: float | None = None,
    ) -> dict:
        """Emit an event with dataset-level facets (schema, quality, volume)."""
        output_facets: dict = {}

        if schema_fields:
            output_facets["schema"] = {
                "_producer": _PRODUCER,
                "_schemaURL": _OL_SCHEMA,
                "fields": schema_fields,
            }

        if row_count is not None:
            output_facets["dataQualityMetrics"] = {
                "_producer": _PRODUCER,
                "_schemaURL": _OL_SCHEMA,
                "rowCount": row_count,
            }

        if quality_score is not None:
            output_facets["dataQualityAssertions"] = {
                "_producer": _PRODUCER,
                "_schemaURL": _OL_SCHEMA,
                "assertions": [{
                    "assertion": "qualityScore",
                    "success": quality_score >= self.quality_threshold,
                    "column": "*",
                }],
            }

        outputs = [{
            "namespace": self.namespace,
            "name": dataset_name,
            "facets": output_facets,
        }]
        return self._emit("COMPLETE", job_name, outputs=outputs)

    def _emit(
        self,
        event_type: str,
        job_name: str,
        inputs: list | None = None,
        outputs: list | None = None,
        facets: dict | None = None,
    ) -> dict:
        """Build and emit an OpenLineage event."""
        event = {
            "eventType": event_type,
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "run": {
                "runId": self._run_id,
                "facets": facets or {},
            },
            "job": {
                "namespace": self.namespace,
                "name": job_name,
                "facets": {
                    "jobType": {
                        "_producer": _PRODUCER,
                        "_schemaURL": _OL_SCHEMA,
                        "processingType": "BATCH",
                        "integration": "DATA_GOVERNANCE_PIPELINE",
                        "jobType": "TASK",
                    }
                },
            },
            "inputs": self._normalize_datasets(inputs),
            "outputs": self._normalize_datasets(outputs),
            "producer": _PRODUCER,
            "schemaURL": _OL_SCHEMA,
        }

        if self.dry_run:
            logger.info("[OL] DRY RUN — would emit %s %s", event_type, job_name)
            return event

        self._persist_event(event)

        if self.http_endpoint:
            self._post_event(event)

        self.gov.transformation_applied("OPENLINEAGE_EVENT", {
            "event_type": event_type,
            "job": job_name,
            "inputs": len(event["inputs"]),
            "outputs": len(event["outputs"]),
        })

        logger.info("[OL] %s %s — %d inputs, %d outputs",
                     event_type, job_name,
                     len(event["inputs"]), len(event["outputs"]))
        return event

    def _persist_event(self, event: dict) -> None:
        """Append a serialised event to the JSONL log file (thread-safe)."""
        with self._lock:
            with open(self.output_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")

    def _normalize_datasets(self, datasets: list | None) -> list[dict]:
        """Convert string dataset names to OpenLineage dataset objects."""
        if not datasets:
            return []
        result = []
        for ds in datasets:
            if isinstance(ds, dict):
                result.append(ds)
            else:
                result.append({
                    "namespace": self.namespace,
                    "name": str(ds),
                    "facets": {},
                })
        return result

    def _post_event(self, event: dict) -> None:
        """POST event to an OpenLineage HTTP endpoint."""
        try:
            import requests
            resp = requests.post(
                self.http_endpoint,
                json=event,
                timeout=5,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code >= 400:
                logger.warning("[OL] HTTP POST failed: %d %s",
                               resp.status_code, resp.text[:200])
        except ImportError:
            logger.warning("[OL] 'requests' package not installed "
                           "— cannot POST events. pip install requests")
            return
        except Exception as exc:
            logger.warning("[OL] Could not POST event: %s", exc)

    def new_run(self) -> str:
        """Start a new run (generates new run ID). Returns the run ID."""
        self._run_id = str(uuid.uuid4())
        return self._run_id
