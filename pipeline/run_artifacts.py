"""
RunArtifacts — every file path a pipeline run produces, in one place.

GovernanceLogger used to construct a dozen report paths inline in its
__init__, which coupled path layout to event logging.  This dataclass
owns the layout; GovernanceLogger exposes thin back-compat properties.

Lives at Layer 1 (not pipeline.reporting) because GovernanceLogger is
Layer 1 and pipeline.reporting eagerly imports Layer-5 report machinery —
importing it from here would invert the layer DAG.

Layer 1 — imports from Layer 0 only.

Revision history
────────────────
1.0   2026-06-12   Extracted from GovernanceLogger.__init__.
"""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RunArtifacts:
    """Resolved output paths for one pipeline run.

    Per-run files carry the run timestamp; history files
    (cost/quality) accumulate across runs and do not.
    """

    log_dir: Path
    timestamp: str

    log_file: Path = field(init=False)
    ledger_file: Path = field(init=False)
    ledger_anchor_file: Path = field(init=False)
    pii_report_file: Path = field(init=False)
    validation_report_file: Path = field(init=False)
    profile_report_file: Path = field(init=False)
    dlq_file: Path = field(init=False)
    metrics_report_file: Path = field(init=False)
    classification_file: Path = field(init=False)
    transfer_log_file: Path = field(init=False)
    cost_log_file: Path = field(init=False)
    quality_log_file: Path = field(init=False)
    snapshot_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        d, ts = self.log_dir, self.timestamp
        set_attr = object.__setattr__  # frozen dataclass
        set_attr(self, "log_file", d / f"pipeline_{ts}.log")
        set_attr(self, "ledger_file", d / f"audit_ledger_{ts}.jsonl")
        # Anchor sidecar: last chain hash + entry count, so ledger
        # truncation or deletion is detectable
        set_attr(self, "ledger_anchor_file",
                 Path(str(d / f"audit_ledger_{ts}.jsonl") + ".anchor"))
        set_attr(self, "pii_report_file", d / f"pii_report_{ts}.json")
        set_attr(self, "validation_report_file",
                 d / f"validation_report_{ts}.json")
        set_attr(self, "profile_report_file", d / f"profile_report_{ts}.json")
        set_attr(self, "dlq_file", d / f"dlq_{ts}.csv")
        set_attr(self, "metrics_report_file", d / f"metrics_report_{ts}.json")
        set_attr(self, "classification_file",
                 d / f"classification_report_{ts}.json")
        set_attr(self, "transfer_log_file", d / f"transfer_log_{ts}.json")
        set_attr(self, "cost_log_file", d / "cost_history.jsonl")
        set_attr(self, "quality_log_file", d / "quality_history.jsonl")
        set_attr(self, "snapshot_dir", d / "snapshots")

    def ensure_directories(self) -> None:
        """Create the log and snapshot directories."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
