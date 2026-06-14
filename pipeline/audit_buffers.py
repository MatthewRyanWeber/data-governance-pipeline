"""
In-memory aggregation buffers for the governance audit trail.

GovernanceLogger's event wrappers append findings here as a run
progresses; ReportWriter reads them at the end to emit the PII /
validation / classification / transfer reports.  Pulling them into a
plain holder keeps GovernanceLogger a thin facade rather than the owner
of both the event vocabulary and the aggregation state.

Layer 1 — no internal imports beyond Layer 0.

Revision history
────────────────
1.0   2026-06-14   Extracted from GovernanceLogger.
"""

from dataclasses import dataclass, field


@dataclass
class AuditBuffers:
    """Run-scoped aggregation the report writers consume."""

    pii_findings: list[dict] = field(default_factory=list)
    validation_results: list[dict] = field(default_factory=list)
    classification_tags: list[dict] = field(default_factory=list)
    transfer_events: list[dict] = field(default_factory=list)
    dlq_rows_total: int = 0
