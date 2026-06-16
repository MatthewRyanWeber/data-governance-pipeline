"""
Per-partition governance entrypoint — Path A's "governance as a per-partition
library".

The thesis of Path A is that you do NOT scale the single Python process to
100TB/day; you let a distributed engine (Spark, Ray, Dask) own the fan-out and
run this pipeline's *governance* on each partition. `govern_partition` is the
unit that engine maps over partitions: it runs the governance stages on one
partition and writes that partition's audit chain into its own
`PartitionedLedger` segment — no shared-writer bottleneck. After the run the
segments compose into one verifiable Merkle root.

    from pipeline.partitioned_ledger import PartitionedLedger
    from pipeline.partitioned_governance import govern_partition

    ledger = PartitionedLedger("s3-or-local/run_ledger/")

    # Spark: one call per partition, each on its own executor —
    #   def _govern(idx, it):
    #       import pandas as pd
    #       df = pd.DataFrame(list(it))
    #       out, _ = govern_partition(df, segment_id=f"part-{idx:05d}", ledger=ledger)
    #       return out.itertuples(index=False)
    #   rdd.mapPartitionsWithIndex(_govern)...
    # then once on the driver:
    #   ledger.seal(); assert ledger.verify()

Layer 3 — composes governance_logger, transform, partitioned_ledger.

Revision history
────────────────
1.0   2026-06-15   Initial release: govern_partition + a concurrent coordinator.
1.1   2026-06-15   Optional observe_config runs the DataObserver per partition
                   (dup-key / null-spike detectors) into the partition's segment.
1.2   2026-06-16   segment_id validated before deriving the per-segment log_dir,
                   with an is_relative_to guard so a crafted id cannot place the
                   partition's reports outside the ledger root.
1.3   2026-06-16   Two guards instead of three: is_relative_to owns traversal,
                   ledger.segment() owns the filename charset — the redundant
                   explicit validate_segment_id call was dropped.
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.partitioned_ledger import PartitionedLedger

logger = logging.getLogger("DataPipeline")


def govern_partition(
    df: "pd.DataFrame",
    segment_id: str,
    ledger: "PartitionedLedger",
    *,
    pii_strategy: str = "mask",
    skip_pii: bool = False,
    observe_config: dict | None = None,
    dry_run: bool = False,
):
    """Govern ONE partition independently and write its audit chain to a segment.

    Safe to call from a distributed engine's per-partition task: it shares no
    mutable state with other partitions — its events go to its own ledger
    segment (a distinct file), and its ancillary reports to its own log dir.

    ``observe_config`` (an observability config block — business_keys,
    critical_fields, …) runs the DataObserver on the governed partition, so the
    silent-failure detectors (duplicate business keys, null spikes/floors) cover
    each partition and their alerts chain into the partition's segment. The
    absolute checks (dup-keys, null-floor) act per partition immediately;
    baseline checks (volume/drift) build per-partition history.

    Returns (governed_df, meta).
    """
    from pipeline.governance_logger import GovernanceLogger
    from pipeline.transform import Transformer
    from pipeline.helpers import detect_pii

    # Two guards, each owning one property: is_relative_to stops segment_id
    # from escaping the ledger root as a path component (the log_dir below
    # joins it onto root_dir); ledger.segment() validates the filename charset
    # (rejecting "."/".." and non-charset ids) and runs before GovernanceLogger
    # is built, so no directory is ever created for a rejected id.
    log_dir = (ledger.root_dir / segment_id).resolve()
    if not log_dir.is_relative_to(ledger.root_dir.resolve()):
        raise ValueError(
            f"segment_id {segment_id!r} resolves outside the ledger root"
        )

    # The partition's own independent ledger chain.
    segment = ledger.segment(segment_id)
    gov = GovernanceLogger(
        source_name=segment_id,
        log_dir=str(log_dir),
        dry_run=dry_run,
        ledger=segment,                # events chain into THIS partition's segment
    )

    pii_findings = None if skip_pii else detect_pii(list(df.columns))
    transformer = Transformer(gov)
    governed = transformer.transform(df, pii_findings, pii_strategy, drop_cols=[])

    observe_alerts = 0
    if observe_config:
        from pipeline.monitoring.observability import DataObserver, OBSERVER_CONFIG_KEYS
        observer = DataObserver(
            gov, dry_run=dry_run,
            **{k: observe_config[k] for k in OBSERVER_CONFIG_KEYS if k in observe_config},
        )
        observe_alerts = observer.observe(governed, dataset=segment_id)["alert_count"]

    return governed, {
        "segment_id": segment_id,
        "rows_in": len(df),
        "rows_out": len(governed),
        "pii_actions": dict(transformer.pii_actions),
        "observe_alerts": observe_alerts,
    }


def govern_partitions(
    partitions,
    ledger: "PartitionedLedger",
    *,
    max_workers: int = 8,
    **kwargs,
):
    """Govern many (segment_id, df) partitions concurrently, then seal + verify.

    The local/reference coordinator — it does in one process, with a thread
    pool, what a distributed engine does across executors: fan governance over
    partitions into independent segments, then compose and verify the root.

    Returns (governed_by_segment: dict, seal_record: dict).
    """
    items = list(partitions)
    governed: dict = {}

    def _work(item):
        segment_id, df = item
        out, meta = govern_partition(df, segment_id, ledger, **kwargs)
        return segment_id, out, meta

    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(items)))) as pool:
        for segment_id, out, _meta in pool.map(_work, items):
            governed[segment_id] = out

    record = ledger.seal()
    logger.info(
        "[PARTITIONED_GOVERNANCE] governed %s partitions -> %s events, root %s",
        record.get("segment_count"), record.get("total_events"),
        (record.get("merkle_root") or "")[:12],
    )
    return governed, record
