"""
Estimates and logs the compute + storage cost of each pipeline run for
cloud data warehouse destinations — Snowflake, BigQuery, and Redshift.

Uses embedded current list prices that can be overridden with negotiated
rates.  All estimates are clearly labelled as estimates.

Layer 3 — imports from pipeline.constants and pipeline.governance_logger.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py into standalone module.
"""

import copy
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd

    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class CostEstimator:
    """
    Estimates and logs the compute + storage cost of each pipeline run for
    cloud data warehouse destinations — Snowflake, BigQuery, and Redshift.

    Almost no ETL tool does this natively.  CostEstimator gives you a
    per-run cost breakdown so you can track spend, set budgets, and
    spot expensive pipelines before your cloud bill arrives.

    How it works
    ------------
    Rather than calling live pricing APIs (which require credentials and
    change frequently), CostEstimator uses embedded current list prices
    that you can override with your negotiated rates via the ``pricing``
    parameter.  All estimates are clearly labelled as estimates.

    Snowflake  -- based on warehouse size (X-Small to X-Large), elapsed
                  seconds, on-demand credit price, and bytes written.
    BigQuery   -- based on bytes scanned (query cost) plus bytes written
                  (storage cost for one month).
    Redshift   -- based on node type, number of nodes, elapsed seconds,
                  and bytes written.
    Generic    -- for all other destinations: a simple GB-processed rate
                  (useful for on-premise or non-listed clouds).

    All costs are in USD.  Storage costs are projected for one month.
    Compute costs are based on actual elapsed pipeline time.

    Quick-start
    -----------
        from pipeline.reporting import CostEstimator
        import time
        t0 = time.time()
        # ... run your pipeline ...
        estimator = CostEstimator(gov)
        report = estimator.estimate(
            db_type         = "snowflake",
            elapsed_seconds = time.time() - t0,
            rows_processed  = len(df),
            bytes_processed = df.memory_usage(deep=True).sum(),
            bytes_written   = len(df) * 500,
            warehouse_size  = "Medium",
        )

    Parameters
    ----------
    gov          : GovernanceLogger
    cost_log     : str | Path   Where to append JSONL cost records.
                                Defaults to "pipeline_cost_history.jsonl".
    pricing      : dict | None  Override any pricing tier.  Keys match the
                                structure of CostEstimator.DEFAULT_PRICING.
    warn_budget  : float | None Alert if a single run exceeds this USD amount.

    Pricing reference (embedded defaults, US list prices as of 2025)
    -----------------------------------------------------------------
    Snowflake  $2.00 / credit (on-demand)
               X-Small=1cr/hr  Small=2  Medium=4  Large=8  X-Large=16
               Storage: $0.023/GB/month

    BigQuery   $6.25 / TB scanned (on-demand)
               Storage (active):   $0.020/GB/month
               Storage (longterm): $0.010/GB/month

    Redshift   dc2.large=$0.25/hr  ra3.xlplus=$1.086/hr  ra3.4xlarge=$3.26/hr
               ra3.16xlarge=$13.04/hr  dc2.8xlarge=$4.80/hr
               Managed storage: $0.024/GB/month

    Generic    $0.05 / GB processed
    """

    # ── Embedded list prices (USD, as of 2025) ───────────────────────────
    DEFAULT_PRICING: dict = {
        "snowflake": {
            "credit_usd":        2.00,
            "credits_per_hour":  {
                "X-Small": 1,
                "Small":   2,
                "Medium":  4,
                "Large":   8,
                "X-Large": 16,
            },
            "storage_usd_per_gb_month": 0.023,
        },
        "bigquery": {
            "query_usd_per_tb":              6.25,
            "storage_active_usd_per_gb_month": 0.020,
            "storage_longterm_usd_per_gb_month": 0.010,
        },
        "redshift": {
            "node_usd_per_hour": {
                "dc2.large":    0.250,
                "dc2.8xlarge":  4.800,
                "ra3.xlplus":   1.086,
                "ra3.4xlarge":  3.260,
                "ra3.16xlarge": 13.040,
            },
            "storage_usd_per_gb_month": 0.024,
        },
        "generic": {
            "usd_per_gb_processed": 0.05,
        },
    }

    # ── Map pipeline db_type strings to estimator keys ───────────────────
    _DB_TYPE_MAP: dict[str, str] = {
        "snowflake":  "snowflake",
        "redshift":   "redshift",
        "bigquery":   "bigquery",
    }

    def __init__(
        self,
        gov:         "GovernanceLogger",
        cost_log:    str | Path | None = None,
        pricing:     dict | None = None,
        warn_budget: float | None = None,
    ) -> None:
        self.gov         = gov
        self.cost_log    = Path(cost_log) if cost_log else gov.log_dir / "cost_history.jsonl"
        self.warn_budget = warn_budget

        # Deep-merge caller overrides into defaults
        self._pricing = copy.deepcopy(self.DEFAULT_PRICING)
        if pricing:
            for plat_key, overrides in pricing.items():
                if plat_key not in self._pricing:
                    self._pricing[plat_key] = {}
                if isinstance(overrides, dict):
                    self._pricing[plat_key].update(overrides)

    # ── Byte helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _to_gb(n_bytes: int | float) -> float:
        return max(0.0, float(n_bytes) / 1_073_741_824)

    @staticmethod
    def _to_tb(n_bytes: int | float) -> float:
        return max(0.0, float(n_bytes) / 1_099_511_627_776)

    @staticmethod
    def _infer_bytes(df: "pd.DataFrame | None", rows: int, cols: int = 10) -> int:
        """Estimate bytes from a DataFrame or from row/col count."""
        if df is not None:
            try:
                return int(df.memory_usage(deep=True).sum())
            except Exception as exc:
                logger.warning("Could not infer bytes from DataFrame: %s", exc)
        return rows * cols * 50

    # ── Platform estimators ───────────────────────────────────────────────

    def _estimate_snowflake(
        self,
        elapsed_seconds: float,
        bytes_processed: int,
        bytes_written:   int,
        warehouse_size:  str = "X-Small",
    ) -> dict:
        p = self._pricing["snowflake"]
        size = warehouse_size if warehouse_size in p["credits_per_hour"] else "X-Small"
        credits_per_hour = p["credits_per_hour"][size]
        credit_usd       = p["credit_usd"]

        # Snowflake bills in 1-second increments with a 60-second minimum
        billed_seconds = max(60.0, elapsed_seconds)
        billed_hours   = billed_seconds / 3600
        credits_used   = credits_per_hour * billed_hours
        compute_usd    = round(credits_used * credit_usd, 6)

        gb_stored      = self._to_gb(bytes_written)
        storage_usd    = round(gb_stored * p["storage_usd_per_gb_month"], 6)
        total_usd      = round(compute_usd + storage_usd, 6)

        return {
            "platform":        "snowflake",
            "warehouse_size":  size,
            "credits_per_hour": credits_per_hour,
            "credits_used":    round(credits_used, 6),
            "credit_price_usd": credit_usd,
            "billed_seconds":  round(billed_seconds, 2),
            "elapsed_seconds": round(elapsed_seconds, 2),
            "compute_usd":     compute_usd,
            "gb_stored":       round(gb_stored, 6),
            "storage_usd_monthly": storage_usd,
            "total_usd":       total_usd,
            "pricing_model":   "on-demand credits + managed storage",
            "note":            "60-second minimum billing applied",
        }

    def _estimate_bigquery(
        self,
        bytes_processed: int,
        bytes_written:   int,
        longterm_storage: bool = False,
    ) -> dict:
        p = self._pricing["bigquery"]

        tb_scanned   = self._to_tb(bytes_processed)
        query_usd    = round(tb_scanned * p["query_usd_per_tb"], 6)

        gb_written   = self._to_gb(bytes_written)
        storage_key  = ("storage_longterm_usd_per_gb_month"
                        if longterm_storage else
                        "storage_active_usd_per_gb_month")
        storage_usd  = round(gb_written * p[storage_key], 6)
        total_usd    = round(query_usd + storage_usd, 6)

        return {
            "platform":         "bigquery",
            "tb_scanned":       round(tb_scanned, 8),
            "query_usd_per_tb": p["query_usd_per_tb"],
            "query_usd":        query_usd,
            "gb_written":       round(gb_written, 6),
            "storage_type":     "longterm" if longterm_storage else "active",
            "storage_usd_monthly": storage_usd,
            "total_usd":        total_usd,
            "pricing_model":    "on-demand query + storage",
            "note":             "First 1 TB/month free on on-demand pricing",
        }

    def _estimate_redshift(
        self,
        elapsed_seconds: float,
        bytes_written:   int,
        node_type:       str = "dc2.large",
        num_nodes:       int = 1,
    ) -> dict:
        p = self._pricing["redshift"]
        ntype      = node_type if node_type in p["node_usd_per_hour"] else "dc2.large"
        node_rate  = p["node_usd_per_hour"][ntype]

        hours_used = elapsed_seconds / 3600
        compute_usd = round(node_rate * num_nodes * hours_used, 6)

        gb_stored   = self._to_gb(bytes_written)
        storage_usd = round(gb_stored * p["storage_usd_per_gb_month"], 6)
        total_usd   = round(compute_usd + storage_usd, 6)

        return {
            "platform":          "redshift",
            "node_type":         ntype,
            "num_nodes":         num_nodes,
            "node_usd_per_hour": node_rate,
            "elapsed_seconds":   round(elapsed_seconds, 2),
            "elapsed_hours":     round(hours_used, 6),
            "compute_usd":       compute_usd,
            "gb_stored":         round(gb_stored, 6),
            "storage_usd_monthly": storage_usd,
            "total_usd":         total_usd,
            "pricing_model":     "per-node-hour + managed storage",
        }

    def _estimate_generic(
        self,
        bytes_processed: int,
        elapsed_seconds: float,
    ) -> dict:
        p   = self._pricing["generic"]
        gb  = self._to_gb(bytes_processed)
        usd = round(gb * p["usd_per_gb_processed"], 6)
        return {
            "platform":          "generic",
            "gb_processed":      round(gb, 6),
            "usd_per_gb":        p["usd_per_gb_processed"],
            "elapsed_seconds":   round(elapsed_seconds, 2),
            "total_usd":         usd,
            "pricing_model":     "per-GB processed (generic estimate)",
            "note":              "Use Snowflake/BigQuery/Redshift db_type for accurate pricing",
        }

    # ── Main entry point ──────────────────────────────────────────────────

    def estimate(
        self,
        db_type:          str,
        elapsed_seconds:  float,
        rows_processed:   int,
        bytes_processed:  int | None  = None,
        bytes_written:    int | None  = None,
        df:               "pd.DataFrame | None" = None,
        warehouse_size:   str         = "X-Small",
        node_type:        str         = "dc2.large",
        num_nodes:        int         = 1,
        longterm_storage: bool        = False,
        run_label:        str | None  = None,
    ) -> dict:
        """
        Estimate the cost of this pipeline run and log it.

        Parameters
        ----------
        db_type          : str    Destination platform (snowflake/bigquery/redshift/...)
        elapsed_seconds  : float  Total pipeline wall-clock time in seconds.
        rows_processed   : int    Number of rows loaded.
        bytes_processed  : int    Bytes scanned/read (inferred from df if omitted).
        bytes_written    : int    Bytes written to destination (inferred if omitted).
        df               : pd.DataFrame | None   Used to infer byte counts.
        warehouse_size   : str    Snowflake warehouse size (X-Small to X-Large).
        node_type        : str    Redshift node type (dc2.large, ra3.xlplus, ...).
        num_nodes        : int    Redshift cluster node count.
        longterm_storage : bool   BigQuery: use long-term storage pricing.
        run_label        : str    Optional tag for the cost log.

        Returns
        -------
        dict  Full cost breakdown with total_usd, compute_usd, storage_usd,
              platform metadata, and timestamp.
        """
        # Infer byte counts if not supplied
        if bytes_processed is None:
            bytes_processed = self._infer_bytes(df, rows_processed)
        if bytes_written is None:
            bytes_written = bytes_processed

        platform = self._DB_TYPE_MAP.get(db_type.lower(), "generic")

        if platform == "snowflake":
            breakdown = self._estimate_snowflake(
                elapsed_seconds, bytes_processed, bytes_written, warehouse_size
            )
        elif platform == "bigquery":
            breakdown = self._estimate_bigquery(
                bytes_processed, bytes_written, longterm_storage
            )
        elif platform == "redshift":
            breakdown = self._estimate_redshift(
                elapsed_seconds, bytes_written, node_type, num_nodes
            )
        else:
            breakdown = self._estimate_generic(bytes_processed, elapsed_seconds)

        ts = datetime.now(timezone.utc).isoformat()
        report = {
            "timestamp":        ts,
            "run_label":        run_label,
            "db_type":          db_type,
            "rows_processed":   rows_processed,
            "bytes_processed":  bytes_processed,
            "bytes_written":    bytes_written,
            "elapsed_seconds":  round(elapsed_seconds, 2),
            "breakdown":        breakdown,
            "total_usd":        breakdown["total_usd"],
            "estimate":         True,
        }

        # Append to cost log
        try:
            with open(self.cost_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(report, default=str) + "\n")
        except OSError as exc:
            logger.warning("Could not write cost log: %s", exc)

        # Governance ledger event
        self.gov.transformation_applied("COST_ESTIMATED", {
            "platform":        platform,
            "db_type":         db_type,
            "total_usd":       breakdown["total_usd"],
            "compute_usd":     breakdown.get("compute_usd", breakdown["total_usd"]),
            "storage_usd":     breakdown.get("storage_usd_monthly", 0.0),
            "elapsed_seconds": round(elapsed_seconds, 2),
            "rows":            rows_processed,
            "pricing_model":   breakdown.get("pricing_model"),
        })

        # Console output
        self._log_report(report, breakdown)

        # Budget warning
        if self.warn_budget and breakdown["total_usd"] > self.warn_budget:
            logger.warning(
                "COST ALERT: run cost $%.4f exceeds budget $%.4f",
                breakdown["total_usd"], self.warn_budget,
            )
            self.gov.transformation_applied("COST_BUDGET_EXCEEDED", {
                "total_usd":   breakdown["total_usd"],
                "budget_usd":  self.warn_budget,
                "overage_usd": round(breakdown["total_usd"] - self.warn_budget, 6),
            })

        return report

    # ── Convenience: estimate directly from GovernanceLogger ledger ───────

    def estimate_from_ledger(
        self,
        db_type:        str = "generic",
        warehouse_size: str  = "X-Small",
        node_type:      str  = "dc2.large",
        num_nodes:      int  = 1,
        run_label:      str | None = None,
    ) -> dict | None:
        """
        Automatically extract elapsed time, rows, and bytes from the
        governance ledger and run estimate() — no manual measurement needed.

        Call this at the end of a pipeline run after all stages have
        completed and been logged.

        Returns
        -------
        dict | None   Cost report, or None if ledger has insufficient data.
        """
        entries  = self.gov.ledger_entries
        start_ts = None
        end_ts   = None
        rows     = 0
        bytes_est = 0

        for e in entries:
            action = e.get("action", "")
            detail = e.get("detail", {}) or {}
            ts_str = e.get("timestamp_utc", "")

            if action == "PIPELINE_STARTED" and ts_str:
                try:
                    start_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            if action in ("LOAD_COMPLETE", "TRANSFORM_COMPLETE"):
                r = detail.get("rows_written") or detail.get("final_row_count") or 0
                if r:
                    rows = max(rows, int(r))

            if action == "EXTRACT_COMPLETE":
                r = detail.get("rows", 0) or 0
                if r:
                    rows = max(rows, int(r))

            if ts_str:
                try:
                    end_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

        if not start_ts or not end_ts or rows == 0:
            return None

        elapsed = (end_ts - start_ts).total_seconds()
        if elapsed <= 0:
            elapsed = 1.0

        # Conservative byte estimate: ~500 bytes per row
        bytes_est = rows * 500

        return self.estimate(
            db_type         = db_type,
            elapsed_seconds = elapsed,
            rows_processed  = rows,
            bytes_processed = bytes_est,
            bytes_written   = bytes_est,
            warehouse_size  = warehouse_size,
            node_type       = node_type,
            num_nodes       = num_nodes,
            run_label       = run_label,
        )

    # ── Console logger ────────────────────────────────────────────────────

    @staticmethod
    def _log_report(report: dict, breakdown: dict) -> None:
        border = "─" * 60
        platform = breakdown.get("platform", "?").upper()
        total    = breakdown["total_usd"]
        compute  = breakdown.get("compute_usd", total)
        storage  = breakdown.get("storage_usd_monthly", 0.0)

        lines = [
            f"  {border}",
            f"  COST ESTIMATE  [{platform}]  (estimated, not billed)",
            f"  {border}",
            f"  Compute       : ${compute:>12.6f}",
            f"  Storage/month : ${storage:>12.6f}",
            "  " + "─" * 41,
            f"  TOTAL         : ${total:>12.6f}",
            f"  {border}",
            f"  Rows processed: {report['rows_processed']:,}",
            f"  Elapsed       : {report['elapsed_seconds']:.2f}s",
        ]

        if platform == "SNOWFLAKE":
            lines.append(
                f"  Warehouse     : {breakdown.get('warehouse_size')}  "
                f"({breakdown.get('credits_used', 0):.4f} credits @ "
                f"${breakdown.get('credit_price_usd', 0):.2f}/credit)"
            )
        elif platform == "BIGQUERY":
            lines.append(
                f"  TB scanned    : {breakdown.get('tb_scanned', 0):.8f} TB"
            )
        elif platform == "REDSHIFT":
            lines.append(
                f"  Cluster       : {breakdown.get('num_nodes')}x "
                f"{breakdown.get('node_type')}  "
                f"@ ${breakdown.get('node_usd_per_hour', 0):.3f}/node/hr"
            )

        lines.append(
            f"  Pricing note  : {breakdown.get('note', breakdown.get('pricing_model', ''))}"
        )
        lines.append(f"  {border}")

        logger.info("\n%s", "\n".join(lines))

    # ── History and reporting ─────────────────────────────────────────────

    def history(self, n: int = 50) -> list[dict]:
        """Return the last n cost records from the log file."""
        if not self.cost_log.exists():
            return []
        records: list[dict] = []
        for line in self.cost_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return list(reversed(records[-n:]))

    def cumulative_cost(self, n: int = 1000) -> dict:
        """
        Aggregate cost summary across recent runs.

        Returns
        -------
        dict  {total_usd, run_count, avg_usd_per_run, by_platform,
               most_expensive_run, cheapest_run}
        """
        records = self.history(n)
        if not records:
            return {
                "total_usd": 0.0, "run_count": 0, "avg_usd_per_run": 0.0,
                "by_platform": {}, "most_expensive_run": None,
                "cheapest_run": None,
            }
        by_platform: dict[str, float] = {}
        total = 0.0
        for r in records:
            usd = r.get("total_usd", 0.0)
            total += usd
            plat = r.get("breakdown", {}).get(
                "platform", r.get("db_type", "unknown")
            )
            by_platform[plat] = by_platform.get(plat, 0.0) + usd

        sorted_recs = sorted(records, key=lambda r: r.get("total_usd", 0.0))
        return {
            "total_usd":           round(total, 6),
            "run_count":           len(records),
            "avg_usd_per_run":     round(total / len(records), 6),
            "by_platform":         {k: round(v, 6) for k, v in by_platform.items()},
            "most_expensive_run":  sorted_recs[-1],
            "cheapest_run":        sorted_recs[0],
        }

    def monthly_projection(self, runs_per_day: float = 1.0) -> dict:
        """
        Project monthly cost based on recent run history.

        Parameters
        ----------
        runs_per_day : float   Expected pipeline runs per day.

        Returns
        -------
        dict  {projected_monthly_usd, based_on_runs, avg_run_usd}
        """
        records = self.history(n=30)
        if not records:
            return {
                "projected_monthly_usd": 0.0,
                "based_on_runs": 0,
                "avg_run_usd": 0.0,
            }
        avg = sum(r.get("total_usd", 0.0) for r in records) / len(records)
        monthly = avg * runs_per_day * 30.44
        return {
            "projected_monthly_usd": round(monthly, 4),
            "based_on_runs":         len(records),
            "avg_run_usd":           round(avg, 6),
            "runs_per_day":          runs_per_day,
        }
