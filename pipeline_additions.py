"""
=============================================================
  PIPELINE ADDITIONS  v1.0.0
  11 additional metadata features for pipeline_v3.py
=============================================================

FEATURES
--------
  ①  DataProductRegistry        — Persists owner, domain, SLA tier, cost
                                   centre, and consumer list per table.
                                   State: data_products.json

  ②  CDCTracker                 — Tracks inserted / updated / deleted row
                                   counts run-over-run using DB row-count
                                   snapshots.  State: cdc_state.json

  ③  ErasureNotificationRegistry— Stores downstream pipeline webhook URLs;
                                   called by ErasureHandler.execute() to
                                   propagate Art.17 erasure downstream.
                                   Config: erasure_notify.json

  ④  ExpectationSuiteVersioner  — Saves a GX expectation suite snapshot
                                   after every build and diffs against the
                                   previous version to detect suite drift.
                                   State: suite_history.jsonl

  ⑤  Per-column GX in catalog   — Adds gx_pass_rate / gx_failures fields
                                   to ColumnMeta and wires per-column GX
                                   results into the catalog payload and
                                   catalog connector push_data_quality.
                                   (Edits to catalog_connectors.py)

  ⑥  EncryptionKeyTracker       — Records key_version alongside every
                                   encrypted column so key rotation knows
                                   which rows need re-encryption.
                                   State: encryption_key_versions.json

  ⑦  TagTaxonomy                — Controlled vocabulary for pipeline tags.
                                   Normalises free-form tags to canonical
                                   names and warns on unknown tags.
                                   Config: tag_taxonomy.yaml

  ⑧  Multi-hop lineage          — Adds parent_run_id to OpenLineage events
                                   so downstream pipeline runs can be linked
                                   into a single cross-pipeline lineage graph.
                                   (Edit to metadata_extensions.py)

  ⑨  SensitivityScorer          — Computes a numeric sensitivity score
                                   (0-100) from PII count, encryption status,
                                   classification, and retention period.
                                   Appended to catalog payload and ledger.

  ⑩  ObservabilityWebhook       — Pushes quality failures to Soda Cloud,
                                   PagerDuty, Monte Carlo, or any generic
                                   HTTP webhook endpoint.

  ⑪  RunCostEstimator           — Estimates compute cost and carbon
                                   footprint per run from elapsed time,
                                   row count, and cloud provider rates.
                                   State: run_cost_log.jsonl

WIRING
------
All features are orchestrated by AdditionsOrchestrator, which exposes
hook methods called from pipeline_v3.py main().

pipeline_v3.py imports this module with a HAS_ADDITIONS guard:
    try:
        from pipeline_additions import (
            AdditionsOrchestrator,
            prompt_additions_config,
            generate_tag_taxonomy,
        )
        HAS_ADDITIONS = True
    except ImportError:
        HAS_ADDITIONS = False
=============================================================
"""

from __future__ import annotations

import hashlib
import json
import logging
# import os
# import time
# import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Anchor all state files to the script's own directory ──────────────────
_BASE_DIR = Path(__file__).resolve().parent

log = logging.getLogger("PipelineAdditions")

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ═════════════════════════════════════════════════════════════════════════════
#  ① DATA PRODUCT REGISTRY
# ═════════════════════════════════════════════════════════════════════════════
class DataProductRegistry:
    """
    Stores ownership and organisational metadata for every table this
    pipeline produces.  Answers "who owns this table and who depends on it?"

    Why this matters
    ----------------
    Without ownership metadata, when a pipeline breaks at 3am:
    • Nobody knows who to page.
    • Nobody knows which downstream teams are affected.
    • Data stewards can't assign data quality remediation to anyone.

    Fields stored per table
    -----------------------
    owner           — Primary owner (email or username).
    team            — Owning team / squad name.
    domain          — Data domain (HR, Finance, Product, etc.).
    sla_tier        — 1 (critical), 2 (important), 3 (standard).
    cost_centre     — Budget code or cost centre for FinOps allocation.
    consumers       — List of downstream teams / pipelines / dashboards.
    description     — Human-readable purpose of this table.
    tags            — Organisational tags (separate from pipeline tags).
    created_at      — When first registered.
    updated_at      — When last updated.

    State file
    ----------
    data_products.json  — keyed by table name:
        { "employees": { "owner": "alice@example.com", ... } }
    """

    REGISTRY_FILE = _BASE_DIR / "data_products.json"

    def __init__(self, gov) -> None:
        self.gov = gov

    def register(
        self,
        table:        str,
        owner:        str,
        team:         str          = "",
        domain:       str          = "",
        sla_tier:     int          = 3,
        cost_centre:  str          = "",
        consumers:    list[str]    = (),
        description:  str          = "",
        tags:         list[str]    = (),
        update:       bool         = False,
    ) -> dict:
        """
        Register or update a data product entry.

        Parameters
        ----------
        table       : str        Destination table name (registry key).
        owner       : str        Primary owner email / username.
        team        : str        Owning team.
        domain      : str        Data domain.
        sla_tier    : int        1=critical, 2=important, 3=standard.
        cost_centre : str        Budget code.
        consumers   : list[str]  Downstream consumers.
        description : str        Table purpose.
        tags        : list[str]  Organisational tags.
        update      : bool       If True, merge into existing entry.
                                 If False, skip if entry already exists.

        Returns
        -------
        dict  The registered entry.
        """
        registry = self._load()
        now      = datetime.now(timezone.utc).isoformat()

        if table in registry and not update:
            return registry[table]

        existing  = registry.get(table, {})
        entry = {
            "table"      : table,
            "owner"      : owner or existing.get("owner", ""),
            "team"       : team  or existing.get("team",  ""),
            "domain"     : domain or existing.get("domain", ""),
            "sla_tier"   : sla_tier,
            "cost_centre": cost_centre or existing.get("cost_centre", ""),
            "consumers"  : list(consumers) or existing.get("consumers", []),
            "description": description or existing.get("description", ""),
            "tags"       : list(tags) or existing.get("tags", []),
            "created_at" : existing.get("created_at", now),
            "updated_at" : now,
            "pipeline_id": (self.gov.ledger_entries[0]["pipeline_id"]
                            if self.gov.ledger_entries else ""),
        }
        registry[table] = entry
        self._save(registry)

        self.gov._event("DATA_PRODUCT", "PRODUCT_REGISTERED",
                        {"table": table, "owner": owner,
                         "sla_tier": sla_tier, "domain": domain})
        log.info("[DATA PRODUCT] Registered '%s'  owner=%s  tier=%s", table, owner, sla_tier)
        return entry

    def get(self, table: str) -> dict | None:
        """Return the registered data product entry for table, or None."""
        return self._load().get(table)

    def get_or_register_interactive(self, table: str) -> dict:
        """
        Return existing entry or prompt for registration in interactive mode.
        """
        existing = self.get(table)
        if existing:
            print(f"  ✓  [DATA PRODUCT] '{table}': owner={existing['owner']}  "
                  f"tier={existing['sla_tier']}  domain={existing['domain']}")
            return existing

        print(f"\n  [DATA PRODUCT] No ownership record for '{table}'.")
        owner   = input("    Owner (email/username): ").strip()
        team    = input("    Team: ").strip()
        domain  = input("    Domain (HR/Finance/Product/etc.): ").strip()
        tier    = input("    SLA tier (1=critical, 2=important, 3=standard) [3]: ").strip()
        cost    = input("    Cost centre: ").strip()
        cons_r  = input("    Consumers (comma-sep, or Enter to skip): ").strip()
        desc    = input("    Description: ").strip()
        consumers = [c.strip() for c in cons_r.split(",") if c.strip()]
        return self.register(table, owner, team, domain,
                             int(tier) if tier.isdigit() else 3,
                             cost, consumers, desc)

    def export_catalog(self, output_path: str = "data_product_catalog.json") -> str:
        """Export all registered products to a standalone JSON catalog."""
        registry = self._load()
        catalog  = {
            "generated_utc"  : datetime.now(timezone.utc).isoformat(),
            "total_products" : len(registry),
            "products"       : list(registry.values()),
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(catalog, f, indent=2)
        log.info("[DATA PRODUCT] Catalog exported → %s", output_path)
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
#  ② CDC TRACKER
# ═════════════════════════════════════════════════════════════════════════════
class CDCTracker:
    """
    Change Data Capture tracker: records inserted / updated / deleted counts
    by comparing DB row counts before and after each pipeline run.

    Why this matters
    ----------------
    total_rows_loaded tells you rows written but not what changed.
    For incremental pipelines: did 1,000 rows arrive because:
      (a) 1,000 new records?  or
      (b) 900 new records + 100 updates to existing ones?
    These have very different implications for downstream consumers.

    Method
    ------
    BEFORE load: query COUNT(*) from the destination table (0 if table
                 doesn't exist yet).  Save to cdc_state.json.
    AFTER  load: query COUNT(*) again.  Compute:
      inserted = max(0, count_after - count_before)
      deleted  = max(0, count_before - count_after + rows_loaded)
      updated  = rows_loaded - inserted (lower bound estimate)

    Note: Without natural-key comparison this is an estimate.  For exact
    CDC, set natural_keys in the pipeline config so the upsert path
    can report true insert/update counts.

    State file
    ----------
    cdc_state.json  — { "table_name": { "row_count": 1000,
                                         "snapshot_at": "...", ... } }
    """

    STATE_FILE    = _BASE_DIR / "cdc_state.json"

    def __init__(self, gov) -> None:
        self.gov        = gov
        self._before: dict[str, int] = {}

    def snapshot_before(self, db_type: str, db_cfg: dict, table: str) -> int:
        """
        Query current row count before load.  Returns 0 if table absent.
        Call this BEFORE the load step.
        """
        count = self._query_count(db_type, db_cfg, table)
        self._before[table] = count
        return count

    def compute_diff(
        self,
        db_type:     str,
        db_cfg:      dict,
        table:       str,
        rows_loaded: int,
        natural_keys: list[str] | None = None,
        log_dir:      str = "governance_logs",
    ) -> dict:
        """
        Compute and record the CDC diff after load.

        Parameters
        ----------
        db_type      : str        Database type.
        db_cfg       : dict       Database config.
        table        : str        Destination table.
        rows_loaded  : int        Total rows written this run.
        natural_keys : list | None If provided, uses upsert semantics for
                                   more accurate insert/update split.
        log_dir      : str        Output directory for the CDC report.

        Returns
        -------
        dict  { "inserted": int, "updated": int, "deleted": int,
                "count_before": int, "count_after": int }
        """
        count_before = self._before.get(table, 0)
        count_after  = self._query_count(db_type, db_cfg, table)
        delta        = count_after - count_before

        if natural_keys:
            # With upsert: all rows_loaded are either insert or update.
            # Exact split requires comparing each row — estimate here.
            inserted = max(0, delta)
            updated  = max(0, rows_loaded - inserted)
            deleted  = 0
        else:
            inserted = max(0, delta)
            updated  = 0
            deleted  = max(0, count_before - count_after + rows_loaded - inserted)

        result = {
            "table"        : table,
            "count_before" : count_before,
            "count_after"  : count_after,
            "rows_loaded"  : rows_loaded,
            "inserted"     : inserted,
            "updated"      : updated,
            "deleted"      : deleted,
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
            "pipeline_id"  : (self.gov.ledger_entries[0]["pipeline_id"]
                              if self.gov.ledger_entries else ""),
        }

        # Persist snapshot for next run.
        state = self._load_state()
        state[table] = {"row_count": count_after,
                        "snapshot_at": result["run_timestamp"]}
        self._save_state(state)

        # Write per-run report.
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(log_dir) / f"cdc_report_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        self.gov._event("CDC", "CDC_DIFF_COMPUTED", result)
        print(f"  ✓  [CDC] {table}: "
              f"+{inserted} inserted  ~{updated} updated  -{deleted} deleted  "
              f"(total: {count_after:,})")
        return result

    def _query_count(self, db_type: str, db_cfg: dict, table: str) -> int:
        """Query COUNT(*) from table; return 0 if table doesn't exist."""
        try:
            from sqlalchemy import create_engine, text, inspect as sainspect
            if db_type == "sqlite":
                engine = create_engine(f"sqlite:///{db_cfg['db_name']}.db")
            elif db_type == "postgresql":
                engine = create_engine(
                    f"postgresql+psycopg2://{db_cfg['user']}:{db_cfg['password']}"
                    f"@{db_cfg['host']}:{db_cfg.get('port',5432)}/{db_cfg['db_name']}"
                )
            else:
                return 0
            with engine.connect() as conn:
                if table not in sainspect(engine).get_table_names():
                    return 0
                row = conn.execute(text(f"SELECT COUNT(*) FROM \"{table}\"")).fetchone()
                return int(row[0]) if row else 0
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.debug("[CDC] Count query failed for %s: %s", table, exc)
            return 0

    def _load_state(self) -> dict:
        if not self.STATE_FILE.exists():
            return {}
        with open(self.STATE_FILE, encoding="utf-8") as f:
            return json.load(f)

    def _save_state(self, state: dict) -> None:
        with open(self.STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  ③ ERASURE NOTIFICATION REGISTRY
# ═════════════════════════════════════════════════════════════════════════════
class ErasureNotificationRegistry:
    """
    Stores downstream pipeline / system webhook URLs and calls them when an
    Art.17 erasure is executed in the source table.

    Why this matters
    ----------------
    GDPR Art.17(2) requires controllers to inform downstream processors
    that received the personal data to also erase it.  Without this:
    • Downstream BI tables, data marts, or ML training sets may still
      contain the erased subject's data.
    • The controller cannot demonstrate full compliance at audit time.

    How it works
    ------------
    1. Register downstream systems with register().
    2. ErasureHandler.execute() calls notify_all() after successful deletion.
    3. Each registered endpoint receives a POST with:
         { "subject_hash": "...", "source_table": "...",
           "erased_at": "...", "pipeline_id": "..." }
       The subject_id is hashed — raw PII is never sent over the wire.

    State file
    ----------
    erasure_notify.json  — list of registered endpoints:
        [ { "name": "warehouse_pipeline",
            "url":  "https://warehouse.internal/hooks/erasure",
            "description": "Downstream data warehouse ETL" } ]
    """

    REGISTRY_FILE = _BASE_DIR / "erasure_notify.json"

    def __init__(self, gov) -> None:
        self.gov = gov

    def register(self, name: str, url: str, description: str = "") -> None:
        """Register a downstream system for erasure notification."""
        endpoints = self._load()
        # De-duplicate by name.
        endpoints = [e for e in endpoints if e["name"] != name]
        endpoints.append({"name": name, "url": url, "description": description})
        self._save(endpoints)
        self.gov._event("ERASURE", "DOWNSTREAM_REGISTERED",
                        {"name": name, "url": url})
        log.info("[ERASURE NOTIFY] Registered downstream: %s → %s", name, url)

    def notify_all(
        self,
        subject_id:    str,
        source_table:  str,
        rows_erased:   int,
        timeout:       float = 5.0,
    ) -> dict[str, bool]:
        """
        POST erasure notification to all registered endpoints.

        Parameters
        ----------
        subject_id   : str    Raw subject ID (will be hashed before sending).
        source_table : str    Table where erasure was performed.
        rows_erased  : int    Number of rows deleted/nullified.
        timeout      : float  HTTP timeout per request.

        Returns
        -------
        dict[str, bool]  { endpoint_name: success }
        """
        endpoints    = self._load()
        if not endpoints:
            return {}

        subject_hash = hashlib.sha256(str(subject_id).encode()).hexdigest()
        pipeline_id  = (self.gov.ledger_entries[0]["pipeline_id"]
                        if self.gov.ledger_entries else "")
        payload = {
            "subject_hash" : subject_hash,
            "source_table" : source_table,
            "rows_erased"  : rows_erased,
            "erased_at"    : datetime.now(timezone.utc).isoformat(),
            "pipeline_id"  : pipeline_id,
            "gdpr_article" : "Art.17 Right to Erasure",
        }

        results: dict[str, bool] = {}
        for ep in endpoints:
            name = ep["name"]
            url  = ep["url"]
            try:
                if HAS_REQUESTS:
                    resp = _requests.post(url, json=payload, timeout=timeout)
                    success = resp.status_code < 400
                else:
                    import urllib.request, urllib.error
                    req = urllib.request.Request(
                        url,
                        data=json.dumps(payload).encode(),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=timeout)
                    success = True
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log.warning("[ERASURE NOTIFY] %s failed: %s", name, exc)
                success = False

            results[name] = success
            symbol = "✓" if success else "⚠"
            print(f"  {symbol}  [ERASURE NOTIFY] {name}: "
                  f"{'OK' if success else 'FAILED'}")
            self.gov._event("ERASURE", "DOWNSTREAM_NOTIFIED",
                            {"name": name, "url": url, "success": success,
                             "source_table": source_table},
                            level="INFO" if success else "WARNING")

        succeeded = sum(results.values())
        print(f"  [ERASURE] {succeeded}/{len(endpoints)} downstream "
              f"system(s) notified.")
        return results

    def list_endpoints(self) -> list[dict]:
        return self._load()

    def _load(self) -> list[dict]:
        if not self.REGISTRY_FILE.exists():
            return []
        with open(self.REGISTRY_FILE, encoding="utf-8") as f:
            return json.load(f)

    def _save(self, endpoints: list[dict]) -> None:
        with open(self.REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(endpoints, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  ④ EXPECTATION SUITE VERSIONER
# ═════════════════════════════════════════════════════════════════════════════
class ExpectationSuiteVersioner:
    """
    Snapshots the GX expectation suite after every build and diffs it
    against the previous version to detect silent expectation drift.

    Why this matters
    ----------------
    The SchemaValidator rebuilds the GX suite from scratch every run.
    If someone removes an expectation or changes a threshold, that change
    is silent — no diff, no version, no audit trail.  Data quality could
    become weaker without anyone noticing.

    What gets diffed
    ----------------
    ADDED      — New expectation present this run that wasn't before.
    REMOVED    — Expectation in the previous suite that's gone now.
    MODIFIED   — Same expectation type + column but different parameters.

    State file
    ----------
    suite_history.jsonl  — One entry per run per suite name:
        { "suite_name": "pipeline_suite_abc123",
          "version":     3,
          "run_id":      "...",
          "timestamp":   "...",
          "count":       22,
          "expectations": [ {"type": "...", "column": "...", "params": {...}} ],
          "diff":        { "added": [], "removed": [], "modified": [] } }
    """

    HISTORY_FILE  = _BASE_DIR / "suite_history.jsonl"

    def __init__(self, gov) -> None:
        self.gov = gov

    def snapshot(
        self,
        suite_name:    str,
        expectations:  list,
    ) -> dict:
        """
        Save a snapshot of the current suite and compute diff vs last version.

        Parameters
        ----------
        suite_name    : str    GX suite name.
        expectations  : list   List of GX expectation objects.

        Returns
        -------
        dict  The snapshot record including any diff.
        """
        current_specs = self._serialize_suite(expectations)
        previous      = self._load_last(suite_name)
        version       = (previous["version"] + 1) if previous else 1

        diff = {"added": [], "removed": [], "modified": []}
        if previous:
            prev_specs = {self._key(e): e for e in previous["expectations"]}
            curr_specs = {self._key(e): e for e in current_specs}
            diff["added"]   = [e for k, e in curr_specs.items() if k not in prev_specs]
            diff["removed"] = [e for k, e in prev_specs.items() if k not in curr_specs]
            for k in set(prev_specs) & set(curr_specs):
                if prev_specs[k].get("params") != curr_specs[k].get("params"):
                    diff["modified"].append({
                        "expectation": k,
                        "before": prev_specs[k].get("params"),
                        "after" : curr_specs[k].get("params"),
                    })

        has_drift = any(diff[k] for k in diff)
        pipeline_id = (self.gov.ledger_entries[0]["pipeline_id"]
                       if self.gov.ledger_entries else "")
        snapshot = {
            "suite_name"   : suite_name,
            "version"      : version,
            "run_id"       : pipeline_id,
            "timestamp"    : datetime.now(timezone.utc).isoformat(),
            "count"        : len(current_specs),
            "expectations" : current_specs,
            "diff"         : diff,
        }
        with open(self.HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(snapshot) + "\n")

        if has_drift:
            self.gov._event("VALIDATION", "SUITE_DRIFT_DETECTED",
                            {"suite": suite_name, "version": version,
                             "added": len(diff["added"]),
                             "removed": len(diff["removed"]),
                             "modified": len(diff["modified"])},
                            level="WARNING")
            print(f"  ⚠  [SUITE v{version}] Drift detected: "
                  f"+{len(diff['added'])} added  "
                  f"-{len(diff['removed'])} removed  "
                  f"~{len(diff['modified'])} modified")
        else:
            self.gov._event("VALIDATION", "SUITE_SNAPSHOT_SAVED",
                            {"suite": suite_name, "version": version,
                             "count": len(current_specs)})
            print(f"  ✓  [SUITE v{version}] {len(current_specs)} expectations "
                  f"— no drift vs v{version - 1}" if version > 1
                  else f"  ✓  [SUITE v1] {len(current_specs)} expectations — baseline saved")
        return snapshot

    def _serialize_suite(self, expectations: list) -> list[dict]:
        specs = []
        for exp in expectations:
            typ  = type(exp).__name__
            col  = getattr(exp, "column", None)
            params: dict = {}
            for attr in ("min_value", "max_value", "value_set", "regex",
                         "type_", "value", "mostly"):
                v = getattr(exp, attr, None)
                if v is not None:
                    params[attr] = v
            specs.append({"type": typ, "column": col, "params": params})
        return specs

    def _key(self, spec: dict) -> str:
        return f"{spec['type']}::{spec.get('column','')}"

    def _load_last(self, suite_name: str) -> dict | None:
        if not self.HISTORY_FILE.exists():
            return None
        last = None
        with open(self.HISTORY_FILE, encoding="utf-8") as f:
            for line in f:
                entry = json.loads(line)
                if entry["suite_name"] == suite_name:
                    last = entry
        return last


# ═════════════════════════════════════════════════════════════════════════════
#  ⑥ ENCRYPTION KEY TRACKER
# ═════════════════════════════════════════════════════════════════════════════
class EncryptionKeyTracker:
    """
    Records which key version encrypted which columns, enabling safe key
    rotation by knowing exactly which rows need re-encryption.

    Why this matters
    ----------------
    When a Fernet key is rotated:
    • Rows encrypted with the OLD key cannot be decrypted with the NEW key.
    • Without per-column key version tracking, you can't tell which rows
      need re-encryption without attempting decryption on every row.

    How it works
    ------------
    Every time ColumnEncryptor.encrypt() runs, EncryptionKeyTracker.record()
    is called with:
      - table name
      - column names
      - key_version (a short identifier for the key, NOT the key itself)
      - pipeline_id and run_timestamp

    A query like "find all runs that used key v1 for column salary" lets
    a rotation job know exactly which data to re-encrypt.

    State file
    ----------
    encryption_key_versions.json  — keyed by "table::column":
        { "employees::salary": [
            { "key_version": "v1", "pipeline_id": "...", "timestamp": "..." },
            { "key_version": "v2", "pipeline_id": "...", "timestamp": "..." }
          ]
        }
    """

    STATE_FILE    = _BASE_DIR / "encryption_key_versions.json"

    def __init__(self, gov) -> None:
        self.gov = gov

    def record(
        self,
        table:       str,
        columns:     list[str],
        key_version: str,
    ) -> None:
        """
        Record key version metadata for encrypted columns.

        Parameters
        ----------
        table       : str        Destination table name.
        columns     : list[str]  Column names that were encrypted.
        key_version : str        Short key version ID (e.g. "v1", "2024-01").
                                 NOT the key value itself.
        """
        state = self._load()
        pipeline_id = (self.gov.ledger_entries[0]["pipeline_id"]
                       if self.gov.ledger_entries else "")
        ts = datetime.now(timezone.utc).isoformat()
        for col in columns:
            key = f"{table}::{col}"
            state.setdefault(key, []).append({
                "key_version": key_version,
                "pipeline_id": pipeline_id,
                "timestamp"  : ts,
            })
        self._save(state)
        self.gov._event("ENCRYPTION", "KEY_VERSION_RECORDED",
                        {"table": table, "columns": columns,
                         "key_version": key_version})
        log.info("[KEY TRACK] %s column(s) recorded as key_version=%s in %s",
                 len(columns), key_version, table)

    def find_by_version(self, key_version: str) -> list[dict]:
        """
        Return all table::column entries encrypted with a given key version.
        Used by key rotation jobs to find data that needs re-encryption.
        """
        state   = self._load()
        matches = []
        for col_key, history in state.items():
            # Use the most recent version recorded for this column.
            if history and history[-1]["key_version"] == key_version:
                table, col = col_key.split("::", 1)
                matches.append({"table": table, "column": col,
                                 "last_seen": history[-1]["timestamp"]})
        return matches

    def current_version(self, table: str, column: str) -> str | None:
        """Return the most recently recorded key version for a column."""
        state = self._load()
        hist  = state.get(f"{table}::{column}", [])
        return hist[-1]["key_version"] if hist else None

    def _load(self) -> dict:
        if not self.STATE_FILE.exists():
            return {}
        with open(self.STATE_FILE, encoding="utf-8") as f:
            return json.load(f)

    def _save(self, state: dict) -> None:
        with open(self.STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
#  ⑦ TAG TAXONOMY
# ═════════════════════════════════════════════════════════════════════════════
class TagTaxonomy:
    """
    Controlled vocabulary for pipeline tags.

    Why this matters
    ----------------
    Free-form tags diverge across pipelines: "contains-pii", "contains_pii",
    "has-pii", "pii-present", "PII" all mean the same thing but as separate
    tags they splinter catalog tag clouds and break tag-based access control.

    How it works
    ------------
    1. Load a YAML tag taxonomy (or use the built-in default).
    2. normalise(tags) maps any incoming tag to its canonical form.
    3. Unknown tags trigger a warning (or abort in strict mode).
    4. Canonical tags are consistently applied across all catalog pushes.

    Taxonomy YAML format
    --------------------
    tags:
      pii:
        canonical: "contains-pii"
        aliases:   ["has-pii", "contains_pii", "pii-present", "PII"]
        description: "Table contains personal data under GDPR Art.4(1)"
        category: "privacy"
      gdpr-special-category:
        canonical: "gdpr-special-category"
        aliases:   ["special-category", "art9", "gdpr-art9"]
        description: "GDPR Article 9 special category data"
        category: "privacy"
      ...
    """

    DEFAULT_TAXONOMY = {
        "contains-pii":           {"canonical": "contains-pii",
                                    "aliases": ["has-pii","contains_pii","pii-present","PII","pii"]},
        "gdpr-special-category":  {"canonical": "gdpr-special-category",
                                    "aliases": ["special-category","art9","gdpr-art9","special_category"]},
        "encrypted":              {"canonical": "encrypted",
                                    "aliases": ["column-encrypted","aes-encrypted","encrypted-at-rest"]},
        "gdpr-compliant":         {"canonical": "gdpr-compliant",
                                    "aliases": ["gdpr","GDPR","gdpr_compliant"]},
        "ccpa-compliant":         {"canonical": "ccpa-compliant",
                                    "aliases": ["ccpa","CCPA","ccpa_compliant"]},
        "data-governance-pipeline":{"canonical": "data-governance-pipeline",
                                    "aliases": ["gov-pipeline","governance-pipeline"]},
        "classification-public":  {"canonical": "classification-public",
                                    "aliases": ["public","PUBLIC"]},
        "classification-internal":{"canonical": "classification-internal",
                                    "aliases": ["internal","INTERNAL"]},
        "classification-confidential":{"canonical":"classification-confidential",
                                    "aliases":["confidential","CONFIDENTIAL"]},
        "classification-restricted":{"canonical":"classification-restricted",
                                    "aliases":["restricted","RESTRICTED"]},
    }

    def __init__(self, gov, taxonomy_path: str | None = None) -> None:
        self.gov      = gov
        self._taxonomy: dict[str, str] = {}  # alias → canonical
        if taxonomy_path and Path(taxonomy_path).exists():
            self.load(taxonomy_path)
        else:
            self._build_from_dict(self.DEFAULT_TAXONOMY)

    def load(self, taxonomy_path: str) -> None:
        """Load taxonomy from a YAML file."""
        if not HAS_YAML:
            log.warning("[TAXONOMY] pyyaml not installed — using defaults.")
            self._build_from_dict(self.DEFAULT_TAXONOMY)
            return
        with open(taxonomy_path, encoding="utf-8") as f:
            data = _yaml.safe_load(f)
        taxonomy_dict = data.get("tags", data)
        self._build_from_dict(taxonomy_dict)
        log.info("[TAXONOMY] Loaded from %s (%s alias mappings)",
                 taxonomy_path, len(self._taxonomy))

    def normalise(
        self,
        tags:   list[str],
        strict: bool = False,
    ) -> list[str]:
        """
        Map tags to their canonical forms and deduplicate.

        Parameters
        ----------
        tags   : list[str]  Raw tag list.
        strict : bool       If True, raise on unknown tags.
                            If False, pass them through with a warning.

        Returns
        -------
        list[str]  Deduplicated canonical tag list.
        """
        canonical: list[str] = []
        seen: set[str] = set()
        for tag in tags:
            normalised = self._taxonomy.get(tag.lower(), self._taxonomy.get(tag))
            if normalised is None:
                # Unknown tag — check if it looks like a version string or run ID.
                if tag.startswith("v") and tag[1:].replace(".", "").isdigit():
                    normalised = tag  # version tags pass through
                elif strict:
                    raise ValueError(f"Unknown tag: '{tag}'. "
                                     f"Add it to the taxonomy or use a canonical form.")
                else:
                    log.warning("[TAXONOMY] Unknown tag '%s' — passing through.", tag)
                    normalised = tag
            if normalised not in seen:
                canonical.append(normalised)
                seen.add(normalised)
        return canonical

    def _build_from_dict(self, taxonomy_dict: dict) -> None:
        self._taxonomy = {}
        for canonical, spec in taxonomy_dict.items():
            if isinstance(spec, dict):
                canon = spec.get("canonical", canonical)
                self._taxonomy[canon.lower()] = canon
                self._taxonomy[canon]         = canon
                for alias in spec.get("aliases", []):
                    self._taxonomy[alias.lower()] = canon
                    self._taxonomy[alias]         = canon
            else:
                self._taxonomy[canonical.lower()] = canonical


def generate_tag_taxonomy(output_path: str = "tag_taxonomy.yaml") -> str:
    """Write a default tag taxonomy YAML file for customisation."""
    default = """# Pipeline Tag Taxonomy
# Edit canonical names and add aliases to fit your organisation.
# All pipelines sharing this file will use the same tag vocabulary.

tags:
  contains-pii:
    canonical: "contains-pii"
    aliases:   ["has-pii", "contains_pii", "pii-present", "PII", "pii"]
    description: "Table contains personal data under GDPR Art.4(1)"
    category: "privacy"

  gdpr-special-category:
    canonical: "gdpr-special-category"
    aliases:   ["special-category", "art9", "gdpr-art9"]
    description: "GDPR Article 9 special category data"
    category: "privacy"

  encrypted:
    canonical: "encrypted"
    aliases:   ["column-encrypted", "aes-encrypted", "encrypted-at-rest"]
    description: "One or more columns encrypted at rest"
    category: "security"

  gdpr-compliant:
    canonical: "gdpr-compliant"
    aliases:   ["gdpr", "GDPR"]
    description: "Processed under GDPR lawful basis"
    category: "compliance"

  ccpa-compliant:
    canonical: "ccpa-compliant"
    aliases:   ["ccpa", "CCPA"]
    description: "Subject to CCPA opt-out rights"
    category: "compliance"

  data-governance-pipeline:
    canonical: "data-governance-pipeline"
    aliases:   ["gov-pipeline", "governance-pipeline"]
    description: "Loaded by the data governance ETL pipeline"
    category: "provenance"

  classification-public:
    canonical: "classification-public"
    aliases:   ["public", "PUBLIC"]
    category: "classification"

  classification-internal:
    canonical: "classification-internal"
    aliases:   ["internal", "INTERNAL"]
    category: "classification"

  classification-confidential:
    canonical: "classification-confidential"
    aliases:   ["confidential", "CONFIDENTIAL"]
    category: "classification"

  classification-restricted:
    canonical: "classification-restricted"
    aliases:   ["restricted", "RESTRICTED"]
    category: "classification"
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(default)
    log.info("[TAXONOMY] Default taxonomy written → %s", output_path)
    return output_path


# ═════════════════════════════════════════════════════════════════════════════
#  ⑨ SENSITIVITY SCORER
# ═════════════════════════════════════════════════════════════════════════════
class SensitivityScorer:
    """
    Computes a numeric sensitivity score (0–100) for a dataset.

    Why this matters
    ----------------
    A 4-level classification label (PUBLIC / INTERNAL / CONFIDENTIAL /
    RESTRICTED) is too coarse for risk ranking.  A table with 20 PII
    fields, 3 special-category fields, no encryption, and a 90-day
    retention policy is far more sensitive than one with 1 PII field
    and AES-256 encryption — but both might be "CONFIDENTIAL".

    A numeric score enables:
    • Automated risk ranking across hundreds of tables.
    • Prioritising data governance remediation work.
    • Catalog dashboards showing sensitivity heatmaps.
    • Dynamic access control thresholds.

    Scoring model (100 points total)
    ---------------------------------
    PII field count          (30)  — 5 pts per PII field, capped at 30.
    Special category fields  (20)  — 10 pts per Art.9 field, capped at 20.
    Encryption status        (15)  — 0 if all PII encrypted, 15 if none.
    Classification level     (15)  — PUBLIC=0, INTERNAL=5, CONFIDENTIAL=10,
                                      RESTRICTED=15.
    Retention risk           (10)  — > 5yr=10, 1-5yr=7, 6-12mo=4, <6mo=0.
    Masking coverage         (10)  — 0 if all PII masked, 10 if none masked.
    """

    CLASSIFICATION_SCORES = {
        "PUBLIC":       0,
        "INTERNAL":     5,
        "CONFIDENTIAL": 10,
        "RESTRICTED":   15,
    }

    def __init__(self, gov) -> None:
        self.gov = gov

    def score(
        self,
        pii_findings:        list[dict],
        special_category_count: int,
        encrypted_cols:      list[str],
        masked_cols:         list[str],
        classification:      str,
        retention_days:      int,
    ) -> dict:
        """
        Compute the sensitivity score for a dataset.

        Parameters
        ----------
        pii_findings         : list[dict]  PII findings from _detect_pii().
        special_category_count: int        Number of Art.9 special-category fields.
        encrypted_cols       : list[str]   Columns encrypted with AES-256.
        masked_cols          : list[str]   Columns SHA-256 masked.
        classification       : str         Classification level string.
        retention_days       : int         Data retention period in days.

        Returns
        -------
        dict  { "score": int, "components": {...}, "risk_level": str }
        """
        pii_cols    = [f["field"] for f in pii_findings]
        pii_count   = len(pii_cols)
        enc_set     = set(encrypted_cols)
        masked_set  = set(masked_cols)

        # PII count component (0–30)
        pii_score = min(pii_count * 5, 30)

        # Special category component (0–20)
        sc_score = min(special_category_count * 10, 20)

        # Encryption component (0–15)
        if pii_count == 0:
            enc_score = 0
        else:
            unencrypted_pii = [c for c in pii_cols if c not in enc_set]
            enc_score = int(15 * len(unencrypted_pii) / pii_count)

        # Classification component (0–15)
        cls_score = self.CLASSIFICATION_SCORES.get(
            classification.upper(), 10
        )

        # Retention risk component (0–10)
        if retention_days > 365 * 5:
            ret_score = 10
        elif retention_days > 365:
            ret_score = 7
        elif retention_days > 180:
            ret_score = 4
        else:
            ret_score = 0

        # Masking coverage component (0–10)
        if pii_count == 0:
            mask_score = 0
        else:
            unmasked_pii = [c for c in pii_cols
                            if c not in masked_set and c not in enc_set]
            mask_score = int(10 * len(unmasked_pii) / pii_count)

        total = pii_score + sc_score + enc_score + cls_score + ret_score + mask_score

        risk_level = (
            "CRITICAL"  if total >= 75 else
            "HIGH"      if total >= 50 else
            "MEDIUM"    if total >= 25 else
            "LOW"
        )

        result = {
            "score"      : total,
            "risk_level" : risk_level,
            "components" : {
                "pii_count"    : pii_score,
                "special_cat"  : sc_score,
                "encryption"   : enc_score,
                "classification": cls_score,
                "retention"    : ret_score,
                "masking"      : mask_score,
            },
            "inputs"     : {
                "pii_count"     : pii_count,
                "special_category_count": special_category_count,
                "encrypted_cols": encrypted_cols,
                "masked_cols"   : masked_cols,
                "classification": classification,
                "retention_days": retention_days,
            },
        }
        self.gov._event("CLASSIFICATION", "SENSITIVITY_SCORE_COMPUTED",
                        {"score": total, "risk_level": risk_level,
                         "classification": classification},
                        level="WARNING" if total >= 50 else "INFO")
        print(f"  ✓  [SENSITIVITY] Score: {total}/100  ({risk_level})")
        return result

    def score_column(
        self,
        is_pii:     bool,
        is_special: bool,
        is_encrypted: bool,
        is_masked:  bool,
    ) -> int:
        """
        Compute a per-column sensitivity score (0–100).
        Simpler than the table-level score; used for catalog column annotations.
        """
        score = 0
        if is_pii:        score += 40
        if is_special:    score += 35
        if not is_encrypted and not is_masked and (is_pii or is_special):
            score += 25  # Unprotected sensitive field
        elif not is_encrypted and (is_pii or is_special):
            score += 10  # Masked but not encrypted
        return min(score, 100)


# ═════════════════════════════════════════════════════════════════════════════
#  ⑩ OBSERVABILITY WEBHOOK
# ═════════════════════════════════════════════════════════════════════════════
class ObservabilityWebhook:
    """
    Pushes quality failure events to external observability platforms.

    Supported platforms
    -------------------
    soda_cloud    — Soda Cloud scan results API.
    pagerduty     — PagerDuty Events API v2 (creates/resolves incidents).
    monte_carlo   — Monte Carlo custom metrics API.
    generic       — Any HTTP endpoint accepting JSON POST.

    Slack / email notifications already exist in the Notifier class and
    are not duplicated here.  This class targets purpose-built data
    observability tools that can correlate failures across pipelines.

    Config (in meta_ext / additions config)
    ----------------------------------------
    observability:
      soda_cloud:
        api_key_id:    "..."
        api_key_secret:"..."
        account_id:    "..."
      pagerduty:
        routing_key:   "..."    # PagerDuty integration key
        severity:      "error"  # critical / error / warning / info
      monte_carlo:
        api_key_id:    "..."
        api_key_secret:"..."
      generic:
        url:           "https://hooks.example.com/quality"
        headers:       {"X-API-Key": "..."}
    """

    def __init__(self, gov, config: dict) -> None:
        self.gov    = gov
        self.config = config or {}

    def notify_on_failure(
        self,
        table:        str,
        source_path:  str,
        quality_meta: dict,
        run_stats:    dict,
    ) -> dict[str, bool]:
        """
        Fire all configured webhooks if quality thresholds are breached.

        Only fires when overall_success=False or pass_rate < 0.95.
        Returns { platform_name: success } dict.
        """
        pass_rate = quality_meta.get("pass_rate", 1.0)
        dlq_rows  = quality_meta.get("dlq_rows", 0)
        is_failure= pass_rate < 0.95 or dlq_rows > 0

        if not is_failure:
            return {}

        results: dict[str, bool] = {}
        pipeline_id = (self.gov.ledger_entries[0]["pipeline_id"]
                       if self.gov.ledger_entries else "")
        summary = (
            f"Quality failure on '{table}': "
            f"pass_rate={pass_rate:.1%}  dlq_rows={dlq_rows}  "
            f"run_id={pipeline_id[:8]}"
        )
        print("  ⚠  [OBSERVABILITY] Quality failure detected — notifying platforms…")

        if "pagerduty" in self.config:
            results["pagerduty"] = self._notify_pagerduty(
                summary, table, quality_meta, pipeline_id
            )
        if "soda_cloud" in self.config:
            results["soda_cloud"] = self._notify_soda(
                table, source_path, quality_meta, pipeline_id
            )
        if "monte_carlo" in self.config:
            results["monte_carlo"] = self._notify_monte_carlo(
                table, quality_meta, pipeline_id
            )
        if "generic" in self.config:
            payload = {
                "event"       : "quality_failure",
                "table"       : table,
                "source"      : source_path,
                "pass_rate"   : pass_rate,
                "dlq_rows"    : dlq_rows,
                "pipeline_id" : pipeline_id,
                "timestamp"   : datetime.now(timezone.utc).isoformat(),
                **run_stats,
            }
            results["generic"] = self._post(
                self.config["generic"]["url"], payload,
                headers=self.config["generic"].get("headers", {})
            )

        for platform, ok in results.items():
            self.gov._event("OBSERVABILITY", "WEBHOOK_FIRED",
                            {"platform": platform, "success": ok,
                             "table": table, "pass_rate": pass_rate},
                            level="INFO" if ok else "WARNING")
        return results

    def _notify_pagerduty(
        self, summary: str, table: str, quality_meta: dict, run_id: str
    ) -> bool:
        cfg = self.config["pagerduty"]
        payload = {
            "routing_key" : cfg["routing_key"],
            "event_action": "trigger",
            "dedup_key"   : f"pipeline-quality-{table}-{run_id[:8]}",
            "payload"     : {
                "summary"  : summary,
                "severity" : cfg.get("severity", "error"),
                "source"   : "data-governance-pipeline",
                "component": table,
                "custom_details": quality_meta,
            },
        }
        ok = self._post(
            "https://events.pagerduty.com/v2/enqueue", payload
        )
        symbol = "✓" if ok else "⚠"
        print(f"  {symbol}  [OBS] PagerDuty: {'triggered' if ok else 'FAILED'}")
        return ok

    def _notify_soda(
        self, table: str, source: str, quality_meta: dict, run_id: str
    ) -> bool:
        cfg = self.config["soda_cloud"]
        # Soda Cloud custom check result ingestion API.
        payload = {
            "type"       : "check_result",
            "checkId"    : f"pipeline-quality-{table}",
            "outcome"    : "fail" if quality_meta.get("pass_rate", 1) < 0.95 else "pass",
            "datasetName": table,
            "sourcePath" : source,
            "metrics"    : {
                "pass_rate": quality_meta.get("pass_rate", 1),
                "dlq_rows" : quality_meta.get("dlq_rows", 0),
                "exp_total": quality_meta.get("expectations_total", 0),
            },
            "runId"      : run_id,
        }
        headers = {
            "soda-api-key-id"    : cfg["api_key_id"],
            "soda-api-key-secret": cfg["api_key_secret"],
        }
        ok = self._post(
            "https://cloud.soda.io/api/v1/scans/ingest", payload, headers
        )
        symbol = "✓" if ok else "⚠"
        print(f"  {symbol}  [OBS] Soda Cloud: {'ingested' if ok else 'FAILED'}")
        return ok

    def _notify_monte_carlo(
        self, table: str, quality_meta: dict, run_id: str
    ) -> bool:
        cfg = self.config["monte_carlo"]
        payload = {
            "query": """
                mutation createOrUpdateMetricMonitoring($dwId: UUID!, $table: String!,
                        $field: String!, $value: Float!) {
                    createOrUpdateMetricMonitoring(dwId: $dwId, tableFullName: $table,
                        metricName: $field, value: $value) { monitor { uuid } }
                }
            """,
            "variables": {
                "table": table,
                "field": "pipeline_pass_rate",
                "value": quality_meta.get("pass_rate", 1.0),
                "runId": run_id,
            },
        }
        headers = {
            "x-mcd-id"    : cfg["api_key_id"],
            "x-mcd-token" : cfg["api_key_secret"],
        }
        ok = self._post(
            "https://api.getmontecarlo.com/graphql", payload, headers
        )
        symbol = "✓" if ok else "⚠"
        print(f"  {symbol}  [OBS] Monte Carlo: {'sent' if ok else 'FAILED'}")
        return ok

    def _post(self, url: str, payload: dict, headers: dict = None) -> bool:
        h = {"Content-Type": "application/json", **(headers or {})}
        try:
            if HAS_REQUESTS:
                resp = _requests.post(url, json=payload, headers=h, timeout=8)
                return resp.status_code < 400
            else:
                import urllib.request
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode(),
                    headers=h,
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=8)
                return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log.warning("[OBS] POST to %s failed: %s", url, exc)
            return False


# ═════════════════════════════════════════════════════════════════════════════
#  ⑪ RUN COST ESTIMATOR
# ═════════════════════════════════════════════════════════════════════════════
class RunCostEstimator:
    """
    Estimates compute cost and carbon footprint for each pipeline run.

    Why this matters
    ----------------
    FinOps teams increasingly require per-job cost attribution.
    Sustainability teams require carbon footprint reporting.
    Neither can be answered without per-run compute estimates.

    Estimation method
    -----------------
    Cost:
      estimated_cost_usd = elapsed_seconds × cpu_rate_per_second
                         + rows_processed  × row_rate_per_million

    Cloud provider rates (approximate, configurable)
    -------------------------------------------------
    aws_t3_medium   : $0.0000138 / second  (on-demand, us-east-1)
    gcp_n1_standard : $0.0000127 / second
    azure_d2s_v3    : $0.0000132 / second
    local           : $0.0          (on-premise / no cloud cost)

    Carbon:
      carbon_gco2e = elapsed_seconds × carbon_intensity_gco2e_per_kwh
                   × power_draw_kw  / 3600
    Carbon intensity defaults to 386 gCO₂e/kWh (US average grid, 2024).
    Power draw defaults to 0.1 kW (typical laptop / small VM).

    State file
    ----------
    run_cost_log.jsonl  — One entry per run:
        { "run_id": "...", "table": "...", "elapsed_seconds": 12.3,
          "rows_processed": 10000, "estimated_cost_usd": 0.00042,
          "carbon_gco2e": 0.013, "cloud_provider": "aws_t3_medium",
          "timestamp": "..." }
    """

    COST_LOG      = _BASE_DIR / "run_cost_log.jsonl"

    # (cost_usd_per_second, row_rate_usd_per_million)
    PROVIDER_RATES = {
        "aws_t3_medium"   : (0.0000138, 0.0001),
        "gcp_n1_standard" : (0.0000127, 0.0001),
        "azure_d2s_v3"    : (0.0000132, 0.0001),
        "local"           : (0.0,       0.0),
    }
    DEFAULT_CARBON_INTENSITY_GCO2E_PER_KWH = 386.0  # US average 2024
    DEFAULT_POWER_KW = 0.1

    def __init__(self, gov) -> None:
        self.gov = gov

    def estimate(
        self,
        table:           str,
        elapsed_seconds: float,
        rows_processed:  int,
        cloud_provider:  str   = "local",
        carbon_intensity: float | None = None,
        power_kw:         float | None = None,
    ) -> dict:
        """
        Compute and persist cost/carbon estimates for this run.

        Parameters
        ----------
        table            : str    Destination table.
        elapsed_seconds  : float  Total pipeline runtime in seconds.
        rows_processed   : int    Total rows loaded this run.
        cloud_provider   : str    One of the PROVIDER_RATES keys.
        carbon_intensity : float  gCO₂e/kWh override (optional).
        power_kw         : float  Power draw override (optional).

        Returns
        -------
        dict  The cost/carbon estimate record.
        """
        cpu_rate, row_rate = self.PROVIDER_RATES.get(
            cloud_provider, self.PROVIDER_RATES["local"]
        )
        cost_usd = (elapsed_seconds * cpu_rate
                    + (rows_processed / 1_000_000) * row_rate)

        ci    = carbon_intensity or self.DEFAULT_CARBON_INTENSITY_GCO2E_PER_KWH
        pw    = power_kw or self.DEFAULT_POWER_KW
        carbon= elapsed_seconds * ci * pw / 3600  # gCO₂e

        pipeline_id = (self.gov.ledger_entries[0]["pipeline_id"]
                       if self.gov.ledger_entries else "")
        record = {
            "run_id"            : pipeline_id,
            "table"             : table,
            "elapsed_seconds"   : round(elapsed_seconds, 2),
            "rows_processed"    : rows_processed,
            "cloud_provider"    : cloud_provider,
            "estimated_cost_usd": round(cost_usd, 6),
            "carbon_gco2e"      : round(carbon, 4),
            "carbon_intensity"  : ci,
            "timestamp"         : datetime.now(timezone.utc).isoformat(),
        }
        with open(self.COST_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        self.gov._event("COST", "RUN_COST_ESTIMATED", record)
        print(f"  ✓  [COST] ${cost_usd:.5f} estimated  |  "
              f"{carbon:.3f} gCO₂e  |  {elapsed_seconds:.1f}s  |  "
              f"{rows_processed:,} rows  ({cloud_provider})")
        return record

    def cumulative_cost(self, table: str | None = None) -> dict:
        """Sum all cost log entries (optionally filtered by table)."""
        if not self.COST_LOG.exists():
            return {"total_cost_usd": 0, "total_carbon_gco2e": 0, "runs": 0}
        records = []
        with open(self.COST_LOG, encoding="utf-8") as f:
            for line in f:
                r = json.loads(line)
                if table is None or r.get("table") == table:
                    records.append(r)
        return {
            "total_cost_usd"    : round(sum(r["estimated_cost_usd"] for r in records), 6),
            "total_carbon_gco2e": round(sum(r["carbon_gco2e"] for r in records), 4),
            "runs"              : len(records),
            "table"             : table,
        }


# ═════════════════════════════════════════════════════════════════════════════
#  ADDITIONS ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════
class AdditionsOrchestrator:
    """
    Wires all 11 new features into pipeline_v3.py main() via hook methods.

    Hook sequence in main()
    -----------------------
    on_extract(df, source_path, db_type, db_cfg, table)
        → CDCTracker.snapshot_before()

    on_suite_built(suite_name, expectations)
        → ExpectationSuiteVersioner.snapshot()

    on_post_validation(pii_findings, encrypted_cols, masked_cols,
                       classification, retention_days)
        → SensitivityScorer.score()

    on_pre_load(df, pii_findings)
        → (DataContractValidator already in ext — no-op here)

    on_post_load(df, source_path, db_type, db_cfg, table,
                 rows_loaded, natural_keys, quality_meta,
                 run_stats, elapsed_seconds)
        → CDCTracker.compute_diff()
        → DataProductRegistry.get_or_register_interactive() / get()
        → EncryptionKeyTracker.record()  (if encrypted_cols)
        → TagTaxonomy.normalise() applied to catalog tags
        → SensitivityScorer result appended to catalog payload
        → RunCostEstimator.estimate()
        → ObservabilityWebhook.notify_on_failure()

    on_erasure(subject_id, source_table, rows_erased)
        → ErasureNotificationRegistry.notify_all()

    on_complete(log_dir, table)
        → DataProductRegistry.export_catalog()
    """

    def __init__(self, gov, config: dict | None = None) -> None:
        cfg = config or {}
        self.gov     = gov
        self.cfg     = cfg

        self.data_product    = DataProductRegistry(gov)
        self.cdc             = CDCTracker(gov)
        self.erasure_notify  = ErasureNotificationRegistry(gov)
        self.suite_versioner = ExpectationSuiteVersioner(gov)
        self.key_tracker     = EncryptionKeyTracker(gov)
        self.tag_taxonomy    = TagTaxonomy(
            gov,
            taxonomy_path=cfg.get("tag_taxonomy_path")
        )
        self.sensitivity     = SensitivityScorer(gov)
        self.obs_webhook     = ObservabilityWebhook(
            gov, cfg.get("observability", {})
        )
        self.cost_estimator  = RunCostEstimator(gov)

        # Stash sensitivity score for catalog payload enrichment.
        self._sensitivity_result: dict = {}
        self._cdc_result: dict = {}

    # ── Hooks ────────────────────────────────────────────────────────────────

    def on_extract(
        self,
        db_type: str,
        db_cfg:  dict,
        table:   str,
    ) -> None:
        """Call before load — snapshots current row count for CDC."""
        self.cdc.snapshot_before(db_type, db_cfg, table)

    def on_suite_built(
        self,
        suite_name:   str,
        expectations: list,
    ) -> dict:
        """Call after SchemaValidator.build_suite() — versions the suite."""
        return self.suite_versioner.snapshot(suite_name, expectations)

    def on_post_validation(
        self,
        pii_findings:           list[dict],
        encrypted_cols:         list[str],
        masked_cols:            list[str],
        classification:         str,
        retention_days:         int,
    ) -> dict:
        """Call after validation — computes sensitivity score."""
        special_count = sum(1 for f in pii_findings
                            if f.get("special_category"))
        result = self.sensitivity.score(
            pii_findings        = pii_findings,
            special_category_count = special_count,
            encrypted_cols      = encrypted_cols,
            masked_cols         = masked_cols,
            classification      = classification,
            retention_days      = retention_days,
        )
        self._sensitivity_result = result
        return result

    def on_encrypt(
        self,
        table:       str,
        columns:     list[str],
        key_version: str,
    ) -> None:
        """Call after ColumnEncryptor.encrypt() — records key version."""
        if columns and key_version:
            self.key_tracker.record(table, columns, key_version)

    def on_post_load(
        self,
        db_type:      str,
        db_cfg:       dict,
        table:        str,
        rows_loaded:  int,
        natural_keys: list[str] | None,
        quality_meta: dict,
        run_stats:    dict,
        elapsed_seconds: float,
        interactive:  bool          = True,
        log_dir:      str           = "governance_logs",
    ) -> None:
        """Call after successful load."""
        # CDC diff.
        self._cdc_result = self.cdc.compute_diff(
            db_type, db_cfg, table, rows_loaded, natural_keys, log_dir
        )

        # Data product ownership.
        if interactive:
            self.data_product.get_or_register_interactive(table)
        else:
            existing = self.data_product.get(table)
            if not existing:
                # Register with defaults in non-interactive mode.
                import getpass
                self.data_product.register(
                    table       = table,
                    owner       = getpass.getuser(),
                    description = f"Auto-registered by pipeline run {self.gov.ledger_entries[0]['pipeline_id'][:8] if self.gov.ledger_entries else ''}",
                )

        # Observability webhooks on quality failure.
        if self.cfg.get("observability"):
            self.obs_webhook.notify_on_failure(
                table, "", quality_meta, run_stats
            )

        # Cost + carbon estimate.
        self.cost_estimator.estimate(
            table            = table,
            elapsed_seconds  = elapsed_seconds,
            rows_processed   = rows_loaded,
            cloud_provider   = self.cfg.get("cloud_provider", "local"),
        )

    def on_erasure(
        self,
        subject_id:   str,
        source_table: str,
        rows_erased:  int,
    ) -> dict[str, bool]:
        """Call after ErasureHandler.execute() — notifies downstream systems."""
        return self.erasure_notify.notify_all(subject_id, source_table, rows_erased)

    def on_complete(self, log_dir: str = "governance_logs") -> None:
        """Call at the end of a successful run."""
        self.data_product.export_catalog(
            str(Path(log_dir) / "data_product_catalog.json")
        )

    def normalise_tags(self, tags: list[str]) -> list[str]:
        """Apply tag taxonomy normalisation to a list of tags."""
        return self.tag_taxonomy.normalise(tags)

    @property
    def sensitivity_score(self) -> int:
        return self._sensitivity_result.get("score", 0)

    @property
    def cdc_result(self) -> dict:
        return self._cdc_result


# ═════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE CONFIG WIZARD
# ═════════════════════════════════════════════════════════════════════════════
def prompt_additions_config() -> dict:
    """Interactive wizard for all 11 addition features."""
    def yn(msg, default=False):
        s = "[Y/n]" if default else "[y/N]"
        r = input(f"{msg} {s}: ").strip().lower()
        return default if not r else r in ("y", "yes")
    def ask(msg, default=""):
        r = input(f"  {msg} [{default}]: " if default else f"  {msg}: ").strip()
        return r or default

    cfg: dict = {}
    print("\n" + "═" * 64)
    print("  PIPELINE ADDITIONS — 11 additional metadata features")
    print("═" * 64)

    # ① Data product registry
    if yn("\n[①] Register data product ownership metadata?", True):
        cfg["data_product_auto"] = True

    # ② CDC tracker — always on
    cfg["cdc_enabled"] = True

    # ③ Erasure notification
    if yn("\n[③] Configure downstream erasure notifications?", False):
        cfg["erasure_notify"] = []
        while True:
            name = ask("Downstream system name (or Enter to finish)").strip()
            if not name: break
            url  = ask(f"  Webhook URL for '{name}'").strip()
            desc = ask("  Description (optional)").strip()
            cfg["erasure_notify"].append(
                {"name": name, "url": url, "description": desc}
            )

    # ④ Suite versioning — always on

    # ⑥ Encryption key version
    if yn("\n[⑥] Track encryption key versions?", True):
        cfg["key_version"] = ask("Key version identifier (e.g. v1, 2025-01)", "v1")

    # ⑦ Tag taxonomy
    if yn("\n[⑦] Use tag taxonomy / controlled vocabulary?", True):
        existing = ask("Path to existing taxonomy YAML (Enter to use defaults)", "")
        if existing and Path(existing).exists():
            cfg["tag_taxonomy_path"] = existing
        else:
            if yn("  Generate default tag_taxonomy.yaml?", True):
                generate_tag_taxonomy("tag_taxonomy.yaml")
                cfg["tag_taxonomy_path"] = "tag_taxonomy.yaml"

    # ⑧ Multi-hop lineage parent run ID
    parent = ask("\n[⑧] Parent run ID for multi-hop lineage (Enter to skip)", "")
    if parent:
        cfg["parent_run_id"] = parent

    # ⑨ Sensitivity scoring — always on

    # ⑩ Observability webhooks
    if yn("\n[⑩] Configure observability webhooks?", False):
        obs: dict = {}
        if yn("  PagerDuty?", False):
            obs["pagerduty"] = {
                "routing_key": ask("PagerDuty integration key"),
                "severity"   : ask("Severity (critical/error/warning)", "error"),
            }
        if yn("  Soda Cloud?", False):
            obs["soda_cloud"] = {
                "api_key_id"    : ask("Soda API key ID"),
                "api_key_secret": ask("Soda API key secret"),
            }
        if yn("  Monte Carlo?", False):
            obs["monte_carlo"] = {
                "api_key_id"    : ask("Monte Carlo API key ID"),
                "api_key_secret": ask("Monte Carlo API key secret"),
            }
        if yn("  Generic webhook?", False):
            obs["generic"] = {"url": ask("Webhook URL")}
        if obs:
            cfg["observability"] = obs

    # ⑪ Cost / carbon
    if yn("\n[⑪] Estimate compute cost and carbon footprint?", True):
        providers = ["aws_t3_medium", "gcp_n1_standard", "azure_d2s_v3", "local"]
        print("  Cloud providers: " + "  ".join(f"{i+1}.{p}" for i, p in enumerate(providers)))
        choice = ask("Provider [4=local]", "4")
        try:
            cfg["cloud_provider"] = providers[int(choice) - 1]
        except (ValueError, IndexError):
            cfg["cloud_provider"] = "local"

    return cfg
