"""
Import governance policy from an external catalog into the pipeline's own
governance state files.

`governance_preflight.py` enforces policy from a handful of JSON/SQLite files in
`config/` (schema baselines, column purposes, purpose limitation, quality
baselines). An org that already keeps this policy in a catalog (Atlan, Collibra,
a home-grown store) shouldn't re-type it here. This module maps a *normalized*
catalog export onto those files so the preflight then enforces the org's
existing policy — closing the loop the lineage emitter only opened outward.

Design: the importer is catalog-agnostic. A `CatalogAdapter` produces a list of
normalized DatasetPolicy dicts; `PolicyImporter` merges them into the governance
files. Concrete adapters (JSON export, Atlan) just produce that normalized form,
so the mapping is testable without any live catalog.

Normalized DatasetPolicy (every field optional except source_label)::

    {
      "source_label":      "customers",                  # keys every file
      "columns":           ["id", "email", "ssn"],       # -> schema_registry
      "dtypes":            {"id": "int64"},              # -> schema_registry
      "column_purposes":   {"email": "contact"},         # -> column_purpose
      "pii_columns":       ["ssn"],                       # -> column_purpose (PII)
      "allowed_columns":   ["id", "email"],              # -> purpose_registry
      "purpose":           "billing",                     # -> purpose_registry
      "expected_row_count": 1000,                         # -> anomaly_baseline
      "null_rates":        {"email": 0.02},              # -> anomaly_baseline
    }

Layer 3 — imports from Layer 0 (constants, helpers).

Revision history
────────────────
1.0   2026-06-19   Initial release: PolicyImporter + JsonExportAdapter +
                   AtlanCatalogAdapter sketch.
1.1   2026-06-22   AtlanCatalogAdapter.fetch() glue now covered by tests with
                   a faked pyatlan SDK; dropped the no-cover pragmas. Only a
                   live tenant / real network round-trip stays unexercised.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pipeline.constants import BASE_DIR
from pipeline.helpers import atomic_json_write

logger = logging.getLogger(__name__)

_CONFIG_DIR = BASE_DIR / "config"


class CatalogAdapter(Protocol):
    """Anything that can produce normalized DatasetPolicy dicts."""

    def fetch(self) -> list[dict]:
        ...


class JsonExportAdapter:
    """Reads normalized DatasetPolicy dicts from a JSON export file.

    The export is either a list of policies or a dict with a top-level
    ``"datasets"`` list. This is the dependency-free integration path: most
    catalogs can export JSON, or a small fetcher can produce it.
    """

    def __init__(self, export_path: str | Path) -> None:
        self.export_path = Path(export_path)

    def fetch(self) -> list[dict]:
        data = json.loads(self.export_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data = data.get("datasets", [])
        if not isinstance(data, list):
            raise ValueError(
                "Catalog export must be a list of policies or a dict with a "
                "'datasets' list.")
        return data


class AtlanCatalogAdapter:
    """Sketch adapter for the Atlan catalog (needs live credentials).

    Kept thin on purpose: the only Atlan-specific part is fetching assets and
    mapping each to the normalized form in `_normalize_asset` — a pure function
    over plain dicts. The fetch glue (construct client → find_all → flatten →
    normalize) is covered by tests with a faked pyatlan SDK; only a live tenant
    and the real network round-trip remain unexercised.
    """

    def __init__(self, base_url: str, api_key: str,
                 source_label_attr: str = "name") -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.source_label_attr = source_label_attr

    def fetch(self) -> list[dict]:
        try:
            from pyatlan.client.atlan import AtlanClient
            from pyatlan.model.assets import Table
        except ImportError as exc:
            raise RuntimeError(
                "pyatlan is required for AtlanCatalogAdapter — "
                "pip install pyatlan") from exc

        client = AtlanClient(base_url=self.base_url, api_key=self.api_key)
        policies = []
        for table in client.asset.find_all(asset_type=Table):
            policies.append(self._normalize_asset(self._asset_to_dict(table)))
        return policies

    @staticmethod
    def _asset_to_dict(table) -> dict:
        """Flatten a pyatlan Table asset into the plain dict _normalize maps."""
        return {
            "name": getattr(table, "name", ""),
            "columns": [
                {
                    "name": getattr(col, "name", ""),
                    "data_type": getattr(col, "data_type", None),
                    "purpose": getattr(col, "user_description", None),
                    "is_pii": "pii" in (getattr(col, "meanings", "") or "").lower(),
                }
                for col in (getattr(table, "columns", None) or [])
            ],
            "purpose": getattr(table, "user_description", None),
        }

    def _normalize_asset(self, asset: dict) -> dict:
        """Map a catalog asset dict onto the normalized DatasetPolicy shape."""
        columns = asset.get("columns", [])
        column_purposes = {
            c["name"]: c["purpose"] for c in columns
            if c.get("name") and c.get("purpose")
        }
        pii_columns = [c["name"] for c in columns if c.get("is_pii") and c.get("name")]
        dtypes = {
            c["name"]: c["data_type"] for c in columns
            if c.get("name") and c.get("data_type")
        }
        policy = {
            "source_label": asset.get(self.source_label_attr) or asset.get("name", ""),
            "columns": [c["name"] for c in columns if c.get("name")],
        }
        if dtypes:
            policy["dtypes"] = dtypes
        if column_purposes:
            policy["column_purposes"] = column_purposes
        if pii_columns:
            policy["pii_columns"] = pii_columns
        if asset.get("purpose"):
            policy["purpose"] = asset["purpose"]
        return policy


class PolicyImporter:
    """
    Merge normalized catalog policy into the preflight's governance files.

    Quick-start
    -----------
        from pipeline.catalog.policy_importer import (
            PolicyImporter, JsonExportAdapter)
        importer = PolicyImporter()
        summary = importer.import_from(JsonExportAdapter("catalog_export.json"))

    Merges, never clobbers: an imported source updates only its own entry in each
    file, leaving other sources (and unrelated fields) intact. Files are written
    atomically; first import creates them.
    """

    def __init__(self, config_dir: str | Path | None = None,
                 dry_run: bool = False) -> None:
        self.config_dir = Path(config_dir) if config_dir else _CONFIG_DIR
        self.dry_run = dry_run

    def _load(self, name: str) -> dict:
        path = self.config_dir / name
        if not path.exists():
            return {}
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            # A corrupt existing file must not be silently overwritten — surface
            # it and abort this file's merge so the operator can look.
            logger.error("Could not read existing %s: %s — skipping its merge.",
                         name, exc)
            raise
        return loaded if isinstance(loaded, dict) else {}

    def _write(self, name: str, data: dict) -> None:
        if self.dry_run:
            logger.info("[POLICY-IMPORT] dry_run — would write %s (%d source(s)).",
                        name, len(data))
            return
        self.config_dir.mkdir(parents=True, exist_ok=True)
        atomic_json_write(self.config_dir / name, json.dumps(data, indent=2))

    def import_from(self, adapter: CatalogAdapter) -> dict:
        """Fetch policies from the adapter and merge them into the config files."""
        policies = adapter.fetch()
        summary: dict = {
            "datasets": 0,
            "schema_registry": [],
            "column_purpose": [],
            "purpose_registry": [],
            "anomaly_baseline": [],
        }

        schema_registry = self._load("schema_registry.json")
        column_purpose = self._load("column_purpose.json")
        purpose_registry = self._load("purpose_registry.json")
        anomaly_baseline = self._load("anomaly_baseline.json")
        now = datetime.now(timezone.utc).isoformat()

        for policy in policies:
            label = policy.get("source_label")
            if not label:
                logger.warning("[POLICY-IMPORT] skipping a policy with no source_label.")
                continue
            summary["datasets"] += 1

            if policy.get("columns"):
                schema_registry[label] = {
                    "columns": list(policy["columns"]),
                    "dtypes": dict(policy.get("dtypes", {})),
                    "updated_utc": now,
                }
                summary["schema_registry"].append(label)

            purposes = dict(policy.get("column_purposes", {}))
            for pii_col in policy.get("pii_columns", []):
                purposes.setdefault(pii_col, "PII")
            if purposes:
                merged = column_purpose.get(label, {})
                merged.update(purposes)
                column_purpose[label] = merged
                summary["column_purpose"].append(label)

            if policy.get("allowed_columns") or policy.get("purpose"):
                entry = purpose_registry.get(label, {})
                if policy.get("allowed_columns"):
                    entry["allowed_columns"] = list(policy["allowed_columns"])
                if policy.get("purpose"):
                    entry["purpose"] = policy["purpose"]
                purpose_registry[label] = entry
                summary["purpose_registry"].append(label)

            if policy.get("expected_row_count") is not None or policy.get("null_rates"):
                entry = anomaly_baseline.get(label, {})
                if policy.get("expected_row_count") is not None:
                    entry["expected_row_count"] = policy["expected_row_count"]
                if policy.get("null_rates"):
                    entry["null_rates"] = dict(policy["null_rates"])
                anomaly_baseline[label] = entry
                summary["anomaly_baseline"].append(label)

        if summary["schema_registry"]:
            self._write("schema_registry.json", schema_registry)
        if summary["column_purpose"]:
            self._write("column_purpose.json", column_purpose)
        if summary["purpose_registry"]:
            self._write("purpose_registry.json", purpose_registry)
        if summary["anomaly_baseline"]:
            self._write("anomaly_baseline.json", anomaly_baseline)

        logger.info("[POLICY-IMPORT] imported %d dataset(s) from catalog.",
                    summary["datasets"])
        return summary
