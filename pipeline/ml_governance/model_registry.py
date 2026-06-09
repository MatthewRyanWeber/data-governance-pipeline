"""
AI/ML model registry — tracks model-to-dataset relationships.

Records which datasets trained which models, model versioning,
training data lineage, and quality metrics per model version.

Layer 3 — imports from Layer 0 (constants, helpers), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Taste fixes: dry_run support, instance lock, use
                   atomic_json_write, fix mutable-default falsy trap,
                   warn on auto-register, rename terse locals.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR
from pipeline.helpers import atomic_json_write

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_REGISTRY_FILE = BASE_DIR / "config" / "model_registry.json"


class ModelRegistry:
    """
    Tracks AI/ML models, their training datasets, and lineage.

    Quick-start
    -----------
        from pipeline.ml_governance import ModelRegistry
        reg = ModelRegistry(gov)
        reg.register_model("churn_predictor", framework="sklearn",
                           datasets=["customers", "transactions"])
        reg.log_training_run("churn_predictor", metrics={"accuracy": 0.92})
        lineage = reg.training_lineage("churn_predictor")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        registry_file: str | Path | None = None,
        dry_run: bool = False,
    ) -> None:
        self.gov = gov
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self.registry_file = Path(registry_file) if registry_file else _REGISTRY_FILE
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        self._registry: dict = self._load()

    def _load(self) -> dict:
        if not self.registry_file.exists():
            return {"models": {}}
        try:
            return json.loads(self.registry_file.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load model registry: %s", exc)
            return {"models": {}}

    def _save(self) -> None:
        with self._lock:
            self._registry["updated_utc"] = datetime.now(timezone.utc).isoformat()
            data = json.dumps(self._registry, indent=2, default=str)
            atomic_json_write(self.registry_file, data)

    def register_model(
        self,
        model_name: str,
        framework: str = "",
        description: str = "",
        owner: str = "",
        datasets: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        """
        Register a new model or update an existing one.

        Parameters
        ----------
        model_name : str           Unique model identifier.
        framework  : str           ML framework (sklearn, pytorch, tensorflow, etc).
        description: str           What the model does.
        owner      : str           Model owner / team.
        datasets   : list[str]     Training dataset names (links to catalog).
        tags       : list[str]     Searchable tags.
        """
        if self.dry_run:
            logger.info("[ML] [DRY RUN] Would register model '%s'", model_name)
            return self._registry["models"].get(model_name, {})  # type: ignore[no-any-return]

        now = datetime.now(timezone.utc).isoformat()

        existing = self._registry["models"].get(model_name, {})
        model = {
            "model_name": model_name,
            "framework": framework or existing.get("framework", ""),
            "description": description or existing.get("description", ""),
            "owner": owner or existing.get("owner", ""),
            "datasets": datasets if datasets is not None else existing.get("datasets", []),
            "tags": tags if tags is not None else existing.get("tags", []),
            "versions": existing.get("versions", []),
            "created_utc": existing.get("created_utc", now),
            "updated_utc": now,
        }

        self._registry["models"][model_name] = model
        self._save()

        self.gov.transformation_applied("MODEL_REGISTERED", {
            "model": model_name, "framework": framework,
            "dataset_count": len(model["datasets"]),
            "version_count": len(model["versions"]),
        })
        logger.info("[ML] Registered model '%s' (framework=%s, datasets=%d)",
                     model_name, framework, len(model["datasets"]))
        return model

    def log_training_run(
        self,
        model_name: str,
        metrics: dict | None = None,
        hyperparameters: dict | None = None,
        datasets: list[str] | None = None,
        artifact_path: str = "",
        notes: str = "",
    ) -> int:
        """
        Log a training run for a model. Returns the version number.
        """
        if self.dry_run:
            logger.info("[ML] [DRY RUN] Would log training run for '%s'", model_name)
            return 0

        if model_name not in self._registry["models"]:
            logger.warning("[ML] Auto-registering unknown model '%s'", model_name)
            self.register_model(model_name, datasets=datasets)

        model = self._registry["models"][model_name]
        version = len(model["versions"]) + 1

        if datasets:
            for ds in datasets:
                if ds not in model["datasets"]:
                    model["datasets"].append(ds)

        run = {
            "version": version,
            "metrics": metrics or {},
            "hyperparameters": hyperparameters or {},
            "datasets_used": datasets or model["datasets"],
            "artifact_path": artifact_path,
            "notes": notes,
            "trained_utc": datetime.now(timezone.utc).isoformat(),
        }

        model["versions"].append(run)
        model["updated_utc"] = datetime.now(timezone.utc).isoformat()
        self._save()

        self.gov.transformation_applied("MODEL_TRAINING_LOGGED", {
            "model": model_name, "version": version,
            "metrics": metrics or {},
            "datasets": run["datasets_used"],
        })
        logger.info("[ML] Training run logged: '%s' v%d — metrics=%s",
                     model_name, version, metrics or {})
        return version

    def training_lineage(self, model_name: str) -> dict:
        """
        Get full training lineage for a model.

        Returns model info with all training runs, datasets, and metrics.
        """
        model = self._registry["models"].get(model_name)
        if not model:
            raise ValueError(f"Model '{model_name}' not found in registry")

        return {
            "model_name": model_name,
            "framework": model["framework"],
            "owner": model["owner"],
            "total_versions": len(model["versions"]),
            "training_datasets": model["datasets"],
            "versions": model["versions"],
            "created_utc": model["created_utc"],
            "updated_utc": model["updated_utc"],
        }

    def impact_analysis(self, dataset_name: str) -> list[dict]:
        """
        Find all models affected by a dataset change.

        Given a dataset name, returns all models that were trained on it.
        """
        affected = []
        for model_name, model in self._registry["models"].items():
            if dataset_name in model.get("datasets", []):
                affected.append({
                    "model_name": model_name,
                    "framework": model["framework"],
                    "owner": model["owner"],
                    "versions_trained": len(model["versions"]),
                    "last_trained": (
                        model["versions"][-1]["trained_utc"]
                        if model["versions"] else None
                    ),
                })

        if affected:
            self.gov.transformation_applied("MODEL_IMPACT_ANALYSIS", {
                "dataset": dataset_name,
                "affected_models": len(affected),
                "model_names": [m["model_name"] for m in affected],
            })

        return affected

    def list_models(self, framework: str | None = None) -> list[dict]:
        """List all registered models."""
        models = []
        for model in self._registry["models"].values():
            if framework and model.get("framework") != framework:
                continue
            models.append({
                "model_name": model["model_name"],
                "framework": model["framework"],
                "owner": model["owner"],
                "versions": len(model["versions"]),
                "datasets": model["datasets"],
                "updated_utc": model["updated_utc"],
            })
        return models

    def delete_model(self, model_name: str) -> bool:
        """Remove a model from the registry."""
        if self.dry_run:
            logger.info("[ML] [DRY RUN] Would delete model '%s'", model_name)
            return False

        if model_name in self._registry["models"]:
            del self._registry["models"][model_name]
            self._save()
            logger.info("[ML] Deleted model '%s'", model_name)
            return True
        return False

    def compare_versions(
        self, model_name: str,
        version_a: int, version_b: int,
    ) -> dict:
        """Compare metrics between two model versions."""
        model = self._registry["models"].get(model_name)
        if not model:
            raise ValueError(f"Model '{model_name}' not found")

        version_a_entry = version_b_entry = None
        for v in model["versions"]:
            if v["version"] == version_a:
                version_a_entry = v
            if v["version"] == version_b:
                version_b_entry = v

        if not version_a_entry or not version_b_entry:
            raise ValueError(f"Version(s) not found for '{model_name}'")

        metric_diff = {}
        all_metrics = (set(version_a_entry.get("metrics", {}))
                       | set(version_b_entry.get("metrics", {})))
        for metric_name in all_metrics:
            val_a = version_a_entry.get("metrics", {}).get(metric_name)
            val_b = version_b_entry.get("metrics", {}).get(metric_name)
            metric_diff[metric_name] = {
                "version_a": val_a,
                "version_b": val_b,
                "diff": (val_b - val_a) if val_a is not None and val_b is not None else None,
            }

        return {
            "model_name": model_name,
            "version_a": version_a,
            "version_b": version_b,
            "metric_diff": metric_diff,
            "datasets_a": version_a_entry.get("datasets_used", []),
            "datasets_b": version_b_entry.get("datasets_used", []),
        }
