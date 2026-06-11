"""
Tests for pipeline.ml_governance.model_registry.ModelRegistry.

Comprehensive coverage of model registration, training run logging, lineage
tracking, impact analysis, version comparison, dry-run mode, persistence,
deletion, list filtering, and error handling.

Revision history
────────────────
1.0   2026-06-08   Initial release: 12 tests across registration, training,
                   lineage, impact analysis, version comparison, and dry-run.
2.0   2026-06-09   Expanded to 30 tests: persistence round-trip, list_models
                   filtering, delete edge cases, compare_versions with
                   disjoint metrics, multi-dataset lineage accumulation,
                   training run with hyperparameters/artifact/notes, empty
                   registry operations, re-register preserves created_utc,
                   impact analysis governance event, concurrent-safe
                   register via threading.
2.1   2026-06-11   Regression test: concurrent log_training_run calls must
                   produce unique, gapless version numbers.
"""

import json
import logging
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pipeline.ml_governance.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


# ── Helper ────────────────────────────────────────────────────────────────────

def _make_gov():
    """Lightweight stand-in for GovernanceLogger."""
    gov = MagicMock()
    gov.transformation_applied = MagicMock()
    return gov


# ═══════════════════════════════════════════════════════════════════════════════
#  1. Registration
# ═══════════════════════════════════════════════════════════════════════════════


class TestRegisterModel(unittest.TestCase):
    """register_model creates entries and persists them to disk."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_new_model_returns_entry(self):
        result = self.reg.register_model(
            "churn_predictor",
            framework="sklearn",
            description="Predicts customer churn",
            owner="data-team",
            datasets=["customers", "transactions"],
            tags=["production", "v1"],
        )
        self.assertEqual(result["model_name"], "churn_predictor")
        self.assertEqual(result["framework"], "sklearn")
        self.assertEqual(result["datasets"], ["customers", "transactions"])
        self.assertEqual(result["tags"], ["production", "v1"])
        self.assertEqual(result["versions"], [])

    def test_register_model_persists_to_disk(self):
        self.reg.register_model("fraud_detector", framework="pytorch")
        data = json.loads(self.registry_file.read_text(encoding="utf-8"))
        self.assertIn("fraud_detector", data["models"])
        self.assertEqual(data["models"]["fraud_detector"]["framework"], "pytorch")

    def test_register_model_logs_governance_event(self):
        self.reg.register_model(
            "sentiment_model", framework="tensorflow",
            datasets=["reviews"],
        )
        self.gov.transformation_applied.assert_called_once()
        call_args = self.gov.transformation_applied.call_args
        self.assertEqual(call_args[0][0], "MODEL_REGISTERED")
        self.assertEqual(call_args[0][1]["model"], "sentiment_model")

    def test_update_existing_model_preserves_versions(self):
        self.reg.register_model("scorer", framework="sklearn")
        self.reg.log_training_run("scorer", metrics={"accuracy": 0.85})
        self.reg.register_model("scorer", framework="xgboost")
        result = self.reg.register_model("scorer")
        self.assertEqual(len(result["versions"]), 1)
        self.assertEqual(result["framework"], "xgboost")

    def test_register_with_empty_datasets_defaults_to_list(self):
        """Passing datasets=None stores an empty list, not None."""
        result = self.reg.register_model("bare_model")
        self.assertIsInstance(result["datasets"], list)
        self.assertEqual(result["datasets"], [])

    def test_register_with_empty_tags_defaults_to_list(self):
        result = self.reg.register_model("bare_model")
        self.assertIsInstance(result["tags"], list)
        self.assertEqual(result["tags"], [])

    def test_re_register_preserves_created_utc(self):
        """Re-registering a model must not overwrite the original created_utc."""
        self.reg.register_model("stable_model", framework="sklearn")
        original = self.reg._registry["models"]["stable_model"]["created_utc"]
        self.reg.register_model("stable_model", framework="xgboost")
        after = self.reg._registry["models"]["stable_model"]["created_utc"]
        self.assertEqual(original, after)

    def test_register_multiple_models_all_present(self):
        for name in ("alpha", "beta", "gamma"):
            self.reg.register_model(name, framework="sklearn")
        models = self.reg.list_models()
        names = {m["model_name"] for m in models}
        self.assertEqual(names, {"alpha", "beta", "gamma"})


# ═══════════════════════════════════════════════════════════════════════════════
#  2. Training runs
# ═══════════════════════════════════════════════════════════════════════════════


class TestLogTrainingRun(unittest.TestCase):
    """log_training_run appends version entries with metrics."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_log_training_run_returns_version_number(self):
        self.reg.register_model("classifier", framework="sklearn")
        version = self.reg.log_training_run(
            "classifier",
            metrics={"accuracy": 0.91, "f1": 0.88},
            hyperparameters={"n_estimators": 100},
        )
        self.assertEqual(version, 1)

    def test_sequential_runs_increment_version(self):
        self.reg.register_model("classifier", framework="sklearn")
        v1 = self.reg.log_training_run("classifier", metrics={"accuracy": 0.88})
        v2 = self.reg.log_training_run("classifier", metrics={"accuracy": 0.92})
        self.assertEqual(v1, 1)
        self.assertEqual(v2, 2)

    def test_auto_registers_unknown_model(self):
        with self.assertLogs("pipeline.ml_governance.model_registry", level="WARNING") as cm:
            version = self.reg.log_training_run(
                "unknown_model",
                metrics={"loss": 0.05},
                datasets=["synthetic_data"],
            )
        self.assertEqual(version, 1)
        self.assertTrue(any("Auto-registering" in m for m in cm.output))

    def test_training_run_stores_hyperparameters(self):
        self.reg.register_model("tuned", framework="sklearn")
        self.reg.log_training_run(
            "tuned",
            metrics={"accuracy": 0.93},
            hyperparameters={"learning_rate": 0.01, "epochs": 50},
        )
        lineage = self.reg.training_lineage("tuned")
        hp = lineage["versions"][0]["hyperparameters"]
        self.assertEqual(hp["learning_rate"], 0.01)
        self.assertEqual(hp["epochs"], 50)

    def test_training_run_stores_artifact_and_notes(self):
        self.reg.register_model("documented", framework="pytorch")
        self.reg.log_training_run(
            "documented",
            metrics={"loss": 0.03},
            artifact_path="/models/documented_v1.pt",
            notes="Trained on 2026-06-09 with augmented data",
        )
        lineage = self.reg.training_lineage("documented")
        run = lineage["versions"][0]
        self.assertEqual(run["artifact_path"], "/models/documented_v1.pt")
        self.assertIn("augmented data", run["notes"])

    def test_training_run_accumulates_datasets(self):
        """Logging a run with new datasets adds them to the model's dataset list."""
        self.reg.register_model("evolving", datasets=["base_data"])
        self.reg.log_training_run(
            "evolving",
            metrics={"accuracy": 0.80},
            datasets=["base_data", "extra_data"],
        )
        model = self.reg._registry["models"]["evolving"]
        self.assertIn("extra_data", model["datasets"])
        self.assertIn("base_data", model["datasets"])

    def test_training_run_logs_governance_event(self):
        self.reg.register_model("tracked", framework="sklearn")
        self.gov.transformation_applied.reset_mock()
        self.reg.log_training_run("tracked", metrics={"accuracy": 0.90})
        calls = self.gov.transformation_applied.call_args_list
        event_types = [c[0][0] for c in calls]
        self.assertIn("MODEL_TRAINING_LOGGED", event_types)


# ═══════════════════════════════════════════════════════════════════════════════
#  3. Training lineage
# ═══════════════════════════════════════════════════════════════════════════════


class TestTrainingLineage(unittest.TestCase):
    """training_lineage returns full history for a registered model."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_lineage_includes_all_versions_and_datasets(self):
        self.reg.register_model(
            "recommender", framework="pytorch",
            datasets=["user_events", "item_catalog"],
        )
        self.reg.log_training_run("recommender", metrics={"ndcg": 0.72})
        self.reg.log_training_run("recommender", metrics={"ndcg": 0.78})
        lineage = self.reg.training_lineage("recommender")
        self.assertEqual(lineage["model_name"], "recommender")
        self.assertEqual(lineage["framework"], "pytorch")
        self.assertEqual(lineage["total_versions"], 2)
        self.assertEqual(lineage["training_datasets"], ["user_events", "item_catalog"])
        self.assertEqual(len(lineage["versions"]), 2)
        self.assertEqual(lineage["versions"][0]["metrics"]["ndcg"], 0.72)
        self.assertEqual(lineage["versions"][1]["metrics"]["ndcg"], 0.78)

    def test_lineage_raises_for_unknown_model(self):
        with self.assertRaises(ValueError) as ctx:
            self.reg.training_lineage("nonexistent_model")
        self.assertIn("nonexistent_model", str(ctx.exception))

    def test_lineage_has_timestamps(self):
        self.reg.register_model("timed", framework="sklearn")
        self.reg.log_training_run("timed", metrics={"accuracy": 0.90})
        lineage = self.reg.training_lineage("timed")
        self.assertIn("created_utc", lineage)
        self.assertIn("updated_utc", lineage)
        self.assertIn("trained_utc", lineage["versions"][0])


# ═══════════════════════════════════════════════════════════════════════════════
#  4. Impact analysis
# ═══════════════════════════════════════════════════════════════════════════════


class TestImpactAnalysis(unittest.TestCase):
    """impact_analysis finds all models trained on a given dataset."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_impact_analysis_returns_affected_models(self):
        self.reg.register_model(
            "churn_v1", framework="sklearn",
            datasets=["customers", "transactions"],
        )
        self.reg.register_model(
            "churn_v2", framework="xgboost",
            datasets=["customers", "interactions"],
        )
        self.reg.register_model(
            "fraud_detector", framework="pytorch",
            datasets=["transactions", "fraud_labels"],
        )
        affected = self.reg.impact_analysis("customers")
        affected_names = [m["model_name"] for m in affected]
        self.assertIn("churn_v1", affected_names)
        self.assertIn("churn_v2", affected_names)
        self.assertNotIn("fraud_detector", affected_names)
        self.assertEqual(len(affected), 2)

    def test_impact_analysis_returns_empty_for_unused_dataset(self):
        self.reg.register_model("scorer", framework="sklearn", datasets=["sales"])
        affected = self.reg.impact_analysis("nonexistent_dataset")
        self.assertEqual(affected, [])

    def test_impact_analysis_logs_governance_event_when_affected(self):
        self.reg.register_model("model_x", datasets=["shared_data"])
        self.gov.transformation_applied.reset_mock()
        self.reg.impact_analysis("shared_data")
        calls = self.gov.transformation_applied.call_args_list
        event_types = [c[0][0] for c in calls]
        self.assertIn("MODEL_IMPACT_ANALYSIS", event_types)

    def test_impact_analysis_no_event_when_none_affected(self):
        self.reg.register_model("model_y", datasets=["other_data"])
        self.gov.transformation_applied.reset_mock()
        self.reg.impact_analysis("nonexistent_dataset")
        for call in self.gov.transformation_applied.call_args_list:
            self.assertNotEqual(call[0][0], "MODEL_IMPACT_ANALYSIS")

    def test_impact_analysis_includes_last_trained(self):
        self.reg.register_model("trained_model", datasets=["key_data"])
        self.reg.log_training_run("trained_model", metrics={"accuracy": 0.88})
        affected = self.reg.impact_analysis("key_data")
        self.assertEqual(len(affected), 1)
        self.assertIsNotNone(affected[0]["last_trained"])

    def test_impact_analysis_last_trained_none_when_no_versions(self):
        self.reg.register_model("untrained", datasets=["key_data"])
        affected = self.reg.impact_analysis("key_data")
        self.assertEqual(len(affected), 1)
        self.assertIsNone(affected[0]["last_trained"])


# ═══════════════════════════════════════════════════════════════════════════════
#  5. Version comparison
# ═══════════════════════════════════════════════════════════════════════════════


class TestCompareVersions(unittest.TestCase):
    """compare_versions computes metric diffs between two model versions."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )
        self.reg.register_model("model_a", framework="sklearn")
        self.reg.log_training_run(
            "model_a", metrics={"accuracy": 0.85, "f1": 0.80},
        )
        self.reg.log_training_run(
            "model_a", metrics={"accuracy": 0.91, "f1": 0.87},
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_compare_versions_shows_metric_diff(self):
        result = self.reg.compare_versions("model_a", 1, 2)
        self.assertEqual(result["model_name"], "model_a")
        self.assertEqual(result["version_a"], 1)
        self.assertEqual(result["version_b"], 2)
        self.assertAlmostEqual(
            result["metric_diff"]["accuracy"]["diff"], 0.06, places=5,
        )
        self.assertAlmostEqual(
            result["metric_diff"]["f1"]["diff"], 0.07, places=5,
        )
        self.assertEqual(result["metric_diff"]["accuracy"]["version_a"], 0.85)
        self.assertEqual(result["metric_diff"]["accuracy"]["version_b"], 0.91)

    def test_compare_versions_raises_for_missing_version(self):
        with self.assertRaises(ValueError):
            self.reg.compare_versions("model_a", 1, 99)

    def test_compare_versions_raises_for_missing_model(self):
        with self.assertRaises(ValueError):
            self.reg.compare_versions("nonexistent", 1, 2)

    def test_compare_versions_with_disjoint_metrics(self):
        """When versions have different metric sets, missing values are None."""
        self.reg.register_model("model_b", framework="pytorch")
        self.reg.log_training_run("model_b", metrics={"accuracy": 0.80})
        self.reg.log_training_run("model_b", metrics={"f1": 0.75})
        result = self.reg.compare_versions("model_b", 1, 2)
        self.assertIsNone(result["metric_diff"]["accuracy"]["version_b"])
        self.assertIsNone(result["metric_diff"]["f1"]["version_a"])
        self.assertIsNone(result["metric_diff"]["accuracy"]["diff"])
        self.assertIsNone(result["metric_diff"]["f1"]["diff"])

    def test_compare_versions_includes_datasets_used(self):
        result = self.reg.compare_versions("model_a", 1, 2)
        self.assertIn("datasets_a", result)
        self.assertIn("datasets_b", result)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. Dry-run mode
# ═══════════════════════════════════════════════════════════════════════════════


class TestDryRunMode(unittest.TestCase):
    """dry_run=True prevents all writes to disk and registry mutations."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file, dry_run=True,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_register_does_not_persist(self):
        self.reg.register_model("ghost_model", framework="sklearn")
        self.assertFalse(self.registry_file.exists())

    def test_dry_run_log_training_returns_zero(self):
        version = self.reg.log_training_run(
            "ghost_model", metrics={"accuracy": 0.99},
        )
        self.assertEqual(version, 0)

    def test_dry_run_delete_returns_false(self):
        result = self.reg.delete_model("anything")
        self.assertFalse(result)

    def test_dry_run_register_logs_info(self):
        with self.assertLogs("pipeline.ml_governance.model_registry", level="INFO") as cm:
            self.reg.register_model("phantom", framework="pytorch")
        self.assertTrue(any("DRY RUN" in m for m in cm.output))
        self.assertTrue(any("phantom" in m for m in cm.output))

    def test_dry_run_does_not_call_governance_for_register(self):
        self.reg.register_model("invisible", framework="sklearn")
        self.gov.transformation_applied.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
#  7. Listing and filtering
# ═══════════════════════════════════════════════════════════════════════════════


class TestListModels(unittest.TestCase):
    """list_models returns all models, optionally filtered by framework."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_list_models_empty_registry(self):
        self.assertEqual(self.reg.list_models(), [])

    def test_list_models_filter_by_framework(self):
        self.reg.register_model("sk_model", framework="sklearn")
        self.reg.register_model("pt_model", framework="pytorch")
        self.reg.register_model("sk_model_2", framework="sklearn")
        sklearn_models = self.reg.list_models(framework="sklearn")
        self.assertEqual(len(sklearn_models), 2)
        for m in sklearn_models:
            self.assertEqual(m["framework"], "sklearn")

    def test_list_models_no_match_returns_empty(self):
        self.reg.register_model("sk_model", framework="sklearn")
        result = self.reg.list_models(framework="jax")
        self.assertEqual(result, [])

    def test_list_models_includes_version_count(self):
        self.reg.register_model("versioned", framework="sklearn")
        self.reg.log_training_run("versioned", metrics={"accuracy": 0.80})
        self.reg.log_training_run("versioned", metrics={"accuracy": 0.85})
        models = self.reg.list_models()
        self.assertEqual(models[0]["versions"], 2)


# ═══════════════════════════════════════════════════════════════════════════════
#  8. Deletion
# ═══════════════════════════════════════════════════════════════════════════════


class TestDeleteModel(unittest.TestCase):
    """delete_model removes a model from the registry and persists."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_delete_existing_model(self):
        self.reg.register_model("doomed", framework="sklearn")
        self.assertTrue(self.reg.delete_model("doomed"))
        self.assertEqual(self.reg.list_models(), [])

    def test_delete_nonexistent_returns_false(self):
        self.assertFalse(self.reg.delete_model("never_existed"))

    def test_delete_persists_removal(self):
        self.reg.register_model("ephemeral", framework="sklearn")
        self.reg.delete_model("ephemeral")
        data = json.loads(self.registry_file.read_text(encoding="utf-8"))
        self.assertNotIn("ephemeral", data["models"])


# ═══════════════════════════════════════════════════════════════════════════════
#  9. Persistence round-trip
# ═══════════════════════════════════════════════════════════════════════════════


class TestPersistence(unittest.TestCase):
    """Registry survives a fresh load from the same file."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_round_trip_preserves_models(self):
        reg1 = ModelRegistry(self.gov, registry_file=self.registry_file)
        reg1.register_model("persistent", framework="sklearn", datasets=["ds1"])
        reg1.log_training_run("persistent", metrics={"accuracy": 0.95})

        reg2 = ModelRegistry(self.gov, registry_file=self.registry_file)
        models = reg2.list_models()
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0]["model_name"], "persistent")
        self.assertEqual(models[0]["versions"], 1)

    def test_round_trip_preserves_lineage(self):
        reg1 = ModelRegistry(self.gov, registry_file=self.registry_file)
        reg1.register_model("lineage_test", framework="pytorch", datasets=["data_a"])
        reg1.log_training_run("lineage_test", metrics={"loss": 0.05})
        reg1.log_training_run("lineage_test", metrics={"loss": 0.02})

        reg2 = ModelRegistry(self.gov, registry_file=self.registry_file)
        lineage = reg2.training_lineage("lineage_test")
        self.assertEqual(lineage["total_versions"], 2)
        self.assertEqual(lineage["versions"][0]["metrics"]["loss"], 0.05)
        self.assertEqual(lineage["versions"][1]["metrics"]["loss"], 0.02)

    def test_load_from_corrupt_file_returns_empty(self):
        """Corrupt JSON falls back to an empty registry."""
        self.registry_file.write_text("NOT VALID JSON {{{{", encoding="utf-8")
        with self.assertLogs("pipeline.ml_governance.model_registry", level="WARNING"):
            reg = ModelRegistry(self.gov, registry_file=self.registry_file)
        self.assertEqual(reg.list_models(), [])

    def test_load_from_missing_file_returns_empty(self):
        reg = ModelRegistry(self.gov, registry_file=self.registry_file)
        self.assertEqual(reg.list_models(), [])


# ═══════════════════════════════════════════════════════════════════════════════
#  10. Thread safety
# ═══════════════════════════════════════════════════════════════════════════════


class TestThreadSafety(unittest.TestCase):
    """Concurrent register_model calls must not corrupt the registry."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = _make_gov()
        self.reg = ModelRegistry(
            self.gov, registry_file=self.registry_file,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_concurrent_registers(self):
        errors = []

        def register(name):
            try:
                self.reg.register_model(name, framework="sklearn")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=register, args=(f"model_{i}",))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(self.reg.list_models()), 10)

    def test_concurrent_training_runs_get_unique_versions(self):
        """Regression: version = len(versions) + 1 was computed outside the
        lock, so two concurrent runs could be assigned the same version."""
        self.reg.register_model("contended", framework="sklearn")
        versions = []
        errors = []

        def train(index):
            try:
                versions.append(
                    self.reg.log_training_run(
                        "contended", metrics={"accuracy": 0.5 + index / 100},
                    )
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=train, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(sorted(versions), list(range(1, 11)))
        stored = self.reg._registry["models"]["contended"]["versions"]
        stored_versions = sorted(run["version"] for run in stored)
        self.assertEqual(stored_versions, list(range(1, 11)))


if __name__ == "__main__":
    unittest.main()
