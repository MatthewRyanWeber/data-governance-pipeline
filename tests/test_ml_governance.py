"""
Tests for pipeline.ml_governance.model_registry.ModelRegistry.

Covers model registration, training run logging, lineage tracking,
impact analysis, version comparison, dry-run mode, and persistence.

Revision history
────────────────
1.0   2026-06-08   Initial release: 12 tests across registration, training,
                   lineage, impact analysis, version comparison, and dry-run.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pipeline.ml_governance.model_registry import ModelRegistry


class TestRegisterModel(unittest.TestCase):
    """register_model creates entries and persists them to disk."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = MagicMock()
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


class TestLogTrainingRun(unittest.TestCase):
    """log_training_run appends version entries with metrics."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = MagicMock()
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


class TestTrainingLineage(unittest.TestCase):
    """training_lineage returns full history for a registered model."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = MagicMock()
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


class TestImpactAnalysis(unittest.TestCase):
    """impact_analysis finds all models trained on a given dataset."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = MagicMock()
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
        self.gov.transformation_applied.assert_called_with(
            "MODEL_REGISTERED", unittest.mock.ANY,
        )


class TestCompareVersions(unittest.TestCase):
    """compare_versions computes metric diffs between two model versions."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = MagicMock()
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


class TestDryRunMode(unittest.TestCase):
    """dry_run=True prevents all writes to disk and registry mutations."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.registry_file = Path(self.tmp) / "registry.json"
        self.gov = MagicMock()
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


if __name__ == "__main__":
    unittest.main()
