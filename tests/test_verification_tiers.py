"""
Enforce honesty about destination verification tiers — "no claim without proof".

A recurring failure mode for a project this broad is the README claiming more
than the test suite proves. These tests make that drift a CI failure:

  1. The tier assignments match a reviewed snapshot, so a tier can't change
     (or a destination be added) without a deliberate test update — which is
     the moment to add the evidence that justifies the new tier.
  2. Every CORE and EMULATOR destination — the tiers that CLAIM an engine/
     emulator test runs in CI — actually appears in a tests/integration file.
     A destination claiming 'core' with only mock/contract coverage fails here.
  3. The README's machine-readable tier counts equal the registry's counts, so
     the headline number can't drift above what the registry actually holds.

Revision history
────────────────
1.0   2026-06-14   Initial release: tier snapshot, integration-evidence, and
                   README count enforcement.
"""

import re
import unittest
from collections import Counter
from pathlib import Path

from pipeline.loaders import (
    _VERIFICATION_TIER, TIER_CORE, TIER_EMULATOR, TIER_CLOUD, TIER_EXPERIMENTAL,
)

_REPO = Path(__file__).resolve().parent.parent
_INTEGRATION_DIR = _REPO / "tests" / "integration"
_README = _REPO / "README.md"

# Every file that drives a real engine/emulator in CI.
_INTEGRATION_FILES = list(_INTEGRATION_DIR.glob("*.py")) + [
    _REPO / "tests" / "test_integration_db.py"
]

# Reviewed snapshot. Changing a destination's tier requires updating this AND
# the evidence that justifies it — that friction is the point.
_EXPECTED_TIER = {
    # core — real engine/embedded client in CI
    "sqlite": "core", "postgresql": "core", "postgres": "core", "mysql": "core",
    "mssql": "core", "mongodb": "core", "duckdb": "core", "parquet": "core",
    "deltalake": "core", "iceberg": "core", "s3": "core", "azure_blob": "core",
    "kafka": "core", "clickhouse": "core", "pgvector": "core", "postgis": "core",
    "cockroachdb": "core", "sftp": "core", "chroma": "core", "lancedb": "core",
    "qdrant": "core", "weaviate": "core", "milvus": "core", "oracle": "core",
    "db2": "core", "synapse": "core", "yellowbrick": "core",
    # emulator
    "snowflake": "emulator", "bigquery": "emulator", "pinecone": "emulator",
    # cloud — credential-gated
    "gcs": "cloud", "redshift": "cloud", "databricks": "cloud", "firebolt": "cloud",
    "hana": "cloud", "datasphere": "cloud", "motherduck": "cloud",
    "quickbooks": "cloud", "snowflake_vector": "cloud", "bigquery_vector": "cloud",
    # experimental — wired + mock-tested only, no engine/emulator proof
    "fabric": "experimental", "athena": "experimental",
}


class TestVerificationTiers(unittest.TestCase):

    def test_registry_matches_reviewed_snapshot(self):
        self.assertEqual(
            dict(_VERIFICATION_TIER), _EXPECTED_TIER,
            "Tier registry changed without updating the reviewed snapshot. "
            "If a destination's tier changed, update _EXPECTED_TIER here AND "
            "ensure the evidence (an integration/emulator/credentialed test) "
            "justifies the new tier.",
        )

    def test_core_and_emulator_destinations_have_an_integration_test(self):
        # These tiers claim a real engine/emulator runs them in CI, so the
        # db_type must appear in some tests/integration file. Cloud and
        # experimental tiers are exempt (credential-gated / unproven by design).
        blobs = [p.read_text(encoding="utf-8") for p in _INTEGRATION_FILES if p.exists()]
        if not blobs:
            self.skipTest("integration test files not present in this tree")
        for db_type, tier in _VERIFICATION_TIER.items():
            if tier not in (TIER_CORE, TIER_EMULATOR):
                continue
            pattern = re.compile(rf"\b{re.escape(db_type)}\b")
            present = any(pattern.search(b) for b in blobs)
            self.assertTrue(
                present,
                f"'{db_type}' is tier '{tier}' (claims an engine/emulator test) "
                f"but its db_type appears in no tests/integration file. Add a "
                f"real test or demote it to cloud/experimental.",
            )

    @unittest.skipUnless(
        _README.exists(),
        "README.md not present in this tree (e.g. a minimal Docker image)",
    )
    def test_readme_counts_match_registry(self):
        counts = Counter(_VERIFICATION_TIER.values())
        marker = (
            f"<!-- TIER-COUNTS: core={counts[TIER_CORE]} "
            f"emulator={counts[TIER_EMULATOR]} cloud={counts[TIER_CLOUD]} "
            f"experimental={counts[TIER_EXPERIMENTAL]} -->"
        )
        readme = _README.read_text(encoding="utf-8")
        self.assertIn(
            marker, readme,
            f"README tier-count marker is stale or missing. It must read:\n"
            f"  {marker}\n(update the README's destination counts to match the "
            f"registry, then this marker).",
        )


if __name__ == "__main__":
    unittest.main()
