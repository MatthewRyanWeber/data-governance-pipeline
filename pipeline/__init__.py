"""
data-governance-pipeline — GDPR/CCPA-compliant ETL with full audit logging.

Quick-start
-----------
    from pipeline import GovernanceLogger, Extractor, Transformer
    from pipeline.loaders import resolve_loader

Revision history
----------------
1.0   2026-06-07   Initial package init with lazy imports.
"""

from pipeline.constants import VERSION

__version__ = VERSION


# Lazy imports — only resolve when accessed
def __getattr__(name: str):
    _IMPORTS = {
        "GovernanceLogger": "pipeline.governance_logger",
        "Extractor": "pipeline.extract",
        "Transformer": "pipeline.transform",
        "DataProfiler": "pipeline.profiler",
        "DeadLetterQueue": "pipeline.dead_letter_queue",
        "SchemaValidator": "pipeline.schema_validator",
        "CheckpointManager": "pipeline.checkpoint",
        "TypeCoercer": "pipeline.type_coercer",
        "DataStandardiser": "pipeline.data_standardiser",
        "BusinessRuleEngine": "pipeline.business_rules",
        "DataEnricher": "pipeline.data_enricher",
        "ReferentialIntegrityChecker": "pipeline.referential_integrity",
        "IncrementalFilter": "pipeline.incremental_filter",
        "PartitionedLedger": "pipeline.partitioned_ledger",
        "CompressionHandler": "pipeline.compression",
        "SecretsManager": "pipeline.secrets_manager",
        "RunContext": "pipeline.constants",
        "DEFAULT_RUN_CONTEXT": "pipeline.constants",
        "default_run_context": "pipeline.constants",
    }
    if name in _IMPORTS:
        import importlib
        module = importlib.import_module(_IMPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module 'pipeline' has no attribute {name!r}")


__all__ = [
    "GovernanceLogger",
    "Extractor",
    "Transformer",
    "DataProfiler",
    "SchemaValidator",
    "CheckpointManager",
    "BusinessRuleEngine",
    "SecretsManager",
    "RunContext",
    "VERSION",
]
