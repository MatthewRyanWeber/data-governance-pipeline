"""
MongoDB loader — writes DataFrames to MongoDB collections.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class MongoLoader).
"""

import json
import logging
from typing import TYPE_CHECKING

from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class MongoLoader(BaseLoader):
    """MongoDB loader."""

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)

    def load(self, df, cfg, collection):
        if self._dry_run_guard(collection, len(df)):
            return
        self._validate_config(cfg, ["db_name"])
        from pymongo import MongoClient
        uri = cfg.get("uri") or (
            f"mongodb://{cfg.get('host', 'localhost')}:"
            f"{cfg.get('port', 27017)}/"
        )
        with MongoClient(uri) as client:
            records = json.loads(df.to_json(orient="records", date_format="iso"))
            client[cfg["db_name"]][collection].insert_many(records)
            self.gov.load_complete(len(records), collection)
            self.gov.destination_registered("mongodb", cfg["db_name"], collection)
