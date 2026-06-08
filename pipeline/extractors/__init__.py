"""
Extractor sub-package — database and REST API source readers.

Complements pipeline.extract (file-based) and pipeline.streaming
(message-queue-based) with pull-based extraction from databases and HTTP APIs.

Revision history
────────────────
1.0   2026-06-08   Initial release with DatabaseExtractor and RESTExtractor.
"""

from pipeline.extractors.database_extractor import DatabaseExtractor
from pipeline.extractors.rest_extractor import RESTExtractor

__all__ = ["DatabaseExtractor", "RESTExtractor"]
