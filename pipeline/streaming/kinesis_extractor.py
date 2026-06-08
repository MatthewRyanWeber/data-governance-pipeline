"""
AWS Kinesis stream extractor — reads from a Kinesis data stream.

Iterates over all shards, fetching records in micro-batches and yielding
each batch as a pandas DataFrame.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
"""

import json
import logging
import time
from typing import Generator, TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class KinesisStreamExtractor:
    """
    Read records from an AWS Kinesis stream and yield DataFrames.

    Quick-start
    -----------
        from pipeline.streaming import KinesisStreamExtractor
        ext = KinesisStreamExtractor(gov, stream_name="events-stream")
        for batch_df in ext.consume():
            process(batch_df)
        ext.close()
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        stream_name: str,
        region: str = "us-east-1",
        batch_size: int = 500,
    ) -> None:
        self.gov = gov
        self.stream_name = stream_name
        self.region = region
        self.batch_size = batch_size
        self._client = None

        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "boto3 is required for KinesisStreamExtractor. "
                "Install it with: pip install boto3"
            )

        self._client = boto3.client("kinesis", region_name=self.region)
        logger.info(
            "KinesisStreamExtractor initialised — stream=%s, region=%s",
            self.stream_name, self.region,
        )

    def _get_shard_ids(self) -> list[str]:
        """Retrieve all shard IDs for the configured stream."""
        response = self._client.list_shards(StreamName=self.stream_name)
        shard_ids = [shard["ShardId"] for shard in response.get("Shards", [])]
        logger.info("Found %d shards for stream %s.", len(shard_ids), self.stream_name)
        return shard_ids

    def consume(self) -> Generator[pd.DataFrame, None, None]:
        """
        Iterate over all shards and yield micro-batches as DataFrames.

        Each batch contains up to ``batch_size`` deserialized JSON records.
        """
        shard_ids = self._get_shard_ids()

        for shard_id in shard_ids:
            iterator_response = self._client.get_shard_iterator(
                StreamName=self.stream_name,
                ShardId=shard_id,
                ShardIteratorType="TRIM_HORIZON",
            )
            shard_iterator = iterator_response["ShardIterator"]
            records: list[dict] = []

            while shard_iterator:
                response = self._client.get_records(
                    ShardIterator=shard_iterator,
                    Limit=self.batch_size,
                )
                shard_iterator = response.get("NextShardIterator")

                for record in response.get("Records", []):
                    try:
                        value = json.loads(record["Data"].decode("utf-8"))
                        records.append(value)
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        logger.warning(
                            "Skipping malformed Kinesis record in shard %s: %s",
                            shard_id, exc,
                        )
                        continue

                    if len(records) >= self.batch_size:
                        logger.info("Yielding Kinesis batch of %d records.", len(records))
                        yield pd.DataFrame(records)
                        records = []

                if not response.get("Records"):
                    break

                # Kinesis rate-limits reads — back off briefly between fetches
                time.sleep(0.2)

            if records:
                logger.info("Yielding final Kinesis batch of %d records from shard %s.", len(records), shard_id)
                yield pd.DataFrame(records)

    def close(self) -> None:
        """Release the Kinesis client."""
        self._client = None
        logger.info("Kinesis client released.")
