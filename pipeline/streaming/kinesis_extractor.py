"""
AWS Kinesis stream extractor — reads from a Kinesis data stream.

Iterates over all shards, fetching records in micro-batches and yielding
each batch as a pandas DataFrame.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-08   Paginate list_shards via NextToken for streams with many shards.
1.2   2026-06-11   Fix silent data loss: empty GetRecords pages no longer end
                   the shard — iteration continues with NextShardIterator and
                   stops on iterator None or MillisBehindLatest == 0.  Added
                   optional per-shard sequence-number checkpointing
                   (checkpoint_path) with atomic writes and
                   AFTER_SEQUENCE_NUMBER resume.
"""

import json
import logging
import time
from pathlib import Path
from typing import Generator, TYPE_CHECKING

import pandas as pd

from pipeline.helpers import atomic_json_write

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
        checkpoint_path: str | Path | None = None,
    ) -> None:
        self.gov = gov
        self.stream_name = stream_name
        self.region = region
        self.batch_size = batch_size
        # Optional config-driven checkpoint file: {"shards": {shard_id: seq}}
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
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
        """Retrieve all shard IDs, paginating through NextToken if needed."""
        shard_ids: list[str] = []
        kwargs = {"StreamName": self.stream_name}
        while True:
            assert self._client is not None
            response = self._client.list_shards(**kwargs)
            shard_ids.extend(
                shard["ShardId"] for shard in response.get("Shards", [])
            )
            next_token = response.get("NextToken")
            if not next_token:
                break
            kwargs = {"NextToken": next_token}
        logger.info("Found %d shards for stream %s.", len(shard_ids), self.stream_name)
        return shard_ids

    def _load_checkpoint(self) -> dict:
        """Read the per-shard sequence-number checkpoint, if configured."""
        if self.checkpoint_path is None or not self.checkpoint_path.exists():
            return {"shards": {}}
        try:
            state: dict = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            return state
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Could not read Kinesis checkpoint %s: %s — starting from "
                "TRIM_HORIZON.", self.checkpoint_path, exc,
            )
            return {"shards": {}}

    def _save_checkpoint(self, state: dict) -> None:
        """Persist the checkpoint atomically so a crash cannot corrupt it."""
        if self.checkpoint_path is None:
            return
        atomic_json_write(self.checkpoint_path, json.dumps(state, indent=2))

    def _shard_iterator(self, shard_id: str, last_sequence: str | None) -> str:
        """Build the initial shard iterator, resuming after a checkpoint."""
        assert self._client is not None
        kwargs: dict = {
            "StreamName": self.stream_name,
            "ShardId": shard_id,
        }
        if last_sequence:
            kwargs["ShardIteratorType"] = "AFTER_SEQUENCE_NUMBER"
            kwargs["StartingSequenceNumber"] = last_sequence
            logger.info(
                "Resuming shard %s after sequence %s.", shard_id, last_sequence,
            )
        else:
            kwargs["ShardIteratorType"] = "TRIM_HORIZON"
        return str(self._client.get_shard_iterator(**kwargs)["ShardIterator"])

    def consume(self) -> Generator[pd.DataFrame, None, None]:
        """
        Iterate over all shards and yield micro-batches as DataFrames.

        Each batch contains up to ``batch_size`` deserialized JSON records.
        Empty GetRecords pages are normal mid-shard and do not end the shard;
        a shard ends when NextShardIterator is None (shard closed) or
        MillisBehindLatest reaches 0 (caught up to the tip).

        When ``checkpoint_path`` is configured, the last processed sequence
        number per shard is persisted after each yielded batch (the caller
        resuming proves the batch was processed — at-least-once semantics).
        """
        shard_ids = self._get_shard_ids()
        checkpoint = self._load_checkpoint()

        for shard_id in shard_ids:
            last_sequence = checkpoint["shards"].get(shard_id)
            shard_iterator = self._shard_iterator(shard_id, last_sequence)
            records: list[dict] = []

            while shard_iterator:
                assert self._client is not None
                response = self._client.get_records(
                    ShardIterator=shard_iterator,
                    Limit=self.batch_size,
                )
                shard_iterator = response.get("NextShardIterator")

                for record in response.get("Records", []):
                    try:
                        value = json.loads(record["Data"].decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        logger.warning(
                            "Skipping malformed Kinesis record in shard %s: %s",
                            shard_id, exc,
                        )
                        continue
                    records.append(value)
                    sequence_number = record.get("SequenceNumber")
                    if sequence_number:
                        last_sequence = sequence_number

                    if len(records) >= self.batch_size:
                        logger.info("Yielding Kinesis batch of %d records.", len(records))
                        yield pd.DataFrame(records)
                        records = []
                        # Caller resumed -> batch processed, safe to checkpoint
                        if last_sequence:
                            checkpoint["shards"][shard_id] = last_sequence
                            self._save_checkpoint(checkpoint)

                if response.get("MillisBehindLatest") == 0:
                    logger.info("Shard %s caught up to stream tip — stopping.", shard_id)
                    break

                # Kinesis rate-limits reads — back off briefly between fetches
                time.sleep(0.2)

            if records:
                logger.info("Yielding final Kinesis batch of %d records from shard %s.", len(records), shard_id)
                yield pd.DataFrame(records)
                if last_sequence:
                    checkpoint["shards"][shard_id] = last_sequence
                    self._save_checkpoint(checkpoint)

    def close(self) -> None:
        """Release the Kinesis client."""
        self._client = None
        logger.info("Kinesis client released.")
