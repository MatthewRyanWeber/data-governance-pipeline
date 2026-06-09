"""
Kafka stream extractor — consumes from Kafka topics, yields micro-batches.

Reads JSON-encoded messages from one or more Kafka topics and yields each
micro-batch as a pandas DataFrame. Offsets are committed manually so that
downstream checkpoint semantics stay in sync with consumption.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
"""

import json
import logging
from typing import Generator, TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class KafkaStreamExtractor:
    """
    Consume messages from Kafka topics and yield DataFrames in micro-batches.

    Quick-start
    -----------
        from pipeline.streaming import KafkaStreamExtractor
        ext = KafkaStreamExtractor(
            gov, bootstrap_servers="localhost:9092",
            group_id="pipeline-cg", topics=["events"],
        )
        for batch_df in ext.consume():
            process(batch_df)
        ext.close()
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        bootstrap_servers: str,
        group_id: str,
        topics: list[str],
        batch_size: int = 1000,
        timeout_ms: int = 5000,
    ) -> None:
        self.gov = gov
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self.topics = topics
        self.batch_size = batch_size
        self.timeout_ms = timeout_ms
        self._consumer = None

        try:
            from confluent_kafka import Consumer
        except ImportError:
            raise RuntimeError(
                "confluent-kafka is required for KafkaStreamExtractor. "
                "Install it with: pip install confluent-kafka"
            )

        config = {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
        self._consumer = Consumer(config)
        self._consumer.subscribe(self.topics)
        logger.info(
            "KafkaStreamExtractor initialised — servers=%s, group=%s, topics=%s",
            self.bootstrap_servers, self.group_id, self.topics,
        )

    def consume(self) -> Generator[pd.DataFrame, None, None]:
        """
        Poll Kafka and yield micro-batches as DataFrames.

        Each batch contains up to ``batch_size`` deserialized JSON records.
        Stops when no messages are received within ``timeout_ms``.
        """
        records: list[dict] = []
        empty_polls = 0
        max_empty_polls = 3

        while True:
            assert self._consumer is not None
            message = self._consumer.poll(timeout=self.timeout_ms / 1000.0)

            if message is None:
                empty_polls += 1
                if empty_polls >= max_empty_polls:
                    if records:
                        yield pd.DataFrame(records)
                        records = []
                    logger.info("No messages after %d empty polls — stopping.", max_empty_polls)
                    break
                continue

            if message.error():
                logger.warning("Kafka consumer error: %s", message.error())
                continue

            empty_polls = 0
            try:
                value = json.loads(message.value().decode("utf-8"))
                records.append(value)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.warning("Skipping malformed message at offset %s: %s", message.offset(), exc)
                continue

            if len(records) >= self.batch_size:
                logger.info("Yielding Kafka batch of %d records.", len(records))
                yield pd.DataFrame(records)
                records = []

        if records:
            logger.info("Yielding final Kafka batch of %d records.", len(records))
            yield pd.DataFrame(records)

    def commit(self) -> None:
        """Commit current consumer offsets to Kafka."""
        if self._consumer is not None:
            self._consumer.commit(asynchronous=False)
            logger.info("Kafka offsets committed.")

    def close(self) -> None:
        """Close the Kafka consumer and release resources."""
        if self._consumer is not None:
            self._consumer.close()
            self._consumer = None
            logger.info("Kafka consumer closed.")
