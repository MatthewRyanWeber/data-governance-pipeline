"""
Google Cloud Pub/Sub extractor — pulls messages from a subscription.

Reads JSON-encoded messages from a Pub/Sub subscription and yields each
micro-batch as a pandas DataFrame. Messages are acknowledged after the
batch is yielded to the caller.

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


class PubSubStreamExtractor:
    """
    Pull messages from a Google Cloud Pub/Sub subscription and yield DataFrames.

    Quick-start
    -----------
        from pipeline.streaming import PubSubStreamExtractor
        ext = PubSubStreamExtractor(
            gov, project_id="my-project", subscription_id="pipeline-sub",
        )
        for batch_df in ext.consume():
            process(batch_df)
        ext.close()
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        project_id: str,
        subscription_id: str,
        batch_size: int = 500,
        timeout: int = 30,
    ) -> None:
        self.gov = gov
        self.project_id = project_id
        self.subscription_id = subscription_id
        self.batch_size = batch_size
        self.timeout = timeout
        self._subscriber = None

        try:
            from google.cloud import pubsub_v1  # type: ignore[attr-defined]
        except ImportError:
            raise RuntimeError(
                "google-cloud-pubsub is required for PubSubStreamExtractor. "
                "Install it with: pip install google-cloud-pubsub"
            )

        self._subscriber = pubsub_v1.SubscriberClient()
        self._subscription_path = self._subscriber.subscription_path(
            self.project_id, self.subscription_id,
        )
        logger.info(
            "PubSubStreamExtractor initialised — project=%s, subscription=%s",
            self.project_id, self.subscription_id,
        )

    def consume(self) -> Generator[pd.DataFrame, None, None]:
        """
        Pull messages and yield micro-batches as DataFrames.

        Each batch contains up to ``batch_size`` deserialized JSON records.
        Stops when a pull returns zero messages.
        """
        while True:
            response = self._subscriber.pull(  # type: ignore[union-attr]
                request={
                    "subscription": self._subscription_path,
                    "max_messages": self.batch_size,
                },
                timeout=self.timeout,
            )

            received_messages = response.received_messages
            if not received_messages:
                logger.info("No more Pub/Sub messages — stopping.")
                break

            records: list[dict] = []
            ack_ids: list[str] = []

            for message in received_messages:
                ack_ids.append(message.ack_id)
                try:
                    value = json.loads(message.message.data.decode("utf-8"))
                    records.append(value)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    logger.warning("Skipping malformed Pub/Sub message %s: %s", message.message.message_id, exc)
                    continue

            if records:
                logger.info("Yielding Pub/Sub batch of %d records.", len(records))
                yield pd.DataFrame(records)

            # Acknowledge all pulled messages (including malformed ones)
            if ack_ids:
                self._subscriber.acknowledge(  # type: ignore[union-attr]
                    request={
                        "subscription": self._subscription_path,
                        "ack_ids": ack_ids,
                    },
                )
                logger.info("Acknowledged %d Pub/Sub messages.", len(ack_ids))

    def close(self) -> None:
        """Close the Pub/Sub subscriber client."""
        if self._subscriber is not None:
            self._subscriber.close()
            self._subscriber = None
            logger.info("Pub/Sub subscriber closed.")
