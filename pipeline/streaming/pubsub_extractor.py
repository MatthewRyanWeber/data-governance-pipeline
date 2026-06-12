"""
Google Cloud Pub/Sub extractor — pulls messages from a subscription.

Reads JSON-encoded messages from a Pub/Sub subscription and yields each
micro-batch as a pandas DataFrame. Parseable messages are acknowledged
after the batch is yielded to the caller; malformed messages are nacked
(ack deadline set to 0) so they stay visible for inspection or dead-letter
routing instead of being silently lost.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
----------------
1.0   2026-06-07   Initial extraction from monolith.
1.1   2026-06-11   Empty subscription no longer raises DeadlineExceeded —
                   pull timeouts are treated as "no messages".  Malformed
                   messages are nacked (modify_ack_deadline 0) instead of
                   acknowledged, so they are no longer permanently lost.
"""

import json
import logging
from typing import Generator, TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


def _pull_timeout_errors() -> tuple[type[BaseException], ...]:
    """
    Return the google-api-core timeout exception classes, if available.

    Imported lazily because google-api-core may not be installed (tests
    mock the Pub/Sub client) — an empty tuple in an except clause simply
    catches nothing.
    """
    try:
        from google.api_core import exceptions as gax_exceptions
    except (ImportError, AttributeError):
        # AttributeError covers test environments that stub the google
        # namespace package with a MagicMock lacking __spec__.
        return ()
    candidates = (
        getattr(gax_exceptions, "DeadlineExceeded", None),
        getattr(gax_exceptions, "RetryError", None),
    )
    return tuple(
        c for c in candidates
        if isinstance(c, type) and issubclass(c, BaseException)
    )


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
        Stops when a pull returns zero messages or times out (an empty
        subscription raises DeadlineExceeded — treated as "no messages").

        Malformed messages are nacked (ack deadline 0) rather than
        acknowledged, so they remain on the subscription for inspection or
        dead-letter routing instead of being permanently lost.
        """
        timeout_errors = _pull_timeout_errors()

        while True:
            try:
                response = self._subscriber.pull(  # type: ignore[union-attr]
                    request={
                        "subscription": self._subscription_path,
                        "max_messages": self.batch_size,
                    },
                    timeout=self.timeout,
                )
            except timeout_errors as exc:
                logger.info("Pub/Sub pull timed out (%s) — treating as empty subscription.", exc)
                break

            received_messages = response.received_messages
            if not received_messages:
                logger.info("No more Pub/Sub messages — stopping.")
                break

            records: list[dict] = []
            ack_ids: list[str] = []
            nack_ids: list[str] = []

            for message in received_messages:
                try:
                    value = json.loads(message.message.data.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    logger.warning("Nacking malformed Pub/Sub message %s: %s", message.message.message_id, exc)
                    nack_ids.append(message.ack_id)
                    continue
                records.append(value)
                ack_ids.append(message.ack_id)

            if records:
                logger.info("Yielding Pub/Sub batch of %d records.", len(records))
                yield pd.DataFrame(records)

            # Acknowledge only the messages that parsed successfully
            if ack_ids:
                self._subscriber.acknowledge(  # type: ignore[union-attr]
                    request={
                        "subscription": self._subscription_path,
                        "ack_ids": ack_ids,
                    },
                )
                logger.info("Acknowledged %d Pub/Sub messages.", len(ack_ids))

            # Nack malformed messages so they redeliver / dead-letter
            if nack_ids:
                self._subscriber.modify_ack_deadline(  # type: ignore[union-attr]
                    request={
                        "subscription": self._subscription_path,
                        "ack_ids": nack_ids,
                        "ack_deadline_seconds": 0,
                    },
                )
                logger.warning("Nacked %d malformed Pub/Sub messages.", len(nack_ids))

    def close(self) -> None:
        """Close the Pub/Sub subscriber client."""
        if self._subscriber is not None:
            self._subscriber.close()
            self._subscriber = None
            logger.info("Pub/Sub subscriber closed.")
