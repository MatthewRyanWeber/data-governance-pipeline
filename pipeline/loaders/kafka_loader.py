"""
Kafka loader -- publishes governed, PII-masked DataFrames to Apache Kafka
topics as JSON messages with configurable keying, compression, and upsert.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class KafkaLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   Topic supplied via the table arg no longer fails config
                   validation; upsert requires natural_keys instead of
                   silently appending; removed the pre-record tombstone sends
                   that could delete data on partial failure (the keyed
                   record alone wins log compaction).
"""

import json
import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_KAFKA_LOADER
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class KafkaLoader(BaseLoader):
    """Publish DataFrames to Kafka topics with delivery guarantees."""

    SUPPORTS_UPSERT = False  # append-only event stream, no upsert semantics

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_KAFKA_LOADER:
            raise RuntimeError(
                "KafkaLoader requires the kafka-python package.\n"
                "Install with:  pip install kafka-python"
            )

    def load(self, df, cfg, table="", if_exists="append",
             natural_keys=None) -> int:
        """
        Publish df to a Kafka topic.

        Returns the number of messages successfully delivered.
        """
        if if_exists not in ("append", "upsert"):
            raise ValueError(
                f"KafkaLoader: if_exists must be 'append' or 'upsert', "
                f"got '{if_exists}'."
            )

        topic = table or cfg.get("topic")
        if not topic:
            raise ValueError(
                "KafkaLoader: supply topic via cfg['topic'] or the table arg."
            )
        if not cfg.get("bootstrap_servers"):
            raise ValueError(
                "KafkaLoader: cfg must contain 'bootstrap_servers'."
            )
        if if_exists == "upsert" and not natural_keys:
            raise ValueError(
                "KafkaLoader: if_exists='upsert' requires natural_keys."
            )
        if self._dry_run_guard(topic, len(df)):
            return 0
        # Topic was already resolved from either source above, so only
        # bootstrap_servers must come from cfg.
        self._validate_config(cfg, ["bootstrap_servers"])

        producer = self._build_producer(cfg)
        try:
            if if_exists == "upsert":
                rows = self._publish_upsert(df, producer, topic,
                                            natural_keys, cfg)
            else:
                rows = self._publish_append(df, producer, topic, cfg)
        finally:
            producer.flush()
            producer.close()

        self.gov.load_complete(rows, topic)
        self.gov.destination_registered(
            "kafka", cfg.get("bootstrap_servers", ""), topic,
        )
        self.gov.load_event("KAFKA_PUBLISH_COMPLETE", {
            "topic": topic,
            "rows": rows,
            "if_exists": if_exists,
            "key_column": cfg.get("key_column"),
            "acks": cfg.get("acks", "all"),
            "compression": cfg.get("compression_type", "none"),
        })
        return rows

    def publish_governance_event(self, cfg, event, topic="governance_events"):
        """Publish a single governance event dict to a Kafka topic."""
        if not cfg.get("bootstrap_servers"):
            raise ValueError(
                "KafkaLoader: cfg must contain 'bootstrap_servers'."
            )
        producer = self._build_producer(cfg)
        try:
            body = json.dumps(event, default=str).encode("utf-8")
            future = producer.send(topic, value=body)
            future.get(timeout=10)
            producer.flush()
        finally:
            producer.close()

    def _build_producer(self, cfg: dict):
        """Construct a KafkaProducer from cfg."""
        from kafka import KafkaProducer as _KP

        kwargs: dict = {
            "bootstrap_servers": cfg["bootstrap_servers"],
            "value_serializer": lambda v: (
                None if v is None
                else v if isinstance(v, bytes)
                else json.dumps(v, default=str).encode("utf-8")
            ),
            "key_serializer": lambda k: (
                str(k).encode("utf-8") if k is not None else None
            ),
            "acks": ("all" if str(cfg.get("acks", "all")) in ("all", "-1")
                     else int(cfg.get("acks", 1))),
            "retries": int(cfg.get("retries", 3)),
            "linger_ms": int(cfg.get("linger_ms", 0)),
        }
        comp = cfg.get("compression_type", "none")
        if comp and comp != "none":
            kwargs["compression_type"] = comp

        if cfg.get("security_protocol"):
            kwargs["security_protocol"] = cfg["security_protocol"]
        if cfg.get("sasl_mechanism"):
            kwargs["sasl_mechanism"] = cfg["sasl_mechanism"]
            kwargs["sasl_plain_username"] = cfg.get("sasl_username", "")
            kwargs["sasl_plain_password"] = cfg.get("sasl_password", "")
        if cfg.get("ssl_cafile"):
            kwargs["ssl_cafile"] = cfg["ssl_cafile"]

        return _KP(**kwargs)

    def _publish_append(self, df, producer, topic, cfg) -> int:
        """Publish every row as an individual Kafka message."""
        key_col = cfg.get("key_column")
        records = df.to_dict(orient="records")
        futures = []
        for rec in records:
            key = str(rec[key_col]) if key_col and key_col in rec else None
            futures.append(producer.send(topic, key=key, value=rec))

        sent = 0
        for fut in futures:
            try:
                fut.get(timeout=10)
                sent += 1
            except Exception as exc:
                logger.warning("KafkaLoader: delivery failed: %s", exc)
        return sent

    def _publish_upsert(self, df, producer, topic, natural_keys, cfg) -> int:
        """Upsert via keyed records for log-compacted topics.

        No tombstones: the keyed record alone wins compaction, and a
        tombstone sent before a record that then fails delivery would
        delete the previous value.
        """
        key_col = (natural_keys[0] if len(natural_keys) == 1
                   else cfg.get("key_column"))
        records = df.to_dict(orient="records")
        futures = []
        for rec in records:
            key = str(rec[key_col]) if key_col and key_col in rec else None
            futures.append(producer.send(topic, key=key, value=rec))

        sent = 0
        for fut in futures:
            try:
                fut.get(timeout=10)
                sent += 1
            except Exception as exc:
                logger.warning("KafkaLoader: upsert delivery failed: %s", exc)
        return sent
