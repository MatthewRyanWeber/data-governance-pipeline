"""
pipeline_streaming.py  —  Streaming Source Extractors
======================================================
Adds real-time / event-driven data ingestion to pipeline_v3.

Four streaming classes:
    KafkaExtractor    — Consume from Apache Kafka topics (kafka-python)
    KafkaLoader       — Publish DataFrames to Apache Kafka topics
    KinesisExtractor  — AWS Kinesis Data Streams (boto3)
    PubSubExtractor   — Google Cloud Pub/Sub (google-cloud-pubsub)

Each extractor:
  • Polls or subscribes to its source
  • Deserialises JSON payloads into pandas DataFrames
  • Passes each batch through the standard pipeline stages
    (classify → validate → transform → load)
  • Logs every batch to the GovernanceLogger audit ledger
  • Supports a configurable batch_size and poll timeout
  • Runs until a stop_event is set (threading.Event) so it
    integrates cleanly with the native scheduler or REST API

Usage
-----
    from pipeline_streaming import KafkaExtractor
    from pipeline_v3 import GovernanceLogger

    gov = GovernanceLogger("stream_run")
    gov.pipeline_start({})

    extractor = KafkaExtractor(gov)
    extractor.stream(
        cfg={
            "bootstrap_servers": "localhost:9092",
            "topic": "orders",
            "group_id": "pipeline-consumer",
        },
        on_batch=lambda df: print(df),
        batch_size=100,
        timeout_ms=5000,
    )

Requirements
------------
    pip install kafka-python boto3 google-cloud-pubsub
"""

from __future__ import annotations

import json
import threading
import time
from typing import Callable

# ── Optional dependencies ─────────────────────────────────────────────────────

try:
    from kafka import KafkaConsumer as _KafkaConsumer
    from kafka import KafkaProducer as _KafkaProducer
    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False

try:
    import boto3 as _boto3
    HAS_KINESIS = True
except ImportError:
    HAS_KINESIS = False

try:
    from google.cloud import pubsub_v1 as _pubsub
    HAS_PUBSUB = True
except ImportError:
    HAS_PUBSUB = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: KafkaExtractor
# ═════════════════════════════════════════════════════════════════════════════


def _safe_json_decode(raw: bytes) -> object:
    """
    Safely decode a Kafka message value from JSON.
    Returns None for messages that cannot be decoded rather than
    crashing the entire consumer loop on a single malformed message.
    """
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        import logging as _log
        _log.getLogger(__name__).warning(
            "KafkaExtractor: could not decode message — skipping. "
            "Raw bytes (first 100): %s", raw[:100]
        )
        return None


class KafkaExtractor:
    """
    Consume JSON messages from a Kafka topic in micro-batches.

    Each message value is expected to be a JSON object (dict).
    Messages are accumulated into a DataFrame and delivered to
    ``on_batch`` once ``batch_size`` messages have been received
    or ``flush_interval_s`` seconds have elapsed since the last
    flush — whichever comes first.

    Parameters
    ----------
    gov : GovernanceLogger
        Audit logger from pipeline_v3.

    Required cfg keys
    -----------------
    bootstrap_servers : str | list[str]
        Kafka broker address(es), e.g. ``"localhost:9092"``.
    topic : str
        Topic name to subscribe to.
    group_id : str
        Consumer group ID.

    Optional cfg keys
    -----------------
    auto_offset_reset : str   ``"earliest"`` or ``"latest"``  (default ``"latest"``)
    security_protocol : str   ``"PLAINTEXT"`` / ``"SSL"`` / ``"SASL_SSL"``
    sasl_mechanism    : str   ``"PLAIN"`` / ``"SCRAM-SHA-256"`` etc.
    sasl_username     : str
    sasl_password     : str
    ssl_cafile        : str   Path to CA certificate file for SSL.
    """

    def __init__(self, gov) -> None:
        self.gov = gov
        if not HAS_KAFKA:
            raise RuntimeError("KafkaExtractor requires: pip install kafka-python")
        if not HAS_PANDAS:
            raise RuntimeError("KafkaExtractor requires pandas")

    def stream(
        self,
        cfg: dict,
        on_batch: Callable,
        batch_size: int = 500,
        timeout_ms: int = 5000,
        flush_interval_s: float = 10.0,
        stop_event: threading.Event | None = None,
        max_batches: int | None = None,
    ) -> None:
        """
        Begin consuming from the Kafka topic.

        Blocks until ``stop_event`` is set, ``max_batches`` is reached,
        or the process is interrupted.

        Parameters
        ----------
        cfg             : dict   Connection configuration (see class docstring).
        on_batch        : callable  Called with a pd.DataFrame for each batch.
        batch_size      : int    Flush after this many messages.
        timeout_ms      : int    Kafka poll timeout in milliseconds.
        flush_interval_s: float  Force flush after this many seconds even if
                                  batch_size has not been reached.
        stop_event      : threading.Event | None
                          Set this to stop streaming gracefully.
        max_batches     : int | None
                          Stop after this many batches (useful for testing).
        """
        consumer_kwargs = {
            "bootstrap_servers": cfg["bootstrap_servers"],
            "group_id":          cfg["group_id"],
            "auto_offset_reset": cfg.get("auto_offset_reset", "latest"),
            "value_deserializer": lambda v: _safe_json_decode(v),
        }
        if cfg.get("security_protocol"):
            consumer_kwargs["security_protocol"] = cfg["security_protocol"]
        if cfg.get("sasl_mechanism"):
            consumer_kwargs["sasl_mechanism"]    = cfg["sasl_mechanism"]
            consumer_kwargs["sasl_plain_username"] = cfg.get("sasl_username", "")
            consumer_kwargs["sasl_plain_password"] = cfg.get("sasl_password", "")
        if cfg.get("ssl_cafile"):
            consumer_kwargs["ssl_cafile"] = cfg["ssl_cafile"]

        consumer = _KafkaConsumer(cfg["topic"], **consumer_kwargs)

        self.gov.transformation_applied("KAFKA_STREAM_STARTED", {
            "topic":      cfg["topic"],
            "group_id":   cfg["group_id"],
            "batch_size": batch_size,
        })

        buffer     = []
        last_flush = time.time()
        batch_count = 0

        try:
            while True:
                if stop_event and stop_event.is_set():
                    break

                records = consumer.poll(timeout_ms=timeout_ms)
                for _tp, messages in records.items():
                    for msg in messages:
                        if msg.value is None:
                            continue   # skip malformed / tombstone messages
                        if isinstance(msg.value, dict):
                            buffer.append(msg.value)
                        elif isinstance(msg.value, list):
                            buffer.extend(msg.value)

                elapsed = time.time() - last_flush
                if buffer and (len(buffer) >= batch_size or elapsed >= flush_interval_s):
                    df = pd.json_normalize(buffer)
                    self.gov.transformation_applied("KAFKA_BATCH_RECEIVED", {
                        "topic": cfg["topic"],
                        "rows":  len(df),
                        "batch": batch_count,
                    })
                    on_batch(df)
                    buffer.clear()
                    last_flush = time.time()
                    batch_count += 1
                    if max_batches and batch_count >= max_batches:
                        break

                if max_batches and batch_count >= max_batches:
                    break

        finally:
            if buffer:
                df = pd.json_normalize(buffer)
                self.gov.transformation_applied("KAFKA_FINAL_FLUSH", {
                    "topic": cfg["topic"], "rows": len(df)
                })
                on_batch(df)
            consumer.close()
            self.gov.transformation_applied("KAFKA_STREAM_STOPPED", {"topic": cfg["topic"]})


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: KinesisExtractor
# ═════════════════════════════════════════════════════════════════════════════

class KinesisExtractor:
    """
    Poll an AWS Kinesis Data Stream in micro-batches via GetRecords.

    Iterates over all shards in the stream, maintaining one shard
    iterator per shard.  Records are JSON-decoded and accumulated
    into DataFrames delivered to ``on_batch``.

    Parameters
    ----------
    gov : GovernanceLogger

    Required cfg keys
    -----------------
    stream_name     : str   Kinesis stream name.
    region_name     : str   AWS region, e.g. ``"us-east-1"``.

    Optional cfg keys
    -----------------
    aws_access_key_id     : str   Falls back to environment / IAM role.
    aws_secret_access_key : str
    shard_iterator_type   : str   ``"TRIM_HORIZON"`` | ``"LATEST"``
                                   (default ``"TRIM_HORIZON"``)
    """

    def __init__(self, gov) -> None:
        self.gov = gov
        if not HAS_KINESIS:
            raise RuntimeError("KinesisExtractor requires: pip install boto3")
        if not HAS_PANDAS:
            raise RuntimeError("KinesisExtractor requires pandas")

    def _get_client(self, cfg: dict):
        kwargs = {"region_name": cfg["region_name"]}
        if cfg.get("aws_access_key_id"):
            kwargs["aws_access_key_id"]     = cfg["aws_access_key_id"]
            kwargs["aws_secret_access_key"] = cfg["aws_secret_access_key"]
        return _boto3.client("kinesis", **kwargs)

    def _shard_iterators(self, client, stream_name: str, iterator_type: str) -> list[str]:
        shards = client.list_shards(StreamName=stream_name)["Shards"]
        iters  = []
        for shard in shards:
            resp = client.get_shard_iterator(
                StreamName=stream_name,
                ShardId=shard["ShardId"],
                ShardIteratorType=iterator_type,
            )
            iters.append(resp["ShardIterator"])
        return iters

    def stream(
        self,
        cfg: dict,
        on_batch: Callable,
        batch_size: int = 500,
        poll_interval_s: float = 1.0,
        stop_event: threading.Event | None = None,
        max_batches: int | None = None,
    ) -> None:
        """
        Begin polling Kinesis shards.

        Parameters
        ----------
        cfg             : dict   Connection configuration.
        on_batch        : callable  Called with a pd.DataFrame for each batch.
        batch_size      : int    Records per GetRecords call per shard.
        poll_interval_s : float  Sleep between poll loops.
        stop_event      : threading.Event | None
        max_batches     : int | None
        """
        stream_name   = cfg["stream_name"]
        iterator_type = cfg.get("shard_iterator_type", "TRIM_HORIZON")
        client        = self._get_client(cfg)

        self.gov.transformation_applied("KINESIS_STREAM_STARTED", {
            "stream": stream_name, "iterator_type": iterator_type
        })

        shard_iters = self._shard_iterators(client, stream_name, iterator_type)
        batch_count = 0

        try:
            while True:
                if stop_event and stop_event.is_set():
                    break

                all_records = []
                new_iters   = []
                for it in shard_iters:
                    try:
                        resp    = client.get_records(ShardIterator=it, Limit=batch_size)
                        records = resp.get("Records", [])
                        next_it = resp.get("NextShardIterator")
                        if next_it:
                            new_iters.append(next_it)
                        for rec in records:
                            try:
                                payload = json.loads(rec["Data"])
                                if isinstance(payload, dict):
                                    all_records.append(payload)
                                elif isinstance(payload, list):
                                    all_records.extend(payload)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                pass
                    except Exception as e:
                        self.gov.transformation_applied("KINESIS_SHARD_ERROR", {"error": str(e)})

                shard_iters = [i for i in new_iters if i]

                if all_records:
                    df = pd.json_normalize(all_records)
                    self.gov.transformation_applied("KINESIS_BATCH_RECEIVED", {
                        "stream": stream_name, "rows": len(df), "batch": batch_count
                    })
                    on_batch(df)
                    batch_count += 1
                    if max_batches and batch_count >= max_batches:
                        break

                time.sleep(poll_interval_s)

        finally:
            self.gov.transformation_applied("KINESIS_STREAM_STOPPED", {"stream": stream_name})


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: PubSubExtractor
# ═════════════════════════════════════════════════════════════════════════════

class PubSubExtractor:
    """
    Pull messages from a Google Cloud Pub/Sub subscription.

    Messages are expected to contain JSON payloads.  Each pull cycle
    delivers up to ``max_messages`` records.  Messages are acknowledged
    only after ``on_batch`` returns successfully.

    Parameters
    ----------
    gov : GovernanceLogger

    Required cfg keys
    -----------------
    project_id      : str   GCP project ID.
    subscription_id : str   Pub/Sub subscription name.

    Optional cfg keys
    -----------------
    credentials_path : str  Path to service account JSON key.
                             Omit to use Application Default Credentials.
    """

    def __init__(self, gov) -> None:
        self.gov = gov
        if not HAS_PUBSUB:
            raise RuntimeError(
                "PubSubExtractor requires: pip install google-cloud-pubsub"
            )
        if not HAS_PANDAS:
            raise RuntimeError("PubSubExtractor requires pandas")

    def stream(
        self,
        cfg: dict,
        on_batch: Callable,
        max_messages: int = 500,
        poll_interval_s: float = 2.0,
        stop_event: threading.Event | None = None,
        max_batches: int | None = None,
    ) -> None:
        """
        Begin pulling from the Pub/Sub subscription.

        Parameters
        ----------
        cfg             : dict   Connection configuration.
        on_batch        : callable  Called with a pd.DataFrame for each batch.
        max_messages    : int    Messages per pull request.
        poll_interval_s : float  Sleep between pull requests.
        stop_event      : threading.Event | None
        max_batches     : int | None
        """
        subscriber_kwargs = {}
        if cfg.get("credentials_path"):
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(
                cfg["credentials_path"]
            )
            subscriber_kwargs["credentials"] = creds

        subscriber  = _pubsub.SubscriberClient(**subscriber_kwargs)
        sub_path    = subscriber.subscription_path(cfg["project_id"], cfg["subscription_id"])
        batch_count = 0

        self.gov.transformation_applied("PUBSUB_STREAM_STARTED", {
            "project": cfg["project_id"], "subscription": cfg["subscription_id"]
        })

        try:
            while True:
                if stop_event and stop_event.is_set():
                    break

                response = subscriber.pull(
                    request={"subscription": sub_path, "max_messages": max_messages}
                )
                msgs = response.received_messages
                if msgs:
                    records   = []
                    ack_ids   = []
                    for msg in msgs:
                        ack_ids.append(msg.ack_id)
                        try:
                            payload = json.loads(msg.message.data.decode("utf-8"))
                            if isinstance(payload, dict):
                                records.append(payload)
                            elif isinstance(payload, list):
                                records.extend(payload)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            pass

                    if records:
                        df = pd.json_normalize(records)
                        self.gov.transformation_applied("PUBSUB_BATCH_RECEIVED", {
                            "subscription": cfg["subscription_id"],
                            "rows": len(df), "batch": batch_count,
                        })
                        on_batch(df)
                        batch_count += 1

                    # Acknowledge after successful on_batch
                    subscriber.acknowledge(
                        request={"subscription": sub_path, "ack_ids": ack_ids}
                    )

                    if max_batches and batch_count >= max_batches:
                        break

                time.sleep(poll_interval_s)

        finally:
            subscriber.close()
            self.gov.transformation_applied("PUBSUB_STREAM_STOPPED", {
                "subscription": cfg["subscription_id"]
            })


# ═════════════════════════════════════════════════════════════════════════════
#  CLASS: KafkaLoader  (v1.0)
#  Publish governed, PII-masked DataFrames to Apache Kafka topics.
# ═════════════════════════════════════════════════════════════════════════════

class KafkaLoader:
    """
    Publish a governed, PII-masked DataFrame to a Kafka topic as a stream
    of JSON messages — one message per row, or in configurable micro-batches.

    This closes the pipeline loop: KafkaExtractor reads raw events from an
    upstream topic, the pipeline governs and transforms them, and KafkaLoader
    publishes the clean results to a downstream topic.

    Architecture
    ────────────
    Each DataFrame row is serialised to JSON and published as an individual
    Kafka message.  The message key can be set from a DataFrame column to
    ensure that records with the same key land on the same partition (useful
    for ordered processing of per-user or per-entity events).

    For governance audit trails, every batch publication is logged to the
    GovernanceLogger audit ledger with topic, row count, partition count,
    and delivery confirmation status.

    Required cfg keys
    -----------------
    bootstrap_servers : str | list[str]
        Kafka broker address(es), e.g. "localhost:9092" or
        ["broker1:9092", "broker2:9092"].
    topic             : str
        Destination topic name.

    Optional cfg keys
    -----------------
    key_column        : str   DataFrame column to use as the message key.
                              If omitted, messages are published without a key
                              (round-robin partition assignment).
    value_serializer  : str   "json" (default) — serialise each row as JSON.
    compression_type  : str   "none" | "gzip" | "snappy" | "lz4" | "zstd"
                              Default "none".
    acks              : str   "0" | "1" | "all"  (default "all" — wait for
                              all in-sync replicas to acknowledge).
    retries           : int   Number of send retries on transient failure
                              (default 3).
    batch_size_bytes  : int   Kafka producer internal batch size in bytes
                              (default 16384).
    linger_ms         : int   Time to wait for additional messages before
                              flushing the internal buffer (default 0).
    security_protocol : str   "PLAINTEXT" | "SSL" | "SASL_SSL"
    sasl_mechanism    : str   "PLAIN" | "SCRAM-SHA-256" etc.
    sasl_username     : str
    sasl_password     : str
    ssl_cafile        : str   Path to CA certificate for SSL connections.

    Load modes
    ----------
    append  (default)
        Publish all rows.  New rows are always appended to the topic — Kafka
        topics are immutable append-only logs by design.

    upsert  (natural_keys provided)
        Publish a tombstone message (null value) for each unique key before
        publishing the updated record.  This enables log-compacted topics to
        reflect the latest state per key.

    Requirements
    ------------
        pip install kafka-python

    Quick-start
    ───────────
        from pipeline_streaming import KafkaLoader
        from pipeline_v3 import GovernanceLogger

        gov    = GovernanceLogger(run_id="run_001", src="employees.csv")
        loader = KafkaLoader(gov)

        rows = loader.load(
            df,
            cfg={
                "bootstrap_servers": "localhost:9092",
                "topic": "clean_employees",
                "key_column": "employee_id",
                "acks": "all",
                "compression_type": "gzip",
            },
        )
        print(f"Published {rows} messages to Kafka")
    """

    def __init__(self, gov) -> None:
        self.gov = gov
        if not HAS_KAFKA:
            raise RuntimeError(
                "KafkaLoader requires the kafka-python package.\n"
                "Install with:  pip install kafka-python"
            )

    # ── Public API ────────────────────────────────────────────────────────────

    def load(
        self,
        df,
        cfg:          dict,
        table:        str  = "",        # treated as topic override if provided
        if_exists:    str  = "append",
        natural_keys: list | None = None,
    ) -> int:
        """
        Publish df to a Kafka topic.

        Parameters
        ----------
        df            DataFrame to publish.
        cfg           Connection config dict (see class docstring).
                      Must contain bootstrap_servers and topic.
        table         Optional topic override — if provided, takes precedence
                      over cfg["topic"].  Included for loader dispatch
                      compatibility with pipeline_v3._run_load().
        if_exists     "append" (default) | "upsert"
                      "upsert" publishes tombstone records for each unique key
                      before the updated value on log-compacted topics.
        natural_keys  Column name(s) used as message keys in upsert mode.

        Returns
        -------
        int   Number of messages successfully published.
        """
        if if_exists not in ("append", "upsert"):
            raise ValueError(
                f"KafkaLoader: if_exists must be 'append' or 'upsert', "
                f"got '{if_exists}'."
            )

        topic = table or cfg.get("topic")
        if not topic:
            raise ValueError(
                "KafkaLoader: topic must be supplied via cfg['topic'] "
                "or the table parameter."
            )

        bootstrap = cfg.get("bootstrap_servers")
        if not bootstrap:
            raise ValueError(
                "KafkaLoader: cfg must contain 'bootstrap_servers'."
            )

        producer = self._build_producer(cfg)

        try:
            if if_exists == "upsert" and natural_keys:
                rows = self._publish_upsert(df, producer, topic,
                                            natural_keys, cfg)
            else:
                rows = self._publish_append(df, producer, topic, cfg)
        finally:
            producer.flush()
            producer.close()

        self.gov._event(  # type: ignore[attr-defined]
            "LOAD", "KAFKA_PUBLISH_COMPLETE",
            {
                "topic":      topic,
                "rows":       rows,
                "if_exists":  if_exists,
                "key_column": cfg.get("key_column"),
                "acks":       cfg.get("acks", "all"),
                "compression":cfg.get("compression_type", "none"),
            },
        )
        return rows

    def publish_governance_event(
        self,
        cfg:   dict,
        event: dict,
        topic: str = "governance_events",
    ) -> None:
        """
        Publish a single governance event dict to a Kafka topic.

        This lets downstream systems (SIEM, security tools, real-time
        dashboards) subscribe to governance events as they happen rather
        than polling the JSONL audit ledger file.

        Parameters
        ----------
        cfg   Connection config (bootstrap_servers required).
        event Governance event dict (from the audit ledger).
        topic Destination topic name (default: "governance_events").
        """
        producer = self._build_producer(cfg)
        try:
            serialised = json.dumps(event, default=str).encode("utf-8")
            producer.send(topic, value=serialised)
            producer.flush()
        finally:
            producer.close()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_producer(self, cfg: dict) -> "_KafkaProducer":
        """Build and return a configured KafkaProducer."""
        kwargs = {
            "bootstrap_servers":  cfg["bootstrap_servers"],
            "value_serializer":   lambda v: v if isinstance(v, bytes)
                                  else json.dumps(v, default=str).encode("utf-8"),
            "key_serializer":     lambda k: str(k).encode("utf-8") if k else None,
            "acks":               str(cfg.get("acks", "all")),
            "retries":            int(cfg.get("retries", 3)),
            "compression_type":   cfg.get("compression_type", "none") or None,
            "batch_size":         int(cfg.get("batch_size_bytes", 16384)),
            "linger_ms":          int(cfg.get("linger_ms", 0)),
        }
        # Strip None compression — kafka-python treats None as no compression
        if kwargs["compression_type"] in (None, "none"):
            kwargs.pop("compression_type")

        if cfg.get("security_protocol"):
            kwargs["security_protocol"] = cfg["security_protocol"]
        if cfg.get("sasl_mechanism"):
            kwargs["sasl_mechanism"]       = cfg["sasl_mechanism"]
            kwargs["sasl_plain_username"]  = cfg.get("sasl_username", "")
            kwargs["sasl_plain_password"]  = cfg.get("sasl_password", "")
        if cfg.get("ssl_cafile"):
            kwargs["ssl_cafile"] = cfg["ssl_cafile"]

        return _KafkaProducer(**kwargs)

    def _publish_append(
        self,
        df,
        producer: "_KafkaProducer",
        topic:    str,
        cfg:      dict,
    ) -> int:
        """Publish every row in df as a Kafka message."""
        key_col  = cfg.get("key_column")
        futures  = []

        for _, row in df.iterrows():
            key   = str(row[key_col]) if key_col and key_col in row else None
            value = row.to_dict()
            futures.append(
                producer.send(topic, key=key, value=value)
            )

        # Wait for all sends to complete and count successes
        sent = 0
        for future in futures:
            try:
                future.get(timeout=10)
                sent += 1
            except Exception as exc:  # pylint: disable=broad-exception-caught
                import logging
                logging.getLogger(__name__).warning(
                    "KafkaLoader: message delivery failed: %s", exc
                )

        return sent

    def _publish_upsert(
        self,
        df,
        producer:     "_KafkaProducer",
        topic:        str,
        natural_keys: list,
        cfg:          dict,
    ) -> int:
        """
        Upsert mode for log-compacted topics:
        1. Publish a tombstone (null value) for each unique key.
        2. Publish the new record with the same key.

        This ensures compacted topics reflect the latest state per key
        without requiring the consumer to handle duplicates.
        """
        key_col  = natural_keys[0] if len(natural_keys) == 1 else None
        futures  = []

        for _, row in df.iterrows():
            key = str(row[key_col]) if key_col and key_col in row else None

            # Step 1: tombstone — null value deletes the old record on compact topics
            if key:
                producer.send(topic, key=key, value=None)

            # Step 2: publish updated record
            futures.append(
                producer.send(topic, key=key, value=row.to_dict())
            )

        sent = 0
        for future in futures:
            try:
                future.get(timeout=10)
                sent += 1
            except Exception as exc:  # pylint: disable=broad-exception-caught
                import logging
                logging.getLogger(__name__).warning(
                    "KafkaLoader: upsert delivery failed: %s", exc
                )

        return sent
