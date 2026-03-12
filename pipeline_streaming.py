"""
pipeline_streaming.py  —  Streaming Source Extractors
======================================================
Adds real-time / event-driven data ingestion to pipeline_v3.

Three stream sources:
    KafkaExtractor    — Apache Kafka topics (kafka-python)
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
            "value_deserializer": lambda v: json.loads(v.decode("utf-8")),
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
