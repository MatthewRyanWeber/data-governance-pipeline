"""
Tests for pipeline.streaming — Kafka, Kinesis, and Pub/Sub stream extractors.

Covers consume/commit patterns, shard iteration, message acknowledgement,
malformed-message handling, and resource cleanup for all three extractors.
"""

# Revision history
# ----------------
# 1.0   2026-06-08   Initial test suite for streaming extractors.
# 1.1   2026-06-11   Regression tests: Kafka offset commit on resume, bounded
#                    error polls, close-on-break; Kinesis empty mid-shard
#                    pages, MillisBehindLatest stop, sequence checkpointing;
#                    Pub/Sub malformed messages nacked (not acked) and
#                    DeadlineExceeded treated as empty subscription.

import json
import logging
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class MockGov:
    """Records every governance call for assertion."""

    def __init__(self):
        self.events = []

    def __getattr__(self, name):
        def recorder(*args, **kwargs):
            self.events.append((name, args, kwargs))
        return recorder


# ---------------------------------------------------------------------------
# Kafka
# ---------------------------------------------------------------------------

class TestKafkaStreamExtractor(unittest.TestCase):
    """Tests for KafkaStreamExtractor — mock confluent_kafka."""

    def setUp(self):
        # Other test modules call logging.disable(CRITICAL) at module level,
        # which would break assertLogs here in combined runs
        logging.disable(logging.NOTSET)

    @patch.dict("sys.modules", {"confluent_kafka": MagicMock()})
    def _build_extractor(self, messages=None):
        """Create a KafkaStreamExtractor with a mocked Consumer."""
        import sys
        mock_consumer_cls = sys.modules["confluent_kafka"].Consumer
        mock_consumer = MagicMock()
        mock_consumer_cls.return_value = mock_consumer

        if messages is not None:
            mock_consumer.poll.side_effect = messages

        from pipeline.streaming.kafka_extractor import KafkaStreamExtractor
        ext = KafkaStreamExtractor(
            gov=MockGov(),
            bootstrap_servers="localhost:9092",
            group_id="test-cg",
            topics=["test-topic"],
            batch_size=3,
            timeout_ms=1000,
        )
        return ext, mock_consumer

    def _make_message(self, payload, offset=0, error=None):
        """Build a mock Kafka message."""
        msg = MagicMock()
        msg.error.return_value = error
        msg.value.return_value = json.dumps(payload).encode("utf-8")
        msg.offset.return_value = offset
        return msg

    def test_consume_yields_batch_at_batch_size(self):
        """Batch is yielded as soon as batch_size records accumulate."""
        msgs = [
            self._make_message({"id": 1}, offset=0),
            self._make_message({"id": 2}, offset=1),
            self._make_message({"id": 3}, offset=2),
            None, None, None,  # 3 empty polls to trigger stop
        ]
        ext, _ = self._build_extractor(messages=msgs)
        batches = list(ext.consume())
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 3)
        self.assertListEqual(list(batches[0]["id"]), [1, 2, 3])

    def test_consume_stops_after_max_empty_polls(self):
        """Consumer stops when three consecutive polls return None."""
        msgs = [
            self._make_message({"id": 1}, offset=0),
            None, None, None,
        ]
        ext, _ = self._build_extractor(messages=msgs)
        batches = list(ext.consume())
        # 1 record flushed in the final batch
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 1)

    def test_consume_skips_malformed_json(self):
        """Malformed messages are skipped, valid ones are still batched."""
        bad_msg = MagicMock()
        bad_msg.error.return_value = None
        bad_msg.value.return_value = b"NOT-JSON"
        bad_msg.offset.return_value = 0

        msgs = [
            bad_msg,
            self._make_message({"id": 2}, offset=1),
            None, None, None,
        ]
        ext, _ = self._build_extractor(messages=msgs)

        with self.assertLogs("pipeline.streaming.kafka_extractor", level=logging.WARNING):
            batches = list(ext.consume())

        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 1)
        self.assertEqual(batches[0].iloc[0]["id"], 2)

    def test_commit_calls_consumer_commit(self):
        """commit() delegates to the underlying consumer with async=False."""
        ext, mock_consumer = self._build_extractor(messages=[None, None, None])
        ext.commit()
        mock_consumer.commit.assert_called_once_with(asynchronous=False)

    def test_close_releases_consumer(self):
        """close() calls consumer.close() and sets internal ref to None."""
        ext, mock_consumer = self._build_extractor(messages=[None, None, None])
        ext.close()
        mock_consumer.close.assert_called_once()
        self.assertIsNone(ext._consumer)

    def test_offsets_committed_when_caller_resumes_after_batch(self):
        """Regression: offsets are committed once the caller resumes after a
        yield — previously commit() had zero callers, so every restart
        re-read the whole topic."""
        msgs = [
            self._make_message({"id": 1}, offset=0),
            self._make_message({"id": 2}, offset=1),
            self._make_message({"id": 3}, offset=2),
            None, None, None,
        ]
        ext, mock_consumer = self._build_extractor(messages=msgs)
        batches = list(ext.consume())
        self.assertEqual(len(batches), 1)
        mock_consumer.commit.assert_called_with(asynchronous=False)
        self.assertGreaterEqual(mock_consumer.commit.call_count, 1)

    def test_offsets_not_committed_if_caller_breaks_mid_iteration(self):
        """A caller that breaks before resuming must not commit the
        in-flight batch (at-least-once semantics)."""
        msgs = [
            self._make_message({"id": i}, offset=i) for i in range(3)
        ] + [None, None, None]
        ext, mock_consumer = self._build_extractor(messages=msgs)
        generator = ext.consume()
        next(generator)
        generator.close()
        mock_consumer.commit.assert_not_called()

    def test_consumer_closed_when_caller_breaks(self):
        """Regression: the consumer is closed via try/finally even when the
        caller abandons the generator mid-iteration."""
        msgs = [
            self._make_message({"id": i}, offset=i) for i in range(3)
        ] + [None, None, None]
        ext, mock_consumer = self._build_extractor(messages=msgs)
        generator = ext.consume()
        next(generator)
        generator.close()
        mock_consumer.close.assert_called_once()

    def test_persistent_broker_error_raises_after_bound(self):
        """Regression: consecutive error polls are bounded — a persistently
        broken broker raises instead of looping forever."""
        error_msg = MagicMock()
        error_msg.error.return_value = "broker transport failure"
        ext, _ = self._build_extractor(messages=[error_msg] * 50)
        with self.assertLogs("pipeline.streaming.kafka_extractor", level=logging.WARNING):
            with self.assertRaises(RuntimeError):
                list(ext.consume())


# ---------------------------------------------------------------------------
# Kinesis
# ---------------------------------------------------------------------------

class TestKinesisStreamExtractor(unittest.TestCase):
    """Tests for KinesisStreamExtractor — mock boto3."""

    def setUp(self):
        # Undo logging.disable pollution so assertLogs works in combined runs
        logging.disable(logging.NOTSET)

    @patch("boto3.client")
    def _build_extractor(self, mock_boto_client, shard_ids=None,
                         shard_records=None):
        """Create a KinesisStreamExtractor with a mocked boto3 client."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        if shard_ids is not None:
            mock_client.list_shards.return_value = {
                "Shards": [{"ShardId": sid} for sid in shard_ids],
            }

        if shard_records is not None:
            mock_client.get_shard_iterator.return_value = {
                "ShardIterator": "iter-0",
            }
            mock_client.get_records.side_effect = shard_records

        from pipeline.streaming.kinesis_extractor import KinesisStreamExtractor
        ext = KinesisStreamExtractor(
            gov=MockGov(),
            stream_name="test-stream",
            region="us-east-1",
            batch_size=2,
        )
        return ext, mock_client

    def _kinesis_record(self, payload):
        return {"Data": json.dumps(payload).encode("utf-8")}

    @patch("time.sleep")
    def test_consume_iterates_single_shard(self, _mock_sleep):
        """Records from a single shard are yielded as DataFrames."""
        records_page = {
            "Records": [
                self._kinesis_record({"id": 1}),
                self._kinesis_record({"id": 2}),
            ],
            "NextShardIterator": "iter-1",
        }
        empty_page = {"Records": [], "NextShardIterator": None}

        ext, _ = self._build_extractor(
            shard_ids=["shard-000"],
            shard_records=[records_page, empty_page],
        )
        batches = list(ext.consume())
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 2)

    @patch("time.sleep")
    def test_consume_iterates_multiple_shards(self, _mock_sleep):
        """Each shard is iterated independently."""
        page_shard0 = {
            "Records": [self._kinesis_record({"shard": 0, "id": 1})],
            "NextShardIterator": "iter-0-1",
        }
        empty_shard0 = {"Records": [], "NextShardIterator": None}
        page_shard1 = {
            "Records": [self._kinesis_record({"shard": 1, "id": 2})],
            "NextShardIterator": "iter-1-1",
        }
        empty_shard1 = {"Records": [], "NextShardIterator": None}

        ext, mock_client = self._build_extractor(
            shard_ids=["shard-000", "shard-001"],
            shard_records=[
                page_shard0, empty_shard0,
                page_shard1, empty_shard1,
            ],
        )
        batches = list(ext.consume())
        # Each shard produces one final batch
        self.assertEqual(len(batches), 2)
        # Verify get_shard_iterator called once per shard
        self.assertEqual(mock_client.get_shard_iterator.call_count, 2)

    @patch("time.sleep")
    def test_consume_skips_malformed_kinesis_record(self, _mock_sleep):
        """Malformed records are skipped without crashing."""
        records_page = {
            "Records": [
                {"Data": b"NOT-JSON"},
                self._kinesis_record({"id": 1}),
            ],
            "NextShardIterator": "iter-1",
        }
        empty_page = {"Records": [], "NextShardIterator": None}

        ext, _ = self._build_extractor(
            shard_ids=["shard-000"],
            shard_records=[records_page, empty_page],
        )

        with self.assertLogs("pipeline.streaming.kinesis_extractor", level=logging.WARNING):
            batches = list(ext.consume())

        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0].iloc[0]["id"], 1)

    def test_close_releases_client(self):
        """close() sets _client to None."""
        ext, _ = self._build_extractor(shard_ids=[], shard_records=[])
        ext.close()
        self.assertIsNone(ext._client)

    @patch("time.sleep")
    def test_empty_page_mid_shard_does_not_end_shard(self, _mock_sleep):
        """Regression: Kinesis routinely returns empty pages mid-shard —
        treating them as end-of-shard silently dropped all later records."""
        page_with_data = {
            "Records": [self._kinesis_record({"id": 1})],
            "NextShardIterator": "iter-1",
        }
        empty_mid_shard = {"Records": [], "NextShardIterator": "iter-2"}
        page_after_gap = {
            "Records": [self._kinesis_record({"id": 2})],
            "NextShardIterator": "iter-3",
            "MillisBehindLatest": 0,
        }

        ext, _ = self._build_extractor(
            shard_ids=["shard-000"],
            shard_records=[page_with_data, empty_mid_shard, page_after_gap],
        )
        batches = list(ext.consume())
        all_ids = [row["id"] for batch in batches for _, row in batch.iterrows()]
        self.assertEqual(sorted(all_ids), [1, 2])

    @patch("time.sleep")
    def test_stops_when_caught_up_to_stream_tip(self, _mock_sleep):
        """MillisBehindLatest == 0 ends the shard even though the iterator
        is still live."""
        caught_up_page = {
            "Records": [self._kinesis_record({"id": 1})],
            "NextShardIterator": "iter-live",
            "MillisBehindLatest": 0,
        }
        ext, mock_client = self._build_extractor(
            shard_ids=["shard-000"],
            shard_records=[caught_up_page],
        )
        batches = list(ext.consume())
        self.assertEqual(len(batches), 1)
        self.assertEqual(mock_client.get_records.call_count, 1)


class TestKinesisCheckpointing(unittest.TestCase):
    """Regression: sequence-number checkpointing and resume (finding 2)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.checkpoint_file = Path(self.tmp) / "kinesis_checkpoint.json"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _record(self, payload, sequence_number):
        return {
            "Data": json.dumps(payload).encode("utf-8"),
            "SequenceNumber": sequence_number,
        }

    @patch("boto3.client")
    def _build(self, mock_boto_client, shard_records=None, batch_size=2):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_shards.return_value = {
            "Shards": [{"ShardId": "shard-000"}],
        }
        mock_client.get_shard_iterator.return_value = {"ShardIterator": "iter-0"}
        if shard_records is not None:
            mock_client.get_records.side_effect = shard_records

        from pipeline.streaming.kinesis_extractor import KinesisStreamExtractor
        ext = KinesisStreamExtractor(
            gov=MockGov(),
            stream_name="test-stream",
            batch_size=batch_size,
            checkpoint_path=self.checkpoint_file,
        )
        return ext, mock_client

    @patch("time.sleep")
    def test_checkpoint_written_after_batch(self, _mock_sleep):
        """The last processed sequence number is persisted per shard."""
        page = {
            "Records": [
                self._record({"id": 1}, "seq-001"),
                self._record({"id": 2}, "seq-002"),
            ],
            "NextShardIterator": "iter-1",
            "MillisBehindLatest": 0,
        }
        ext, _ = self._build(shard_records=[page])
        list(ext.consume())
        self.assertTrue(self.checkpoint_file.exists())
        state = json.loads(self.checkpoint_file.read_text(encoding="utf-8"))
        self.assertEqual(state["shards"]["shard-000"], "seq-002")

    @patch("time.sleep")
    def test_resume_uses_after_sequence_number(self, _mock_sleep):
        """A pre-existing checkpoint resumes with AFTER_SEQUENCE_NUMBER
        instead of re-reading the shard from TRIM_HORIZON."""
        self.checkpoint_file.write_text(
            json.dumps({"shards": {"shard-000": "seq-099"}}),
            encoding="utf-8",
        )
        empty_page = {
            "Records": [],
            "NextShardIterator": None,
            "MillisBehindLatest": 0,
        }
        ext, mock_client = self._build(shard_records=[empty_page])
        list(ext.consume())
        iterator_kwargs = mock_client.get_shard_iterator.call_args.kwargs
        self.assertEqual(iterator_kwargs["ShardIteratorType"], "AFTER_SEQUENCE_NUMBER")
        self.assertEqual(iterator_kwargs["StartingSequenceNumber"], "seq-099")

    @patch("time.sleep")
    def test_no_checkpoint_starts_at_trim_horizon(self, _mock_sleep):
        """Without a checkpoint entry the shard starts at TRIM_HORIZON."""
        empty_page = {
            "Records": [],
            "NextShardIterator": None,
            "MillisBehindLatest": 0,
        }
        ext, mock_client = self._build(shard_records=[empty_page])
        list(ext.consume())
        iterator_kwargs = mock_client.get_shard_iterator.call_args.kwargs
        self.assertEqual(iterator_kwargs["ShardIteratorType"], "TRIM_HORIZON")


# ---------------------------------------------------------------------------
# Pub/Sub
# ---------------------------------------------------------------------------

class TestPubSubStreamExtractor(unittest.TestCase):
    """Tests for PubSubStreamExtractor — mock google.cloud.pubsub_v1."""

    def setUp(self):
        # Undo logging.disable pollution so assertLogs works in combined runs
        logging.disable(logging.NOTSET)

    def _build_extractor(self, pull_responses):
        """Create a PubSubStreamExtractor with a mocked SubscriberClient."""
        mock_pubsub_module = MagicMock()
        mock_subscriber = MagicMock()
        mock_pubsub_module.SubscriberClient.return_value = mock_subscriber
        mock_subscriber.subscription_path.return_value = (
            "projects/test-project/subscriptions/test-sub"
        )
        mock_subscriber.pull.side_effect = pull_responses

        mock_google = MagicMock()
        mock_google.cloud.pubsub_v1 = mock_pubsub_module
        modules_patch = {
            "google": mock_google,
            "google.cloud": mock_google.cloud,
            "google.cloud.pubsub_v1": mock_pubsub_module,
        }

        with patch.dict("sys.modules", modules_patch):
            from pipeline.streaming.pubsub_extractor import PubSubStreamExtractor
            ext = PubSubStreamExtractor(
                gov=MockGov(),
                project_id="test-project",
                subscription_id="test-sub",
                batch_size=5,
                timeout=10,
            )

        return ext, mock_subscriber

    def _make_received_message(self, payload, ack_id="ack-1", message_id="msg-1"):
        """Build a mock Pub/Sub received message."""
        msg = MagicMock()
        msg.ack_id = ack_id
        msg.message.data = json.dumps(payload).encode("utf-8")
        msg.message.message_id = message_id
        return msg

    def test_consume_yields_batch_and_acknowledges(self):
        """Messages are yielded as a DataFrame and then acknowledged."""
        received = [
            self._make_received_message({"id": 1}, ack_id="ack-1"),
            self._make_received_message({"id": 2}, ack_id="ack-2"),
        ]
        pull_resp_with_data = MagicMock()
        pull_resp_with_data.received_messages = received

        pull_resp_empty = MagicMock()
        pull_resp_empty.received_messages = []

        ext, mock_subscriber = self._build_extractor(
            [pull_resp_with_data, pull_resp_empty],
        )
        batches = list(ext.consume())

        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 2)

        # Verify acknowledge was called with both ack IDs
        mock_subscriber.acknowledge.assert_called_once()
        ack_call_request = mock_subscriber.acknowledge.call_args[1]["request"]
        self.assertIn("ack-1", ack_call_request["ack_ids"])
        self.assertIn("ack-2", ack_call_request["ack_ids"])

    def test_consume_nacks_malformed_messages(self):
        """Malformed messages are nacked (ack deadline 0), never acked —
        acking them before parse permanently lost the data."""
        bad_msg = MagicMock()
        bad_msg.ack_id = "ack-bad"
        bad_msg.message.data = b"NOT-JSON"
        bad_msg.message.message_id = "msg-bad"

        good_msg = self._make_received_message({"id": 1}, ack_id="ack-good")

        pull_resp = MagicMock()
        pull_resp.received_messages = [bad_msg, good_msg]

        pull_resp_empty = MagicMock()
        pull_resp_empty.received_messages = []

        ext, mock_subscriber = self._build_extractor(
            [pull_resp, pull_resp_empty],
        )

        with self.assertLogs("pipeline.streaming.pubsub_extractor", level=logging.WARNING):
            batches = list(ext.consume())

        # Only the valid record ends up in the DataFrame
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 1)

        # Only the parseable message is acknowledged
        ack_request = mock_subscriber.acknowledge.call_args[1]["request"]
        self.assertNotIn("ack-bad", ack_request["ack_ids"])
        self.assertIn("ack-good", ack_request["ack_ids"])

        # The malformed message is nacked via modify_ack_deadline(0)
        nack_request = mock_subscriber.modify_ack_deadline.call_args[1]["request"]
        self.assertIn("ack-bad", nack_request["ack_ids"])
        self.assertEqual(nack_request["ack_deadline_seconds"], 0)

    def test_deadline_exceeded_treated_as_empty(self):
        """An empty subscription raises DeadlineExceeded on pull — consume()
        must treat it as 'no messages', not crash."""
        from google.api_core.exceptions import DeadlineExceeded

        ext, mock_subscriber = self._build_extractor(
            [DeadlineExceeded("deadline exceeded")],
        )
        batches = list(ext.consume())
        self.assertEqual(batches, [])
        mock_subscriber.acknowledge.assert_not_called()

    def test_close_releases_subscriber(self):
        """close() calls subscriber.close() and sets ref to None."""
        pull_resp_empty = MagicMock()
        pull_resp_empty.received_messages = []

        ext, mock_subscriber = self._build_extractor([pull_resp_empty])
        ext.close()
        mock_subscriber.close.assert_called_once()
        self.assertIsNone(ext._subscriber)


if __name__ == "__main__":
    unittest.main()
