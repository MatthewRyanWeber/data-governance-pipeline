"""
Tests for pipeline.streaming — Kafka, Kinesis, and Pub/Sub stream extractors.

Covers consume/commit patterns, shard iteration, message acknowledgement,
malformed-message handling, and resource cleanup for all three extractors.
"""

# Revision history
# ----------------
# 1.0   2026-06-08   Initial test suite for streaming extractors.

import json
import logging
import unittest
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


# ---------------------------------------------------------------------------
# Kinesis
# ---------------------------------------------------------------------------

class TestKinesisStreamExtractor(unittest.TestCase):
    """Tests for KinesisStreamExtractor — mock boto3."""

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


# ---------------------------------------------------------------------------
# Pub/Sub
# ---------------------------------------------------------------------------

class TestPubSubStreamExtractor(unittest.TestCase):
    """Tests for PubSubStreamExtractor — mock google.cloud.pubsub_v1."""

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

    def test_consume_acknowledges_malformed_messages(self):
        """Malformed messages are still acknowledged (not redelivered)."""
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

        # Both ack IDs (including the malformed one) are acknowledged
        ack_request = mock_subscriber.acknowledge.call_args[1]["request"]
        self.assertIn("ack-bad", ack_request["ack_ids"])
        self.assertIn("ack-good", ack_request["ack_ids"])

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
