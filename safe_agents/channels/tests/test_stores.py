"""sa#152 — durable seam bindings (DynamoDbDedupeStore, S3 sinks) against fakes.

Hand-rolled fake boto3 clients (no moto, no new deps, no live AWS): the fakes are
the minimal surface each store touches, and the DynamoDB fake raises a
botocore-shaped ConditionalCheckFailedException so `add` idempotency is exercised
through the real duck-typed path.
"""

import json
from datetime import datetime, timezone

from safe_agents.channels.stores import DynamoDbDedupeStore, S3DropSink, S3VerdictSink
from safe_agents.channels.screening import make_screen_record
from safe_agents.channels.trust_map import digest_identity, make_drop_record

_FIXED = datetime(2026, 7, 8, 12, 34, 56, tzinfo=timezone.utc)
_TS = "2026-07-08T12:34:56+00:00"
_IDENTITY = "peer:example"


class _FakeClientError(Exception):
    """Shaped like botocore's ClientError for the duck-typed idempotency check."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeDynamoClient:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.get_calls: list[dict] = []
        self.put_calls: list[dict] = []

    def get_item(self, *, TableName, Key, ConsistentRead=False):
        self.get_calls.append({"TableName": TableName, "Key": Key, "ConsistentRead": ConsistentRead})
        pk = Key["dedupe_pk"]["S"]
        return {"Item": self.items[pk]} if pk in self.items else {}

    def put_item(self, *, TableName, Item, ConditionExpression=None):
        self.put_calls.append(
            {"TableName": TableName, "Item": Item, "ConditionExpression": ConditionExpression}
        )
        pk = Item["dedupe_pk"]["S"]
        if ConditionExpression and "attribute_not_exists" in ConditionExpression and pk in self.items:
            raise _FakeClientError("ConditionalCheckFailedException")
        self.items[pk] = Item


class FakeS3Client:
    def __init__(self) -> None:
        self.puts: list[dict] = []

    def put_object(self, *, Bucket, Key, Body, ContentType=None):
        self.puts.append({"Bucket": Bucket, "Key": Key, "Body": Body, "ContentType": ContentType})


# --- DynamoDbDedupeStore --------------------------------------------------

def _store(fake, ttl_days=30):
    return DynamoDbDedupeStore("dedupe-table", ttl_days=ttl_days, client=fake, clock=lambda: _FIXED)


def test_dedupe_absent_then_present_after_add():
    fake = FakeDynamoClient()
    store = _store(fake)
    key = (_IDENTITY, "evt-1")

    assert key not in store
    assert fake.get_calls[-1]["ConsistentRead"] is True  # strongly consistent read

    store.add(key)
    assert key in store


def test_dedupe_add_is_idempotent():
    fake = FakeDynamoClient()
    store = _store(fake)
    key = (_IDENTITY, "evt-1")

    store.add(key)
    store.add(key)  # ConditionalCheckFailed is swallowed — no raise

    assert len(fake.put_calls) == 2
    assert key in store


def test_dedupe_pk_is_pii_safe_and_ttl_set():
    fake = FakeDynamoClient()
    store = _store(fake, ttl_days=7)
    store.add((_IDENTITY, "evt-42"))

    item = fake.put_calls[0]["Item"]
    pk = item["dedupe_pk"]["S"]
    assert pk == f"{digest_identity(_IDENTITY)}#evt-42"
    assert _IDENTITY not in pk  # raw identity never at rest

    expected_ttl = int(_FIXED.timestamp()) + 7 * 86400
    assert item["ttl"]["N"] == str(expected_ttl)


def test_dedupe_expired_but_undeleted_row_still_hits():
    """An expired row DynamoDB has not yet reaped is still a dedupe hit: __contains__
    never reads the ttl attribute, so the ~48h TTL-deletion lag can only WIDEN the
    dedupe window, never narrow it — the lag fails toward dropping a replay
    (sa#213 dedupe-ttl-30d-replay, near-side semantics)."""
    fake = FakeDynamoClient()
    store = _store(fake)
    key = (_IDENTITY, "evt-replay")
    store.add(key)
    # Simulate the row sitting past expiry, unreaped: force its ttl into the past.
    pk = fake.put_calls[0]["Item"]["dedupe_pk"]["S"]
    fake.items[pk]["ttl"]["N"] = str(int(_FIXED.timestamp()) - 1)

    assert key in store  # still deduped — presence, not ttl arithmetic, decides


def test_dedupe_replay_after_ttl_deletion_reads_as_new():
    """Once DynamoDB TTL actually deletes the row, a replayed (identity, event_id) is
    indistinguishable from never-seen: __contains__ misses and add() re-arms a fresh
    30d ttl (sa#213 dedupe-ttl-30d-replay, far-side semantics). Whether
    accepted-as-NEW is intended or a finding is a recorded DECISION in the trigger
    ledger, not this test's claim — this pins only what the code DOES. NB the gate
    order bounds the blast radius: expiry (gate 4) runs before dedupe (gate 6), so a
    byte-identical stale replay is expiry-dropped upstream; only an envelope whose
    sender-declared expiry outlives the dedupe ttl reaches this path."""
    fake = FakeDynamoClient()
    store = _store(fake)
    key = (_IDENTITY, "evt-replay")
    store.add(key)
    # DynamoDB TTL reaps the row (up to ~48h after expiry; deletion, not filtering).
    pk = fake.put_calls[0]["Item"]["dedupe_pk"]["S"]
    del fake.items[pk]

    assert key not in store  # the replay reads as NEW
    store.add(key)  # ...and gate 6 would re-admit it, re-arming a fresh window
    assert key in store
    assert fake.put_calls[-1]["Item"]["ttl"]["N"] == str(int(_FIXED.timestamp()) + 30 * 86400)


# --- S3 sinks -------------------------------------------------------------

def test_drop_sink_writes_pii_safe_json_at_dated_key():
    fake = FakeS3Client()
    sink = S3DropSink("drop-bucket", client=fake, clock=lambda: _FIXED)
    record = make_drop_record("webhook", _IDENTITY, "authenticity_failed", _TS)

    sink.append(record)

    assert len(fake.puts) == 1
    put = fake.puts[0]
    assert put["Bucket"] == "drop-bucket"
    assert put["Key"].startswith("channels/drops/2026/07/08/")
    assert put["Key"].endswith(".json")
    assert put["ContentType"] == "application/json"

    body = json.loads(put["Body"])
    assert body["reason"] == "authenticity_failed"
    assert body["identity_digest"] == digest_identity(_IDENTITY)
    assert _IDENTITY not in put["Body"].decode("utf-8")  # raw identity never written


def test_verdict_sink_writes_screen_record_under_verdicts_prefix():
    fake = FakeS3Client()
    sink = S3VerdictSink("drop-bucket", client=fake, clock=lambda: _FIXED)
    record = make_screen_record("webhook", _IDENTITY, "evt-1", False, "injection_suspected", _TS)

    sink.append(record)

    put = fake.puts[0]
    assert put["Key"].startswith("channels/verdicts/2026/07/08/")
    body = json.loads(put["Body"])
    assert body["passed"] is False
    assert body["reason"] == "injection_suspected"
    assert body["identity_digest"] == digest_identity(_IDENTITY)
