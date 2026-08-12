"""channels.stores — the durable seam bindings behind the airlock (sa#152).

The reference dispatcher (channels/dispatch.py) takes three injected seams whose
in-memory forms are a `set` and two `list`s; this module binds them to AWS:

- `DynamoDbDedupeStore` — the `__contains__`/`add` dedupe store as a DynamoDB
  table with per-item TTL. Keys the dispatch tuple `(channel_identity, event_id)`
  through `digest_identity`, so the sender's raw identity is never stored at rest.
- `S3DropSink` / `S3VerdictSink` — the `append`-only `DropRecord` / `ScreenRecord`
  sinks as date-partitioned S3 objects.

boto3 is imported lazily inside each client accessor (never at module top), so
the SDK stays importable without the `aws` extra, and every client is injectable
so tests drive hand-rolled fakes with no boto3, moto, or live AWS.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from safe_agents.channels.trust_map import digest_identity

_SECONDS_PER_DAY = 86400


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_conditional_check_failure(exc: Exception) -> bool:
    """True iff `exc` is a DynamoDB ConditionalCheckFailedException.

    Duck-typed on the botocore `ClientError.response` shape so this module needs
    no botocore import (keeping it importable without the `aws` extra) and a
    hand-rolled fake can raise the same shape in tests.
    """
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    return response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


class DynamoDbDedupeStore:
    """DynamoDB-backed dedupe store for channels/dispatch.py's gate 6.

    Item layout:
        dedupe_pk (S) = "<digest_identity(channel_identity)>#<event_id>"
        ttl       (N) = now + ttl_days, in epoch seconds (DynamoDB TTL attribute)

    `__contains__` is a strongly-consistent GetItem; `add` is a conditional
    PutItem (`attribute_not_exists(dedupe_pk)`) whose ConditionalCheckFailed is
    swallowed, so a concurrent double-add is idempotent rather than an error.
    """

    _PK_ATTR = "dedupe_pk"
    _TTL_ATTR = "ttl"

    def __init__(
        self,
        table_name: str,
        *,
        ttl_days: int = 30,
        client: Any = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._table_name = table_name
        self._ttl_days = ttl_days
        self._client = client
        self._clock = clock

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3  # noqa: PLC0415 — lazy: no creds needed at import time

            self._client = boto3.client("dynamodb")
        return self._client

    def _pk(self, key: tuple[str, str]) -> str:
        channel_identity, event_id = key
        return f"{digest_identity(channel_identity)}#{event_id}"

    def __contains__(self, key: tuple[str, str]) -> bool:
        response = self._get_client().get_item(
            TableName=self._table_name,
            Key={self._PK_ATTR: {"S": self._pk(key)}},
            ConsistentRead=True,
        )
        return "Item" in response

    def add(self, key: tuple[str, str]) -> None:
        ttl = int(self._clock().timestamp()) + self._ttl_days * _SECONDS_PER_DAY
        try:
            self._get_client().put_item(
                TableName=self._table_name,
                Item={
                    self._PK_ATTR: {"S": self._pk(key)},
                    self._TTL_ATTR: {"N": str(ttl)},
                },
                ConditionExpression=f"attribute_not_exists({self._PK_ATTR})",
            )
        except Exception as exc:  # noqa: BLE001 — re-raised unless it is the idempotent case
            if _is_conditional_check_failure(exc):
                return
            raise


class _S3JsonSink:
    """Shared `append`-only S3 object sink for PII-safe channel records.

    Each `append` PutObjects the record's JSON at a date-partitioned key:
        {prefix}YYYY/MM/DD/{iso-ts}-{uuid4}.json
    The record is any object with `.model_dump_json()` (DropRecord / ScreenRecord),
    both of which already digest the sender identity — this sink stores exactly
    what it is handed and adds no raw identity of its own.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str,
        *,
        client: Any = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._bucket = bucket
        self._prefix = prefix
        self._client = client
        self._clock = clock

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3  # noqa: PLC0415 — lazy: no creds needed at import time

            self._client = boto3.client("s3")
        return self._client

    def append(self, record: Any) -> None:
        now = self._clock()
        key = f"{self._prefix}{now:%Y/%m/%d}/{now.isoformat()}-{uuid4()}.json"
        self._get_client().put_object(
            Bucket=self._bucket,
            Key=key,
            Body=record.model_dump_json().encode("utf-8"),
            ContentType="application/json",
        )


class S3DropSink(_S3JsonSink):
    """The `drops` seam: append-only `DropRecord`s under `channels/drops/`."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "channels/drops/",
        *,
        client: Any = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        super().__init__(bucket, prefix, client=client, clock=clock)


class S3VerdictSink(_S3JsonSink):
    """The `verdicts` seam: append-only `ScreenRecord`s under `channels/verdicts/`."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "channels/verdicts/",
        *,
        client: Any = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        super().__init__(bucket, prefix, client=client, clock=clock)
