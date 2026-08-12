"""channels.airlock.handler — the API Gateway → dispatch → SQS Lambda binding (sa#152).

Thin by design: the whole point of the reference dispatcher
(channels/dispatch.py) is that it stays unchanged and transport-free, so this
handler only binds seams. It builds the airlock once per container from the
in-image manifest and the Secrets-Manager webhook token, then per request:
lowercases headers, decodes the body, calls `dispatch`, and — on an accepted
envelope — SendMessages it to the accepted queue.

Response discipline is 200-always: drops are silent to the sender by design, and
an unexpected exception is logged (structured JSON) and still answered 200. A 5xx
would make the provider retry, the retry would dedupe, and the record would
strand — so the airlock never signals failure back over the wire.

Env contract (fixed; the infra side binds these):
  CHANNELS_MANIFEST            in-image manifest path (unset ⇒ empty manifest)
  CHANNELS_DEDUPE_TABLE        DynamoDB dedupe table name
  CHANNELS_DROP_BUCKET         S3 bucket for drop (and verdict) records
  CHANNELS_DROP_PREFIX         drop key prefix (default channels/drops/)
  CHANNELS_VERDICT_PREFIX      verdict key prefix (default channels/verdicts/)
  CHANNELS_ACCEPTED_QUEUE_URL  SQS queue for accepted, stamped envelopes
  CHANNELS_WEBHOOK_SECRET_ARN  Secrets Manager ARN of the shared webhook token
  BROKER_VERIFY_KEYS_SECRET_ARN  optional; ARN of the JSON {key_id: pubkey_pem}
                               chain-verification map (unset ⇒ verification OFF)
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.manifest import (
    AirlockRuntime,
    ChannelsManifest,
    build_airlock,
    load_channels_manifest,
)
from safe_agents.channels.keys import resolve_verification_keys
from safe_agents.channels.signing import make_gate
from safe_agents.channels.stores import DynamoDbDedupeStore, S3DropSink, S3VerdictSink
from safe_agents.channels.trust_map import digest_identity, make_drop_record
from safe_agents.channels.webhook import WebhookRequest

logger = logging.getLogger(__name__)
# The Lambda runtime hangs its handler on the ROOT logger but leaves levels at
# the WARNING default, so an unleveled module logger silently drops every
# .info() — including the structured drop/accept lines this module exists to
# emit. Verified live (sa#152 bringup): invocations logged nothing.
logger.setLevel(logging.INFO)

DEFAULT_DROP_PREFIX = "channels/drops/"
DEFAULT_VERDICT_PREFIX = "channels/verdicts/"


# ---------------------------------------------------------------------------
# boto3 seam factories — kept as module-level functions so tests monkeypatch
# them with fakes (and boto3 stays a lazy, per-cold-start import).
# ---------------------------------------------------------------------------

def _dynamodb_client() -> Any:
    import boto3  # noqa: PLC0415

    return boto3.client("dynamodb")


def _s3_client() -> Any:
    import boto3  # noqa: PLC0415

    return boto3.client("s3")


def _sqs_client() -> Any:
    import boto3  # noqa: PLC0415

    return boto3.client("sqs")


def _fetch_webhook_token(secret_arn: str) -> str:
    import boto3  # noqa: PLC0415

    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_arn)["SecretString"]


# ---------------------------------------------------------------------------
# Drop-sink logging wrapper — one structured line per real drop (never a dedupe
# no-op, which appends nothing), carrying only the machine-safe fields.
# ---------------------------------------------------------------------------

class _LoggingDropSink:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def append(self, record: Any) -> None:
        logger.info(
            json.dumps(
                {
                    "event": "channel_drop",
                    "reason": record.reason,
                    "identity_digest": record.identity_digest,
                    "detail": record.detail,
                }
            )
        )
        self._inner.append(record)


# ---------------------------------------------------------------------------
# The per-container runtime, built once and cached.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _HandlerState:
    airlock: AirlockRuntime
    dedupe: DynamoDbDedupeStore
    drops: _LoggingDropSink
    verdicts: S3VerdictSink | None
    verify_chain: Any
    sqs: Any
    queue_url: str


_STATE: _HandlerState | None = None


def _load_manifest() -> ChannelsManifest:
    path = os.environ.get("CHANNELS_MANIFEST")
    if not path:
        return ChannelsManifest()
    return load_channels_manifest(path)


def _build_state() -> _HandlerState:
    manifest = _load_manifest()
    token = _fetch_webhook_token(os.environ["CHANNELS_WEBHOOK_SECRET_ARN"])
    airlock = build_airlock(manifest, token=token)

    dedupe = DynamoDbDedupeStore(
        os.environ["CHANNELS_DEDUPE_TABLE"],
        ttl_days=airlock.dedupe_ttl_days,
        client=_dynamodb_client(),
    )

    bucket = os.environ["CHANNELS_DROP_BUCKET"]
    s3 = _s3_client()
    drops = _LoggingDropSink(
        S3DropSink(bucket, os.environ.get("CHANNELS_DROP_PREFIX", DEFAULT_DROP_PREFIX), client=s3)
    )
    verdicts = (
        S3VerdictSink(
            bucket, os.environ.get("CHANNELS_VERDICT_PREFIX", DEFAULT_VERDICT_PREFIX), client=s3
        )
        if airlock.verdict_sink
        else None
    )

    # Chain-signature verification (channels/SIGNING.md). Ships OFF: with no
    # BROKER_VERIFY_KEYS_SECRET_ARN configured the resolver is None, make_gate
    # returns None, and dispatch skips the gate — unsigned peers pass. A
    # set-but-unfetchable/malformed keys secret fails the cold start closed.
    verify_chain = make_gate(resolve_verification_keys())

    return _HandlerState(
        airlock=airlock,
        dedupe=dedupe,
        drops=drops,
        verdicts=verdicts,
        verify_chain=verify_chain,
        sqs=_sqs_client(),
        queue_url=os.environ["CHANNELS_ACCEPTED_QUEUE_URL"],
    )


def _get_state() -> _HandlerState:
    global _STATE
    if _STATE is None:
        _STATE = _build_state()
    return _STATE


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

def _ok() -> dict:
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"ok": True}),
    }


def _request_from_event(event: dict) -> WebhookRequest:
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    return WebhookRequest(headers=headers, body=body)


def _handle(event: dict) -> dict:
    method = event.get("requestContext", {}).get("http", {}).get("method")
    if method is not None and method != "POST":
        # Only POST carries an inbound signal; anything else is a silent no-op.
        return _ok()

    state = _get_state()
    try:
        request = _request_from_event(event)
    except ValueError as exc:  # covers binascii.Error and UnicodeDecodeError
        # A body that can't even be decoded is dropped `malformed` like any
        # gate-2/3 failure; identity is unknowable, so the record digests "".
        # Only the exception TYPE is logged — a UnicodeDecodeError message
        # embeds raw payload bytes.
        state.drops.append(
            make_drop_record(
                state.airlock.adapter.channel_type,
                "",
                "malformed",
                datetime.now(timezone.utc).isoformat(),
            )
        )
        logger.info(
            json.dumps({"event": "channel_drop_undecodable", "error": type(exc).__name__})
        )
        return _ok()

    accepted = dispatch(
        request,
        adapter=state.airlock.adapter,
        trust_map=state.airlock.trust_map,
        screen=state.airlock.screen,
        verify_chain=state.verify_chain,
        verdicts=state.verdicts,
        dedupe_store=state.dedupe,
        drops=state.drops,
        now=datetime.now(timezone.utc),
        zone=state.airlock.zone,
    )

    if accepted is not None:
        state.sqs.send_message(
            QueueUrl=state.queue_url, MessageBody=accepted.model_dump_json()
        )
        logger.info(
            json.dumps(
                {
                    "event": "channel_accepted",
                    "identity_digest": digest_identity(accepted.sender.channel_identity),
                    "event_id": accepted.event_id,
                }
            )
        )

    return _ok()


def handler(event: dict, context: Any = None) -> dict:
    """Lambda entrypoint. Always answers 200; never raises to the provider."""
    try:
        return _handle(event)
    except Exception as exc:  # noqa: BLE001 — 200-always: a 5xx would retry, dedupe, and strand
        logger.error(
            json.dumps({"event": "handler_error", "error": f"{type(exc).__name__}: {exc}"})
        )
        return _ok()
