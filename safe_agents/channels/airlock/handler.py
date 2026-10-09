"""channels.airlock.handler — the API Gateway → dispatch → SQS Lambda binding.

Thin by design: the whole point of the reference dispatcher
(channels/dispatch.py) is that it stays unchanged and transport-free, so this
handler only binds seams. It builds the airlock once per container from the
in-image manifest and the Secrets-Manager webhook token secret, then per request:
lowercases headers, decodes the body, calls `dispatch_outcome`, and — on an
accepted envelope — SendMessages it to the accepted queue.

Response discipline (channels/ADAPTERS.md §"What the sender is told"): the status
is 200 on every path, an unexpected exception included, which is logged
(structured JSON). A 5xx would make the provider retry, the retry would dedupe,
and the record would strand, and a status that varied would tell a prober which
gate it reached. The body is `{"ok": true}` toward everyone, with one exception:
a sender that passed gate 1 with its own token and whose identity is in the
trust map is told `{"ok": false, "refusal": "permanent"}` when the airlock
evaluated its envelope and refused it before the screen, and
`{"ok": false, "refusal": "transient"}` when the airlock could not evaluate
because its verification keys or its dedupe store were unavailable. A screen refusal, a replay, and a failure of the airlock
while handling the request read as an acceptance.

The verification keys are fetched at cold start. When that fetch fails the
handler still serves: the keys are fetched again by the next request that
reaches gate 3.5, and cached once the fetch succeeds. Every other cold-start
failure still fails the whole cold start, as before: a failed webhook-token
fetch, or a token secret that is not a usable identity → token map, leaves no
way to authenticate anyone, and a manifest that does not load leaves no trust
map. Each request is then answered `{"ok": true}`, the failure is
logged as `handler_error`, and nothing is cached.

Env contract (fixed; the infra side binds these):
  CHANNELS_MANIFEST            in-image manifest path (unset ⇒ no trust map, so
                               every sender drops; the zone is `unconfigured`)
  CHANNELS_DEDUPE_TABLE        DynamoDB dedupe table name
  CHANNELS_DROP_BUCKET         S3 bucket for drop (and verdict) records
  CHANNELS_DROP_PREFIX         drop key prefix (default channels/drops/)
  CHANNELS_VERDICT_PREFIX      verdict key prefix (default channels/verdicts/)
  CHANNELS_ACCEPTED_QUEUE_URL  SQS queue for accepted, stamped envelopes
  CHANNELS_WEBHOOK_SECRET_ARN  Secrets Manager ARN of the webhook token secret. For
                               the signed-webhook adapter, a JSON map, one entry
                               per peer: {channel_identity: token}, keyed as the
                               trust map writes the identity (a bare string is
                               refused at cold start); for the owner adapter, the
                               bot's one token as a bare string
  BROKER_VERIFY_KEYS_SECRET_ARN  optional; ARN of the JSON chain-verification map
                               {key_id: {public_key, zone, sender_identities,
                               signer_posture, custody_evidence}}
                               (channels/SIGNING.md S8 and S10; unset ⇒ verification OFF)
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from safe_agents.channels.dispatch import KeySourceUnavailable, RefusalClass, dispatch_outcome
from safe_agents.channels.manifest import (
    UNCONFIGURED_ZONE,
    AirlockRuntime,
    ChannelsManifest,
    build_airlock,
    load_channels_manifest,
)
from safe_agents.channels.keys import (
    VERIFY_KEYS_SECRET_ARN_ENV,
    SigningConfigError,
    resolve_verification_keys,
)
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.schemas.event_trigger import MAX_FORWARD_BYTES
from safe_agents.channels.signing import ChainVerifyResult, make_gate
from safe_agents.channels.stores import DynamoDbDedupeStore, S3DropSink, S3VerdictSink
from safe_agents.channels.trust_map import digest_identity, make_drop_record
from safe_agents.channels.webhook import WebhookRequest

logger = logging.getLogger(__name__)
# The Lambda runtime hangs its handler on the ROOT logger but leaves levels at
# the WARNING default, so an unleveled module logger silently drops every
# .info() — including the structured drop/accept lines this module exists to
# emit. Verified live (airlock bringup): invocations logged nothing.
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
# Gate 3.5's seam when verification keys are configured.
# ---------------------------------------------------------------------------

class _KeyedVerifyGate:
    """The chain-verification seam, fetching its keys until a fetch succeeds.

    Constructed only when a keys ARN is configured. A fetch that fails (the
    secret unreachable or malformed: `SigningConfigError`) caches nothing, and
    the call raises `KeySourceUnavailable`, which the dispatcher records
    `not_evaluated`/`key_source`. The fetch is attempted only for a request
    that reaches gate 3.5, so a request that fails gate 1 never drives one.
    """

    def __init__(self) -> None:
        self._gate: Any = None

    def resolve(self) -> bool:
        """Fetch the keys if they are not cached yet; True once they are."""
        if self._gate is not None:
            return True
        try:
            self._gate = make_gate(resolve_verification_keys())
        except SigningConfigError as exc:
            # The message names the setting and the fault, never key material
            # (keys.py builds every SigningConfigError that way).
            logger.error(
                json.dumps(
                    {"event": "verify_keys_unavailable", "error": f"{type(exc).__name__}: {exc}"}
                )
            )
            return False
        return self._gate is not None

    def __call__(self, envelope: EventTrigger) -> ChainVerifyResult:
        if not self.resolve():
            raise KeySourceUnavailable
        return self._gate(envelope)


# ---------------------------------------------------------------------------
# The per-container runtime, built once and cached.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _HandlerState:
    airlock: AirlockRuntime
    dedupe: DynamoDbDedupeStore
    drops: _LoggingDropSink
    verdicts: S3VerdictSink | None
    verify_chain: _KeyedVerifyGate | None
    sqs: Any
    queue_url: str


_STATE: _HandlerState | None = None


def _load_manifest() -> ChannelsManifest:
    path = os.environ.get("CHANNELS_MANIFEST")
    if not path:
        # No consumer manifest: an empty trust map, so gate 5 drops every sender.
        # The zone is a named placeholder for this case. A manifest that IS
        # configured must name its own zone and never inherits this one.
        return ChannelsManifest(zone=UNCONFIGURED_ZONE)
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
    # BROKER_VERIFY_KEYS_SECRET_ARN configured the seam is None and dispatch
    # skips the gate, so unsigned peers pass. When it is configured the keys
    # are fetched now; a set-but-unfetchable or malformed keys secret (an entry
    # with no custody record included, SIGNING.md S10) does not fail the cold
    # start. Every envelope that reaches gate 3.5 meanwhile is refused
    # `not_evaluated`, never passed unverified, and the next one fetches again.
    verify_chain: _KeyedVerifyGate | None = None
    if os.environ.get(VERIFY_KEYS_SECRET_ARN_ENV):
        verify_chain = _KeyedVerifyGate()
        verify_chain.resolve()

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

# The three bodies, serialized once so the uniform one is the same bytes on
# every path that sends it.
_UNIFORM_BODY = json.dumps({"ok": True})
_REFUSAL_BODIES: dict[RefusalClass, str] = {
    "permanent": json.dumps({"ok": False, "refusal": "permanent"}),
    "transient": json.dumps({"ok": False, "refusal": "transient"}),
}


def _respond(refusal: RefusalClass | None = None) -> dict:
    """Status 200 always; the body carries the refusal class and nothing else."""
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": _UNIFORM_BODY if refusal is None else _REFUSAL_BODIES[refusal],
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
        return _respond()

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
        return _respond()

    outcome = dispatch_outcome(
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

    accepted = outcome.envelope
    if accepted is not None:
        state.sqs.send_message(
            QueueUrl=state.queue_url, MessageBody=accepted.to_wire(max_bytes=MAX_FORWARD_BYTES)
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

    return _respond(outcome.refusal)


def handler(event: dict, context: Any = None) -> dict:
    """Lambda entrypoint. Always answers status 200; never raises to the provider."""
    try:
        return _handle(event)
    except Exception as exc:  # noqa: BLE001 — status 200 always: a 5xx would retry, dedupe, and strand
        logger.error(
            json.dumps({"event": "handler_error", "error": f"{type(exc).__name__}: {exc}"})
        )
        return _respond()
