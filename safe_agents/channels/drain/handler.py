"""channels.drain.handler — the accepted-queue → broker-turn Lambda binding (sa#155).

The worker-side half of the airlock (sa#152): the airlock enqueues accepted,
stamped EventTrigger envelopes; this handler drains them. Per SQS record it
parses the envelope, drops it if expired (SCHEMAS C6), verifies the principal,
builds an ephemeral in-process ``BrokerRuntime`` from the image-baked
AgentManifest, feeds the provenance chain into that runtime's broker-held turn
(``ingest_chain`` — SCHEMAS C5, DRAIN.md D1/D2), and only then hands the
envelope to the consumer's Receiver — through a minimal brokered-call facade
that exposes ONLY ``handle_request``, never the turn controls, so ingest and
action share one turn the receiver cannot roll (sa#136, DRAIN.md D2).

There is deliberately NO second trust surface here: no re-screening, no
re-stamping, no dedupe store. The airlock is the sole gate surface and this
worker trusts the stamp (DRAIN.md D3); the queue delivers at-least-once, so
receiver idempotency is a contract obligation (D4), not a worker mechanism.

Record disposition (DRAIN.md D7) — the queue has no DLQ, so redelivery is only
for failures that can heal:
  TERMINAL  — malformed body, principal mismatch, expired envelope. Logged as
              a structured ``drain_terminal_drop`` and treated as handled;
              redelivering a permanently-bad record would just poison-loop it
              for the retention period and then vanish it silently.
  TRANSIENT — receiver exception, runtime build failure. Reported via
              ``reportBatchItemFailures`` for redelivery.

Env contract (image-baked; the infra side binds these):
  CHANNELS_DRAIN_MANIFEST      path to the consumer AgentManifest (yaml/json)
  CHANNELS_DRAIN_RECEIVER      dotted receiver provider path ("pkg.module:ClassName")
  BROKER_HMAC_KEY_SECRET_ARN   optional Secrets Manager ARN of the grant HMAC key;
                               fetched once at cold start and exported as
                               BROKER_HMAC_KEY (the name build_runtime's grant
                               store reads) so the key plaintext never sits in
                               Lambda env config

Missing or invalid config fails closed LOUDLY (structured log + raise): the
whole batch errors and the queue redelivers it rather than silently dropping
accepted signals.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from safe_agents.broker.schemas import AgentManifest
from safe_agents.broker.taint.propagation import InputTrustMap
from safe_agents.channels.drain.receiver import Receiver, load_receiver
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.trust_map import digest_identity, ingest_chain

logger = logging.getLogger(__name__)
# Same rationale as the airlock handler: the Lambda runtime leaves module
# loggers at the WARNING default, silently dropping every structured .info().
logger.setLevel(logging.INFO)


class DrainConfigError(RuntimeError):
    """Missing/invalid image-baked drain config — fail the whole invocation."""


class _TerminalDrop(Exception):
    """A permanently-bad record: logged and dropped, never redelivered (D7)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _BrokeredCalls:
    """The receiver-facing runtime facade: ``handle_request`` and nothing else.

    The Receiver acts through the broker but must not be able to roll the
    broker-held turn (DRAIN.md D2): handing it the raw ``BrokerRuntime`` would
    expose ``new_turn()``/``session_turn()``, letting a buggy or compromised
    receiver launder the ingested taint before acting. This facade is what
    ``receive`` gets instead.
    """

    __slots__ = ("_runtime",)

    def __init__(self, runtime: Any) -> None:
        self._runtime = runtime

    def handle_request(self, request: Any) -> Any:
        """Forward one brokered call to the real runtime's decided path."""
        return self._runtime.handle_request(request)


# ---------------------------------------------------------------------------
# Seam factories — module-level so tests monkeypatch them with fakes.
# ---------------------------------------------------------------------------

def _fetch_hmac_key(secret_arn: str) -> str:
    """Fetch the grant HMAC key from Secrets Manager (airlock's fetch posture)."""
    import boto3  # noqa: PLC0415

    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_arn)["SecretString"]


def _resolve_hmac_key() -> None:
    """Export the fetched key as BROKER_HMAC_KEY for build_runtime's grant store.

    ``build_runtime`` reads ``os.environ["BROKER_HMAC_KEY"]`` when it constructs
    the grant store, so setting it here — once, at cold start, before any record
    builds a runtime — is the seam. An ARN that is set but unfetchable fails the
    whole invocation closed (a drain running with the dev fallback key would
    silently fail every grant HMAC check instead). The key value is never logged.
    """
    secret_arn = os.environ.get("BROKER_HMAC_KEY_SECRET_ARN")
    if not secret_arn:
        return
    try:
        os.environ["BROKER_HMAC_KEY"] = _fetch_hmac_key(secret_arn)
    except Exception as exc:
        raise DrainConfigError(
            "BROKER_HMAC_KEY_SECRET_ARN is set but the secret fetch failed "
            f"({type(exc).__name__})"
        ) from exc


def _build_runtime(manifest: AgentManifest) -> Any:
    """Build one ephemeral in-process BrokerRuntime from the manifest.

    Lazy import keeps ``broker_server``'s prototype HTTP machinery off this
    module's import path. Backend selection stays ``build_runtime``'s env
    contract (BROKER_STORE / BROKER_AUDIT_* / BROKER_SECRETS /
    BROKER_ENVELOPE_LOAD); the drain deployment additionally sets
    BROKER_AUDIT_PREFIX so its audit chain never forks the broker service's.
    """
    from safe_agents.broker.prototype.broker_server import build_runtime  # noqa: PLC0415

    runtime, _sink = build_runtime(manifest)
    return runtime


# ---------------------------------------------------------------------------
# The per-container state, built once and cached.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _DrainState:
    manifest: AgentManifest
    receiver: Receiver
    receiver_map: InputTrustMap
    principal_id: str


_STATE: _DrainState | None = None


def _load_manifest() -> AgentManifest:
    """Read the image-baked AgentManifest named by CHANNELS_DRAIN_MANIFEST.

    The same minimal ``yaml.safe_load`` + ``model_validate`` posture as the
    broker's ``load_agent_manifest`` (YAML is a JSON superset, so a .json
    manifest parses through the same path). Never store-loaded: the manifest —
    and with it the receiver seam's trust boundary — rides the image layer.
    """
    path = os.environ.get("CHANNELS_DRAIN_MANIFEST")
    if not path:
        raise DrainConfigError("CHANNELS_DRAIN_MANIFEST is unset — the drain has no manifest")
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise DrainConfigError(
            f"drain manifest {path} must be a YAML/JSON mapping; got {type(raw).__name__}"
        )
    return AgentManifest.model_validate(raw)


def _build_state() -> _DrainState:
    _resolve_hmac_key()
    manifest = _load_manifest()
    if manifest.principal is None:
        raise DrainConfigError(
            "drain manifest has no principal: block — the worker cannot verify "
            "envelope addressing without one"
        )
    receiver_path = os.environ.get("CHANNELS_DRAIN_RECEIVER")
    if not receiver_path:
        raise DrainConfigError("CHANNELS_DRAIN_RECEIVER is unset — the drain has no receiver")
    receiver = load_receiver(receiver_path)
    return _DrainState(
        manifest=manifest,
        receiver=receiver,
        receiver_map=receiver.input_trust_map(),
        principal_id=manifest.principal.agentId,
    )


def _get_state() -> _DrainState:
    global _STATE
    if _STATE is None:
        try:
            _STATE = _build_state()
        except Exception as exc:
            # Config problems are loud and fatal for the whole invocation —
            # the batch is redelivered rather than silently dropped.
            logger.error(
                json.dumps({"event": "drain_config_error", "error": type(exc).__name__})
            )
            raise
    return _STATE


# ---------------------------------------------------------------------------
# Record handling
# ---------------------------------------------------------------------------

def _process_record(record: dict, state: _DrainState) -> None:
    """Drain one SQS record: parse → expiry → principal check → ingest → act.

    The call ORDER is the contract (DRAIN.md D1/D2): the provenance chain is
    ingested into the runtime's broker-held session turn BEFORE the receiver's
    first action, and the receiver acts through the SAME runtime (via the
    ``_BrokeredCalls`` facade), so its calls are decided under the taint the
    chain carried in. Expiry is checked before any budget-spending step
    (SCHEMAS C6) — an expired envelope never builds a runtime.
    """
    try:
        envelope = EventTrigger.model_validate_json(record.get("body") or "")
    except ValueError as exc:
        # Only the exception TYPE is logged — a ValidationError message embeds
        # input values, i.e. payload content (the airlock's PII discipline).
        logger.info(
            json.dumps({"event": "drain_malformed", "error": type(exc).__name__})
        )
        raise _TerminalDrop("malformed") from exc

    identity_digest = digest_identity(envelope.sender.channel_identity)

    # Hard TTL (SCHEMAS C6): expired envelopes drop before ingest or any other
    # budget-spending step. Replays of a stale message can never spend budget.
    if envelope.is_expired(datetime.now(timezone.utc)):
        logger.info(
            json.dumps(
                {
                    "event": "drain_expired",
                    "event_id": envelope.event_id,
                    "identity_digest": identity_digest,
                }
            )
        )
        raise _TerminalDrop("expired")

    if envelope.principal != state.principal_id:
        # A mismatch is a hard per-record failure, never a re-route: this
        # runtime is single-principal by construction (DRAIN.md D5).
        logger.error(
            json.dumps(
                {
                    "event": "drain_principal_mismatch",
                    "event_id": envelope.event_id,
                    "identity_digest": identity_digest,
                }
            )
        )
        raise _TerminalDrop("principal_mismatch")

    runtime = _build_runtime(state.manifest)

    # sa#176 — the human-as-owner approval fork. An owner-class approval envelope
    # ACTIONS a held intent out-of-band instead of starting an agent turn. The fork
    # REQUIRES sender_class == "owner": that label is set ONLY at the airlock's gate 8
    # from the trust map and is unforgeable on the wire, so a non-owner envelope that
    # carries an approval-shaped payload does NOT fork — it falls through to the normal
    # agent-turn path below where the broker decides every call. There is deliberately
    # no owner auto-allow here.
    #
    # This branch runs neither session_turn() nor ingest_chain(): there is no agent
    # turn to taint. approve_intent()/reject_intent() act on the STORED
    # materializedRequest (WYSIWYE) under a synthesized allow, so the human message's
    # own taint cannot change what executes — the Doer needs no turn state for it.
    if envelope.sender_class == "owner" and envelope.payload.get("kind") == "approval":
        # AUTHENTICATED owner identity (airlock-stamped), NEVER read from the payload.
        approved_by = f"owner:{envelope.sender.channel_identity}"
        intent_id = envelope.payload.get("intent_id")
        decision = envelope.payload.get("decision")
        if not isinstance(intent_id, str) or decision not in ("yes", "no"):
            # A malformed approval payload is a permanent error, never redelivered.
            raise _TerminalDrop("malformed")
        result = (
            runtime.approve_intent(intent_id, approved_by)
            if decision == "yes"
            else runtime.reject_intent(intent_id, approved_by)
        )
        # PII-safe: no payload content or intent internals beyond decision/executed.
        logger.info(
            json.dumps(
                {
                    "event": "drain_approval",
                    "event_id": envelope.event_id,
                    "identity_digest": identity_digest,
                    "decision": decision,
                    "executed": result.executed,
                }
            )
        )
        return

    # sa#193 Phase 6c — the human-as-owner flag fork. An owner-class flag envelope
    # marks an already-EXECUTED intent as reviewed-wrong (writing false_action) out
    # of band instead of starting an agent turn. Like the approval fork it REQUIRES
    # sender_class == "owner" (the unforgeable gate-8 label): a non-owner envelope
    # carrying a flag-shaped payload does NOT fork — it falls through to the normal
    # agent-turn path below. flag_intent() acts on the STORED intent, so no agent
    # turn is started and the human message's own taint cannot change what happens.
    if envelope.sender_class == "owner" and envelope.payload.get("kind") == "flag":
        # AUTHENTICATED owner identity (airlock-stamped), NEVER read from the payload.
        flagged_by = f"owner:{envelope.sender.channel_identity}"
        intent_id = envelope.payload.get("intent_id")
        if not isinstance(intent_id, str):
            # A malformed flag payload is a permanent error, never redelivered.
            raise _TerminalDrop("malformed")
        result = runtime.flag_intent(intent_id, flagged_by)
        # PII-safe: no payload content or intent internals beyond executed.
        logger.info(
            json.dumps(
                {
                    "event": "drain_flag",
                    "event_id": envelope.event_id,
                    "identity_digest": identity_digest,
                    "executed": result.executed,
                }
            )
        )
        return

    # Normal path — an agent turn. Feed the provenance chain into the broker-held
    # session turn BEFORE the receiver acts (DRAIN.md D1/D2), so its calls are decided
    # under the taint the chain carried in.
    turn = runtime.session_turn()
    ingest_chain(envelope, turn, state.receiver_map)
    logger.info(
        json.dumps(
            {
                "event": "drain_ingested",
                "event_id": envelope.event_id,
                "identity_digest": identity_digest,
                "tainted": turn.tainted,
            }
        )
    )

    state.receiver.receive(envelope, _BrokeredCalls(runtime))
    logger.info(
        json.dumps({"event": "drain_received", "event_id": envelope.event_id})
    )


def handler(event: dict, context: Any = None) -> dict:
    """Lambda entrypoint for the SQS accepted-queue trigger.

    Implements ``reportBatchItemFailures`` semantics for TRANSIENT failures
    only (receiver exception, runtime build failure): those records are
    reported back for redelivery without failing their batch siblings (the
    infra side sets batchSize=1, but partial-batch correctness does not
    assume it). TERMINAL failures (malformed, principal mismatch, expired)
    are logged as ``drain_terminal_drop`` and NOT reported — the queue has no
    DLQ, so redelivering them would poison-loop for the retention period and
    then vanish silently; the structured log is the observable surface
    (alarm-able the sa#153 way). Config errors raise out of the handler —
    the WHOLE batch errors, by design.
    """
    state = _get_state()
    failures: list[dict] = []
    for record in event.get("Records") or []:
        message_id = record.get("messageId", "")
        try:
            _process_record(record, state)
        except _TerminalDrop as exc:
            # Terminally handled: logged, dropped, never redelivered (D7).
            logger.error(
                json.dumps(
                    {
                        "event": "drain_terminal_drop",
                        "message_id": message_id,
                        "reason": exc.reason,
                    }
                )
            )
        except Exception as exc:  # noqa: BLE001 — a receiver/runtime error fails ONE record
            logger.error(
                json.dumps(
                    {
                        "event": "drain_record_error",
                        "message_id": message_id,
                        "error": type(exc).__name__,
                    }
                )
            )
            failures.append({"itemIdentifier": message_id})
    return {"batchItemFailures": failures}
