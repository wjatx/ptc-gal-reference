"""sa#166 — the worked peer-agent-inbound drain consumer (examples/webhook_peer).

The drain conformance suite (test_drain_handler.py) proves the worker's side of
the contract; test_example_receiver.py proves missileer's always-tainted
internal-observer archetype. This suite proves the CONTRASTING archetype:
webhook-peer's ``InboundLogReceiver`` loads through the real provider-path
loader, satisfies the protocol, and its OWN trust map extends the airlock's
already-admitted peer trust to the drain side — it trusts ``"peer:"`` and
``"channel:"`` sources (an accepted peer chain's origin + stamp hops), unlike
missileer's ``"internal:"``-only map. It still honours the D4 idempotency
obligation the same way missileer does. No AWS calls.
"""

import json

from examples.webhook_peer.inbound_log_receiver import InboundLogReceiver
from safe_agents.channels.drain.receiver import Receiver, load_receiver
from safe_agents.channels.schemas import EventTrigger

_RECEIVER_PATH = "examples.webhook_peer.inbound_log_receiver:InboundLogReceiver"
_TS = "2026-07-10T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"


def _envelope(
    event_id: str = "evt-1", *, channel_identity: str = "peer:example"
) -> EventTrigger:
    return EventTrigger.model_validate(
        {
            "event_id": event_id,
            "principal": "example-agent",
            "sender": {
                "channel_type": "webhook",
                "channel_identity": channel_identity,
                "evidence": ["sig:pass"],
            },
            "payload": {"msg": "status report"},
            "provenance": [
                {
                    "zone": "peer",
                    "source": channel_identity,
                    "evidence": [],
                    "label": "trusted",
                    "ts": _TS,
                },
                {
                    "zone": "channels",
                    "source": "channel:webhook",
                    "evidence": [],
                    "label": "trusted",
                    "ts": _TS,
                },
            ],
            "sender_class": "peer-agent",
            "ts": _TS,
            "expiry": _FUTURE,
        }
    )


class FakeBrokerRuntime:
    """The one-member surface the receiver touches: ``handle_request``.

    Emulates the broker enforcement layer's idempotency semantics
    (``broker/enforcement/engine.py`` step 1): a request whose
    ``idempotency_key`` was seen before returns the stored outcome WITHOUT
    executing again. ``executions`` therefore counts effective actions, the
    thing D4 says duplicates must not multiply.
    """

    def __init__(self) -> None:
        self.executions: list = []
        self._idempotency: dict[str, dict] = {}

    def handle_request(self, request):
        key = request.idempotency_key
        if key is not None and key in self._idempotency:
            return {**self._idempotency[key], "idempotent": True}
        self.executions.append(request)
        response = {"decision_kind": "allow", "result": {"status": "ok"}, "idempotent": False}
        if key is not None:
            self._idempotency[key] = response
        return response


# --- the seam: real loader, real protocol --------------------------------------

def test_loads_via_provider_path_and_satisfies_protocol():
    receiver = load_receiver(_RECEIVER_PATH)
    assert isinstance(receiver, InboundLogReceiver)
    assert isinstance(receiver, Receiver)


def test_receiver_trusts_the_peer_and_channel_stamp_prefixes():
    trust_map = InboundLogReceiver().input_trust_map()
    assert callable(trust_map)
    # The deliberate contrast with missileer: an accepted peer chain's origin
    # hop and channel stamp hop are BOTH trusted here, so the drain does not
    # taint the turn on its own account. Anything else still taints.
    assert trust_map("peer:example") is True
    assert trust_map("channel:webhook") is True
    assert trust_map("internal:x") is False
    assert trust_map("external:y") is False


# --- D4: duplicate deliveries replay, they do not double-act --------------------

def test_duplicate_envelope_produces_one_effective_action():
    receiver = InboundLogReceiver()
    runtime = FakeBrokerRuntime()
    envelope = _envelope(event_id="evt-dup")

    receiver.receive(envelope, runtime)
    receiver.receive(envelope, runtime)  # at-least-once delivery, second copy

    assert len(runtime.executions) == 1


def test_distinct_events_are_distinct_actions():
    receiver = InboundLogReceiver()
    runtime = FakeBrokerRuntime()

    receiver.receive(_envelope(event_id="evt-a"), runtime)
    receiver.receive(_envelope(event_id="evt-b"), runtime)
    # Same event_id from a DIFFERENT sender identity is a different D4 key too.
    receiver.receive(_envelope(event_id="evt-a", channel_identity="peer:other"), runtime)

    assert len(runtime.executions) == 3
    keys = {r.idempotency_key for r in runtime.executions}
    assert len(keys) == 3


# --- what the action is: a granted op, PII-safe args, correct agent segment -----

def test_action_is_a_granted_ledger_append_with_digested_identity():
    receiver = InboundLogReceiver()
    runtime = FakeBrokerRuntime()
    receiver.receive(_envelope(), runtime)

    [request] = runtime.executions
    assert (request.tool, request.op) == ("ledger", "append")
    assert request.args["kind"] == "ledger_delta"
    assert request.args["logical_date"] == "2026-07-10"
    assert request.args["agent"] == "example-agent"
    assert request.idempotency_key.startswith("example-agent:drain:")
    # Neither the args nor the key carry the raw channel identity — only its
    # digest (the drop-log discipline, consumer-side).
    serialized = json.dumps(request.args) + request.idempotency_key
    assert "peer:example" not in serialized
    assert "sha256:" in request.args["content"]


def test_non_allow_outcome_is_accepted_as_the_safe_result():
    # Abstain polarity: a broker that decides require_approval (e.g. an
    # untrusted-source chain) has HANDLED the envelope; the receiver must not
    # raise or retry.
    class HoldingRuntime:
        def handle_request(self, request):
            return {"decision_kind": "require_approval", "intent_id": "intent-1"}

    InboundLogReceiver().receive(_envelope(), HoldingRuntime())  # no exception
