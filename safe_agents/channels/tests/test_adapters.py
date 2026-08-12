"""sa#80 exit predicate — the channel-adapter and dispatch conformance suite.

Each test proves one clause from channels/ADAPTERS.md §"Conformance"; the
mapping table lives there. `StubInboundAdapter`/`StubOutboundAdapter` are
instrumented ABC implementations used to observe gate ordering.
"""

import hashlib
from datetime import datetime
from typing import Any

import pytest

from safe_agents.broker.taint.context import TurnContext
from safe_agents.broker.taint.propagation import build_trust_map
from safe_agents.channels.adapters import InboundAdapter, OutboundAdapter
from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.trust_map import (
    CLASS_HOP_LABEL,
    ChannelTrustMap,
    TrustMapEntry,
    ingest_chain,
)

_TS = "2026-07-08T00:00:00+00:00"
_EXPIRY = "2026-07-08T01:00:00+00:00"
_EXPIRED_EXPIRY = "2026-07-07T23:00:00+00:00"
_NOW = datetime.fromisoformat(_TS)


def _digest(identity: str) -> str:
    return "sha256:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _provenance_entry(**overrides) -> dict:
    base = {
        "zone": "test-zone",
        "source": "internal:test",
        "evidence": [],
        "label": "trusted",
        "ts": _TS,
    }
    base.update(overrides)
    return base


def _envelope(**overrides) -> EventTrigger:
    """A minimal valid EventTrigger; override any field via kwargs."""
    base = {
        "event_id": "evt-1",
        "principal": "test-principal",
        "sender": {
            "channel_type": "stub-channel",
            "channel_identity": "stub:identity",
            "evidence": [],
        },
        "payload": {"key": "value"},
        "provenance": [_provenance_entry()],
        "ts": _TS,
        "expiry": _EXPIRY,
    }
    base.update(overrides)
    return EventTrigger.model_validate(base)


class StubInboundAdapter(InboundAdapter):
    """Instrumented InboundAdapter: records call order, injectable behavior."""

    channel_type = "stub-channel"

    def __init__(
        self,
        *,
        verify_result: bool = True,
        identity: str = "stub:identity",
        envelope: EventTrigger | None = None,
        normalize_raises: Exception | None = None,
    ) -> None:
        self.calls: list[str] = []
        self._verify_result = verify_result
        self._identity = identity
        self._envelope = envelope
        self._normalize_raises = normalize_raises

    def verify_token(self, request: Any) -> bool:
        self.calls.append("verify_token")
        return self._verify_result

    def extract_identity(self, request: Any) -> str:
        self.calls.append("extract_identity")
        return self._identity

    def normalize(self, request: Any) -> EventTrigger:
        self.calls.append("normalize")
        if self._normalize_raises is not None:
            raise self._normalize_raises
        assert self._envelope is not None, "StubInboundAdapter needs envelope= to normalize"
        return self._envelope


class StubOutboundAdapter(OutboundAdapter):
    """Instrumented OutboundAdapter: records delivery calls, injectable ref."""

    channel_type = "stub-channel"

    def __init__(self, delivery_ref: str = "stub-delivery-ref") -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self._delivery_ref = delivery_ref

    def deliver(self, principal: str, rendered_output: str, channel_metadata: dict) -> str:
        self.calls.append((principal, rendered_output, channel_metadata))
        return self._delivery_ref


class _StubScreen:
    """A screen callable that records every envelope it was invoked with."""

    def __init__(self, result: bool = True) -> None:
        self.calls: list[EventTrigger] = []
        self._result = result

    def __call__(self, envelope: EventTrigger) -> bool:
        self.calls.append(envelope)
        return self._result


def test_verify_failure_short_circuits_before_body_read():
    adapter = StubInboundAdapter(verify_result=False)
    screen = _StubScreen()
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=ChannelTrustMap(entries=[]),
        screen=screen,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert adapter.calls == ["verify_token"]
    assert screen.calls == []
    assert len(drops) == 1
    assert drops[0].reason == "authenticity_failed"
    assert drops[0].identity_digest == _digest("")


def test_malformed_payload_drops_before_trust_map():
    identity = "chat:malformed-1"
    adapter = StubInboundAdapter(identity=identity, normalize_raises=ValueError("bad payload"))
    screen = _StubScreen()
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=ChannelTrustMap(entries=[]),
        screen=screen,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert adapter.calls == ["verify_token", "extract_identity", "normalize"]
    assert screen.calls == []
    assert len(drops) == 1
    assert drops[0].reason == "malformed"
    assert drops[0].identity_digest == _digest(identity)


def test_expired_envelope_drops_before_screen():
    identity = "chat:expired-1"
    envelope = _envelope(
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
        expiry=_EXPIRED_EXPIRY,
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    screen = _StubScreen()
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        # No mapping at all — proves expiry is checked before trust-map is consulted.
        trust_map=ChannelTrustMap(entries=[]),
        screen=screen,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert screen.calls == []
    assert len(drops) == 1
    assert drops[0].reason == "expired"


def test_unmapped_sender_never_reaches_screen():
    identity = "chat:unmapped-1"
    envelope = _envelope(
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    screen = _StubScreen()
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=ChannelTrustMap(entries=[]),
        screen=screen,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert screen.calls == []
    assert len(drops) == 1
    assert drops[0].reason == "unmapped"


def test_principal_mismatch_drops():
    identity = "chat:mismatch-1"
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="other-principal",
                sender_class="owner",
            )
        ]
    )
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert len(drops) == 1
    assert drops[0].reason == "principal_mismatch"


def test_replay_is_a_noop():
    identity = "chat:replay-1"
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    screen = _StubScreen()
    dedupe_store: set = set()
    drops = []

    first = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=screen,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )
    second = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=screen,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert first is not None
    assert second is None
    assert len(screen.calls) == 1
    assert drops == []


def test_screen_refusal_blocks_emission():
    identity = "chat:refused-1"
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    screen = _StubScreen(result=False)
    dedupe_store: set = set()
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=screen,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert len(screen.calls) == 1
    assert len(drops) == 1
    assert drops[0].reason == "screen_refused"
    # Dedupe is marked seen before the screen runs, so a refused message's
    # replays never re-spend screening budget (channels/ADAPTERS.md, gate 6).
    assert envelope.dedupe_key() in dedupe_store


def test_screen_pass_changes_nothing():
    identity = "chat:pass-1"
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    screen = _StubScreen(result=True)

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=screen,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )

    assert result is not None
    assert screen.calls == [envelope]
    assert len(result.provenance) == len(envelope.provenance) + 1
    assert result.provenance[:-1] == envelope.provenance
    assert result.sender_class == "owner"
    # Every other field is identical to the pre-stamp envelope.
    reverted = result.model_copy(
        update={"provenance": envelope.provenance, "sender_class": envelope.sender_class}
    )
    assert reverted == envelope


def test_emitted_envelope_is_stamped():
    identity = "peer:abc"
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class="peer-agent",
            )
        ]
    )
    # Wire value pre-set to "owner" — must be overwritten by the resolution's
    # class (closes channels/SCHEMAS.md C4).
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
        sender_class="owner",
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=None,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="receiver-zone",
    )

    assert result is not None
    assert result.sender_class == "peer-agent"
    receiver_entry = result.provenance[-1]
    assert receiver_entry.zone == "receiver-zone"
    assert receiver_entry.source == "channel:stub-channel"
    assert receiver_entry.evidence == ["token:pass"]
    assert receiver_entry.label == CLASS_HOP_LABEL["peer-agent"]


def test_dispatch_result_feeds_turn_ingestion():
    # Untrusted-origin fixture: the wire chain already carries an untrusted
    # hop (an inbound email); dispatch appends its own trusted receiver hop,
    # but chain-inherited taint must still reach the turn.
    untrusted_identity = "chat:untrusted-1"
    untrusted_trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=untrusted_identity,
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    untrusted_envelope = _envelope(
        principal="test-principal",
        sender={
            "channel_type": "stub-channel",
            "channel_identity": untrusted_identity,
            "evidence": [],
        },
        provenance=[_provenance_entry(source="email:example.test", label="untrusted")],
    )
    untrusted_adapter = StubInboundAdapter(identity=untrusted_identity, envelope=untrusted_envelope)

    untrusted_result = dispatch(
        "request",
        adapter=untrusted_adapter,
        trust_map=untrusted_trust_map,
        screen=None,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="receiver-zone",
    )
    assert untrusted_result is not None

    # A narrow receiver map trusting only "internal:" — the untrusted email
    # hop taints regardless of what the receiver map says about anything else.
    narrow_receiver_map = build_trust_map(trusted_prefixes=["internal:"])
    tainted_turn = TurnContext(turn_id="t-untrusted")
    ingest_chain(untrusted_result, tainted_turn, narrow_receiver_map)
    assert tainted_turn.tainted is True

    # Control: an all-internal, trusted chain under an owner mapping. The
    # receiver map here must also cover the dispatcher's own stamped hop
    # (source "channel:<type>") for the control to come out clean.
    trusted_identity = "chat:trusted-1"
    trusted_trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=trusted_identity,
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    trusted_envelope = _envelope(
        principal="test-principal",
        sender={
            "channel_type": "stub-channel",
            "channel_identity": trusted_identity,
            "evidence": [],
        },
        provenance=[_provenance_entry(source="internal:scheduler", label="trusted")],
    )
    trusted_adapter = StubInboundAdapter(identity=trusted_identity, envelope=trusted_envelope)

    trusted_result = dispatch(
        "request",
        adapter=trusted_adapter,
        trust_map=trusted_trust_map,
        screen=None,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="receiver-zone",
    )
    assert trusted_result is not None

    broad_receiver_map = build_trust_map(trusted_prefixes=["internal:", "channel:"])
    control_turn = TurnContext(turn_id="t-control")
    ingest_chain(trusted_result, control_turn, broad_receiver_map)
    assert control_turn.tainted is False


def test_stub_adapters_satisfy_interfaces():
    inbound = StubInboundAdapter()
    outbound = StubOutboundAdapter()

    assert isinstance(inbound, InboundAdapter)
    assert isinstance(outbound, OutboundAdapter)
    assert not isinstance(inbound, OutboundAdapter)
    assert not isinstance(outbound, InboundAdapter)

    with pytest.raises(TypeError):
        InboundAdapter()
    with pytest.raises(TypeError):
        OutboundAdapter()


def test_outbound_stub_delivers():
    outbound = StubOutboundAdapter(delivery_ref="ref-123")

    result = outbound.deliver("test-principal", "rendered text", {"key": "value"})

    assert result == "ref-123"
    assert outbound.calls == [("test-principal", "rendered text", {"key": "value"})]


# ---------------------------------------------------------------------------
# Sender-transport binding — gate 3's cross-check between extract_identity
# (gate 2) and the normalized envelope's sender.channel_identity. Backstops
# EventTrigger.dedupe_key()'s sender half for the cases chain verification
# doesn't cover: verification OFF, not yet run, or an adapter whose own
# gate-2/gate-3 identity extraction diverges independently (when verification
# IS on, gate 3.5 also binds sender.channel_identity into the signed
# statement — channels/SIGNING.md).
# ---------------------------------------------------------------------------


def test_sender_identity_mismatch_drops_malformed_before_verify_chain():
    # A non-conformant adapter: gate 2 extracts one identity, but the
    # normalized envelope claims a DIFFERENT sender.channel_identity. This is
    # exactly the shape a divergent adapter (or a forged wire field a
    # conformant adapter failed to bind) would produce.
    claimed = "chat:claimed-1"
    envelope = _envelope(
        sender={"channel_type": "stub-channel", "channel_identity": "chat:different-1", "evidence": []},
    )
    adapter = StubInboundAdapter(identity=claimed, envelope=envelope)
    verify_calls: list[EventTrigger] = []

    def spy_verify_chain(env: EventTrigger):
        verify_calls.append(env)
        raise AssertionError("verify_chain must not run past the sender-identity mismatch")

    drops = []
    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=ChannelTrustMap(entries=[]),
        screen=None,
        verify_chain=spy_verify_chain,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert verify_calls == []
    assert adapter.calls == ["verify_token", "extract_identity", "normalize"]
    assert len(drops) == 1
    assert drops[0].reason == "malformed"
    assert drops[0].detail == "sender_identity_mismatch"
    assert drops[0].identity_digest == _digest(claimed)
    # Untrusted input at the moment of divergence — no verification evidence.
    assert drops[0].chain_verified is False


def test_sender_identity_match_is_unaffected():
    identity = "chat:matched-1"
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=None,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )

    assert result is not None
