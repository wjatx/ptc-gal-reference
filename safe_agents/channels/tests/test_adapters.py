"""The channel-adapter and dispatch conformance suite.

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
        # The zone almost every test here passes to `dispatch`.
        "audience": "test-zone",
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
        audience="receiver-zone",
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
        audience="receiver-zone",
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
        audience="receiver-zone",
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


def test_an_inbound_adapter_claims_a_per_sender_credential_only_by_saying_so():
    """`credential_per_sender` defaults to False: an adapter is treated as
    holding a credential every sender shares until it declares otherwise, so a
    new adapter tells its senders nothing (channels/ADAPTERS.md §"What the
    sender is told")."""
    assert InboundAdapter.credential_per_sender is False
    assert StubInboundAdapter().credential_per_sender is False


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


def _mapped(identity: str, sender_class: str = "peer-agent") -> ChannelTrustMap:
    return ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="stub-channel",
                channel_identity=identity,
                principal="test-principal",
                sender_class=sender_class,
            )
        ]
    )


@pytest.mark.parametrize("asserted", ["owner", "peer-agent", "external"])
def test_wire_sender_class_is_discarded_before_any_gate_reads_it(asserted):
    """A sender that asserts its own class must not have that value seen by the
    screen, which runs before gate 8 sets the receiver's own."""
    identity = "chat:asserts-a-class"
    envelope = _envelope(
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
        sender_class=asserted,
    )
    screen = _StubScreen(result=True)

    result = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=_mapped(identity, "external"),
        screen=screen,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )

    assert [seen.sender_class for seen in screen.calls] == [None]
    assert result is not None and result.sender_class == "external"


def _nested(depth: int) -> dict:
    payload: dict = {"leaf": 1}
    for _ in range(depth):
        payload = {"k": payload}
    return payload


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"key": "\ud800"}, id="lone surrogate"),
        pytest.param({"key": float("nan")}, id="NaN"),
        pytest.param({"key": float("inf")}, id="Infinity"),
        # The airlock's parser accepts this depth; the worker's stops short of it.
        pytest.param(_nested(220), id="nested past the worker parser's limit"),
        # Raises RecursionError, which is not a ValueError: the gate catches both.
        pytest.param(_nested(5000), id="nested past the interpreter's limit"),
    ],
)
def test_unforwardable_envelope_drops_before_it_claims_a_dedupe_key(payload):
    """Each of these parses and validates here and is then lost at the next hop.
    Refused after dedupe, it would lose the message and shadow the honest copy."""
    identity = "chat:poisoned"
    sender = {"channel_type": "stub-channel", "channel_identity": identity, "evidence": []}
    poisoned = _envelope(sender=sender).model_copy(update={"payload": payload})
    with pytest.raises((ValueError, RecursionError)):
        poisoned.to_wire()
    dedupe_store: set = set()
    drops: list = []
    screen = _StubScreen(result=True)

    def receive(envelope: EventTrigger):
        return dispatch(
            "request",
            adapter=StubInboundAdapter(identity=identity, envelope=envelope),
            trust_map=_mapped(identity),
            screen=screen,
            dedupe_store=dedupe_store,
            drops=drops,
            now=_NOW,
            zone="test-zone",
        )

    assert receive(poisoned) is None
    assert [(d.reason, d.detail) for d in drops] == [("malformed", "not_forwardable")]
    assert dedupe_store == set() and screen.calls == []
    # The honest copy with the same dedupe key is still delivered.
    assert receive(_envelope(sender=sender)) is not None


# ---------------------------------------------------------------------------
# Audience: an envelope names the one receiver it is addressed to, and a
# receiver refuses any other (channels/SIGNING.md S9). The last gate-3 check,
# ahead of chain verification, so the drop is never counted against a signer.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "audience",
    [
        pytest.param("another-zone", id="another zone"),
        pytest.param("TEST-ZONE", id="this zone in another case"),
        pytest.param("test-zone ", id="this zone with a trailing space"),
        pytest.param(" test-zone", id="this zone with a leading space"),
        pytest.param("test-zon", id="a prefix of this zone"),
    ],
)
def test_an_envelope_addressed_to_another_zone_drops_before_verification(audience):
    identity = "chat:addressed-elsewhere"
    sender = {"channel_type": "stub-channel", "channel_identity": identity, "evidence": []}
    screen = _StubScreen()
    dedupe_store: set = set()
    drops: list = []
    verify_calls: list[EventTrigger] = []

    def spy_verify_chain(env: EventTrigger):
        verify_calls.append(env)
        raise AssertionError("verify_chain must not run for an envelope addressed elsewhere")

    def receive(envelope: EventTrigger, verify_chain):
        return dispatch(
            "request",
            adapter=StubInboundAdapter(identity=identity, envelope=envelope),
            trust_map=_mapped(identity),
            screen=screen,
            verify_chain=verify_chain,
            dedupe_store=dedupe_store,
            drops=drops,
            now=_NOW,
            zone="test-zone",
        )

    assert receive(_envelope(audience=audience, sender=sender), spy_verify_chain) is None
    assert verify_calls == [] and screen.calls == [] and dedupe_store == set()
    assert len(drops) == 1
    drop = drops[0]
    assert (drop.reason, drop.detail) == ("audience_mismatch", None)
    assert drop.identity_digest == _digest(identity)
    # Nothing was verified, so the record names no signer and claims no check.
    assert drop.chain_verified is False and drop.signer_key_id is None
    # It claimed no dedupe key: the same message addressed here is delivered.
    assert receive(_envelope(sender=sender), None) is not None


def test_audience_is_checked_ahead_of_expiry_and_the_trust_map():
    """Expired, unmapped and addressed elsewhere at once: the audience is what
    the record says, so the receiver spends nothing on a message not meant for it."""
    identity = "chat:addressed-elsewhere"
    envelope = _envelope(
        audience="another-zone",
        expiry=_EXPIRED_EXPIRY,
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    drops: list = []

    result = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=ChannelTrustMap(entries=[]),
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert [d.reason for d in drops] == ["audience_mismatch"]
