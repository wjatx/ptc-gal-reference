"""sa#156 exit predicate — the peer.publish outbound-seam conformance suite.

Each test proves one clause from channels/PUBLISH.md §"Conformance"; the mapping
table lives there. Two layers:

  - The pure `stamp_outbound` layer (P3/P4): the outbound provenance is
    broker-stamped from the sending turn's taint state, never authored by the
    agent, and taint-preserving under relay.
  - The broker layer (P2): the base `peer.publish` manifest entry is an external
    write, so a tainted turn's publish escalates to require_approval through the
    STANDING `tainted_external_write` cut — no publish-specific PDP rule.
"""

from __future__ import annotations

from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.pdp import decide
from safe_agents.broker.schemas import BrokeredCall, Session, Taint
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.tests.scaffold import PRINCIPAL, make_pip
from safe_agents.channels.publish import stamp_outbound
from safe_agents.channels.schemas import EventTrigger

_TS = "2026-07-09T00:00:00+00:00"
_EXPIRY = "2026-07-09T01:00:00+00:00"


def _outbound(
    *,
    turn_tainted: bool,
    inbound: EventTrigger | None = None,
    ingested_sources: list[str] | None = None,
) -> EventTrigger:
    return stamp_outbound(
        zone="email-agent",
        agent_identity="email-agent",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=turn_tainted,
        event_id="conf-1234",
        principal="example-agent",
        payload={"signal": "buy", "ticker": "ACME"},
        ts=_TS,
        expiry=_EXPIRY,
        inbound=inbound,
        ingested_sources=ingested_sources,
    )


def _inbound_untrusted() -> EventTrigger:
    """A received envelope whose origin is an untrusted email (the driving case)."""
    return EventTrigger(
        event_id="upstream-1",
        principal="email-agent",
        sender={"channel_type": "email", "channel_identity": "example-vendor.com", "evidence": ["dkim:pass"]},
        payload={"raw": "trade confirmation"},
        provenance=[
            {"zone": "email-airlock", "source": "email:example-vendor.com", "evidence": ["dkim:pass"],
             "label": "untrusted", "ts": _TS},
        ],
        ts=_TS,
        expiry=_EXPIRY,
    )


# ---------------------------------------------------------------------------
# P2 — peer.publish is an external write; a tainted turn's publish escalates
# ---------------------------------------------------------------------------

def _peer_call(*, tainted: bool) -> BrokeredCall:
    entry = CATALOG_TABLE.entry("peer", "publish")
    assert entry is not None, "no manifest entry for peer.publish"
    sources = ["email:example-vendor.com"] if tainted else []
    return BrokeredCall(
        principal=PRINCIPAL,
        tool="peer",
        op="publish",
        args={"event_id": "e", "principal": "example-agent", "payload": {}},
        manifest=entry,
        taint=Taint(tainted=tainted, sources=sources),
        session=Session(turnId="t", ingestedSources=sources),
        ts="2026-07-09T00:00:00Z",
    )


class TestPeerPublishIsExternalWrite:
    def test_manifest_entry_is_external_write(self) -> None:
        entry = CATALOG_TABLE.entry("peer", "publish")
        assert entry is not None
        assert entry.external is True
        assert entry.effect == "write"
        # bounded-blast, not irreversible → does not force approval on EVERY call
        assert entry.reversible is True

    def test_tainted_turn_publish_escalates(self) -> None:
        # Out-of-loop grant: an UNTAINTED write would be autonomous — so an escalation
        # here is attributable to taint alone, not to the grant rung.
        call = _peer_call(tainted=True)
        facts = make_pip(grant_level=AutonomyLevel.out_of_loop)(call)
        assert decide(call, facts).kind == "require_approval"

    def test_untainted_publish_is_allowed_autonomously(self) -> None:
        call = _peer_call(tainted=False)
        facts = make_pip(grant_level=AutonomyLevel.out_of_loop)(call)
        assert decide(call, facts).kind == "allow"


# ---------------------------------------------------------------------------
# P3 — provenance is broker-stamped and taint-preserving
# ---------------------------------------------------------------------------

class TestOutboundProvenanceIsBrokerStamped:
    def test_tainted_turn_yields_untrusted_chain(self) -> None:
        env = _outbound(turn_tainted=True)
        assert env.tainted is True
        assert env.provenance[-1].label == "untrusted"
        assert env.provenance[-1].source == "peer:email-agent"

    def test_untainted_turn_yields_trusted_hop(self) -> None:
        env = _outbound(turn_tainted=False)
        assert env.tainted is False
        assert env.provenance[-1].label == "trusted"

    def test_relay_appends_and_preserves_upstream(self) -> None:
        # Relaying an inbound untrusted email onward: the upstream untrusted entry
        # rides through unchanged, this zone's hop is appended, and the derived
        # taint stays true regardless of this hop's label.
        inbound = _inbound_untrusted()
        env = _outbound(turn_tainted=True, inbound=inbound)
        assert [e.source for e in env.provenance] == ["email:example-vendor.com", "peer:email-agent"]
        assert env.provenance[0].label == "untrusted"  # upstream unedited
        assert env.tainted is True

    def test_stamp_outbound_has_no_agent_label_parameter(self) -> None:
        # The label is a deterministic function of turn_tainted alone: there is no
        # way for a caller to assert it. A tainted turn is ALWAYS untrusted.
        import inspect

        params = inspect.signature(stamp_outbound).parameters
        assert "label" not in params
        assert "turn_tainted" in params


# ---------------------------------------------------------------------------
# P3 (lineage) — ingested sources ride the chain, not a collapsed taint bit (#168)
# ---------------------------------------------------------------------------

class TestOutboundCarriesIngestedSources:
    def test_fresh_origination_carries_real_source_as_origin_hop(self) -> None:
        # The lineage-collapse fix (PTC §8): a turn that read connector:mcp-news
        # carries that real source as an untrusted origin hop AHEAD of the peer
        # hop — not a bare taint boolean on peer:email-agent.
        env = _outbound(turn_tainted=True, ingested_sources=["connector:mcp-news"])
        assert [e.source for e in env.provenance] == ["connector:mcp-news", "peer:email-agent"]
        assert env.provenance[0].label == "untrusted"
        assert env.tainted is True

    def test_multiple_ingested_sources_each_carried(self) -> None:
        env = _outbound(
            turn_tainted=True,
            ingested_sources=["connector:mcp-news", "search:tavily"],
        )
        assert [e.source for e in env.provenance] == [
            "connector:mcp-news",
            "search:tavily",
            "peer:email-agent",
        ]

    def test_no_ingested_sources_is_backward_compatible(self) -> None:
        # Omitting ingested_sources preserves the prior single-hop shape.
        env = _outbound(turn_tainted=True)
        assert [e.source for e in env.provenance] == ["peer:email-agent"]

    def test_relay_does_not_duplicate_sources_already_in_chain(self) -> None:
        # A relaying turn ingests the inbound chain's sources; carrying them again
        # would duplicate. The upstream entry already carries the lineage.
        inbound = _inbound_untrusted()  # origin: email:example-vendor.com
        env = _outbound(
            turn_tainted=True,
            inbound=inbound,
            ingested_sources=["email:example-vendor.com", "connector:mcp-news"],
        )
        assert [e.source for e in env.provenance] == [
            "email:example-vendor.com",  # upstream, unedited — not re-added
            "connector:mcp-news",  # fresh local read, carried
            "peer:email-agent",
        ]

    def test_receiver_rederives_taint_from_real_source(self) -> None:
        # End-to-end: the receiver feeds the carried origin source through its OWN
        # trust map. It sees connector:mcp-news (the true origin), not peer:*.
        from safe_agents.broker.taint.context import TurnContext
        from safe_agents.channels.trust_map import ingest_chain

        env = _outbound(turn_tainted=True, ingested_sources=["connector:mcp-news"])
        ctx = TurnContext(turn_id="receiver-turn")
        # Receiver trusts nothing here → the untrusted origin hop taints its turn.
        ingest_chain(env, ctx, lambda source: False)
        assert ctx.tainted is True
        assert "connector:mcp-news" in ctx.to_taint().sources


# ---------------------------------------------------------------------------
# P4 — the agent authors intent, not identity
# ---------------------------------------------------------------------------

class TestAgentAuthorsIntentNotIdentity:
    def test_sender_is_broker_set_transport_identity(self) -> None:
        env = _outbound(turn_tainted=False)
        # The wire carries the TRANSPORT channel_type (matches the receiver adapter)
        # and the identity the receiver's trust map keys on — never a sender_class.
        assert env.sender.channel_type == "webhook"
        assert env.sender.channel_identity == "peer:example"

    def test_sender_class_absent_on_the_wire(self) -> None:
        # Receiver-owned (SCHEMAS C4): the sender never asserts its own class.
        env = _outbound(turn_tainted=False)
        assert env.sender_class is None
