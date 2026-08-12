"""sa#81 exit predicate — the trust-mapping conformance suite.

Each test proves one clause from channels/TRUST-MAPPING.md §"Conformance";
the mapping table lives there.
"""

import hashlib

import pytest
from pydantic import ValidationError

from safe_agents.broker.taint.context import TurnContext
from safe_agents.broker.taint.propagation import build_trust_map
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.trust_map import (
    ChannelTrustMap,
    DropRecord,
    TrustMapEntry,
    TrustResolution,
    ingest_chain,
    make_drop_record,
    stamp_inbound,
)

_TS = "2026-07-08T00:00:00+00:00"
_EXPIRY = "2026-07-08T01:00:00+00:00"


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
            "channel_type": "telegram",
            "channel_identity": "chat:12345",
            "evidence": [],
        },
        "payload": {"key": "value"},
        "provenance": [_provenance_entry()],
        "ts": _TS,
        "expiry": _EXPIRY,
    }
    base.update(overrides)
    return EventTrigger.model_validate(base)


@pytest.mark.parametrize("sender_class", ["owner", "peer-agent", "external"])
def test_resolve_maps_each_sender_class(sender_class):
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="telegram",
                channel_identity="chat:12345",
                principal="test-principal",
                sender_class=sender_class,
            )
        ]
    )
    assert trust_map.resolve("telegram", "chat:12345") == TrustResolution(
        principal="test-principal", sender_class=sender_class
    )


def test_unmapped_identity_resolves_none():
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="telegram",
                channel_identity="chat:12345",
                principal="test-principal",
                sender_class="owner",
            )
        ]
    )
    assert trust_map.resolve("telegram", "chat:unknown") is None
    assert trust_map.resolve("peer-agent", "chat:12345") is None


def test_trust_map_config_validates():
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="telegram",
                channel_identity="chat:12345",
                principal="test-principal",
                sender_class="owner",
            ),
            TrustMapEntry(
                channel_type="peer-agent",
                channel_identity="peer:test-agent",
                principal="test-principal",
                sender_class="peer-agent",
            ),
        ]
    )
    assert len(trust_map.entries) == 2

    with pytest.raises(ValidationError):
        TrustMapEntry(
            channel_type="telegram",
            channel_identity="chat:12345",
            principal="test-principal",
            sender_class="owner",
            extra_field="not-in-the-contract",
        )


def test_duplicate_identity_keys_rejected():
    dup_kwargs = {
        "channel_type": "telegram",
        "channel_identity": "chat:12345",
        "principal": "test-principal",
        "sender_class": "owner",
    }
    with pytest.raises(ValidationError):
        ChannelTrustMap(
            entries=[
                TrustMapEntry(**dup_kwargs),
                TrustMapEntry(
                    **{**dup_kwargs, "principal": "other-principal", "sender_class": "external"}
                ),
            ]
        )

    # Same identity string under two different channel_types is allowed —
    # uniqueness is on the (channel_type, channel_identity) pair.
    trust_map = ChannelTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="telegram",
                channel_identity="shared-id",
                principal="test-principal",
                sender_class="owner",
            ),
            TrustMapEntry(
                channel_type="peer-agent",
                channel_identity="shared-id",
                principal="test-principal",
                sender_class="peer-agent",
            ),
        ]
    )
    assert len(trust_map.entries) == 2


def test_stamp_inbound_appends_receiver_entry():
    envelope = _envelope()
    resolution = TrustResolution(principal="test-principal", sender_class="owner")

    stamped = stamp_inbound(
        envelope,
        resolution,
        zone="receiver-zone",
        source="internal:receiver",
        evidence=["auth:pass"],
        ts=_TS,
    )

    assert len(stamped.provenance) == len(envelope.provenance) + 1
    assert stamped.provenance[:-1] == envelope.provenance
    assert len(envelope.provenance) == 1


def test_stamp_inbound_overwrites_wire_sender_class():
    envelope = _envelope(sender_class="owner")
    resolution = TrustResolution(principal="test-principal", sender_class="peer-agent")

    stamped = stamp_inbound(
        envelope,
        resolution,
        zone="receiver-zone",
        source="internal:receiver",
        evidence=[],
        ts=_TS,
    )

    assert stamped.sender_class == "peer-agent"


@pytest.mark.parametrize("sender_class", ["owner", "peer-agent"])
def test_authenticity_never_lowers_taint(sender_class):
    envelope = _envelope(
        provenance=[_provenance_entry(source="email:example.test", label="untrusted")]
    )
    resolution = TrustResolution(principal="test-principal", sender_class=sender_class)

    stamped = stamp_inbound(
        envelope,
        resolution,
        zone="receiver-zone",
        source="internal:receiver",
        evidence=[],
        ts=_TS,
    )

    assert stamped.tainted is True


def test_external_sender_stamp_taints():
    envelope = _envelope(provenance=[_provenance_entry(label="trusted")])
    resolution = TrustResolution(principal="test-principal", sender_class="external")

    stamped = stamp_inbound(
        envelope,
        resolution,
        zone="receiver-zone",
        source="internal:receiver",
        evidence=[],
        ts=_TS,
    )

    assert stamped.tainted is True


def test_sender_asserted_trusted_label_is_only_a_floor():
    """The anti-laundering test: the receiver's InputTrustMap is authoritative
    even when a chain hop's own label disagrees (TRUST-MAPPING.md §"The
    one-way rule", consequence 2)."""
    receiver_map = build_trust_map(trusted_prefixes=["internal:"])

    # (a) forged "trusted" label on a source the receiver distrusts -> tainted
    forged = _envelope(
        provenance=[_provenance_entry(source="email:example.test", label="trusted")]
    )
    forged_ctx = TurnContext(turn_id="t-forged")
    ingest_chain(forged, forged_ctx, receiver_map)
    assert forged_ctx.tainted is True

    # (b) honest "untrusted" label on a source the receiver would otherwise
    # trust -> the label floor still taints
    honest_untrusted = _envelope(
        provenance=[_provenance_entry(source="internal:scheduler", label="untrusted")]
    )
    honest_ctx = TurnContext(turn_id="t-honest")
    ingest_chain(honest_untrusted, honest_ctx, receiver_map)
    assert honest_ctx.tainted is True

    # (c) control: "trusted" label AND a source the receiver trusts -> clean
    control = _envelope(
        provenance=[_provenance_entry(source="internal:scheduler", label="trusted")]
    )
    control_ctx = TurnContext(turn_id="t-control")
    ingest_chain(control, control_ctx, receiver_map)
    assert control_ctx.tainted is False


def test_drop_record_digests_identity():
    raw_identity = "chat:super-secret-id"
    record = make_drop_record("telegram", raw_identity, "unmapped", _TS)

    expected_digest = "sha256:" + hashlib.sha256(raw_identity.encode("utf-8")).hexdigest()
    assert record.identity_digest == expected_digest
    assert raw_identity not in record.model_dump_json()
    assert raw_identity not in str(record.model_dump())

    with pytest.raises(ValidationError):
        DropRecord(
            channel_type="telegram",
            identity_digest="not-a-digest",
            reason="unmapped",
            ts=_TS,
        )


# ---------------------------------------------------------------------------
# sa#161 Phase A1 — evidence-of-check fields on DropRecord
# ---------------------------------------------------------------------------


def test_drop_record_evidence_of_check_defaults_and_round_trips():
    record = make_drop_record("telegram", "chat:x", "unmapped", _TS)
    assert record.chain_verified is False
    assert record.signer_key_id is None

    verified = make_drop_record(
        "telegram", "chat:x", "unmapped", _TS, chain_verified=True, signer_key_id="broker:A"
    )
    assert verified.chain_verified is True
    assert verified.signer_key_id == "broker:A"

    # Old records written before this field existed lack it entirely — the
    # default must apply on model_validate so pre-existing S3-stored JSON
    # still parses.
    legacy_json = record.model_dump_json(exclude={"chain_verified", "signer_key_id"})
    reloaded = DropRecord.model_validate_json(legacy_json)
    assert reloaded.chain_verified is False
    assert reloaded.signer_key_id is None


def test_drop_record_refuses_signer_without_verified_chain():
    with pytest.raises(ValidationError):
        DropRecord(
            channel_type="telegram",
            identity_digest=make_drop_record("telegram", "chat:x", "unmapped", _TS).identity_digest,
            reason="unmapped",
            ts=_TS,
            chain_verified=False,
            signer_key_id="broker:A",
        )
