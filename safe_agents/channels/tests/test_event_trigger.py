"""sa#74 exit predicate — the EventTrigger conformance suite.

Each test proves one contract clause from channels/SCHEMAS.md §"Contract
clauses"; the mapping table lives there. test_driving_use_case_fixture_roundtrips
is the sa#8 fixture (email-agent → example-agent trade signal).
"""

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from safe_agents.broker.taint.context import TurnContext
from safe_agents.broker.taint.propagation import build_trust_map
from safe_agents.channels.schemas import MAX_PAYLOAD_BYTES, EventTrigger, ProvenanceEntry, SenderIdentity

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


def test_dedupe_key_is_stable_and_sender_scoped():
    envelope = _envelope(event_id="evt-1")
    assert envelope.dedupe_key() == ("chat:12345", "evt-1")

    other_sender = _envelope(
        event_id="evt-1",
        sender={"channel_type": "telegram", "channel_identity": "chat:99999", "evidence": []},
    )
    assert envelope.dedupe_key() != other_sender.dedupe_key()

    replay = _envelope(event_id="evt-1")
    assert envelope.dedupe_key() == replay.dedupe_key()


def test_payload_over_cap_is_rejected():
    huge_payload = {"blob": "x" * (MAX_PAYLOAD_BYTES + 1)}
    with pytest.raises(ValidationError):
        _envelope(payload=huge_payload)


def test_payload_ref_requires_digest():
    with pytest.raises(ValidationError):
        _envelope(payload_ref="airlock-raw:msg-1", payload_digest=None)

    envelope = _envelope(payload_ref="airlock-raw:msg-1", payload_digest="sha256:" + "a" * 64)
    assert envelope.payload_ref == "airlock-raw:msg-1"


@pytest.mark.parametrize(
    "digest, valid",
    [
        ("sha256:" + "a" * 64, True),
        ("sha256:" + "A" * 64, False),  # uppercase hex rejected
        ("sha256:" + "a" * 63, False),  # too short
        ("sha1:" + "a" * 64, False),  # wrong scheme
        ("not-a-digest", False),
    ],
)
def test_digest_format_is_sha256_hex(digest, valid):
    if valid:
        assert _envelope(payload_digest=digest).payload_digest == digest
    else:
        with pytest.raises(ValidationError):
            _envelope(payload_digest=digest)


def test_no_writable_taint_field():
    with pytest.raises(ValidationError):
        _envelope(tainted=True)
    with pytest.raises(ValidationError):
        _envelope(taint=True)

    envelope = _envelope()
    with pytest.raises(Exception):
        envelope.tainted = True


def test_taint_derives_from_chain():
    all_trusted = _envelope(provenance=[_provenance_entry(label="trusted")])
    assert all_trusted.tainted is False

    mixed = _envelope(
        provenance=[
            _provenance_entry(label="trusted"),
            _provenance_entry(zone="zone-2", source="email:example-vendor.com", label="untrusted"),
        ]
    )
    assert mixed.tainted is True


def test_stamped_appends_and_originals_are_frozen():
    original = _envelope()
    new_entry = ProvenanceEntry(
        **_provenance_entry(zone="zone-2", source="email:example-vendor.com", label="untrusted")
    )

    stamped = original.stamped(new_entry)
    assert len(stamped.provenance) == len(original.provenance) + 1
    assert len(original.provenance) == 1

    with pytest.raises(ValidationError):
        original.provenance = []

    with_class = original.stamped(new_entry, sender_class="peer-agent")
    assert with_class.sender_class == "peer-agent"

    kept = with_class.stamped(new_entry)
    assert kept.sender_class == "peer-agent"


def test_empty_provenance_is_rejected():
    with pytest.raises(ValidationError):
        _envelope(provenance=[])


def test_sender_class_defaults_none_on_the_wire():
    envelope = _envelope()
    assert envelope.sender_class is None
    dumped = json.loads(envelope.model_dump_json())
    assert dumped["sender_class"] is None


@pytest.mark.parametrize(
    "source, valid",
    [
        ("email:example-vendor.com", True),
        ("example-vendor", False),
        (":x", False),
        ("x:", False),
    ],
)
def test_provenance_source_must_be_namespaced(source, valid):
    if valid:
        assert ProvenanceEntry(**_provenance_entry(source=source)).source == source
    else:
        with pytest.raises(ValidationError):
            ProvenanceEntry(**_provenance_entry(source=source))


def test_expired_envelope_is_detected_deterministically():
    envelope = _envelope(expiry=_EXPIRY)

    before = datetime(2026, 7, 8, 0, 30, tzinfo=timezone.utc)
    after = datetime(2026, 7, 8, 2, 0, tzinfo=timezone.utc)
    assert envelope.is_expired(before) is False
    assert envelope.is_expired(after) is True

    naive_now = datetime(2026, 7, 8, 2, 0)
    with pytest.raises(ValueError):
        envelope.is_expired(naive_now)


def test_provenance_sources_feed_turn_ingestion():
    """C5 bridge: every provenance source is ingested through the real
    TurnContext/InputTrustMap before the worker acts. The chain's own `label`
    and the receiver's trust-map judgment are distinct axes — the control
    below uses a source the RECEIVER trusts, not merely a `label: "trusted"`
    entry."""
    trust_map = build_trust_map(trusted_prefixes=["internal:"])

    tainted_envelope = _envelope(
        provenance=[_provenance_entry(source="email:example-vendor.com", label="untrusted")]
    )
    tainted_ctx = TurnContext(turn_id="t-tainted")
    for entry in tainted_envelope.provenance:
        tainted_ctx.ingest_source(entry.source, trust_map)
    assert tainted_ctx.tainted is True
    assert "email:example-vendor.com" in tainted_ctx.to_taint().sources

    trusted_envelope = _envelope(
        provenance=[_provenance_entry(source="internal:scheduler", label="trusted")]
    )
    trusted_ctx = TurnContext(turn_id="t-trusted")
    for entry in trusted_envelope.provenance:
        trusted_ctx.ingest_source(entry.source, trust_map)
    assert trusted_ctx.tainted is False


def test_driving_use_case_fixture_roundtrips():
    """sa#8: email-agent publishes a trade signal EventTrigger to example-agent."""
    envelope = EventTrigger(
        event_id="CONF-88317",
        principal="example-agent",
        sender=SenderIdentity(
            channel_type="peer-agent",
            channel_identity="peer:email-agent",
            evidence=["sig:pass"],
        ),
        payload={"symbol": "NVDA", "side": "buy", "qty": 10, "limit_price": 128.5},
        payload_digest="sha256:" + "b" * 64,
        payload_ref="airlock-raw:2026-07-08/example-vendor-9931.eml",
        provenance=[
            ProvenanceEntry(
                zone="email-agent",
                source="email:example-vendor.com",
                evidence=["dkim:pass", "spf:pass"],
                label="untrusted",
                ts=_TS,
            )
        ],
        ts=_TS,
        expiry=_EXPIRY,
    )

    round_tripped = EventTrigger.model_validate_json(envelope.model_dump_json())
    assert round_tripped == envelope
    assert envelope.tainted is True
