"""sa#43 exit predicate — the injection-screen conformance suite.

Each test proves one clause from channels/SCREENING.md §Conformance; the
mapping table lives there.
"""

import pytest
from pydantic import ValidationError

from safe_agents.channels.dispatch import dispatch
from safe_agents.channels.screening import SCREEN_ERROR, ScreenRecord, ScreenVerdict, make_screen_record
from safe_agents.channels.tests.test_adapters import (
    _NOW,
    StubInboundAdapter,
    _digest,
    _envelope,
    _provenance_entry,
)
from safe_agents.channels.trust_map import ChannelTrustMap, DropRecord, TrustMapEntry, make_drop_record

_TS = "2026-07-08T00:00:00+00:00"


def _trust_map_for(identity: str, *, sender_class: str = "owner") -> ChannelTrustMap:
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


@pytest.mark.parametrize("bad_reason", ["has spaces", "Uppercase", "a" * 65, ""])
def test_refusing_requires_machine_code_reason(bad_reason):
    with pytest.raises(ValidationError):
        ScreenVerdict.refusing(bad_reason)

    assert ScreenVerdict.refusing("injection_suspected").reason == "injection_suspected"


def test_pass_is_contentless():
    with pytest.raises(ValidationError):
        ScreenVerdict(passed=True, reason="should_not_be_here")

    verdict = ScreenVerdict.passing()
    assert verdict.reason is None
    assert bool(verdict) is True
    assert bool(ScreenVerdict.refusing("injection_suspected")) is False


def test_verdict_refusal_drops_with_detail():
    identity = "chat:refused-verdict-1"
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    drops = []

    result = dispatch(
        "request",
        adapter=adapter,
        trust_map=_trust_map_for(identity),
        screen=lambda e: ScreenVerdict.refusing("injection_suspected"),
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )

    assert result is None
    assert len(drops) == 1
    assert drops[0].reason == "screen_refused"
    assert drops[0].detail == "injection_suspected"


def test_bool_screen_remains_conformant():
    identity = "chat:bool-screen-1"
    trust_map = _trust_map_for(identity)
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    drops = []

    refused = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=trust_map,
        screen=lambda e: False,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )
    assert refused is None
    assert drops[0].reason == "screen_refused"
    assert drops[0].detail is None

    passed = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=trust_map,
        screen=lambda e: True,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )
    assert passed is not None


def test_raising_screen_fails_closed():
    identity = "chat:raising-screen-1"
    trust_map = _trust_map_for(identity)
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )
    adapter = StubInboundAdapter(identity=identity, envelope=envelope)
    calls = []

    def raising_screen(e):
        calls.append(e)
        raise RuntimeError("boom")

    dedupe_store: set = set()
    drops = []

    first = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=raising_screen,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )
    assert first is None
    assert len(drops) == 1
    assert drops[0].reason == "screen_refused"
    assert drops[0].detail == SCREEN_ERROR
    assert envelope.dedupe_key() in dedupe_store
    assert len(calls) == 1

    second = dispatch(
        "request",
        adapter=adapter,
        trust_map=trust_map,
        screen=raising_screen,
        dedupe_store=dedupe_store,
        drops=drops,
        now=_NOW,
        zone="test-zone",
    )
    assert second is None
    # A dedupe hit is a silent no-op — the screen is never re-invoked and no
    # new drop is recorded for the replay.
    assert len(calls) == 1
    assert len(drops) == 1


def test_verdict_sink_records_pass_and_refuse():
    passing_identity = "chat:sink-pass-1"
    passing_envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": passing_identity, "evidence": []},
    )
    verdicts = []

    result = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=passing_identity, envelope=passing_envelope),
        trust_map=_trust_map_for(passing_identity),
        screen=lambda e: ScreenVerdict.passing(),
        verdicts=verdicts,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )
    assert result is not None
    assert len(verdicts) == 1
    assert verdicts[0].passed is True
    assert verdicts[0].reason is None
    assert verdicts[0].identity_digest == _digest(passing_identity)
    assert verdicts[0].event_id == passing_envelope.event_id

    refusing_identity = "chat:sink-refuse-1"
    refusing_envelope = _envelope(
        event_id="evt-refuse",
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": refusing_identity, "evidence": []},
    )
    verdicts2 = []

    dispatch(
        "request",
        adapter=StubInboundAdapter(identity=refusing_identity, envelope=refusing_envelope),
        trust_map=_trust_map_for(refusing_identity),
        screen=lambda e: ScreenVerdict.refusing("injection_suspected"),
        verdicts=verdicts2,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )
    assert len(verdicts2) == 1
    assert verdicts2[0].passed is False
    assert verdicts2[0].reason == "injection_suspected"
    assert verdicts2[0].event_id == "evt-refuse"


def test_verdict_sink_ships_off_and_null_screen_appends_nothing():
    identity = "chat:sink-off-1"
    trust_map = _trust_map_for(identity)
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
    )

    # Default: `verdicts` not passed at all — dispatch works unchanged.
    result = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=trust_map,
        screen=lambda e: True,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )
    assert result is not None

    # verdicts=[] explicit but screen=None: sink stays empty, envelope still emits.
    verdicts = []
    result2 = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=trust_map,
        screen=None,
        verdicts=verdicts,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )
    assert result2 is not None
    assert verdicts == []


def test_pass_never_blesses_taint():
    identity = "chat:tainted-pass-1"
    envelope = _envelope(
        principal="test-principal",
        sender={"channel_type": "stub-channel", "channel_identity": identity, "evidence": []},
        provenance=[_provenance_entry(source="email:example.test", label="untrusted")],
    )

    result = dispatch(
        "request",
        adapter=StubInboundAdapter(identity=identity, envelope=envelope),
        trust_map=_trust_map_for(identity),
        screen=lambda e: ScreenVerdict.passing(),
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone="test-zone",
    )
    assert result is not None
    assert result.tainted is True


def test_drop_record_detail_is_validated():
    record = make_drop_record("stub-channel", "chat:x", "screen_refused", _TS, detail="screen_error")
    assert record.detail == "screen_error"

    default_record = make_drop_record("stub-channel", "chat:x", "unmapped", _TS)
    assert default_record.detail is None

    with pytest.raises(ValidationError):
        DropRecord(
            channel_type="stub-channel",
            identity_digest=_digest("chat:x"),
            reason="screen_refused",
            ts=_TS,
            detail="Not A Code!",
        )


# ---------------------------------------------------------------------------
# sa#161 Phase A1 — evidence-of-check fields on ScreenRecord
# ---------------------------------------------------------------------------


def test_screen_record_evidence_of_check_defaults_and_round_trips():
    record = make_screen_record("stub-channel", "chat:x", "evt-1", True, None, _TS)
    assert record.chain_verified is False
    assert record.signer_key_id is None

    verified = make_screen_record(
        "stub-channel",
        "chat:x",
        "evt-1",
        True,
        None,
        _TS,
        chain_verified=True,
        signer_key_id="broker:A",
    )
    assert verified.chain_verified is True
    assert verified.signer_key_id == "broker:A"

    # Pre-existing S3-stored ScreenRecord JSON lacks these fields entirely —
    # the default must apply on model_validate.
    legacy_json = record.model_dump_json(exclude={"chain_verified", "signer_key_id"})
    reloaded = ScreenRecord.model_validate_json(legacy_json)
    assert reloaded.chain_verified is False
    assert reloaded.signer_key_id is None


def test_screen_record_refuses_signer_without_verified_chain():
    with pytest.raises(ValidationError):
        ScreenRecord(
            channel_type="stub-channel",
            identity_digest=_digest("chat:x"),
            event_id="evt-1",
            passed=True,
            reason=None,
            ts=_TS,
            chain_verified=False,
            signer_key_id="broker:A",
        )
