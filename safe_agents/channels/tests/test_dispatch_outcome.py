"""What the sender is told: the refusal class `dispatch_outcome` returns.

channels/ADAPTERS.md §"What the sender is told" is the contract. A sender that
passed gate 1 with a credential bound to it (`credential_per_sender`) and whose
gate-2 identity is in the trust map learns whether a refusal before the screen
is `permanent` or `transient`; every other sender, and every screen refusal and
replay, learns nothing (`refusal` is None). A transient
refusal is recorded `not_evaluated` and is given only before the dedupe key is
claimed. The transport binding that turns this into a response body is proven in
`test_airlock_handler.py`.
"""

from datetime import datetime
from typing import Any

import pytest

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.dispatch import (
    DispatchOutcome,
    KeySourceUnavailable,
    dispatch,
    dispatch_outcome,
)
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.signing import (
    SIGNATURE_INVALID,
    SIGNATURE_MISSING,
    SIGNER_UNKNOWN,
    ChainVerifyResult,
)
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry

_TS = "2026-07-08T00:00:00+00:00"
_EXPIRY = "2026-07-08T01:00:00+00:00"
_EXPIRED = "2026-07-07T23:00:00+00:00"
_NOW = datetime.fromisoformat(_TS)
_ZONE = "test-zone"
_CHANNEL = "stub-channel"
_IDENTITY = "stub:identity"
_PRINCIPAL = "test-principal"


def _envelope(**overrides: Any) -> EventTrigger:
    base = {
        "event_id": "evt-1",
        "principal": _PRINCIPAL,
        "audience": _ZONE,
        "sender": {"channel_type": _CHANNEL, "channel_identity": _IDENTITY, "evidence": []},
        "payload": {"key": "value"},
        "provenance": [
            {"zone": "peer", "source": "internal:test", "evidence": [], "label": "trusted", "ts": _TS}
        ],
        "ts": _TS,
        "expiry": _EXPIRY,
    }
    base.update(overrides)
    return EventTrigger.model_validate(base)


class _Adapter(InboundAdapter):
    channel_type = _CHANNEL

    def __init__(
        self,
        envelope: EventTrigger | None = None,
        *,
        verify: bool = True,
        identity: str = _IDENTITY,
        identity_raises: bool = False,
        normalize_raises: bool = False,
        originates_envelope: bool = False,
        credential_per_sender: bool = True,
    ) -> None:
        self._envelope = envelope
        self._verify = verify
        self._identity = identity
        self._identity_raises = identity_raises
        self._normalize_raises = normalize_raises
        self.originates_envelope = originates_envelope
        self.credential_per_sender = credential_per_sender

    def verify_token(self, request: Any) -> bool:
        return self._verify

    def extract_identity(self, request: Any) -> str:
        if self._identity_raises:
            raise ValueError("no identity")
        return self._identity

    def normalize(self, request: Any) -> EventTrigger:
        if self._normalize_raises:
            raise ValueError("bad payload")
        assert self._envelope is not None
        return self._envelope


class _CountingTrustMap(ChannelTrustMap):
    """A trust map that counts how many times resolve() was consulted."""

    resolves: int = 0

    def resolve(self, channel_type: str, channel_identity: str):
        object.__setattr__(self, "resolves", self.resolves + 1)
        return super().resolve(channel_type, channel_identity)


def _trust_map(*, mapped: bool) -> ChannelTrustMap:
    if not mapped:
        return _CountingTrustMap(entries=[])
    return _CountingTrustMap(
        entries=[
            TrustMapEntry(
                channel_type=_CHANNEL,
                channel_identity=_IDENTITY,
                principal=_PRINCIPAL,
                sender_class="peer-agent",
            )
        ]
    )


def _failing_verify(reason: str):
    return lambda envelope: ChainVerifyResult(ok=False, reason=reason)


def _passing_verify(envelope: EventTrigger) -> ChainVerifyResult:
    return ChainVerifyResult(ok=True, signer_key_id="broker:A", signer_zone="peer")


def _keys_unavailable(envelope: EventTrigger) -> ChainVerifyResult:
    raise KeySourceUnavailable


def _run(
    adapter: InboundAdapter,
    *,
    mapped: bool = True,
    verify_chain=None,
    screen=None,
    dedupe_store: Any = None,
    trust_map: ChannelTrustMap | None = None,
) -> tuple[DispatchOutcome, list, Any]:
    drops: list = []
    store = set() if dedupe_store is None else dedupe_store
    outcome = dispatch_outcome(
        "request",
        adapter=adapter,
        trust_map=_trust_map(mapped=mapped) if trust_map is None else trust_map,
        screen=screen,
        verify_chain=verify_chain,
        dedupe_store=store,
        drops=drops,
        now=_NOW,
        zone=_ZONE,
    )
    return outcome, drops, store


# Every refusal before the screen that the airlock evaluates. Toward a mapped
# sender each is permanent; toward the same identity unmapped, each is told
# nothing. Gate 5's two arms record `unmapped` for the unmapped identity.
_PRE_SCREEN_REFUSALS = [
    pytest.param(
        lambda: _Adapter(normalize_raises=True), None, ("malformed", None), id="malformed"
    ),
    pytest.param(
        lambda: _Adapter(_envelope(payload={"v": float("nan")})),
        None,
        ("malformed", "not_forwardable"),
        id="not-forwardable",
    ),
    pytest.param(
        lambda: _Adapter(
            _envelope(
                sender={"channel_type": _CHANNEL, "channel_identity": "other", "evidence": []}
            )
        ),
        None,
        ("malformed", "sender_identity_mismatch"),
        id="sender-identity-mismatch",
    ),
    pytest.param(
        lambda: _Adapter(_envelope(audience="another-zone")),
        None,
        ("audience_mismatch", None),
        id="audience-mismatch",
    ),
    pytest.param(
        lambda: _Adapter(_envelope()),
        _failing_verify(SIGNATURE_MISSING),
        (SIGNATURE_MISSING, None),
        id="chain-signature-missing",
    ),
    pytest.param(
        lambda: _Adapter(_envelope()),
        _failing_verify(SIGNATURE_INVALID),
        (SIGNATURE_INVALID, None),
        id="chain-signature-invalid",
    ),
    pytest.param(
        lambda: _Adapter(_envelope()),
        _failing_verify(SIGNER_UNKNOWN),
        (SIGNER_UNKNOWN, None),
        id="chain-signer-unknown",
    ),
    pytest.param(
        lambda: _Adapter(_envelope(expiry=_EXPIRED)), None, ("expired", None), id="expired"
    ),
    pytest.param(
        lambda: _Adapter(_envelope(principal="someone-else")),
        None,
        ("principal_mismatch", None),
        id="principal-mismatch",
    ),
]


@pytest.mark.parametrize("make_adapter,verify_chain,record", _PRE_SCREEN_REFUSALS)
def test_a_mapped_sender_is_told_a_pre_screen_refusal_is_permanent(
    make_adapter, verify_chain, record
):
    outcome, drops, store = _run(make_adapter(), verify_chain=verify_chain)

    assert outcome == DispatchOutcome(None, "permanent")
    assert [(d.reason, d.detail) for d in drops] == [record]
    assert store == set()


@pytest.mark.parametrize("make_adapter,verify_chain,record", _PRE_SCREEN_REFUSALS)
def test_an_unmapped_sender_is_told_nothing_about_the_same_refusal(
    make_adapter, verify_chain, record
):
    outcome, drops, _ = _run(make_adapter(), mapped=False, verify_chain=verify_chain)

    assert outcome == DispatchOutcome(None, None)
    reason, detail = record
    if reason == "principal_mismatch":
        # Gate 5 cannot get as far as the principal for an unmapped identity.
        reason = "unmapped"
    assert [(d.reason, d.detail) for d in drops] == [(reason, detail)]


# The same refusals, plus the two transient ones, from a mapped identity behind an
# adapter whose gate-1 credential is shared across senders. Gate 1 does not say
# who sent the request, so the identity is a claim and nothing is told.
_SHARED_CREDENTIAL_REFUSALS = _PRE_SCREEN_REFUSALS + [
    pytest.param(
        lambda: _Adapter(_envelope()),
        _keys_unavailable,
        ("not_evaluated", "key_source"),
        id="keys-unavailable",
    ),
]


@pytest.mark.parametrize("make_adapter,verify_chain,record", _SHARED_CREDENTIAL_REFUSALS)
def test_a_mapped_sender_behind_a_shared_credential_is_told_nothing(
    make_adapter, verify_chain, record
):
    adapter = make_adapter()
    adapter.credential_per_sender = False

    outcome, drops, store = _run(adapter, verify_chain=verify_chain)

    assert outcome == DispatchOutcome(None, None)
    # The record is what happened, as it is for a sender that is told.
    assert [(d.reason, d.detail) for d in drops] == [record]
    assert store == set()


def test_a_dedupe_store_failure_behind_a_shared_credential_is_told_nothing():
    outcome, drops, _ = _run(
        _Adapter(_envelope(), credential_per_sender=False),
        dedupe_store=_DownStore(fail_on="read"),
    )
    assert outcome == DispatchOutcome(None, None)
    assert [(d.reason, d.detail) for d in drops] == [("not_evaluated", "dedupe_store")]


@pytest.mark.parametrize("flag", [None, 1, "yes"], ids=["interface-default", "truthy-int", "truthy-str"])
def test_only_an_adapter_that_says_true_is_told_anything(flag):
    """`credential_per_sender` must be exactly True. An adapter that keeps the
    interface default, or declares something merely truthy, is told nothing."""
    adapter = _Adapter(normalize_raises=True)
    if flag is None:
        del adapter.credential_per_sender  # falls back to the interface's default
        assert adapter.credential_per_sender is False
    else:
        adapter.credential_per_sender = flag

    outcome, drops, _ = _run(adapter)

    assert outcome == DispatchOutcome(None, None)
    assert [d.reason for d in drops] == ["malformed"]


@pytest.mark.parametrize("per_sender,lookups", [(True, 1), (False, 0)])
def test_the_mapped_lookup_is_made_only_for_a_per_sender_credential(per_sender, lookups):
    """A refusal before gate 5: the only trust-map lookup is the one after gate 2
    that decides what the sender is told, and it is not made when nothing will
    be told."""
    trust_map = _trust_map(mapped=True)
    _run(
        _Adapter(_envelope(audience="another-zone"), credential_per_sender=per_sender),
        trust_map=trust_map,
    )
    assert trust_map.resolves == lookups


def test_an_unmapped_drop_after_a_verified_chain_carries_the_check_that_happened():
    # Gate 3.5 runs before gate 5, so the `unmapped` record carries the
    # verification it passed, the same as every other record past 3.5.
    outcome, drops, store = _run(
        _Adapter(_envelope()), mapped=False, verify_chain=_passing_verify
    )

    assert outcome == DispatchOutcome(None, None)
    assert [(d.reason, d.chain_verified, d.signer_key_id) for d in drops] == [
        ("unmapped", True, "broker:A")
    ]
    assert store == set()


@pytest.mark.parametrize(
    "adapter",
    [
        pytest.param(_Adapter(_envelope(), verify=False), id="authenticity-failed"),
        pytest.param(_Adapter(_envelope(), identity_raises=True), id="no-identity"),
    ],
)
def test_a_sender_that_never_reached_the_trust_map_lookup_is_told_nothing(adapter):
    # The identity the adapter would report is mapped; the request never got
    # far enough for that to count.
    outcome, drops, _ = _run(adapter)
    assert outcome == DispatchOutcome(None, None)
    assert len(drops) == 1


@pytest.mark.parametrize(
    "screen,detail",
    [
        pytest.param(lambda envelope: False, None, id="screen-refused"),
        pytest.param(lambda envelope: 1 / 0, "screen_error", id="screen-error"),
    ],
)
def test_a_screen_refusal_reads_as_an_acceptance_and_is_dedupe_marked(screen, detail):
    envelope = _envelope()
    outcome, drops, store = _run(_Adapter(envelope), screen=screen)

    assert outcome == DispatchOutcome(None, None)
    assert [(d.reason, d.detail) for d in drops] == [("screen_refused", detail)]
    assert store == {envelope.dedupe_key()}


def test_a_replay_is_told_nothing():
    envelope = _envelope()
    store = {envelope.dedupe_key()}
    outcome, drops, _ = _run(_Adapter(envelope), dedupe_store=store)
    assert outcome == DispatchOutcome(None, None)
    assert drops == []


def test_an_acceptance_carries_no_refusal_and_dispatch_returns_the_same_envelope():
    envelope = _envelope()
    outcome, drops, _ = _run(_Adapter(envelope))
    assert outcome.envelope is not None and outcome.refusal is None
    assert drops == []

    again = dispatch(
        "request",
        adapter=_Adapter(envelope),
        trust_map=_trust_map(mapped=True),
        screen=None,
        dedupe_store=set(),
        drops=[],
        now=_NOW,
        zone=_ZONE,
    )
    assert again == outcome.envelope


# ---------------------------------------------------------------------------
# Transient: a fetched input the airlock needed was unavailable
# ---------------------------------------------------------------------------


def test_keys_unavailable_is_transient_toward_a_mapped_sender_and_claims_nothing():
    outcome, drops, store = _run(_Adapter(_envelope()), verify_chain=_keys_unavailable)

    assert outcome == DispatchOutcome(None, "transient")
    assert [(d.reason, d.detail, d.chain_verified) for d in drops] == [
        ("not_evaluated", "key_source", False)
    ]
    assert store == set()


def test_keys_unavailable_tells_an_unmapped_sender_nothing_and_records_what_happened():
    outcome, drops, store = _run(
        _Adapter(_envelope()), mapped=False, verify_chain=_keys_unavailable
    )

    assert outcome == DispatchOutcome(None, None)
    # Gate 3.5 runs before gate 5, so the record is what happened at 3.5.
    assert [(d.reason, d.detail) for d in drops] == [("not_evaluated", "key_source")]
    assert store == set()


def test_keys_unavailable_does_not_touch_an_adapter_that_originates_its_envelope():
    outcome, drops, _ = _run(
        _Adapter(_envelope(), originates_envelope=True), verify_chain=_keys_unavailable
    )
    assert outcome.envelope is not None and outcome.refusal is None
    assert drops == []


def test_keys_unavailable_still_runs_the_gates_before_verification():
    outcome, drops, _ = _run(
        _Adapter(_envelope(audience="another-zone")), verify_chain=_keys_unavailable
    )
    assert outcome == DispatchOutcome(None, "permanent")
    assert [d.reason for d in drops] == ["audience_mismatch"]


def test_any_other_verify_failure_is_not_read_as_an_unavailable_key_source():
    def broken(envelope: EventTrigger) -> ChainVerifyResult:
        raise RuntimeError("a bug in the seam")

    with pytest.raises(RuntimeError):
        _run(_Adapter(_envelope()), verify_chain=broken)


class _DownStore:
    """A dedupe store whose read or write fails, holding nothing either way."""

    def __init__(self, *, fail_on: str) -> None:
        self.fail_on = fail_on
        self.keys: set = set()

    def __contains__(self, key: Any) -> bool:
        if self.fail_on == "read":
            raise ConnectionError("store unreachable")
        return key in self.keys

    def add(self, key: Any) -> None:
        if self.fail_on == "write":
            raise ConnectionError("store unreachable")
        self.keys.add(key)


@pytest.mark.parametrize("fail_on", ["read", "write"])
def test_a_dedupe_store_failure_is_transient_and_claims_nothing(fail_on):
    store = _DownStore(fail_on=fail_on)
    screen_calls: list = []

    def screen(envelope: EventTrigger) -> bool:
        screen_calls.append(envelope)
        return True

    outcome, drops, _ = _run(
        _Adapter(_envelope()), verify_chain=_passing_verify, screen=screen, dedupe_store=store
    )

    assert outcome == DispatchOutcome(None, "transient")
    # Past gate 3.5, so the record carries the check that did happen.
    assert [(d.reason, d.detail, d.chain_verified, d.signer_key_id) for d in drops] == [
        ("not_evaluated", "dedupe_store", True, "broker:A")
    ]
    assert store.keys == set()
    assert screen_calls == []
