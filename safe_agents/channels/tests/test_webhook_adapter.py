"""SignedWebhookAdapter conformance.

The webhook adapter is the concrete edge exercised by dispatch's gates 1-3:
per-sender, constant-time token verification (gate 1), the identity the
presented token is bound to (gate 2), and the schema check (gate 3, including
the channel_type-mismatch rejection). The webhook secret is an identity → token
map, refused at load when it is not one; the refusals are proven here too.
"""

import json
from datetime import datetime

import pytest

import safe_agents.channels.webhook as webhook_mod
from safe_agents.channels.dispatch import dispatch_outcome
from safe_agents.channels.manifest import WebhookAdapterConfig
from safe_agents.channels.schemas import EventTrigger
from safe_agents.channels.trust_map import ChannelTrustMap, TrustMapEntry
from safe_agents.channels.webhook import (
    TOKEN_MAP_SHAPE,
    SignedWebhookAdapter,
    WebhookRequest,
    WebhookTokenMapError,
    parse_token_map,
)

_TOKEN = "s3cr3t-token"
_OTHER_TOKEN = "an0ther-s3cr3t"
_IDENTITY = "peer:example"
_OTHER = "peer:other"
_TOKENS = {_IDENTITY: _TOKEN, _OTHER: _OTHER_TOKEN}
_TS = "2026-07-08T00:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"
_NOW = datetime.fromisoformat(_TS)
_ZONE = "example-airlock"


def _adapter(
    config: WebhookAdapterConfig | None = None, tokens: dict[str, str] | None = None
) -> SignedWebhookAdapter:
    return SignedWebhookAdapter(config or WebhookAdapterConfig(), _TOKENS if tokens is None else tokens)


def _req(body: str = "", token: str | None = _TOKEN, header_key: str = "x-airlock-token") -> WebhookRequest:
    headers = {} if token is None else {header_key: token}
    return WebhookRequest(headers=headers, body=body)


def _body(**overrides) -> str:
    env = {
        "event_id": "evt-1",
        "principal": "example-agent",
        "audience": _ZONE,
        "sender": {"channel_type": "webhook", "channel_identity": _IDENTITY, "evidence": []},
        "payload": {"k": "v"},
        "provenance": [
            {"zone": "peer", "source": _IDENTITY, "evidence": [], "label": "trusted", "ts": _TS}
        ],
        "ts": _TS,
        "expiry": _FUTURE,
    }
    env.update(overrides)
    return json.dumps(env)


def _claiming(identity: str) -> str:
    return _body(sender={"channel_type": "webhook", "channel_identity": identity, "evidence": []})


class _UnreadableBody:
    """A request whose body raises when read: gates 1 and 2 must not touch it."""

    def __init__(self, token: str | None) -> None:
        self.headers = {} if token is None else {"x-airlock-token": token}

    @property
    def body(self) -> str:
        raise AssertionError("the body was read before gate 3")


# --- gate 1: verify_token -------------------------------------------------

@pytest.mark.parametrize("token", [_TOKEN, _OTHER_TOKEN])
def test_verify_token_accepts_each_peers_own_token(token):
    assert _adapter().verify_token(_req(token=token)) is True


def test_verify_token_rejects_wrong_token():
    assert _adapter().verify_token(_req(token="not-the-token")) is False


def test_verify_token_rejects_missing_header():
    assert _adapter().verify_token(_req(token=None)) is False


@pytest.mark.parametrize(
    "presented",
    [
        pytest.param("café-token", id="non-ascii"),
        pytest.param("", id="empty"),
        pytest.param(12345, id="not-a-string"),
        pytest.param(None, id="none"),
        pytest.param(_TOKEN[:-1], id="prefix-all-but-last"),
        pytest.param(_TOKEN[:1], id="prefix-first-char"),
        pytest.param(_TOKEN.upper(), id="upper-cased"),
        pytest.param(_TOKEN + " ", id="trailing-space"),
        pytest.param("\ud800x", id="lone-surrogate"),
    ],
)
def test_verify_token_answers_false_for_any_other_header_value(presented):
    request = WebhookRequest(headers={"x-airlock-token": presented}, body="")
    assert _adapter().verify_token(request) is False


def test_verify_token_honors_configured_header_name():
    adapter = _adapter(WebhookAdapterConfig(token_header="x-custom-token"))
    assert adapter.verify_token(_req(token=_TOKEN, header_key="x-custom-token")) is True
    # Right token under the default header the adapter isn't looking at ⇒ missing ⇒ False.
    assert adapter.verify_token(_req(token=_TOKEN, header_key="x-airlock-token")) is False


@pytest.mark.parametrize("token,expected", [(_TOKEN, True), (_OTHER_TOKEN, True), ("wrong", False)])
def test_gates_1_and_2_never_read_the_body(token, expected):
    adapter = _adapter()
    request = _UnreadableBody(token)
    assert adapter.verify_token(request) is expected
    if expected:
        assert adapter.extract_identity(request) in _TOKENS


@pytest.mark.parametrize("presented", [_TOKEN, _OTHER_TOKEN, "wrong"])
def test_verify_token_compares_every_entry_whichever_matches(monkeypatch, presented):
    """No early exit: the number of comparisons does not depend on which entry,
    if any, the presented token matches."""
    compared: list[bytes] = []
    real = webhook_mod.hmac.compare_digest

    def counting(a, b):
        compared.append(b)
        return real(a, b)

    monkeypatch.setattr(webhook_mod.hmac, "compare_digest", counting)
    adapter = _adapter()

    adapter.verify_token(_req(token=presented))
    assert sorted(compared) == sorted(t.encode() for t in _TOKENS.values())


def test_channel_type_comes_from_config():
    assert _adapter(WebhookAdapterConfig(channel_type="webhook")).channel_type == "webhook"


def test_the_webhook_credential_is_per_sender():
    assert SignedWebhookAdapter.credential_per_sender is True


# --- gate 2: extract_identity --------------------------------------------

@pytest.mark.parametrize("token,identity", [(_TOKEN, _IDENTITY), (_OTHER_TOKEN, _OTHER)])
def test_extract_identity_is_the_identity_the_token_names(token, identity):
    assert _adapter().extract_identity(_req(body=_body(), token=token)) == identity


def test_extract_identity_ignores_the_identity_the_body_claims():
    # The body claims the other peer; the header is this peer's token.
    assert _adapter().extract_identity(_req(body=_claiming(_OTHER), token=_TOKEN)) == _IDENTITY


def test_extract_identity_canonicalizes_the_maps_identities():
    adapter = _adapter(tokens={"  Peer:EXAMPLE  ": _TOKEN})
    assert adapter.extract_identity(_req(token=_TOKEN)) == "peer:example"


@pytest.mark.parametrize("token", ["not-the-token", None])
def test_extract_identity_raises_when_no_token_matches(token):
    with pytest.raises(ValueError):
        _adapter().extract_identity(_req(body=_body(), token=token))


# --- the token map, refused at load ----------------------------------------

# Every sentinel token starts with the marker, so a refusal that echoed even part
# of one is caught, not only one that echoed it whole.
_MARKER = "SENTINEL"
_SENTINELS = (f"{_MARKER}-token-a-91f2", f"{_MARKER}-token-b-3c07")
_A, _B = _SENTINELS


@pytest.mark.parametrize(
    "secret,fault",
    [
        pytest.param(_A, "bare token string", id="bare-string-not-json"),
        pytest.param(json.dumps(_A), "is a bare string", id="bare-json-string"),
        pytest.param("{}", "empty object", id="empty-object"),
        pytest.param(json.dumps([_A, _B]), "JSON array, not an object", id="array"),
        pytest.param("12345", "JSON number, not an object", id="number"),
        pytest.param("null", "JSON null, not an object", id="null"),
        pytest.param('{"peer:a": "' + _A, "is not a JSON object", id="truncated-json"),
        pytest.param(
            '{"peer:a": "' + _A + '", "peer:a": "' + _B + '"}',
            "names one identity more than once",
            id="duplicate-identity",
        ),
        pytest.param(
            json.dumps({f"{_MARKER}:x": _A, f" {_MARKER}:X ": _B}),
            "names one identity twice once identities are canonicalized",
            id="duplicate-identity-after-canonicalization",
        ),
        pytest.param(
            json.dumps({f"{_MARKER}:x": _A, f"{_MARKER}:y": _A}),
            "gives one token to more than one identity",
            id="duplicate-token",
        ),
        pytest.param(
            json.dumps({_A: "peer:a", _B: "peer:a"}),
            "gives one token to more than one identity",
            id="written-the-wrong-way-round",
        ),
        pytest.param(
            '{"' + _A + '": "peer:a", "' + _A + '": "peer:b"}',
            "names one identity more than once",
            id="wrong-way-round-key-named-twice",
        ),
        pytest.param(json.dumps({"peer:a": ""}), "not a non-empty string", id="empty-token"),
        pytest.param(json.dumps({"peer:a": 12345}), "not a non-empty string", id="number-token"),
        pytest.param(json.dumps({"peer:a": {"t": _A}}), "not a non-empty string", id="object-token"),
        pytest.param(
            json.dumps({f"{_MARKER}:x": _B, "   ": _A}), "empty identity", id="empty-identity"
        ),
        pytest.param(
            json.dumps({"peer:a": f"{_MARKER}\ud800-token"}),
            "holds a token that is not encodable as UTF-8",
            id="lone-surrogate-token",
        ),
        pytest.param(
            json.dumps({f"{_MARKER}:\ud800": _A}),
            "holds an identity that is not encodable as UTF-8",
            id="lone-surrogate-identity",
        ),
    ],
)
def test_a_token_secret_that_is_not_a_usable_map_is_refused_by_name(secret, fault):
    with pytest.raises(WebhookTokenMapError) as caught:
        parse_token_map(secret)
    message = str(caught.value)
    assert fault in message
    assert TOKEN_MAP_SHAPE in message
    # Nothing from the secret is carried: not in the message, not in a chained
    # cause. Casefolded, because identities are canonicalized before most checks.
    assert _MARKER.casefold() not in message.casefold()
    assert _MARKER.casefold() not in repr(caught.value).casefold()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None or caught.value.__suppress_context__


@pytest.mark.parametrize(
    "tokens,fault",
    [
        ({"peer:a": _A, "peer:b": _A}, "more than one identity"),
        ({"peer:a": f"{_MARKER}\ud800"}, "token that is not encodable as UTF-8"),
    ],
    ids=["duplicate-token", "lone-surrogate-token"],
)
def test_the_adapter_refuses_a_map_it_is_handed_directly(tokens, fault):
    with pytest.raises(WebhookTokenMapError, match=fault) as caught:
        _adapter(tokens=tokens)
    assert _MARKER.casefold() not in str(caught.value).casefold()


def test_a_usable_map_parses_to_canonical_identities():
    assert parse_token_map(json.dumps({" Peer:A ": _A, "peer:b": _B})) == {
        "peer:a": _A,
        "peer:b": _B,
    }


# --- the body is bound to the token at gate 3 -------------------------------


class _RecordingTrustMap(ChannelTrustMap):
    """A trust map that records every identity it was asked about."""

    looked_up: tuple = ()

    def resolve(self, channel_type: str, channel_identity: str):
        object.__setattr__(self, "looked_up", self.looked_up + (channel_identity,))
        return super().resolve(channel_type, channel_identity)


def _trust_map(*identities: str) -> _RecordingTrustMap:
    return _RecordingTrustMap(
        entries=[
            TrustMapEntry(
                channel_type="webhook",
                channel_identity=identity,
                principal="example-agent",
                sender_class="peer-agent",
            )
            for identity in identities
        ]
    )


@pytest.mark.parametrize("a_mapped", [True, False], ids=["A-mapped", "A-unmapped"])
def test_a_body_claiming_another_peer_drops_before_verification_and_tells_nothing_of_it(a_mapped):
    """A's token, a body claiming B. The request is A's: it drops `malformed`
    (`sender_identity_mismatch`) before gate 3.5 and gate 5, the trust map is
    never asked about B, and the answer is the same whether B is mapped or not.
    A is told what A's own refusal is (permanent when A is mapped), and nothing
    about B."""
    outcomes = []
    for b_mapped in (True, False):
        mapped = [i for i, on in ((_IDENTITY, a_mapped), (_OTHER, b_mapped)) if on]
        trust_map = _trust_map(*mapped)
        drops: list = []

        def verify_chain(envelope):
            raise AssertionError("gate 3.5 must not run for a body the token does not name")

        outcome = dispatch_outcome(
            _req(body=_claiming(_OTHER), token=_TOKEN),
            adapter=_adapter(),
            trust_map=trust_map,
            screen=None,
            verify_chain=verify_chain,
            dedupe_store=set(),
            drops=drops,
            now=_NOW,
            zone=_ZONE,
        )
        assert outcome.envelope is None
        assert [(d.reason, d.detail) for d in drops] == [("malformed", "sender_identity_mismatch")]
        assert _OTHER not in trust_map.looked_up
        outcomes.append(outcome)

    assert outcomes[0] == outcomes[1]
    assert outcomes[0].refusal == ("permanent" if a_mapped else None)


@pytest.mark.parametrize("token", [_TOKEN, _OTHER_TOKEN])
@pytest.mark.parametrize("claimed", [_IDENTITY, _OTHER, "peer:stranger"])
def test_a_wrong_token_is_authenticity_failed_whatever_the_body_claims(token, claimed):
    drops: list = []
    outcome = dispatch_outcome(
        _req(body=_claiming(claimed), token=token + "-wrong"),
        adapter=_adapter(),
        trust_map=_trust_map(_IDENTITY, _OTHER),
        screen=None,
        dedupe_store=set(),
        drops=drops,
        now=_NOW,
        zone=_ZONE,
    )
    assert outcome.envelope is None and outcome.refusal is None
    assert [d.reason for d in drops] == ["authenticity_failed"]


def test_each_peer_is_accepted_under_its_own_token():
    for token, identity in ((_TOKEN, _IDENTITY), (_OTHER_TOKEN, _OTHER)):
        outcome = dispatch_outcome(
            _req(body=_claiming(identity.upper()), token=token),
            adapter=_adapter(),
            trust_map=_trust_map(_IDENTITY, _OTHER),
            screen=None,
            dedupe_store=set(),
            drops=[],
            now=_NOW,
            zone=_ZONE,
        )
        assert outcome.envelope is not None
        assert outcome.envelope.sender.channel_identity == identity


# --- gate 3: normalize ----------------------------------------------------

def test_normalize_returns_typed_envelope():
    env = _adapter().normalize(_req(body=_body()))
    assert isinstance(env, EventTrigger)
    assert env.principal == "example-agent"
    assert env.sender.channel_identity == "peer:example"


def test_normalize_rejects_channel_type_mismatch():
    body = _body(
        sender={"channel_type": "telegram", "channel_identity": "peer:example", "evidence": []}
    )
    with pytest.raises(ValueError, match="does not match adapter channel_type"):
        _adapter().normalize(_req(body=body))


def test_normalize_raises_on_malformed_json():
    with pytest.raises(Exception):
        _adapter().normalize(_req(body="{bad"))


def test_normalize_propagates_pydantic_validation_error():
    # Missing required fields (principal, sender, payload, provenance, ...).
    with pytest.raises(Exception):
        _adapter().normalize(_req(body=json.dumps({"event_id": "evt-1"})))


def test_normalize_canonicalizes_sender_identity_for_dedupe():
    # Gate 6 keys on the emitted envelope's sender.channel_identity: every wire
    # spelling of one identity must yield ONE dedupe key, or a mapped sender
    # could replay a single event_id unlimited times by varying casing.
    keys = set()
    for variant in ("Peer:Example", "PEER:EXAMPLE", "  peer:example  "):
        body = _body(
            sender={"channel_type": "webhook", "channel_identity": variant, "evidence": []}
        )
        env = _adapter().normalize(_req(body=body))
        assert env.sender.channel_identity == "peer:example"
        keys.add(env.dedupe_key())
    assert len(keys) == 1


@pytest.mark.parametrize("variant", ["peer:example", "Peer:Example", "  PEER:EXAMPLE  "])
def test_normalize_sender_identity_matches_extract_identity(variant):
    # dispatch's gate-3 sender-transport-binding check (channels/ADAPTERS.md)
    # requires normalize()'s envelope.sender.channel_identity to equal THIS
    # request's extract_identity() result. Gate 2 reads the identity the token
    # names and gate 3 the one the body claims, both canonicalized by the same
    # rule, so a body that claims its own token's identity matches in every
    # spelling. A body claiming another identity is the mismatch the dispatcher
    # refuses (test above).
    request = _req(body=_claiming(variant), token=_TOKEN)
    adapter = _adapter()
    assert adapter.normalize(request).sender.channel_identity == adapter.extract_identity(request)
