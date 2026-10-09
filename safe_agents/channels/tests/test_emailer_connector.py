"""Base reference `peer` connector (safe_agents.connectors) — transport conformance.

Proves the connector is PURE TRANSPORT (channels/PUBLISH.md): it POSTs the
broker-stamped envelope to the peer descriptor's URL with the shared-secret
header the receiver's `verify_token` checks, refuses a non-'publish' op, refuses
a malformed credential, and never authors provenance. It reports the airlock's
answer from the body (channels/ADAPTERS.md §"What the sender is told") and
never reports `published` for a body that is not the acceptance body. Network
is faked.
"""

from __future__ import annotations

import json

import pytest

from safe_agents.channels.publish import stamp_outbound

from safe_agents.connectors import PeerConnector

_TS = "2026-07-09T00:00:00+00:00"
_EXPIRY = "2026-07-09T01:00:00+00:00"
_CREDENTIAL = json.dumps(
    {"url": "https://peer.example/inbound", "token_header": "x-airlock-token", "token": "shhh"}
)


def _stamped_envelope():
    return stamp_outbound(
        zone="email-agent",
        agent_identity="email-agent",
        channel_type="webhook",
        channel_identity="peer:example",
        turn_tainted=False,
        event_id="conf-1234",
        principal="example-agent",
        audience="example-airlock",
        payload={"signal": "buy"},
        ts=_TS,
        expiry=_EXPIRY,
    )


_ACCEPTED_BODY = b'{"ok": true}'


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, amt=None):
        return self._body if amt is None else self._body[:amt]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeUrlopen:
    def __init__(self):
        self.requests = []
        self.status = 202
        self.body = _ACCEPTED_BODY

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _FakeResponse(self.status, self.body)


@pytest.fixture
def fake_urlopen(monkeypatch):
    fake = _FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


def test_publish_posts_stamped_envelope_with_token_header(fake_urlopen):
    env = _stamped_envelope()
    result = PeerConnector().execute("peer", "publish", {"envelope": env.model_dump()}, _CREDENTIAL)

    assert result["status"] == "published"
    assert result["event_id"] == "conf-1234"
    assert result["http_status"] == 202

    (request,) = fake_urlopen.requests
    assert request.full_url == "https://peer.example/inbound"
    assert request.get_method() == "POST"
    # the shared-secret header the receiver's verify_token compares (case-insensitive)
    assert request.headers.get("X-airlock-token") == "shhh"
    # the body is the stamped envelope verbatim — provenance untouched
    posted = json.loads(request.data)
    assert posted["event_id"] == "conf-1234"
    assert posted["provenance"] == env.model_dump()["provenance"]


def test_rejects_non_publish_op(fake_urlopen):
    with pytest.raises(ValueError, match="only op 'publish'"):
        PeerConnector().execute("peer", "revoke", {"envelope": {}}, _CREDENTIAL)
    assert fake_urlopen.requests == []  # nothing crossed the wire


def test_rejects_malformed_credential_without_echoing_it(fake_urlopen):
    with pytest.raises(ValueError) as exc:
        PeerConnector().execute("peer", "publish", {"envelope": {}}, "not-json-secret")
    assert "not-json-secret" not in str(exc.value)  # credential never echoed
    assert fake_urlopen.requests == []


def test_rejects_malformed_envelope(fake_urlopen):
    # A body that is not a valid EventTrigger never crosses the wire.
    with pytest.raises(Exception):
        PeerConnector().execute("peer", "publish", {"envelope": {"bogus": 1}}, _CREDENTIAL)
    assert fake_urlopen.requests == []


def test_the_posted_body_is_the_envelope_wire_form(fake_urlopen):
    """The connector sends the same form the receiver's gate checks: ASCII, and
    equal to `to_wire()`. A second serializer here could send what the airlock
    then refuses, or rewrite a value the first one would have refused."""
    env = _stamped_envelope().model_copy(update={"payload": {"note": "café \uffff"}})
    PeerConnector().execute("peer", "publish", {"envelope": env.model_dump()}, _CREDENTIAL)
    (request,) = fake_urlopen.requests
    assert request.data.isascii()
    assert request.data.decode("ascii") == env.to_wire()


def test_an_envelope_the_wire_cannot_carry_is_not_posted(fake_urlopen):
    env = _stamped_envelope().model_copy(update={"payload": {"v": float("nan")}})
    with pytest.raises(ValueError):
        PeerConnector().execute("peer", "publish", {"envelope": env.model_dump()}, _CREDENTIAL)
    assert fake_urlopen.requests == []


# What the connector reports for each body the peer answers with. Every body the
# airlock does not send, including near misses, is `unknown`, never `published`.
_PUBLISHED = {"status": "published"}
_UNKNOWN = {"status": "unknown"}


@pytest.mark.parametrize(
    "body,expected",
    [
        pytest.param(b'{"ok": true}', _PUBLISHED, id="accepted"),
        pytest.param(
            b'{"ok": false, "refusal": "permanent"}',
            {"status": "refused", "refusal": "permanent"},
            id="permanent",
        ),
        pytest.param(
            b'{"ok": false, "refusal": "transient"}',
            {"status": "refused", "refusal": "transient"},
            id="transient",
        ),
        pytest.param(b"", _UNKNOWN, id="empty"),
        pytest.param(b"not json", _UNKNOWN, id="not-json"),
        pytest.param(b"\xff\xfe", _UNKNOWN, id="not-utf8"),
        pytest.param(b"[true]", _UNKNOWN, id="not-an-object"),
        pytest.param(b'{"ok": 1}', _UNKNOWN, id="ok-is-one-not-true"),
        pytest.param(b'{"ok": true, "extra": 1}', _UNKNOWN, id="accepted-plus-a-key"),
        pytest.param(b'{"ok": false}', _UNKNOWN, id="refused-without-a-class"),
        pytest.param(b'{"ok": false, "refusal": "later"}', _UNKNOWN, id="unknown-class"),
        pytest.param(b'{"ok": 0, "refusal": "permanent"}', _UNKNOWN, id="ok-is-zero-not-false"),
        pytest.param(
            b'{"ok": true, "refusal": "transient"}', _UNKNOWN, id="ok-true-with-a-class"
        ),
        pytest.param(
            b'{"ok": false, "refusal": "transient", "gate": "x"}',
            _UNKNOWN,
            id="refusal-plus-a-key",
        ),
        pytest.param(
            b'{"ok": true}' + b" " * 2048, _UNKNOWN, id="longer-than-any-answer"
        ),
        pytest.param(b'{"status": "accepted"}', _UNKNOWN, id="some-other-receiver"),
    ],
)
def test_the_result_reports_the_airlock_answer_read_from_the_body(fake_urlopen, body, expected):
    fake_urlopen.status = 200
    fake_urlopen.body = body
    env = _stamped_envelope()
    result = PeerConnector().execute("peer", "publish", {"envelope": env.model_dump()}, _CREDENTIAL)

    assert result == {
        **expected,
        "event_id": "conf-1234",
        "principal": "example-agent",
        "http_status": 200,
    }
