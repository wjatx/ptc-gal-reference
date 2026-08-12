"""Base reference `peer` connector (safe_agents.connectors) — transport conformance.

Proves the connector is PURE TRANSPORT (channels/PUBLISH.md): it POSTs the
broker-stamped envelope to the peer descriptor's URL with the shared-secret
header the receiver's `verify_token` checks, refuses a non-'publish' op, refuses
a malformed credential, and never authors provenance. Network is faked.
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
        payload={"signal": "buy"},
        ts=_TS,
        expiry=_EXPIRY,
    )


class _FakeResponse:
    status = 202

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeUrlopen:
    def __init__(self):
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _FakeResponse()


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
