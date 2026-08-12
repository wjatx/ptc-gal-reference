"""Tests for SearchConnector — the search.query shared read connector (sa#133).

Unlike test_telegram_connector.py (live API, skipped without credentials), the
offline tests here monkeypatch ``urllib.request.urlopen`` so the REAL connector
code runs in CI with the request fully inspectable — endpoint, Authorization
header, and JSON body are asserted byte-for-byte.

Coverage:
  - arg validation: wrong op / bad args rejected with NO HTTP call made
  - unknown provider in the credential names the provider, never the api_key
  - happy path: request shape (endpoint, Bearer header, body) + result
    normalization (Tavily "content" -> "snippet"; absent fields -> ""/None)
  - non-redirectable source endpoint: endpoint/url smuggled into args are
    ignored — the request still goes to the code-resident Tavily endpoint
  - HTTP failure / malformed payload -> RuntimeError, api_key never leaked
  - full broker round-trip: registry -> decide(allow) -> doer -> normalized
    result -> hash-chained AuditRecord (the CI-runnable analog of telegram's
    live test)
  - ungranted: a runtime without a search.query grant neither serves nor
    executes it

A live smoke test against the real Tavily API is gated on TAVILY_KEY.
"""

from __future__ import annotations

import io
import json
import os
import urllib.error

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink, verify_chain
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    FakeSecretsProvider,
)
from safe_agents.broker.schemas import Grant
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import ENVELOPE_HASH, PRINCIPAL, make_grant, make_pip
from safe_agents.connectors import SearchConnector

TAVILY_ENDPOINT = "https://api.tavily.com/search"
API_KEY = "test-key"

# The broker-injected credential: the ONLY source of the provider (and thus endpoint).
CREDENTIAL = json.dumps({"provider": "tavily", "api_key": API_KEY})


class _FakeHTTPResponse:
    """Context-manager + read() — enough for ``json.load(response)``."""

    def __init__(self, payload: dict) -> None:
        self._body = io.BytesIO(json.dumps(payload).encode())

    def read(self, *args):
        return self._body.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeUrlopen:
    """Stands in for urllib.request.urlopen; records every Request it is handed."""

    def __init__(self) -> None:
        self.requests: list = []
        self.payload: dict = {"results": []}
        self.error: Exception | None = None

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return _FakeHTTPResponse(self.payload)


@pytest.fixture
def fake_urlopen(monkeypatch) -> _FakeUrlopen:
    fake = _FakeUrlopen()
    # search_connector does `import urllib.request` and calls the module-global
    # urllib.request.urlopen — patch it there.
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


def _query(args):
    return SearchConnector().execute("search", "query", args, CREDENTIAL)


# ---------------------------------------------------------------------------
# Direct connector tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "description, op, args, expected_fragment",
    [
        ("wrong_op", "fetch", {"query": "x"}, "'query' op"),
        ("non_dict_args", "query", ["query"], "dict"),
        ("missing_query", "query", {}, "non-empty str 'query'"),
        ("empty_query", "query", {"query": ""}, "non-empty str 'query'"),
        ("non_str_query", "query", {"query": 42}, "non-empty str 'query'"),
        ("over_length_query", "query", {"query": "x" * 401}, "400-char limit"),
        ("max_results_zero", "query", {"query": "x", "max_results": 0}, "max_results"),
        ("max_results_over_cap", "query", {"query": "x", "max_results": 11}, "max_results"),
        ("max_results_bool", "query", {"query": "x", "max_results": True}, "max_results"),
        ("max_results_str", "query", {"query": "x", "max_results": "5"}, "max_results"),
        ("unknown_topic", "query", {"query": "x", "topic": "sports"}, "topic"),
    ],
)
def test_malformed_args_rejected(fake_urlopen, description, op, args, expected_fragment):
    with pytest.raises(ValueError, match=expected_fragment):
        SearchConnector().execute("search", op, args, CREDENTIAL)
    # Fail-closed: no HTTP call was made on any rejection path.
    assert fake_urlopen.requests == []


def test_unknown_provider_names_provider_never_the_key(fake_urlopen):
    """An unrecognized provider is named alongside the known list; the api_key
    must never appear in the exception."""
    credential = json.dumps({"provider": "bing", "api_key": "sekrit-key"})
    with pytest.raises(ValueError) as excinfo:
        SearchConnector().execute("search", "query", {"query": "x"}, credential)
    message = str(excinfo.value)
    assert "bing" in message
    assert "tavily" in message
    assert "sekrit-key" not in message
    assert fake_urlopen.requests == []


def test_happy_path_request_shape_and_normalization(fake_urlopen):
    """The request goes to the Tavily endpoint with a Bearer header and the exact
    documented body; Tavily's "content" becomes "snippet" and absent result
    fields normalize to ""/None."""
    fake_urlopen.payload = {
        "results": [
            {
                "title": "NVDA hits new high",
                "url": "https://example.com/nvda",
                "content": "snippet text",
                "score": 0.91,
            },
            {},  # every field absent
        ],
    }
    result = _query({"query": "nvidia stock", "max_results": 3, "topic": "news"})

    (request,) = fake_urlopen.requests
    assert request.full_url == TAVILY_ENDPOINT
    assert request.get_header("Authorization") == f"Bearer {API_KEY}"
    assert json.loads(request.data) == {
        "query": "nvidia stock",
        "max_results": 3,
        "topic": "news",
        "search_depth": "basic",
        "include_answer": False,
    }
    assert result == {
        "provider": "tavily",
        "query": "nvidia stock",
        "results": [
            {
                "title": "NVDA hits new high",
                "url": "https://example.com/nvda",
                "snippet": "snippet text",
                "score": 0.91,
            },
            {"title": "", "url": "", "snippet": "", "score": None},
        ],
    }


def test_endpoint_never_comes_from_args(fake_urlopen):
    """The non-redirectable-source invariant: endpoint/url smuggled into args are
    simply never read — the request still goes to the code-resident endpoint."""
    result = _query(
        {
            "query": "x",
            "endpoint": "https://evil.example",
            "url": "https://evil.example",
        }
    )
    (request,) = fake_urlopen.requests
    assert request.full_url == TAVILY_ENDPOINT
    assert result["provider"] == "tavily"


def test_defaults_applied_when_optional_args_absent(fake_urlopen):
    _query({"query": "x"})
    (request,) = fake_urlopen.requests
    body = json.loads(request.data)
    assert body["max_results"] == 5
    assert body["topic"] == "general"


def test_http_failure_raises_runtime_error_without_the_key(fake_urlopen):
    fake_urlopen.error = urllib.error.URLError("connection refused")
    with pytest.raises(RuntimeError, match="request to 'tavily' failed") as excinfo:
        _query({"query": "x"})
    assert API_KEY not in str(excinfo.value)


def test_http_failure_message_scrubs_an_echoed_key(fake_urlopen):
    """Even if a transport error echoes the Bearer header (as http.client's
    invalid-header ValueError does), the api_key is scrubbed from the wrapped
    message and the original exception is not chained (`from None`)."""
    fake_urlopen.error = ValueError(f"Invalid header value b'Bearer {API_KEY}'")
    with pytest.raises(RuntimeError, match=r"\[REDACTED\]") as excinfo:
        _query({"query": "x"})
    assert API_KEY not in str(excinfo.value)
    assert excinfo.value.__cause__ is None  # nothing unsanitized rides along


@pytest.mark.parametrize(
    "description, credential",
    [
        ("bare_token_not_json", "tvly-raw-token"),
        ("json_but_not_object", json.dumps(["tavily"])),
        ("missing_api_key", json.dumps({"provider": "tavily"})),
        ("missing_provider", json.dumps({"api_key": "k"})),
        ("api_key_not_str", json.dumps({"provider": "tavily", "api_key": 7})),
        ("api_key_empty", json.dumps({"provider": "tavily", "api_key": ""})),
        ("api_key_newline", json.dumps({"provider": "tavily", "api_key": "k\n"})),
        ("api_key_padded", json.dumps({"provider": "tavily", "api_key": " k "})),
    ],
)
def test_malformed_credential_rejected_before_http(fake_urlopen, description, credential):
    """A mis-seeded secret fails as an actionable ValueError with NO fragment of
    the credential in the message, its chain (JSONDecodeError.doc carries the
    full secret), or an HTTP call."""
    with pytest.raises(ValueError, match="credential") as excinfo:
        SearchConnector().execute("search", "query", {"query": "x"}, credential)
    assert credential not in str(excinfo.value)
    # No unsanitized original exception in the rendered chain: either there was
    # none, or `from None` suppressed it (JSONDecodeError.doc holds the secret).
    assert excinfo.value.__context__ is None or excinfo.value.__suppress_context__
    assert fake_urlopen.requests == []


@pytest.mark.parametrize(
    "description, payload",
    [
        ("no_results_list", {"answer": "a synthesized answer but no results list"}),
        ("results_not_a_list", {"results": "nope"}),
        ("non_dict_item_none", {"results": [None]}),
        ("non_dict_item_str", {"results": ["error text"]}),
        ("payload_not_an_object", ["results"]),
    ],
)
def test_malformed_payload_raises_runtime_error(fake_urlopen, description, payload):
    fake_urlopen.payload = payload
    with pytest.raises(RuntimeError, match="malformed response"):
        _query({"query": "x"})


# ---------------------------------------------------------------------------
# Full broker round-trip (CI-runnable analog of telegram's live integration test)
# ---------------------------------------------------------------------------


def _make_runtime(sink: InMemorySink, grants: list[Grant], grant_present: bool = True):
    doer = Doer(
        connectors={"search": SearchConnector()},
        secrets=FakeSecretsProvider({"search": CREDENTIAL}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=grants,
        optable=CATALOG_TABLE,
        doer=doer,
        pip=make_pip(grant_present),
        enforcement_store=InMemoryStore(),
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
    )


def test_search_query_broker_round_trip(fake_urlopen):
    """Full integration: registry -> decide(allow) -> doer executes SearchConnector
    with the broker-injected credential -> normalized results -> audit."""
    fake_urlopen.payload = {
        "results": [
            {"title": "One", "url": "https://example.com/1", "content": "first", "score": 0.9},
            {"title": "Two", "url": "https://example.com/2", "content": "second", "score": 0.5},
        ],
    }
    sink = InMemorySink()
    runtime = _make_runtime(sink, grants=[make_grant("search.query")])

    registry = runtime.served_registry()
    assert [(t.tool, t.op) for t in registry] == [("search", "query")]

    response = runtime.handle_request(
        AgentRequest(
            tool="search",
            op="query",
            args={"query": "nvidia stock", "max_results": 2},
            idempotency_key="test:search-query-1",
        )
    )

    assert response.decision_kind == "allow"
    assert response.result == {
        "provider": "tavily",
        "query": "nvidia stock",
        "results": [
            {"title": "One", "url": "https://example.com/1", "snippet": "first", "score": 0.9},
            {"title": "Two", "url": "https://example.com/2", "snippet": "second", "score": 0.5},
        ],
    }
    # The agent-facing surface must carry no credential anywhere.
    assert API_KEY not in repr(response)

    records = sink.records()
    assert len(records) == 1
    assert (records[-1].tool, records[-1].op) == ("search", "query")
    assert records[-1].decision == "allow"
    assert records[-1].outcome == "executed"
    verify_chain(records)


def test_ungranted_search_is_not_served_and_denied(fake_urlopen):
    """A runtime whose grants omit search.query: removal, not refusal — the
    registry does not serve it, and a raw request is denied without the
    connector ever executing."""
    sink = InMemorySink()
    runtime = _make_runtime(sink, grants=[make_grant("notify.send")], grant_present=False)

    registry = runtime.served_registry()
    assert ("search", "query") not in [(t.tool, t.op) for t in registry]

    response = runtime.handle_request(
        AgentRequest(
            tool="search",
            op="query",
            args={"query": "nvidia stock"},
            idempotency_key="test:search-query-ungranted-1",
        )
    )

    assert response.decision_kind == "deny"
    assert response.result is None
    assert fake_urlopen.requests == []


# ---------------------------------------------------------------------------
# Live smoke (gated: real Tavily API)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("TAVILY_KEY"),
    reason="TAVILY_KEY not set — export a Tavily API key to run live",
)
def test_live_tavily_smoke():
    """One REAL query against the Tavily API — provenance comes back with URLs."""
    credential = json.dumps({"provider": "tavily", "api_key": os.environ["TAVILY_KEY"]})
    result = SearchConnector().execute(
        "search", "query", {"query": "NVIDIA stock", "max_results": 3}, credential
    )
    assert result["provider"] == "tavily"
    assert len(result["results"]) >= 1
    assert any(item["url"] for item in result["results"])
