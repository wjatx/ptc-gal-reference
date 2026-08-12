"""SearchConnector — external web search for the search.query grant (sa#133).

The second shared read connector (after github.whoami): "verify a claim against
the live web" is domain-invariant — a trading agent grounding a market claim and a
dashboard agent grounding a stats blurb need exactly the same retrieval primitive —
so groundedness verification lives in the base per the base/per-agent split.

The broker injects the credential — the connector never sources it. The credential
is a JSON string ('{"provider": "tavily", "api_key": ...}') fetched from the
SecretsProvider (secret name resolves to "<prefix>/connectors/search"). The API
endpoint comes from a code-resident dict keyed by the credential's provider —
NEVER from args. This is TelegramConnector's non-redirectable-target pattern
adapted for reads: for a read connector the non-redirectable fact is the *source
endpoint*. A compromised agent can ask to search but can never choose which
service answers — so it cannot redirect the query text (which may carry sensitive
context) to an attacker-chosen host, nor spoof results from one.

Supported op: "query" — POST to the provider's search API with:
    query        required non-empty str, max 400 chars (Tavily's documented cap)
    max_results  optional int, 1–10 inclusive (default 5)
    topic        optional, "general" (default) or "news"

The return value is provenance-only: retrieved documents (title/url/snippet/score),
never a synthesized answer (we request include_answer=False). The connector asserts
nothing about trustworthiness — "verification" is an agent-side judgment over
provenance, not a fact this connector can supply.

UNTRUSTED INGESTION — read this before consuming results. Search results are
free-text web content: the canonical injection carrier, structurally an inbound
email body per memory/TAINT.md. The broker self-ingests every successful external
read into the TurnContext (sa#134), so results taint the turn deterministically and
a subsequent external write escalates to require_approval. Any memory write of them
must still carry taint: untrusted.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

_TIMEOUT_SECONDS = 15
_MAX_QUERY_LENGTH = 400  # Tavily's documented query cap
_MAX_RESULTS_CAP = 10
_DEFAULT_MAX_RESULTS = 5
_VALID_TOPICS = ("general", "news")

# The source endpoint is a code-resident fact keyed by the credential's provider —
# never a caller-supplied arg. See the module docstring: a compromised agent can
# ask to search but can never choose which service answers.
_PROVIDER_ENDPOINTS = {"tavily": "https://api.tavily.com/search"}


class SearchConnector:
    """Real web-search connector. Only the Doer holds an instance of this."""

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        """Run one search against the provider named by the credential.

        Supported op:
            "query" -> POST the provider's search API with args["query"]
                       (+ optional args["max_results"], args["topic"]).
                       Returns {"provider": str, "query": str, "results":
                       [{"title", "url", "snippet", "score"}, ...]}.

        Raises ValueError for any other op, malformed args, or an unknown
        provider in the credential; RuntimeError for a non-2xx or malformed
        provider response. The Doer redacts the credential from connector
        exceptions before they can reach the audit tape or a log.
        """
        if op != "query":
            raise ValueError(
                f"SearchConnector supports only the 'query' op, got {op!r}"
            )
        if not isinstance(args, dict):
            raise ValueError("SearchConnector 'query' requires a dict of args")

        query = args.get("query")
        if not isinstance(query, str) or not query:
            raise ValueError("SearchConnector 'query' requires a non-empty str 'query'")
        if len(query) > _MAX_QUERY_LENGTH:
            raise ValueError(
                f"SearchConnector 'query' query exceeds the provider's "
                f"{_MAX_QUERY_LENGTH}-char limit ({len(query)} chars)"
            )
        max_results = args.get("max_results", _DEFAULT_MAX_RESULTS)
        if not isinstance(max_results, int) or isinstance(max_results, bool) or not (
            1 <= max_results <= _MAX_RESULTS_CAP
        ):
            raise ValueError(
                f"SearchConnector 'query' max_results must be an int in "
                f"1..{_MAX_RESULTS_CAP}, got {max_results!r}"
            )
        topic = args.get("topic", "general")
        if topic not in _VALID_TOPICS:
            raise ValueError(
                f"SearchConnector 'query' topic must be one of "
                f"{sorted(_VALID_TOPICS)}, got {topic!r}"
            )

        # The endpoint comes ONLY from the code-resident table keyed by the
        # broker-injected credential's provider. Any endpoint/url the caller
        # smuggles into args is simply never read.
        #
        # The parse/shape errors below deliberately carry NO fragment of the
        # credential and suppress the original exception (`from None`) — a raw
        # JSONDecodeError holds the full secret on its .doc attribute, which
        # would outlive the Doer's whole-string redaction in any handler that
        # logs exception attributes rather than str().
        try:
            creds = json.loads(credential)
        except ValueError:
            raise ValueError(
                "SearchConnector credential must be a JSON object like "
                '\'{"provider": ..., "api_key": ...}\' — got unparseable JSON. '
                "Was the secret seeded as a bare token?"
            ) from None
        if not isinstance(creds, dict) or "provider" not in creds or "api_key" not in creds:
            raise ValueError(
                "SearchConnector credential must be a JSON object with "
                "'provider' and 'api_key' keys"
            )
        provider = creds["provider"]
        api_key = creds["api_key"]
        if not isinstance(api_key, str) or not api_key or api_key.strip() != api_key or any(
            c in api_key for c in "\r\n"
        ):
            # A key with whitespace/control chars would make http.client's
            # putheader raise a ValueError that EMBEDS the header value —
            # 'Bearer <key>' — which the Doer's whole-credential redaction
            # would not catch. Reject it here without echoing it.
            raise ValueError(
                "SearchConnector credential api_key must be a non-empty string "
                "with no surrounding whitespace or control characters"
            )
        endpoint = _PROVIDER_ENDPOINTS.get(provider)
        if endpoint is None:
            # Name the provider, never the api_key.
            raise ValueError(
                f"SearchConnector has no endpoint for provider {provider!r}; "
                f"known providers: {sorted(_PROVIDER_ENDPOINTS)}"
            )

        body = json.dumps(
            {
                "query": query,
                "max_results": max_results,
                "topic": topic,
                "search_depth": "basic",
                "include_answer": False,  # provenance-only; no synthesized answer
            }
        ).encode()
        request = urllib.request.Request(  # noqa: S310 — fixed https URL, not user input
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
                payload = json.load(response)
        except Exception as exc:
            # Belt to the validation's suspenders: scrub the api_key from the
            # wrapped message in case ANY transport error echoes a header, then
            # chain `from None` so the original exception (whose own message we
            # cannot sanitize) never rides to the audit tape or a log.
            detail = str(exc).replace(api_key, "[REDACTED]")
            raise RuntimeError(
                f"SearchConnector 'query' request to {provider!r} failed: "
                f"{type(exc).__name__}: {detail}"
            ) from None
        raw_results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(raw_results, list) or not all(
            isinstance(item, dict) for item in raw_results
        ):
            raise RuntimeError(
                f"SearchConnector 'query' got a malformed response from "
                f"{provider!r}: expected a 'results' list of objects"
            )

        return {
            "provider": provider,
            "query": query,
            "results": [
                {
                    "title": item.get("title", ""),
                    "url": item.get("url", ""),
                    "snippet": item.get("content", ""),  # Tavily calls the snippet "content"
                    "score": item.get("score"),
                }
                for item in raw_results
            ],
        }
