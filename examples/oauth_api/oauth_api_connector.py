"""oauth_api_connector.py — the reference OAuth-refresh consumer (#173, PTC Phase 3a).

This is the worked example of the ``oauth_refresh`` credential strategy
(``safe_agents.broker.runtime.credentials.OAuthRefresh``). The manifest declares
``connector_auth: {api: {strategy: oauth_refresh, ...}}``; the broker resolves a
broker-held refresh token into a short-lived access token and hands THAT to this
connector as ``credential`` — the refresh token itself never reaches this file, the
agent, or any log.

Like ``examples/missileer/trackfeed_connector.py``, this is a consumer-owned
connector reached via the ``connector_providers`` injection seam (sa#141) and
written ONLY against the public surface — ``safe_agents.connectors.Connector`` —
never against broker internals (the consumer-boundary AST guard enforces that).

Doctrine 1 (no raw passthrough of long-lived material): this connector receives
only the minted access token, never the refresh token, and never echoes, logs, or
returns the credential it was given.

Doctrine 2 (no raw command/query passthrough): ``execute`` exposes one narrow,
classified capability (``api.query``), not a free-form HTTP verb/URL — the ToolOp
table (#171) classifies the op; a passthrough arg would defeat that classification.

Fictional and deterministic: no real network call, no real OAuth provider.
"""

from __future__ import annotations

from typing import Any

# The ONLY safe-agents import a consumer connector needs — and the only kind the
# consumer-boundary guard permits: the public connector surface, never
# safe_agents.broker internals.
from safe_agents.connectors import Connector


class OAuthApiConnector:
    """Query a (fictional) OAuth-protected API using a broker-minted bearer token.

    Zero-arg instantiable and satisfying the ``Connector`` protocol
    (``execute(tool, op, args, credential)``) — the two things the registry's
    fail-closed provider check demands.
    """

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        # `credential` here is the broker-minted OAuth ACCESS token (never the
        # refresh token — the OAuthRefresh strategy resolves that broker-side and
        # this connector never sees it). Require it, use it to "authorize" the
        # call, never emit it in the result.
        if not credential:
            raise ValueError("oauth_api requires a bearer access token (empty credential)")
        query = (args or {}).get("query", "")
        return {
            "status": "ok",
            "authorized_with": "bearer",
            "query": query,
            "result": [],  # fictional: deterministic empty result set
        }


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the registry's fail-closed check does.
assert isinstance(OAuthApiConnector(), Connector)
