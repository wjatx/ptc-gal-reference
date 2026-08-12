"""trackfeed_connector.py — missileer's CONSUMER-OWNED connector (sa#141 proof).

This is the worked example of the one sanctioned injection seam: the manifest's
``connector_providers`` names this class by dotted path
(``examples.missileer.trackfeed_connector:TrackFeedConnector``) and the broker's
connector registry imports, zero-arg instantiates, and protocol-checks it at
``build_runtime`` time. The consumer writes ONLY against the public surface —
the ``Connector`` protocol from ``safe_agents.connectors`` — never against
broker internals (the consumer-boundary AST guard enforces that).

It overrides the base ``search`` name: missileer's "search" is not a generic web
search but its track-feed query — same grant_class (``search.query``), same
served registry, consumer-supplied implementation. Fictional and deterministic:
no network. The broker-fetched credential is *used* (its presence is required,
mirroring a real feed token) but never logged, echoed, or returned — the agent
side of the broker never sees it.
"""

from __future__ import annotations

from typing import Any

# The ONLY safe-agents import a consumer connector needs — and the only kind the
# consumer-boundary guard permits: the public connector surface, never
# safe_agents.broker internals.
from safe_agents.connectors import Connector


class TrackFeedConnector:
    """Query the (fictional) launch-watch track feed.

    Zero-arg instantiable and satisfying the ``Connector`` protocol
    (``execute(tool, op, args, credential)``) — the two things the registry's
    fail-closed provider check demands.
    """

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        # The credential is the broker-fetched feed token (mapped via the
        # manifest's connector_secrets). Require it, use it, never emit it.
        if not credential:
            raise ValueError("track feed requires a feed token (empty credential)")
        query = (args or {}).get("query", "")
        return {
            "status": "ok",
            "feed": "track-feed",
            "query": query,
            "tracks": [],  # fictional: a quiet sky is the expected answer
        }


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the registry's fail-closed check does.
assert isinstance(TrackFeedConnector(), Connector)
