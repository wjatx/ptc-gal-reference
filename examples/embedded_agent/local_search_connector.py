"""local_search_connector.py — an offline connector for the embedding example.

Reached through the ``connector_providers`` injection seam (sa#141), exactly like
``examples/missileer/trackfeed_connector.py``: the manifest names the connector
``search`` and supplies THIS implementation, which overrides the base
``SearchConnector`` for this consumer only.

Why the example overrides a base connector rather than naming a fresh one. Two
reasons, both structural rather than cosmetic:

  1. **Offline by construction.** Every base connector reaches the network or AWS
     at ``execute()`` time. An example whose whole point is "run this on your
     laptop, no account, no credentials" cannot have an allow path that dials
     out, so the allow path must be consumer-supplied.
  2. **The fake secrets arm knows a fixed set of names.** The Doer fetches a
     credential for every tool it executes, and the default in-memory provider
     raises ``KeyError`` on a name it does not carry
     (``broker/runtime/secrets.py:50-53``). ``search`` is one of the names it
     carries, so overriding it keeps the example zero-configuration.

Fictional and deterministic: an in-process corpus, no I/O of any kind.
"""

from __future__ import annotations

from typing import Any

# The ONLY safe-agents import a consumer connector needs, and the only kind the
# consumer-boundary guard permits: the public connector surface, never
# safe_agents.broker internals.
from safe_agents.connectors import Connector

# The entire "world" this connector can reach. A real consumer would hold a path
# to a local index; the point here is that the reachable set is fixed at import
# and contains no network.
_CORPUS: dict[str, str] = {
    "onboarding": "Run `example-wrapper init` once, then `example-wrapper wrap claude` inside a project.",
    "posture": "`example-wrapper posture` names the rung; a claim without a rung is an overclaim.",
    "broker": "The agent holds no connector credentials. Its only egress is the broker.",
}


class LocalSearchConnector:
    """Search a fixed in-process corpus.

    Zero-arg instantiable and satisfying the ``Connector`` protocol
    (``execute(tool, op, args, credential)``) — the two things the registry's
    fail-closed provider check demands.
    """

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        # `credential` arrives from the broker's SecretsProvider and is deliberately
        # unused: a local corpus needs no authorization. It is never echoed, logged,
        # or returned — Doctrine 1 holds even when the credential is not needed.
        query = (args or {}).get("query", "")
        hits = [
            {"topic": topic, "text": text}
            for topic, text in _CORPUS.items()
            if query.lower() in topic.lower() or query.lower() in text.lower()
        ]
        return {"query": query, "hits": hits}


# Structural conformance, checked at import time so a drift from the protocol
# fails HERE (the consumer's file) before the registry's fail-closed check does.
assert isinstance(LocalSearchConnector(), Connector)
