"""safe_agents.connectors — the connector boundary.

A **connector** is the only thing that ever touches a real external API. The Doer
is the sole holder of connector instances; the agent process never receives one
(see safe_agents.broker.runtime.doer). This package draws the line between:

- **The Connector protocol** — the dispatch contract the Doer calls. It is
  re-exported here from its canonical home (safe_agents.broker.runtime.connector,
  where the Doer imports it) so consumers get the whole connector vocabulary from
  one place: ``from safe_agents.connectors import Connector``.
- **Shared connectors** — genuinely domain-invariant connectors that more than one
  agent can reuse: GitHubConnector (github.whoami), TelegramConnector (notify.send),
  LedgerConnector (ledger.append), SearchConnector (search.query),
  PeerConnector (peer.publish — A2A transport to a peer airlock). These ship in
  the SDK.

What does NOT live here: **single-agent connectors** — e.g. a consumer agent's
ExampleConnector — are *agent-owned*. They live with the agent that needs them, not
in the base platform. ExampleConnector is now fully removed from the base and is
consumer-injected via ``connector_providers`` (the consumer's broker image
carries it). See README.md.

Importing this package pulls in NO single-agent connector — the SDK core has no
hard dependency on any agent-specific connector.
"""

from safe_agents.broker.runtime.connector import (
    AssumedRoleCredential,
    Connector,
    ConnectorCall,
    Credential,
    StubConnector,
)

from .github_connector import GitHubConnector
from .ledger_connector import LedgerConnector
from .mcp_connector import McpConnector
from .peer_connector import PeerConnector
from .search_connector import SearchConnector
from .telegram_connector import TelegramConnector

__all__ = [
    # protocol + test doubles (re-exported from the broker runtime)
    "Connector",
    "Credential",
    "AssumedRoleCredential",
    "ConnectorCall",
    "StubConnector",
    # shared connectors
    "GitHubConnector",
    "LedgerConnector",
    "McpConnector",
    "PeerConnector",
    "SearchConnector",
    "TelegramConnector",
]
