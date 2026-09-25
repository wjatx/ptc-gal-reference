"""broker.runtime — capability-confined doer + broker runtime process.

Composes the built broker modules into one running round-trip:
  registry → taint → BrokeredCall → decide → enforce → doer → audit

The agent's only egress is handle_request(). The Doer is the only holder of
Connector references and the SecretsProvider; neither escapes to the agent surface.

Public API:

  BrokerRuntime    — the full broker runtime; call handle_request() per tool call.
  AgentRequest     — the raw (tool, op, args) from the agent.
  BrokerResponse   — the broker's reply; contains no credential value.
  Doer             — capability-confined executor; compose into BrokerRuntime.
  DoerResult       — outcome of one execute() call.
  ConfinementError — raised by Doer when called with a non-permitted decision.
  ConnectorExecutionError — raised by Doer when the connector call fails (credential redacted).
  CredentialResolutionError — the ConnectorExecutionError raised when the credential cannot be resolved.
  SecretsProvider  — Protocol for credential fetch (injected into Doer).
  FakeSecretsProvider          — in-memory fake for tests.
  LocalFileSecretsProvider     — reads creds from a 0600 JSON file (local arm).
  DirSecretsProvider           — one file per secret leaf under a mount dir (#248).
  LazyBotoSecretsProvider      — lazy boto3 Secrets Manager for deployment.
  Connector        — Protocol for connector tools (held only by the Doer).
  StubConnector    — deterministic stub for tests; records calls.
  ConnectorCall    — record of one StubConnector call (for test assertions).
"""

from safe_agents.broker.marshal import marshal_connector_result

from .connector import AssumedRoleCredential, Connector, ConnectorCall, Credential, StubConnector
from .credentials import (
    AssumedRole,
    CredentialProvider,
    CredentialStrategyError,
    OAuthRefresh,
    StaticSecret,
    build_credential_strategies,
)
from .doer import (
    ConfinementError,
    ConnectorExecutionError,
    CredentialResolutionError,
    Doer,
    DoerResult,
)
from .pep import AgentRequest, BrokerResponse, BrokerRuntime
from .secrets import (
    DirSecretsProvider,
    FakeSecretsProvider,
    LazyBotoSecretsProvider,
    LocalFileSecretsProvider,
    SecretsProvider,
)

__all__ = [
    # runtime
    "BrokerRuntime",
    "AgentRequest",
    "BrokerResponse",
    # doer
    "Doer",
    "DoerResult",
    "ConfinementError",
    "ConnectorExecutionError",
    "CredentialResolutionError",
    # secrets
    "SecretsProvider",
    "FakeSecretsProvider",
    "LocalFileSecretsProvider",
    "DirSecretsProvider",
    "LazyBotoSecretsProvider",
    # connector
    "Connector",
    "marshal_connector_result",
    "Credential",
    "AssumedRoleCredential",
    "StubConnector",
    "ConnectorCall",
    # credential-resolution strategies (#173, #175)
    "CredentialProvider",
    "StaticSecret",
    "OAuthRefresh",
    "AssumedRole",
    "build_credential_strategies",
    "CredentialStrategyError",
]
