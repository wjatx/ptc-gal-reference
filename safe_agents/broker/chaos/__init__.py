"""broker.chaos — failure-injection harness for the broker substrate.

Provides fault-injecting fakes that implement the same Protocols as the real
broker dependencies (EnforcementStore, AuditSink, SecretsProvider, Connector)
but raise or error on command.  Wire these into BrokerRuntime instead of the
real implementations to exercise the broker's behavior under dependency failure.

The invariant being verified: every injected fault produces a loud failure
(an exception propagating to the caller) — never a silent success where the
broker returns decision_kind="allow" as if nothing went wrong.

Exports:
    FaultEnforcementStore  — raises on configured EnforcementStore operations.
    FaultAuditSink         — raises on AuditSink.append().
    FaultSecretsProvider   — raises on SecretsProvider.fetch_secret().
    FaultConnector         — raises on Connector.execute().
    StoreError             — domain error for store faults.
    AuditError             — domain error for audit-sink faults.
    SecretsError           — domain error for secrets faults.
    ConnectorError         — domain error for connector faults.
"""

from .fakes import (
    AuditError,
    ConnectorError,
    FaultAuditSink,
    FaultConnector,
    FaultEnforcementStore,
    FaultSecretsProvider,
    SecretsError,
    StoreError,
)

__all__ = [
    "FaultEnforcementStore",
    "FaultAuditSink",
    "FaultSecretsProvider",
    "FaultConnector",
    "StoreError",
    "AuditError",
    "SecretsError",
    "ConnectorError",
]
