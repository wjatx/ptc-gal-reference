"""Connector protocol and stub connector for tests.

The Doer is the ONLY holder of Connector implementations. The agent process
never receives a Connector reference — the only path to a connector is through
the broker (Doer → connector). "Call the API directly" is not a path that exists
from anything the agent can reach.

Exports:
    Connector             — Protocol the Doer dispatches to.
    Credential            — the value a connector receives: a static string OR a
                            richer, broker-resolved credential (an assumed-role bundle).
    AssumedRoleCredential — the STS-assumed-role bundle a scoped connector runs with
                            (#175); the credential is an identity, not a static secret.
    ConnectorCall         — Record of one call made to a StubConnector (test inspection).
    StubConnector         — Deterministic fake for tests; no network, no real credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Union, runtime_checkable


@dataclass(frozen=True)
class AssumedRoleCredential:
    """Short-lived STS credentials from a per-capability assumed role (#175).

    The ``assumed_role`` strategy (``credentials.AssumedRole``) resolves this
    broker-side by assuming a role the deploy scoped to exactly the capability's
    declared IAM. Only these short-lived credentials reach the connector — never a
    long-lived key, never the broker's own identity (doctrine 1 + doctrine 2:
    the credential is an *identity*, so scope that identity to the declared
    capability). A connector consumes it as, e.g., a boto3 session.

    ``str()`` deliberately renders only the (non-secret) access-key id — the secret
    key and session token must never surface in a log, exception, or the audit tape,
    so ``redaction_values()`` names exactly the substrings the Doer scrubs from any
    connector error.
    """

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: str | None = None  # ISO-8601, informational; not a secret

    def redaction_values(self) -> tuple[str, ...]:
        """The sensitive substrings the Doer must strip from a connector exception.

        The access-key id is an identifier (it appears in CloudTrail) and is left
        visible for debugging; the secret key and session token are the material
        that must never leak.
        """
        return tuple(v for v in (self.secret_access_key, self.session_token) if v)

    def __str__(self) -> str:
        return f"<AssumedRoleCredential akid={self.access_key_id!r} expires={self.expiration!r}>"


# What a connector's ``execute`` receives. The default (static secret / OAuth access
# token) is a plain ``str`` — unchanged since before #173. A per-capability scoped
# connector (#175) instead receives an ``AssumedRoleCredential`` bundle. A connector
# handles only the credential shape its own auth strategy produces.
Credential = Union[str, AssumedRoleCredential]


@runtime_checkable
class Connector(Protocol):
    """Minimal interface a connector must expose to the Doer.

    The Doer calls execute(tool, op, args, credential) with the broker-resolved
    credential. The credential never reaches the agent; the Connector is never
    exposed outside the Doer. ``credential`` is a plain ``str`` for the static/OAuth
    strategies and an ``AssumedRoleCredential`` for the ``assumed_role`` strategy (#175).
    """

    def execute(self, tool: str, op: str, args: Any, credential: Credential) -> Any:
        """Execute the tool op with the broker-provided credential."""
        ...


@dataclass
class ConnectorCall:
    """Record of a single call made to a StubConnector.

    Used in tests to assert what the Doer actually dispatched to the connector
    and that the credential was injected correctly.
    """

    tool: str
    op: str
    args: Any
    credential: Credential
    result: Any


class StubConnector:
    """Deterministic stub connector for tests. No network, no real credentials.

    Records all calls for assertion. Returns a configurable result value.
    """

    def __init__(self, result: Any = None) -> None:
        self._result: Any = result if result is not None else {"status": "ok"}
        self._calls: list[ConnectorCall] = []

    def execute(self, tool: str, op: str, args: Any, credential: Credential) -> Any:
        call = ConnectorCall(
            tool=tool,
            op=op,
            args=args,
            credential=credential,
            result=self._result,
        )
        self._calls.append(call)
        return self._result

    @property
    def calls(self) -> list[ConnectorCall]:
        """Snapshot of all calls made to this stub (read-only copy)."""
        return list(self._calls)

