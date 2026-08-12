"""Capability-confined doer — the only component that holds connector tools.

The Doer executes an allowed or transformed BrokeredCall and nothing else. It:
  - holds the (stub / real) Connector implementations by tool name
  - fetches the connector credential from the injected SecretsProvider at execute time
  - never exposes the credential outside this function scope
  - is the only path through which a connector can be reached

The broker runtime (PEP) holds a Doer reference internally and only forwards
approved calls to it. The agent never sees a Doer, a Connector, or a credential
value — these cross-boundary invariants are:
  1. documented here (design intent)
  2. enforced by the PEP never exposing the Doer through its public surface
  3. test-asserted in broker/tests/test_runtime.py (confinement test)

Confinement guards:
  - execute() raises ConfinementError when called with any decision other than
    allow or transform — the Doer is not an approval path.
  - The credential is fetched lazily inside execute() and never stored on self.
  - A connector exception is re-raised as ConnectorExecutionError with the credential
    redacted from its message — the Doer is the only layer that holds the credential,
    so it is the only place that can guarantee the secret never rides out on an
    exception into the audit 'error' field, the WAL, or a log line.

Exports:
    Doer                    — the capability-confined executor.
    DoerResult              — outcome of one execute() call (no credential field).
    ConfinementError        — raised when execute() gets a non-permitted decision.
    ConnectorExecutionError — raised when the underlying connector call fails (credential
                              redacted); carries a clean, secret-free message.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from safe_agents.broker.schemas import BrokeredCall, Decision
from safe_agents.broker.schemas.decision import Transform

from .connector import Connector, Credential
from .credentials import CredentialProvider, StaticSecret
from .secrets import SecretsProvider

logger = logging.getLogger(__name__)


_REDACTION = "***redacted-credential***"


def _redaction_values(credential: Credential) -> tuple[str, ...]:
    """The sensitive substrings to scrub from a connector error, for any credential shape.

    A static/OAuth credential is a plain string — the whole thing is sensitive. A
    richer credential (an ``AssumedRoleCredential`` bundle) names its own sensitive
    fields via ``redaction_values()`` (the secret key + session token, not the
    non-secret access-key id). Either way the Doer scrubs exactly those substrings.
    """
    method = getattr(credential, "redaction_values", None)
    if callable(method):
        return tuple(v for v in method() if v)
    return (credential,) if isinstance(credential, str) and credential else ()


def _redact(text: str, credential: Credential) -> str:
    """Return ``text`` with every sensitive substring of ``credential`` replaced.

    The Doer is the only component that both holds the credential and sees connector
    exceptions, so redaction happens here — a misbehaving connector that embeds the
    token (or any bundle field) in its error message cannot leak it past this boundary.
    """
    for secret in _redaction_values(credential):
        if secret in text:
            text = text.replace(secret, _REDACTION)
    return text


class ConfinementError(Exception):
    """Raised when the Doer is asked to execute a non-permitted decision.

    Only allow and transform decisions may cause connector execution. Any
    other decision kind reaching the Doer signals a wiring error in the PEP.
    """


class ConnectorRefusedError(Exception):
    """A control inside the connector REFUSED this call; nothing was attempted.

    The marker that separates "policy said no" from "the effect broke" at the
    execution layer (#281). A connector-side gate raises a subclass of this; a
    network timeout, a 500 or a crashed child does not.

    It exists because the two are indistinguishable on the audit tape otherwise:
    both arrive at the PEP as a failed connector call, so a refusal counts as an
    execution failure and anything counting refusals sees none. The base defines
    the marker rather than naming any particular gate, so a connector can signal
    a refusal without the PEP importing that connector's exception types
    (``mcp.host.ToolNotCallableError`` is the first, and deliberately not the
    only conceivable, subclass).
    """


class ConnectorExecutionError(Exception):
    """Raised when the underlying connector call fails.

    Wraps the connector's exception with the credential redacted from the message.
    The original exception is intentionally NOT chained (``raise ... from None``) so
    that neither its ``str()`` nor its ``args`` — which a careless connector might have
    populated with the token — can surface through ``__cause__`` in a traceback.

    ``refused`` carries the one bit that survives that deliberate un-chaining: was
    the underlying exception a :class:`ConnectorRefusedError`? The exception object
    itself must not be chained (it may carry a credential in its args), but its
    TYPE is not secret, so the classification is lifted out before the original is
    dropped. Without this the PEP cannot tell a refusal from a failure, and #281
    is exactly that gap.
    """

    def __init__(self, message: str, *, refused: bool = False) -> None:
        super().__init__(message)
        self.refused = refused


@dataclass
class DoerResult:
    """Outcome of a single Doer.execute() call.

    Contains no credential value — the credential was used inside execute()
    and discarded. The agent-facing surface receives only this object.
    """

    tool: str
    op: str
    result: Any


class Doer:
    """The capability-confined executor. Only the Doer holds Connector references.

    Constructed by the broker runtime at startup. The agent process never
    receives a Doer reference; the PEP holds it internally and forwards only
    calls whose effective decision is allow or transform.

    Parameters
    ----------
    connectors:
        Mapping from tool name to Connector implementation. An absent tool name
        means no connector is registered; execute() raises ValueError.
    secrets:
        SecretsProvider injected at construction. The Doer calls fetch_secret()
        inside execute() — the credential is fetched lazily, used, and discarded.
    secret_name_for:
        Optional callable to map a tool name to the Secrets Manager secret leaf.
        Defaults to the tool name itself (e.g. tool="email" → secret leaf "email").
        Whatever this returns is what the injected SecretsProvider receives — so if
        that provider prefixes (``_PrefixedSecrets`` wraps a leaf to
        ``<prefix>/connectors/<leaf>``, sa#164), the returned value is a *leaf* under
        that prefix, not a full secret id.
    credential_strategies:
        Optional mapping from tool name to a CredentialProvider (#173). A strategy
        resolves the *live* credential at execute time — StaticSecret fetches the
        leaf verbatim (the pre-#173 behavior), OAuthRefresh mints an access token
        from a broker-held refresh token, etc. A tool absent from this map falls back
        to StaticSecret, so an empty/omitted map is byte-for-byte the old behavior.
        Whichever strategy runs, only the resolved credential reaches the connector —
        the agent never sees it, and long-lived material (a refresh token) stays here.
    """

    def __init__(
        self,
        connectors: dict[str, Connector],
        secrets: SecretsProvider,
        secret_name_for: Callable[[str], str] | None = None,
        credential_strategies: dict[str, CredentialProvider] | None = None,
    ) -> None:
        self._connectors = dict(connectors)
        self._secrets = secrets
        self._secret_name_for = secret_name_for or (lambda tool: tool)
        self._credential_strategies = dict(credential_strategies or {})
        self._default_strategy = StaticSecret()

    def execute(self, call: BrokeredCall, decision: Decision) -> DoerResult:
        """Execute the call against the registered connector.

        Only allow and transform decisions are permitted. Any other decision
        raises ConfinementError — the Doer is not an approval or audit path.

        The connector credential is fetched here, passed to the connector, and
        never returned. DoerResult carries only the connector's opaque result.

        Parameters
        ----------
        call:
            The BrokeredCall approved by the enforcement layer.
        decision:
            The effective Decision from enforce(). Must be Allow or Transform.

        Returns
        -------
        DoerResult
            Contains tool, effective op, and the connector's result. No credential.

        Raises
        ------
        ConfinementError
            If decision.kind is not allow or transform.
        ValueError
            If no connector is registered for call.tool.
        """
        if decision.kind not in ("allow", "transform"):
            raise ConfinementError(
                f"doer.execute called with non-permitted decision {decision.kind!r}; "
                "only allow/transform may trigger connector execution"
            )

        connector = self._connectors.get(call.tool)
        if connector is None:
            raise ValueError(f"no connector registered for tool {call.tool!r}")

        # For transform: use the substituted op/args from the decision.
        # For allow: use the call's original op/args verbatim.
        if isinstance(decision, Transform):
            op = decision.op
            args = decision.args
        else:
            op = call.op
            args = call.args

        # Credential resolved at execute time — never stored on self, never returned.
        # The per-tool strategy (#173) resolves the LIVE credential: StaticSecret
        # fetches the leaf verbatim (unchanged), a non-static strategy mints/assumes
        # it broker-side. Long-lived material stays inside the strategy; only the
        # resolved credential crosses into the connector below.
        #
        # UNLESS the connector declares it does not take one. An MCP connector is
        # the case: its session is already authenticated, so it documents
        # `credential` as unused and the host resolves its own credential per
        # CONNECT instead (M25). Resolving here anyway is not merely wasted work —
        # against a vendor issuing ONE-TIME-USE refresh tokens (which OAuth 2.1
        # recommends for public clients) it SPENDS the credential the connect then
        # needs, so a single brokered call burns two grants and fails on the
        # second. Found live against a real brokerage in #238; a static secret hides it
        # completely, which is why every prior proof passed.
        strategy = self._credential_strategies.get(call.tool, self._default_strategy)
        if getattr(connector, "uses_credential", True):
            credential = strategy.resolve(
                secrets=self._secrets, secret_name=self._secret_name_for(call.tool)
            )
        else:
            credential = ""

        try:
            result = connector.execute(call.tool, op, args, credential)
        except Exception as exc:
            # Defense in depth: strip the credential from the failure message before it
            # can reach the audit 'error' field, the WAL, or any log. from None keeps the
            # original (possibly secret-bearing) exception out of the chained traceback.
            refused = isinstance(exc, ConnectorRefusedError)
            verb = "refused" if refused else "failed"
            raise ConnectorExecutionError(
                f"connector {call.tool!r} op {op!r} {verb}: {_redact(str(exc), credential)}",
                refused=refused,
            ) from None
        return DoerResult(tool=call.tool, op=op, result=result)

    def close(self) -> None:
        """Close every connector that exposes ``close()`` (best-effort, loud).

        The service-shutdown half of MCP-HOST.md M20: a connector owning OS
        resources — an MCP stdio child and its private event loop — reaps them
        in ``close()``, so driving each one here, BEFORE process exit, is what
        makes a SIGTERM'd broker task reap its children in order instead of
        abandoning them to the container teardown. One connector's failure
        never blocks another's close; failures log by connector NAME and
        exception TYPE only (never a message that could carry call detail).
        """
        for name, connector in self._connectors.items():
            connector_close = getattr(connector, "close", None)
            if connector_close is None:
                continue
            try:
                connector_close()
            except Exception as exc:  # noqa: BLE001 — best-effort teardown
                logger.error(
                    "connector %r close() failed: %s", name, type(exc).__name__
                )
