"""host.py — the broker as a safe MCP host: compose gate + client + registry.

This is the assembly MCP-HOST.md's reference tier calls for: it wires the three
already-built parts into the broker's call path so "uncallable" is enforced at
*execute* time.

  * the thin ``client`` (client.py) materializes the live advertised definitions
    and runs calls — it holds NO admission logic;
  * the pure ``evaluate_discovery`` gate (discovery.py) decides, for every
    advertised tool, whether it is callable — NO I/O, NO writes;
  * the ``ToolRegistryStore`` (registry.py) is the admitted-tool store the gate
    reads (and the host NEVER writes — computed quarantine only, MCP-HOST.md).

``McpHost`` is per-server: it wraps ONE connected client and the manifest
declaration for that one server (``AgentManifest.mcp_servers[server_id]``). Its
two responsibilities:

  * ``refresh()`` — re-run discovery against the live advertised set, cache the
    ``DiscoveryResult`` snapshot for the session, and surface every failed-closed
    finding LOUDLY, exactly once per refresh (one ERROR log per finding, mirroring
    the loud grant-quarantine surfacing shape).
  * ``call()`` — refuse (``ToolNotCallableError`` carrying the ``ToolState``
    reason) unless the cached snapshot's verdict for the tool is ACTIVE; only then
    delegate to the client. With no refresh yet there is no snapshot, so
    EVERYTHING is uncallable — the host fails closed (MCP-HOST.md: "the running
    agent never auto-gains a tool").

The admission snapshot is a fetched input to every call's admission (#176; PTC
§6.13, GAL §6.15). ``refresh()`` stamps it with the instant read before the
advertised definitions and the registry rows are, and ``call()`` records that
instant as the ``mcp_admission`` as-of on the broker decision the call belongs
to. With a declared ``max_age`` (``AgentManifest.input_max_age_seconds``,
default none), a call that finds the snapshot past its age runs ``refresh()``
first and gates on the fresh snapshot, so a registry row withdrawn or quarantined
since the spawn stops the tool within that age rather than at the next respawn.
A refresh that fails raises, and the call is not made. With no age declared the
snapshot lasts the session, exactly as before.

The host adds no floor and no decision verb. A call that passes the ACTIVE gate is
still a normal ``external=True, effect="read"`` op the PDP gates per-call and whose
response self-taints as ``connector:<server_id>.<tool_name>`` with zero
changes to the PEP — that binding lives in ``mcp_connector.py``.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Optional

from safe_agents.broker.mcp.client import McpClient
from safe_agents.broker.mcp.discovery import (
    DiscoveryResult,
    RegistryRead,
    ToolState,
    ToolVerdict,
    evaluate_discovery,
)
from safe_agents.broker.mcp.registry import ToolRegistryStore
from safe_agents.broker.runtime.doer import ConnectorRefusedError
from safe_agents.broker.runtime.input_age import (
    Clock,
    establish_in_current_decision,
    utc_now,
)
from safe_agents.broker.schemas.mcp_registry import McpServerDecl

logger = logging.getLogger(__name__)


class ToolNotCallableError(ConnectorRefusedError):
    """The host refused a call: the tool is not ACTIVE in the cached snapshot.

    A REFUSAL, not a failure: two-key admission declined this call and
    nothing was attempted. Subclassing the marker is what keeps that visible on
    the audit tape instead of collapsing into `outcome="failed"` beside a
    crashed child.

    ``reason`` is the computed ``ToolState`` (DRIFTED / UNLISTED / DECLARED /
    QUARANTINED / WITHDRAWN) — or ``None`` when the host has no snapshot at all
    (no ``refresh()`` yet), which fails closed exactly like an un-admitted tool.
    ``detail`` is the human-readable cause carried up from the verdict.
    """

    def __init__(
        self,
        server_id: str,
        tool_name: str,
        reason: Optional[ToolState],
        detail: str,
    ) -> None:
        self.server_id = server_id
        self.tool_name = tool_name
        self.reason = reason
        self.detail = detail
        reason_str = reason.value if reason is not None else "no-snapshot"
        super().__init__(
            f"MCP tool {server_id}.{tool_name} is not callable ({reason_str}): {detail}"
        )


class McpHost:
    """Safe host for ONE MCP server: the discovery gate bound to a live client.

    Construct it with the manifest declaration for one ``server_id``, the admitted
    -tool registry store, and a connected ``McpClient`` for that same server. The
    ``server_id`` is taken from the client (OUR config, never the server's), and
    the manifest declaration is keyed under it for the pure gate.

    ``max_age`` is the declared maximum age of the admission snapshot (None, the
    default, declares none); ``clock`` is the instant source for its stamp and
    the age check, injectable for tests.
    """

    def __init__(
        self,
        server_decl: McpServerDecl,
        registry: ToolRegistryStore,
        client: McpClient,
        *,
        max_age: Optional[datetime.timedelta] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        self._server_id = client.server_id
        self._server_decl = server_decl
        self._registry = registry
        self._client = client
        self._max_age = max_age
        self._clock: Clock = clock or utc_now
        # None until the first refresh — no snapshot means EVERYTHING uncallable.
        self._snapshot: Optional[DiscoveryResult] = None
        # When the cached snapshot was fetched: read before its first read.
        self._snapshot_fetched_at: Optional[datetime.datetime] = None

    @property
    def server_id(self) -> str:
        return self._server_id

    @property
    def snapshot(self) -> Optional[DiscoveryResult]:
        """The last cached discovery snapshot (None before the first refresh)."""
        return self._snapshot

    @property
    def snapshot_fetched_at(self) -> Optional[datetime.datetime]:
        """The instant the cached snapshot was fetched (None before the first refresh)."""
        return self._snapshot_fetched_at

    async def refresh(self) -> DiscoveryResult:
        """Re-run discovery against the live advertised set; cache + surface.

        Pulls the advertised definitions via the client, reads the registry rows
        the gate needs (every declared tool AND every advertised tool, so a tool
        the server stopped advertising is still seen as WITHDRAWN), runs the pure
        ``evaluate_discovery``, caches the resulting snapshot for the session, and
        logs one ERROR per finding — exactly once per refresh (MCP-HOST.md M5).
        The snapshot's fetch instant is read BEFORE either read, which can only
        make it look older than it is (#176).
        """
        fetched_at = self._clock()
        advertised = await self._client.list_tool_defs()
        registry_reads = self._gather_reads(
            advertised_names={d.tool_name for d in advertised}
        )
        result = evaluate_discovery(
            manifest_decl={self._server_id: self._server_decl},
            registry_reads=registry_reads,
            advertised=advertised,
        )
        # Set together, with no await between: a call never pairs one
        # snapshot with another's instant.
        self._snapshot = result
        self._snapshot_fetched_at = fetched_at
        self._surface_findings(result)
        return result

    async def call(self, tool_name: str, arguments: Optional[dict] = None) -> Any:
        """Delegate to the client ONLY if the snapshot verdict is ACTIVE.

        No snapshot (no refresh yet) → refuse with ``reason=None`` (fail closed).
        A non-ACTIVE verdict → refuse with that verdict's ``ToolState``. Never
        calls the client on a refused tool — the refusal precedes any transport.

        A snapshot past its declared maximum age is fetched again first (#176),
        and the instant of the snapshot the call is gated on is recorded on the
        decision in progress, refused or not.
        """
        if self._snapshot is not None and self._snapshot_past_age():
            logger.info(
                "MCP server %r admission snapshot past its maximum age; "
                "re-running discovery before the call",
                self._server_id,
            )
            await self.refresh()
        if self._snapshot is None:
            raise ToolNotCallableError(
                self._server_id,
                tool_name,
                reason=None,
                detail="no discovery snapshot; refresh() before any call (fail closed)",
            )
        assert self._snapshot_fetched_at is not None
        establish_in_current_decision("mcp_admission", self._snapshot_fetched_at)
        if not self._snapshot.is_callable(self._server_id, tool_name):
            verdict = self._verdict_for(tool_name)
            raise ToolNotCallableError(
                self._server_id,
                tool_name,
                reason=verdict.state if verdict is not None else None,
                detail=(verdict.detail or verdict.state.value)
                if verdict is not None
                else "tool has no verdict in the current snapshot (not advertised)",
            )
        return await self._client.call_tool(tool_name, arguments or {})

    # -- internals ----------------------------------------------------------

    def _snapshot_past_age(self) -> bool:
        """True when a maximum age is declared and the snapshot has reached it."""
        if self._max_age is None or self._snapshot_fetched_at is None:
            return False
        try:
            end = self._snapshot_fetched_at + self._max_age
        except OverflowError:
            return False  # an end past the last representable instant: no bound
        return self._clock() >= end

    def _gather_reads(
        self, advertised_names: set[str]
    ) -> dict[tuple[str, str], RegistryRead]:
        """Read the registry rows the gate needs, adapting ``ToolReadResult``.

        The union of declared and advertised tool names: the declared set lets the
        gate flag a WITHDRAWN admitted tool the server stopped advertising; the
        advertised set covers everything currently on the wire (incl. UNLISTED).
        The host is the store's only reader here; the gate never touches the store.
        """
        names = {d.tool_name for d in self._server_decl.tools} | advertised_names
        reads: dict[tuple[str, str], RegistryRead] = {}
        for tool_name in names:
            read_result = self._registry.get_tool(self._server_id, tool_name)
            reads[(self._server_id, tool_name)] = RegistryRead(
                row=read_result.tool,
                hmac_quarantined=read_result.quarantined,
            )
        return reads

    def _verdict_for(self, tool_name: str) -> Optional[ToolVerdict]:
        if self._snapshot is None:
            return None
        for verdict in self._snapshot.verdicts:
            if verdict.server_id == self._server_id and verdict.tool_name == tool_name:
                return verdict
        return None

    def _surface_findings(self, result: DiscoveryResult) -> None:
        """One ERROR log per finding (MCP-HOST.md M5, the loud-quarantine shape).

        The findings are a per-refresh snapshot: the gate emits exactly one per
        failed-closed ``(server_id, tool_name)``, so a plain loop here logs each
        once and never floods per call.
        """
        for finding in result.findings:
            logger.error(
                "MCP tool quarantined at discovery: %s.%s reason=%s detail=%s",
                finding.server_id,
                finding.tool_name,
                finding.reason.value,
                finding.detail,
            )
