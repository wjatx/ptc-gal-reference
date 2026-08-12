"""host.py — the broker as a safe MCP host: compose gate + client + registry (#174).

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
    the sa#124 quarantine-surfacing shape).
  * ``call()`` — refuse (``ToolNotCallableError`` carrying the ``ToolState``
    reason) unless the cached snapshot's verdict for the tool is ACTIVE; only then
    delegate to the client. With no refresh yet there is no snapshot, so
    EVERYTHING is uncallable — the host fails closed (MCP-HOST.md: "the running
    agent never auto-gains a tool").

The host adds no floor and no decision verb. A call that passes the ACTIVE gate is
still a normal ``external=True, effect="read"`` op the PDP gates per-call and whose
response self-taints as ``connector:<server_id>.<tool_name>`` (sa#134) with zero
changes to the PEP — that binding lives in ``mcp_connector.py``.
"""

from __future__ import annotations

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
from safe_agents.broker.schemas.mcp_registry import McpServerDecl

logger = logging.getLogger(__name__)


class ToolNotCallableError(ConnectorRefusedError):
    """The host refused a call: the tool is not ACTIVE in the cached snapshot.

    A REFUSAL, not a failure (#281): two-key admission declined this call and
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
    """

    def __init__(
        self,
        server_decl: McpServerDecl,
        registry: ToolRegistryStore,
        client: McpClient,
    ) -> None:
        self._server_id = client.server_id
        self._server_decl = server_decl
        self._registry = registry
        self._client = client
        # None until the first refresh — no snapshot means EVERYTHING uncallable.
        self._snapshot: Optional[DiscoveryResult] = None

    @property
    def server_id(self) -> str:
        return self._server_id

    @property
    def snapshot(self) -> Optional[DiscoveryResult]:
        """The last cached discovery snapshot (None before the first refresh)."""
        return self._snapshot

    async def refresh(self) -> DiscoveryResult:
        """Re-run discovery against the live advertised set; cache + surface.

        Pulls the advertised definitions via the client, reads the registry rows
        the gate needs (every declared tool AND every advertised tool, so a tool
        the server stopped advertising is still seen as WITHDRAWN), runs the pure
        ``evaluate_discovery``, caches the resulting snapshot for the session, and
        logs one ERROR per finding — exactly once per refresh (MCP-HOST.md M5).
        """
        advertised = await self._client.list_tool_defs()
        registry_reads = self._gather_reads(
            advertised_names={d.tool_name for d in advertised}
        )
        result = evaluate_discovery(
            manifest_decl={self._server_id: self._server_decl},
            registry_reads=registry_reads,
            advertised=advertised,
        )
        self._snapshot = result
        self._surface_findings(result)
        return result

    async def call(self, tool_name: str, arguments: Optional[dict] = None) -> Any:
        """Delegate to the client ONLY if the snapshot verdict is ACTIVE.

        No snapshot (no refresh yet) → refuse with ``reason=None`` (fail closed).
        A non-ACTIVE verdict → refuse with that verdict's ``ToolState``. Never
        calls the client on a refused tool — the refusal precedes any transport.
        """
        if self._snapshot is None:
            raise ToolNotCallableError(
                self._server_id,
                tool_name,
                reason=None,
                detail="no discovery snapshot; refresh() before any call (fail closed)",
            )
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
        """One ERROR log per finding (MCP-HOST.md M5, the sa#124 loud shape).

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
