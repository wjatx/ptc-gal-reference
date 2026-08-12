"""client.py — the thin reference MCP client (#174, reference-tier).

One honest instantiation over the official `mcp` python SDK. It does exactly
three things and no more (MCP-HOST.md, "the thin MCP client"):

  * connect to an MCP server (a swappable transport sits behind the seam),
  * `tools/list` -> materialize a `list[McpToolDef]` the gate can hash,
  * `tools/call` -> execute one call.

It holds NO admission logic: it produces `McpToolDef`s and runs calls; the pure
`discovery.evaluate_discovery` gate decides what is callable. Crucially, the
`server_id` on every materialized `McpToolDef` comes from OUR config, never from
the server — a server cannot rename which namespace it belongs to.

The `mcp` SDK is an OPTIONAL extra (`pip install safe-agents[mcp]`). All SDK
imports are lazy (inside functions / TYPE_CHECKING only), so importing this
module — and the base package — never requires the extra; only the
`connect_*` transports (`connect_stdio`, `connect_streamable_http`) and
instantiating a live session touch it.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, AsyncIterator, Optional, Sequence

from safe_agents.broker.schemas.mcp_registry import McpToolDef

if TYPE_CHECKING:  # import only for type checkers — never at runtime
    from mcp import ClientSession


def _plain(value: Any) -> Any:
    """Coerce a possibly-pydantic SDK value to a plain JSON-able value.

    The SDK's own models are `extra="allow"`, so `model_dump(mode="json",
    exclude_none=True)` preserves any vendor-added keys losslessly. Anything
    without `model_dump` (already-plain dict/list/str/None) passes through
    unchanged. Module-private: this is a coercion detail of
    `_tool_def_from_sdk`, not a general utility.
    """
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    return value


def _tool_def_from_sdk(server_id: str, sdk_tool: Any) -> McpToolDef:
    """Map one SDK `Tool` to our `McpToolDef`.

    name -> tool_name, inputSchema -> input_schema, description -> description
    (absent/None becomes "" so the CORE hashed set is total).
    `server_id` is ours, never the server's — duck-typed on the SDK field
    names so this helper needs no SDK import and stays trivially testable.

    The remaining fields (title/outputSchema/icons/annotations/meta/execution)
    are advertised metadata — SIGNED since #223 when present — read via
    `getattr(..., None)` so an older/newer SDK lacking one degrades to `None`
    ("not advertised", which contributes nothing to the hash) rather than
    raising. Any pydantic-model value (or list of them, for `icons`) is
    coerced to a plain dict via `_plain` so the result stays JSON-serializable.
    """
    icons = getattr(sdk_tool, "icons", None)
    return McpToolDef(
        server_id=server_id,
        tool_name=sdk_tool.name,
        input_schema=dict(sdk_tool.inputSchema or {}),
        description=sdk_tool.description or "",
        title=getattr(sdk_tool, "title", None),
        output_schema=_plain(getattr(sdk_tool, "outputSchema", None)),
        icons=[_plain(icon) for icon in icons] if icons is not None else None,
        annotations=_plain(getattr(sdk_tool, "annotations", None)),
        meta=_plain(getattr(sdk_tool, "meta", None)),
        execution=_plain(getattr(sdk_tool, "execution", None)),
    )


class McpClient:
    """A thin wrapper over a connected MCP `ClientSession`.

    Construct it with an already-initialized session (the in-memory transport the
    tests use, or any transport `connect_stdio` opens). It never admits, hashes,
    or decides trust — it materializes definitions and runs calls.
    """

    def __init__(self, server_id: str, session: "ClientSession") -> None:
        self._server_id = server_id
        self._session = session

    @property
    def server_id(self) -> str:
        return self._server_id

    async def list_tool_defs(self) -> list[McpToolDef]:
        """`tools/list` -> the live advertised definitions, stamped with our
        `server_id`. Feed the result straight into `evaluate_discovery`."""
        listing = await self._session.list_tools()
        return [_tool_def_from_sdk(self._server_id, t) for t in listing.tools]

    async def call_tool(
        self, tool_name: str, arguments: Optional[dict] = None
    ) -> Any:
        """`tools/call` for one tool. Returns the SDK `CallToolResult` verbatim —
        the broker handles the response (taint, per-call PDP). Admission is the
        gate's job and must be checked BEFORE calling; this method does not."""
        return await self._session.call_tool(tool_name, arguments or {})


@asynccontextmanager
async def connect_stdio(
    server_id: str,
    command: str,
    args: Optional[Sequence[str]] = None,
    *,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> AsyncIterator[McpClient]:
    """Reference stdio transport: spawn an MCP server subprocess and yield a
    connected `McpClient`. Transport is reference-tier and swappable (MCP-HOST.md);
    this is one honest instantiation, not the contract. Requires the `mcp` extra.

    ``cwd``/``env`` are plain process plumbing (module resolution, PYTHONPATH).
    A provided ``env`` OVERLAYS the SDK's minimal default environment rather
    than replacing it (#221) — the SDK would otherwise spawn the child with
    ONLY the given dict, silently dropping ``PATH``/``HOME`` and breaking
    PATH-resolved commands; ``env=None`` (or ``{}``) spawns with the untouched
    minimal default, never the parent's full environment. Values are never
    logged here. Agent-side callers must never route secret material through
    this argument — the ONE sanctioned credential injector is the broker's own
    native construction path (``prototype/mcp_construction.py``), which
    resolves the credential broker-side at spawn time via the
    CredentialProvider catalog + ``connector_auth.env_map`` (#173/#221); the
    agent never sees the merged environment.
    """
    # Lazy SDK import — the only runtime dependency on the optional extra.
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import get_default_environment, stdio_client

    merged_env = {**get_default_environment(), **env} if env else None
    params = StdioServerParameters(
        command=command, args=list(args or []), cwd=cwd, env=merged_env
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield McpClient(server_id, session)


@asynccontextmanager
async def connect_streamable_http(
    server_id: str,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
) -> AsyncIterator[McpClient]:
    """Reference streamable-HTTP transport: connect to a REMOTE MCP server and
    yield a connected `McpClient` (MCP-HOST.md M21). Same tier as
    `connect_stdio` — reference-tier and swappable, one honest instantiation
    over the official SDK, not the contract. Requires the `mcp` extra.

    ``headers`` carries the resolved credential half for a remote server
    (MCP-HOST.md M25). Header VALUES are secret-adjacent by design and must
    never be logged or repr'd, here or by any caller — note the SDK's own
    transport does not log them either, but an exception carrying the httpx
    client would, which is why nothing here interpolates the client. The ONE
    sanctioned producer of this argument is the broker's native construction
    path (``prototype/mcp_construction.py``), which resolves the credential
    broker-side per connect via the CredentialProvider catalog +
    ``connector_auth.header_map``; the agent never sees it.

    The SDK's context yields ``(read_stream, write_stream, get_session_id)``;
    the session-id getter is deliberately unused — session resumption is not
    part of this slice (a reconnect is a NEW discovery, M18).
    """
    # Lazy SDK import — the only runtime dependency on the optional extra.
    # `streamable_http_client` (mcp>=1.25) takes no `headers`: HTTP settings
    # move to an injected httpx.AsyncClient, which is why migrating and
    # delivering credentials were ONE change (#237), not two. The client is
    # built by the SDK's own factory so MCP's defaults (follow_redirects, the
    # 30s/300s-SSE timeouts) stay the SDK's to choose rather than ours to
    # re-hardcode; if a future SDK moves it, this import fails LOUDLY at
    # connect rather than silently connecting on different defaults.
    from mcp import ClientSession
    from mcp.client.streamable_http import (
        create_mcp_http_client,
        streamable_http_client,
    )

    # The SDK closes only a client it created ITSELF ("if not client_provided"),
    # so an injected one is OURS to close — without this `async with`, every
    # reconnect under an M19 respawn policy would leak a connection pool.
    async with create_mcp_http_client(headers=headers) as http_client:
        async with streamable_http_client(url, http_client=http_client) as (
            read,
            write,
            _get_session_id,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield McpClient(server_id, session)
