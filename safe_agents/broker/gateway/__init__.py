"""gateway — the broker presenting as one MCP server.

The broker's second mouth. The first is the JSON-over-HTTP `/call` handler in
`prototype/broker_server.py`; this one speaks MCP, over stdio or over streamable
HTTP (the network MCP mouth), so a wrapped agent
sees exactly ONE MCP server, whose tools are the ops the broker will serve it.
Admitted tools proxy through the full per-call path — PDP decision, taint,
budgets, audit — because they proxy through `handle_request` like every other
caller.

Built base-side [ruling: maintainer, 2026-07-25]: a mouth belongs with the thing it is a
mouth of. The product wrapper configures and launches this; it does not implement it.

Split the way the client side is already split:

  - `surface.py` — pure, SDK-free: what is advertised and what is answered.
  - `authn.py`   — pure, standard library only: who may speak on the network
    MCP mouth (the closed authenticator catalog) and how refusals are recorded.
  - `network.py` — pure, SDK-free: the guard in front of every network request,
    the serialization of calls into the runtime, and the launch settings.
  - `server.py`  — the thin `mcp` SDK binding, imported lazily.

`safe_agents.broker.gateway` therefore imports with the optional `mcp` extra
absent; only `build_server` / `serve_stdio` / `NetworkMouth.serve` require it.
"""

from safe_agents.broker.gateway.surface import (
    GatewayNameCollision,
    GatewayResult,
    GatewaySurface,
    GatewayTool,
)

__all__ = [
    "GatewaySurface",
    "GatewayTool",
    "GatewayResult",
    "GatewayNameCollision",
]
