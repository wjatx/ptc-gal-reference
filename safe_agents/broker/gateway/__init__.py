"""gateway — the broker presenting as one MCP server (#283).

The broker's second mouth. The first is the JSON-over-HTTP `/call` handler in
`prototype/broker_server.py`; this one speaks MCP over stdio so a wrapped agent
sees exactly ONE MCP server, whose tools are the ops the broker will serve it.
Admitted tools proxy through the full per-call path — PDP decision, taint,
budgets, audit — because they proxy through `handle_request` like every other
caller.

Built base-side [ruling: maintainer, 2026-07-25]: a mouth belongs with the thing it is a
mouth of. The product wrapper configures and launches this; it does not implement it.

Two modules, split the way the client side is already split:

  - `surface.py` — pure, SDK-free: what is advertised and what is answered.
  - `server.py`  — the thin `mcp` SDK binding, imported lazily.

`safe_agents.broker.gateway` therefore imports with the optional `mcp` extra
absent; only `build_server` / `serve_stdio` require it.
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
