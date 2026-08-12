"""Launch the broker's MCP gateway over stdio.

    python -m safe_agents.broker.gateway

This is what a wrapped harness spawns: one process holding one `BrokerRuntime`,
speaking MCP on stdin/stdout. The harness's MCP config points here, and every tool
call it makes is decided and recorded before it executes.

Configuration comes from the environment exactly as the HTTP mouth's does — the
manifest from `BROKER_MANIFEST`, the backends from `BROKER_STORE` / `BROKER_SECRETS`
/ the audit variables — so the gateway introduces no second config surface. On a
durable store arm an unnamed manifest REFUSES rather than falling back to the
checked-in example (`boot_config.resolve_manifest_path`, #197/#199): a defaulted
manifest silently substitutes another agent's principal, grants and envelope, and
`docs/config-provenance.md` is why that must fail loudly.

**stdout belongs to the protocol.** MCP over stdio puts JSON-RPC frames on stdout,
so anything else printed there corrupts the stream. `build_runtime` prints its
backend banner (`[broker] store backend: ...`), which is useful and must not be
lost — so it is redirected to stderr for the duration of the build. This is the
kind of thing that works in every test and breaks the moment a real client
connects, which is why it is handled here rather than discovered later.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys

from safe_agents.broker.api import build_runtime
from safe_agents.broker.gateway.surface import GatewaySurface
from safe_agents.broker.gateway.server import serve_stdio
from safe_agents.broker.prototype.boot_config import load_named_manifest


def main() -> None:
    manifest = load_named_manifest()

    # Compose with stdout redirected to stderr: the banner is diagnostics, and the
    # protocol owns stdout from here on.
    with contextlib.redirect_stdout(sys.stderr):
        runtime, _sink = build_runtime(manifest)
        surface = GatewaySurface(runtime)
        print(
            f"[broker] MCP gateway ready: {len(surface.tools())} tool(s) "
            f"for {manifest.principal.agentId if manifest.principal else '?'}",
            file=sys.stderr,
        )

    try:
        asyncio.run(serve_stdio(surface))
    finally:
        # MCP-HOST.md M20: reap any connector-held child before the process exits.
        runtime.close()


if __name__ == "__main__":
    main()
