"""streamable_http_toy_server — a test-only MCP server over streamable-HTTP (#221 P4).

Spawned as a REAL subprocess by the M21 suite (test_mcp_streamable_http.py) so
the streamable-HTTP transport path is exercised against a genuine remote peer:
killing this process is a real session death, restarting it is a real reconnect
target. Loopback plain-http is the sanctioned M21 carve-out — the server binds
127.0.0.1 only, on the port given as argv[1].

Three tools, all structured output (typed models, matching the fixture
convention of env_echo_server.py): `echo` and `add` are the admitted pair the
suite declares in its `McpServerDecl`; `shout` is deliberately NOT declared, so
it exercises the UNLISTED verdict — a store row alone cannot mint it callable
(MCP-HOST.md M3/M4).

Run:  python safe_agents/broker/tests/fixtures/streamable_http_toy_server.py <port>
"""
from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


class EchoReply(BaseModel):
    """The echoed text — structured output."""

    text: str


class Sum(BaseModel):
    """The integer sum — structured output."""

    total: int


class Shout(BaseModel):
    """The uppercased text — structured output."""

    text: str


def build(port: int) -> FastMCP:
    server = FastMCP("toyhttp", host="127.0.0.1", port=port)

    @server.tool()
    def echo(text: str) -> EchoReply:
        """Echo the given text back unchanged."""
        return EchoReply(text=text)

    @server.tool()
    def add(a: int, b: int) -> Sum:
        """Add two integers."""
        return Sum(total=a + b)

    @server.tool()
    def shout(text: str) -> Shout:
        """Uppercase the given text (the suite leaves this tool undeclared)."""
        return Shout(text=text.upper())

    return server


if __name__ == "__main__":
    build(int(sys.argv[1])).run(transport="streamable-http")
