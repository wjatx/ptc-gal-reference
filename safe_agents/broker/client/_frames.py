"""What the two gateway clients share: the frames, the three calls, the error.

A transport supplies two things, `request` and `notify`. Everything an MCP client
says on top of them is written here once, so the stdio client and the network
client cannot drift apart in what they send or in how they read a result.

Standard library only, and nothing from the rest of the base: this package is
published on the ground that it carries frames and consults nothing
(`safe_agents/broker/client/__init__.py`).
"""

from __future__ import annotations

from typing import Any

# A cold interpreter importing pydantic, the SDK and the broker takes a few seconds
# on a slow machine. Generous, because a timeout here reads as a hang, not a bug.
DEFAULT_TIMEOUT_SECONDS = 60.0

# The protocol revision these clients offer. The server answers with the revision it
# will speak; the clients use only initialize, tools/list and tools/call, which every
# revision carries in the same shape.
PROTOCOL_VERSION = "2025-06-18"

JSONRPC_VERSION = "2.0"


class GatewayClientError(RuntimeError):
    """The gateway did not answer as an MCP server should.

    For the stdio client this carries the child's stderr, so the message says why,
    which is almost always a refusal to boot printed there (an unrecognized secrets
    arm, a missing manifest). The network client has no stderr to carry and leaves
    it empty.
    """

    def __init__(self, message: str, stderr: str = "") -> None:
        detail = f"{message}\n--- gateway stderr ---\n{stderr.rstrip()}" if stderr.strip() else message
        super().__init__(detail)
        self.stderr = stderr


def result_text(result: dict[str, Any]) -> str:
    """The text blocks of a `tools/call` result, joined."""
    return "\n".join(
        block.get("text", "") for block in result.get("content", []) if block.get("type") == "text"
    )


def request_frame(request_id: int, method: str, params: dict[str, Any] | None) -> dict[str, Any]:
    frame: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": request_id, "method": method}
    if params is not None:
        frame["params"] = params
    return frame


def notification_frame(method: str, params: dict[str, Any] | None) -> dict[str, Any]:
    frame: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params is not None:
        frame["params"] = params
    return frame


def result_of(frame: dict[str, Any], method: str) -> dict[str, Any]:
    """The `result` of the reply to `method`, or the JSON-RPC error raised in words."""
    if "error" in frame:
        raise GatewayClientError(f"{method!r} returned a JSON-RPC error: {frame['error']}")
    return frame["result"]


class McpCalls:
    """The calls an MCP client makes, over whatever `request` and `notify` carry them."""

    #: What this client calls itself in `initialize`.
    client_name = "safe-agents-client"

    _next_id = 1

    def _take_id(self) -> int:
        request_id = self._next_id
        self._next_id = request_id + 1
        return request_id

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError

    def initialize(self, client_name: str | None = None) -> dict[str, Any]:
        """The handshake: initialize, then the initialized notification."""
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": client_name or self.client_name, "version": "0"},
            },
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self.request("tools/list")["tools"])

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """The raw `tools/call` result: `content` blocks plus `isError`."""
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})
