"""Watch the broker decide three tool calls, without writing any JSON-RPC by hand.

    python -m safe_agents.broker.gateway.demo [--verbose]

Starts the MCP gateway (`python -m safe_agents.broker.gateway`) as a child process
with this shell's environment, connects to it as an MCP client over stdio, and makes
three calls in order:

  1. `payments__transfer`, which the example manifest never declared. The broker
     refuses it; nothing executes.
  2. `search__query`, a declared read of external content. With the placeholder
     credential that ships, the broker allows it and Tavily then rejects the key.
     With your own key (`python -m safe_agents.broker.gateway.set_search_key`) it
     succeeds, and a successful external read taints the turn.
  3. `notify__send`, a declared external write. After a successful search it is held
     for approval by the taint floor. Without one it reaches its connector, which has
     no credential configured.

The gateway's stderr (its backend banner, including which secrets arm is in force)
is captured and shown only with `--verbose`, so the default output is the calls and
the replies.

It works the same way in PowerShell, where a `printf` pipe into the gateway does not.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from safe_agents.broker.gateway.stdio_client import (
    GatewayClient,
    GatewayClientError,
    result_text,
)

# A search reply is a JSON document of results. Enough lines to show it worked,
# few enough that the next step stays on screen.
_MAX_REPLY_LINES = 12


@dataclass(frozen=True)
class Step:
    title: str
    tool: str
    arguments: dict[str, Any]


STEPS: tuple[Step, ...] = (
    Step(
        "A tool the manifest never declared",
        "payments__transfer",
        {"amount": "1000", "to": "acct-demo"},
    ),
    Step(
        "A declared read of external content",
        "search__query",
        {"query": "Linux Foundation agentic AI", "max_results": 3},
    ),
    Step(
        "A declared external write, made after that read",
        "notify__send",
        {"text": "Summary of the search results"},
    ),
)


class McpClient(Protocol):
    """What the demo needs from a client. `GatewayClient` is the real one."""

    def initialize(self, client_name: str = ...) -> dict[str, Any]: ...
    def list_tools(self) -> list[dict[str, Any]]: ...
    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]: ...


def _indent_reply(text: str) -> str:
    lines = text.splitlines() or [""]
    shown = lines[:_MAX_REPLY_LINES]
    if len(lines) > _MAX_REPLY_LINES:
        shown.append(f"... ({len(lines) - _MAX_REPLY_LINES} more lines)")
    return "\n".join([f"   reply  {shown[0]}", *(f"          {line}" for line in shown[1:])])


def run(client: McpClient, out: TextIO) -> None:
    """Handshake, list the tools, make each call in STEPS, and print what came back."""
    init = client.initialize("safe-agents-demo")
    names = sorted(tool["name"] for tool in client.list_tools())
    server = init.get("serverInfo", {}).get("name", "?")
    print(f"Connected to {server}. It advertises {len(names)} tool(s): {', '.join(names)}", file=out)
    for number, step in enumerate(STEPS, start=1):
        result = client.call_tool(step.tool, step.arguments)
        print(file=out)
        print(f"{number}. {step.title}", file=out)
        print(f"   call   {step.tool} {json.dumps(step.arguments)}", file=out)
        print(_indent_reply(result_text(result)), file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.gateway.demo",
        description=(
            "Start the broker's MCP gateway and make three tool calls against it: "
            "an undeclared tool, a declared read, and a declared write."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="also print the gateway's stderr, including its backend banner",
    )
    args = parser.parse_args(argv)

    # Search results can carry any character. A redirected stdout on Windows uses the
    # ANSI code page, so replace what it cannot encode rather than crash mid-demo.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    client = GatewayClient()
    try:
        run(client, sys.stdout)
    except GatewayClientError as exc:
        print(f"demo: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()
        if args.verbose:
            sys.stdout.flush()
            print("\n--- gateway stderr ---", file=sys.stderr)
            print(client.stderr_text.rstrip(), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
