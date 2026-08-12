"""env_echo_server — a test-only MCP server reporting SELECTED env vars (#221).

Spawned by the native-construction stdio tests to prove clause M16/C9 with a
real child process: the vars the broker composed (the static manifest half plus
the env_map-delivered credential half) are visible INSIDE the child, unmapped
credential fields are not, and the SDK's minimal default environment (PATH)
survived the overlay. Reports only the names it is asked about — it never dumps
the whole environment (values here are test fakes by construction).

Run:  python safe_agents/broker/tests/fixtures/env_echo_server.py   (stdio)
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

mcp = FastMCP("echo")


class EnvReport(BaseModel):
    """Which of the asked-about env vars this process sees — structured output."""

    present: dict[str, str]
    absent: list[str]


@mcp.tool()
def get_env(names: list[str]) -> EnvReport:
    """Report which of the named env vars are set in this process."""
    return EnvReport(
        present={n: os.environ[n] for n in names if n in os.environ},
        absent=[n for n in names if n not in os.environ],
    )


if __name__ == "__main__":
    mcp.run()
