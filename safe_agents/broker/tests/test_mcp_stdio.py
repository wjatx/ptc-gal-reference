"""Real-stdio-transport suite for the MCP host (#219, Leg 1).

Everything in `test_mcp_host.py` rides the SDK's in-memory transport; this file
is the stdio-path counterpart: every test here spawns
`examples/restricted_mcp_server/server.py` (or a deliberately broken command) as
an ACTUAL CHILD PROCESS and drives it through `connect_stdio` and the
`McpConnector` background-loop/async-factory lifecycle — the riskiest
interaction the in-memory tests cannot see (the factory holds a child process
open inside the loop-thread driver task, not just memory streams).

Proven properties (each was first observed live in the Leg-1 probe, then
codified here): discovery → hash → call → repeat → close() reaps the child; a
server crash mid-session is a PROMPT typed failure, never a deadlock or a
30s-timeout hang; a second connect works after close; a spawn failure is
delivered to the caller as the real error (the naive driver idiom surfaced
every spawn failure as a bare TimeoutError with the cause lost).

The suite needs only the `mcp` extra and a spawnable child python — no network,
no AWS — so it runs wherever the in-memory suite runs, just marked `stdio` for
selection (`pytest -m stdio` / `-m "not stdio"`).
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the stdio transport needs the optional `mcp` extra")

from safe_agents.broker.mcp.client import connect_stdio
from safe_agents.broker.mcp.factory import McpChildDeathError, stdio_host_factory
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.prototype import mcp_construction as _mcpc
from safe_agents.broker.runtime import FakeSecretsProvider
from safe_agents.broker.schemas import AgentManifest
from safe_agents.broker.tests.platform_marks import requires_pgrep
from safe_agents.broker.schemas.mcp_registry import (
    McpRespawnPolicy,
    McpServerDecl,
    McpToolDecl,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.connectors.mcp_connector import McpConnector

pytestmark = [pytest.mark.stdio, requires_pgrep]

_SERVER_ID = "ledger"
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
_SERVER_ARGS = ["-m", "examples.restricted_mcp_server.server"]
# The pgrep -f needle for the child. Matches the child's argv, not pytest's.
_CHILD_NEEDLE = "examples.restricted_mcp_server.server"
_DECL = McpServerDecl(
    tools=[McpToolDecl(tool_name="get_entry"), McpToolDecl(tool_name="list_entries")]
)
# Well under the connector's 30s backstop: proves fail-fast, not timeout-rescue.
_PROMPT_S = 10.0


def _server_pids() -> list[int]:
    out = subprocess.run(
        ["pgrep", "-f", _CHILD_NEEDLE], capture_output=True, text=True
    )
    return [int(line) for line in out.stdout.split()] if out.returncode == 0 else []


def _wait_reaped(timeout: float = 10.0) -> bool:
    """True once no child server process remains (poll on a real deadline; the
    suite's no-op time.sleep makes this a fast spin, bounded by pgrep latency)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _server_pids():
            return True
        time.sleep(0.05)
    return False


def _admit_all(registry: MemoryToolRegistry, defs) -> None:
    for d in defs:
        registry.admit_tool(
            RegisteredTool(
                tool_def=d,
                def_hash=compute_tool_def_hash(d),
                status=RegistryStatus.ACTIVE,
                admitted_by="arn:aws:sts::000000000000:assumed-role/Admitter/test",
                admitted_at="2026-07-18T00:00:00Z",
            )
        )


def _ledger_factory(registry: MemoryToolRegistry):
    """The reference factory against the example server, admitting both tools
    between connect and the first refresh (so the snapshot is all-ACTIVE)."""
    inner = stdio_host_factory(
        _SERVER_ID,
        sys.executable,
        _SERVER_ARGS,
        server_decl=_DECL,
        registry=registry,
        cwd=_REPO_ROOT,
    )

    async def factory():
        host = await inner()  # a started SupervisedStdioHost (#221 P3)
        _admit_all(registry, await host.inner._client.list_tool_defs())
        await host.refresh()
        return host

    return factory


@pytest.fixture(autouse=True)
def _no_stray_children():
    """Fail loudly if a test leaks a child server process (the zombie check)."""
    assert _server_pids() == [], "stray child server before test"
    yield
    assert _wait_reaped(), f"child server leaked: pids {_server_pids()}"


# -- plain connect_stdio lifecycle -------------------------------------------


def test_stdio_discovery_hash_call_repeat_and_context_exit_reaps_child():
    """Over a REAL child process: discovery materializes both tools (hashable),
    calls run repeatedly and return structured content, and exiting the context
    terminates the child — no zombie, no hang."""

    async def scenario():
        async with connect_stdio(
            _SERVER_ID, sys.executable, _SERVER_ARGS, cwd=_REPO_ROOT
        ) as client:
            assert _server_pids() != []  # the child is genuinely alive
            defs = await client.list_tool_defs()
            assert sorted(d.tool_name for d in defs) == ["get_entry", "list_entries"]
            # Every materialized def is four-field hashable (the admission input).
            for d in defs:
                assert len(compute_tool_def_hash(d)) == 64
            r1 = await client.call_tool("get_entry", {"entry_id": "L-001"})
            assert r1.isError is False
            # FastMCP's typed return arrives as structured content on the wire —
            # the structured_output:true claim in the example manifest holds.
            assert r1.structuredContent["entry_id"] == "L-001"
            r2 = await client.call_tool("list_entries", {"limit": 2})
            assert r2.isError is False
            assert r2.structuredContent["entry_ids"] == ["L-001", "L-002"]

    asyncio.run(scenario())
    assert _wait_reaped()


# -- connector factory lifecycle ---------------------------------------------


def test_stdio_connector_repeat_calls_and_close_reaps_child():
    """The full connector path over real transport: the stdio host factory runs
    on the connector's loop, repeat sync execute() calls flow, and close()
    tears down loop + session + CHILD PROCESS. A second close() is a no-op."""
    connector = McpConnector(_ledger_factory(MemoryToolRegistry()))
    try:
        r1 = connector.execute(
            _SERVER_ID, "get_entry", {"entry_id": "L-002"}, credential=""
        )
        assert r1.isError is False
        assert r1.structuredContent["account"] == "supplies"
        assert _server_pids() != []
        r2 = connector.execute(_SERVER_ID, "list_entries", {"limit": 3}, credential="")
        assert r2.isError is False
    finally:
        connector.close()
    assert _wait_reaped()
    connector.close()  # idempotent


def test_stdio_second_connect_works_after_close():
    """A fresh connector (fresh child) works after a previous one closed —
    restart semantics for the one-connector-per-lifetime model."""
    first = McpConnector(_ledger_factory(MemoryToolRegistry()))
    try:
        assert first.execute(
            _SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential=""
        ).isError is False
    finally:
        first.close()
    assert _wait_reaped()

    second = McpConnector(_ledger_factory(MemoryToolRegistry()))
    try:
        result = second.execute(_SERVER_ID, "list_entries", {"limit": 1}, credential="")
        assert result.isError is False
        assert result.structuredContent["total"] == 3
    finally:
        second.close()


# -- crash + failure semantics -----------------------------------------------


def test_stdio_server_crash_is_prompt_typed_failure_then_clean_close():
    """SIGKILL the child mid-session: the next call raises the TYPED death
    error PROMPTLY (M17: `McpChildDeathError`, real cause chained — pre-P3 this
    was a raw anyio ClosedResourceError) — never a deadlock, never a wait for
    the 30s backstop — and close() still tears down cleanly with no zombie.
    With no respawn policy declared the failure is stable across retries (M19:
    absent block = no respawn)."""
    connector = McpConnector(_ledger_factory(MemoryToolRegistry()))
    try:
        warm = connector.execute(
            _SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential=""
        )
        assert warm.isError is False
        pids = _server_pids()
        assert pids
        for pid in pids:
            os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + _PROMPT_S
        while _server_pids() and time.monotonic() < deadline:
            time.sleep(0.05)

        for attempt in range(2):  # the failure is stable across retries
            t0 = time.monotonic()
            with pytest.raises(McpChildDeathError) as exc:
                connector.execute(
                    _SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential=""
                )
            assert time.monotonic() - t0 < _PROMPT_S, f"attempt {attempt} hung"
            assert exc.value.server_id == _SERVER_ID
    finally:
        t0 = time.monotonic()
        connector.close()
        assert time.monotonic() - t0 < _PROMPT_S


def test_stdio_respawn_policy_revives_child_and_rechecks_discovery():
    """The M19 knob over REAL transport: SIGKILL the child → the in-flight
    death is typed → the next execute() respawns a NEW child process (fresh
    pid) and the call flows. M18 rides along: a registry row deleted while the
    child was dead governs the respawned session (that tool refuses on the
    fresh snapshot), proving no verdict crossed the death."""
    registry = MemoryToolRegistry()
    inner = stdio_host_factory(
        _SERVER_ID,
        sys.executable,
        _SERVER_ARGS,
        server_decl=_DECL,
        registry=registry,
        cwd=_REPO_ROOT,
        respawn=McpRespawnPolicy(max_attempts=2, backoff_seconds=0.0),
    )

    async def factory():
        host = await inner()
        _admit_all(registry, await host.inner._client.list_tool_defs())
        await host.refresh()
        return host

    connector = McpConnector(factory)
    try:
        assert connector.execute(
            _SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential=""
        ).isError is False
        first_pids = _server_pids()
        assert first_pids
        for pid in first_pids:
            os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + _PROMPT_S
        while _server_pids() and time.monotonic() < deadline:
            time.sleep(0.05)

        # The world changes while the child is dead: get_entry loses its row.
        del registry._rows[(_SERVER_ID, "get_entry")]

        with pytest.raises(McpChildDeathError):  # the death itself is typed
            connector.execute(_SERVER_ID, "list_entries", {"limit": 1}, credential="")

        # Next dispatch respawns: a NEW child, and the call flows again …
        result = connector.execute(_SERVER_ID, "list_entries", {"limit": 1}, credential="")
        assert result.isError is False
        second_pids = _server_pids()
        assert second_pids and set(second_pids).isdisjoint(first_pids)

        # … under a FRESH discovery snapshot: the deleted row now refuses.
        from safe_agents.broker.mcp.host import ToolNotCallableError

        with pytest.raises(ToolNotCallableError):
            connector.execute(_SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential="")
    finally:
        connector.close()
    assert _wait_reaped()


def test_stdio_spawn_failure_delivers_real_error_fast():
    """A factory whose command cannot spawn delivers the TYPED death error to
    the first execute() promptly, with the REAL cause (here FileNotFoundError)
    chained (M17) — the hardening this module exists for: the naive driver
    idiom surfaced every spawn failure as a bare TimeoutError after the full
    30s backstop, cause lost."""
    factory = stdio_host_factory(
        _SERVER_ID,
        "/nonexistent-binary-for-this-test",
        [],
        server_decl=_DECL,
        registry=MemoryToolRegistry(),
    )
    connector = McpConnector(factory)
    try:
        t0 = time.monotonic()
        with pytest.raises(McpChildDeathError) as exc:
            connector.execute(_SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential="")
        assert time.monotonic() - t0 < _PROMPT_S
        assert isinstance(exc.value.__cause__, FileNotFoundError), (
            "the real spawn error must ride __cause__ — nothing gets less "
            "diagnosable than the raw exception was"
        )
    finally:
        connector.close()


def test_stdio_child_that_exits_immediately_fails_fast_not_timeout():
    """A child that dies before speaking MCP (exit 3 straight away) fails the
    connect promptly with the SDK's typed connection error, not a 30s timeout."""
    factory = stdio_host_factory(
        _SERVER_ID,
        sys.executable,
        ["-c", "import sys; sys.exit(3)"],
        server_decl=_DECL,
        registry=MemoryToolRegistry(),
    )
    connector = McpConnector(factory)
    try:
        t0 = time.monotonic()
        with pytest.raises(BaseException) as exc:
            connector.execute(_SERVER_ID, "get_entry", {"entry_id": "L-001"}, credential="")
        assert time.monotonic() - t0 < _PROMPT_S
        assert not isinstance(exc.value, TimeoutError)  # the cause, not the backstop
    finally:
        connector.close()


# ---------------------------------------------------------------------------
# Native construction (#221) — build_mcp_connectors against REAL children.
# The #219 Leg-1 proofs above drive stdio_host_factory directly (the reference
# tier); these drive the SAME transport through the build_runtime construction
# path a manifest's spawn config takes in production, so retiring the provider
# pattern shrank no live coverage.
# ---------------------------------------------------------------------------

_ECHO_SERVER = str(Path(__file__).resolve().parent / "fixtures" / "env_echo_server.py")
_ECHO_NEEDLE = "env_echo_server.py"


def _native_manifest(
    server_id: str,
    tools: list[str],
    args: list[str],
    *,
    static_env: dict | None = None,
    env_map: dict | None = None,
    cwd: str | None = None,
) -> AgentManifest:
    """A minimal manifest whose one MCP server declares native spawn config.

    `command` is sys.executable so the child runs THIS venv's interpreter —
    the test-portable stand-in for the image's PATH-resolved python3.
    """
    server: dict = {
        "tools": [{"tool_name": t, "structured_output": True} for t in tools],
        "command": sys.executable,
        "args": args,
    }
    if static_env:
        server["env"] = static_env
    if cwd:
        server["cwd"] = cwd
    manifest: dict = {
        "envelope": {"polarity": "abstain"},
        "connectors": [server_id],
        "tool_ops": [
            {"tool": server_id, "op": t, "effect": "read", "external": True}
            for t in tools
        ],
        "mcp_servers": {server_id: server},
    }
    if env_map:
        manifest["connector_auth"] = {server_id: {"env_map": env_map}}
    return AgentManifest.model_validate(manifest)


def _prefetched_registry(server_id: str, command_args: list[str], cwd=None, env=None):
    """Fetch the child's live defs once and admit them all — the ceremony's
    result, minus the ceremony (which has its own suite)."""
    registry = MemoryToolRegistry()

    async def fetch():
        async with connect_stdio(
            server_id, sys.executable, command_args, cwd=cwd, env=env
        ) as client:
            return await client.list_tool_defs()

    _admit_all(registry, asyncio.run(fetch()))
    return registry


def test_native_construction_admitted_call_flows_and_close_reaps(monkeypatch):
    """The manifest-declared spawn config, built by build_mcp_connectors, spawns
    the REAL example server and an admitted call flows; close() reaps."""
    registry = _prefetched_registry(_SERVER_ID, _SERVER_ARGS, cwd=_REPO_ROOT)
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "unused-memory-registry")
    monkeypatch.setattr(
        _mcpc, "DynamoToolRegistry", lambda hmac_key, table_name: registry
    )
    manifest = _native_manifest(
        _SERVER_ID, ["get_entry", "list_entries"], _SERVER_ARGS, cwd=_REPO_ROOT
    )
    connectors = _mcpc.build_mcp_connectors(
        manifest,
        secrets=FakeSecretsProvider({_SERVER_ID: ""}),
        credential_strategies={},
        secret_name_for=lambda tool: tool,
    )
    connector = connectors[_SERVER_ID]
    try:
        result = connector.execute(
            _SERVER_ID, "get_entry", {"entry_id": "L-003"}, credential=""
        )
        assert result.isError is False
        assert result.structuredContent["memo"] == "invoice #7"
    finally:
        connector.close()
    assert _wait_reaped()


def test_native_spawn_env_delivery_is_allowlisted_and_overlays_default(monkeypatch):
    """M16/C9 live: the child sees the static half AND the env_map-renamed
    credential field; the UNMAPPED credential field is absent in the child;
    PATH survived (overlay, not replacement). Credential resolution happened at
    spawn, from the broker-side secrets provider."""

    def _echo_pids() -> list[int]:
        out = subprocess.run(
            ["pgrep", "-f", _ECHO_NEEDLE], capture_output=True, text=True
        )
        return [int(line) for line in out.stdout.split()] if out.returncode == 0 else []

    registry = _prefetched_registry("echo", [_ECHO_SERVER])
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "unused-memory-registry")
    monkeypatch.setattr(
        _mcpc, "DynamoToolRegistry", lambda hmac_key, table_name: registry
    )
    manifest = _native_manifest(
        "echo",
        ["get_env"],
        [_ECHO_SERVER],
        static_env={"ECHO_STATIC": "static-half"},
        env_map={"ECHO_API_KEY": "KEY"},
    )
    secrets = FakeSecretsProvider(
        {"echo": json.dumps({"KEY": "spawn-cred-123", "UNMAPPED": "must-not-cross"})}
    )
    connectors = _mcpc.build_mcp_connectors(
        manifest,
        secrets=secrets,
        credential_strategies={},
        secret_name_for=lambda tool: tool,
    )
    connector = connectors["echo"]
    try:
        result = connector.execute(
            "echo",
            "get_env",
            {"names": ["ECHO_STATIC", "ECHO_API_KEY", "UNMAPPED", "PATH"]},
            credential="",
        )
        assert result.isError is False
        report = result.structuredContent
        assert report["present"]["ECHO_STATIC"] == "static-half"
        assert report["present"]["ECHO_API_KEY"] == "spawn-cred-123"
        assert "PATH" in report["present"], "SDK default env must survive the overlay"
        assert report["absent"] == ["UNMAPPED"], (
            "an unmapped credential field crossed into the child"
        )
    finally:
        connector.close()
    # The echo child has its own pgrep needle — reap-check it explicitly.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and _echo_pids():
        time.sleep(0.05)
    assert _echo_pids() == [], "env-echo child leaked"


def test_native_spawn_unsatisfiable_env_map_refuses_before_spawn(monkeypatch):
    """A credential missing a mapped field refuses the SPAWN (the factory
    surfaces McpConstructionError on first dispatch) — no partially-configured
    child is ever spawned."""
    registry = MemoryToolRegistry()
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "unused-memory-registry")
    monkeypatch.setattr(
        _mcpc, "DynamoToolRegistry", lambda hmac_key, table_name: registry
    )
    manifest = _native_manifest(
        "echo",
        ["get_env"],
        [_ECHO_SERVER],
        env_map={"ECHO_API_KEY": "KEY"},
    )
    secrets = FakeSecretsProvider({"echo": json.dumps({"WRONG_FIELD": "x"})})
    connectors = _mcpc.build_mcp_connectors(
        manifest,
        secrets=secrets,
        credential_strategies={},
        secret_name_for=lambda tool: tool,
    )
    connector = connectors["echo"]
    try:
        with pytest.raises(Exception, match="no field 'KEY'"):
            connector.execute("echo", "get_env", {"names": ["PATH"]}, credential="")
    finally:
        connector.close()
    assert _wait_reaped()
