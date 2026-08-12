"""SDK-backed half of the MCP host conformance suite (#174, #219 Leg-1 rider).

MCP-HOST.md's conformance suite (M1-M13) splits across two files. This file
holds Section 1 — the host/connector *integration mechanics*, the assembly
that composes the pure discovery gate (discovery.py), the admitted-tool
registry (registry.py), and the thin MCP client (client.py) into ``McpHost`` +
``McpConnector`` — plus the conformance clauses that genuinely need a live MCP
session: M2-M5 and the live-host half of M13. The SDK-free clauses (M1, M6-M12,
and the pure-gate half of M13) live in `test_mcp_conformance_no_sdk.py` and run
even without the optional `mcp` extra installed.

The `mcp` extra is optional, so this module skips cleanly when it is absent
(`pytest.importorskip`). The fake MCP server is an in-process FastMCP wired to the
client over the SDK's in-memory transport — no network, no subprocess — the same
fixture idiom as `test_mcp_client.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest

pytest.importorskip("mcp", reason="the MCP host needs the optional `mcp` extra")

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from safe_agents.broker.mcp.client import McpClient
from safe_agents.broker.mcp.discovery import ToolState
from safe_agents.broker.mcp.host import McpHost, ToolNotCallableError
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.schemas.mcp_registry import (
    McpServerDecl,
    McpToolDecl,
    McpToolDef,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.connectors.mcp_connector import McpConnector

import logging as _logging

from safe_agents.broker.mcp.registry import compute_row_hmac

_SERVER_ID = "calc"
_HOST_LOGGER = "safe_agents.broker.mcp.host"
_ADMITTED_BY = "arn:aws:sts::000000000000:assumed-role/Admitter/test"
_ADMITTED_AT = "2026-07-17T00:00:00Z"


# ---------------------------------------------------------------------------
# Fixtures — an in-memory FastMCP server + host construction helpers.
# ---------------------------------------------------------------------------


def _fake_server() -> FastMCP:
    server = FastMCP("calc")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two integers."""
        return a + b

    @server.tool()  # no docstring -> the SDK advertises description=None -> ""
    def echo_no_doc(text: str) -> str:
        return text

    return server


def _full_decl() -> McpServerDecl:
    """Manifest declaration naming BOTH advertised tools (the common case)."""
    return McpServerDecl(
        tools=[McpToolDecl(tool_name="add"), McpToolDecl(tool_name="echo_no_doc")]
    )


@contextlib.asynccontextmanager
async def _host_ctx(server: FastMCP, decl: McpServerDecl, registry: MemoryToolRegistry):
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        yield McpHost(decl, registry, McpClient(_SERVER_ID, session))


def _run(coro):
    """Drive one coroutine to completion without a pytest-async plugin."""
    return asyncio.run(coro)


def _admit(
    registry: MemoryToolRegistry,
    tool_def: McpToolDef,
    *,
    status: RegistryStatus = RegistryStatus.ACTIVE,
    def_hash: str | None = None,
) -> None:
    """Write an admitted registry row for ``tool_def`` (matching hash by default).

    Pass an explicit ``def_hash`` (e.g. a wrong one) to simulate drift; pass a
    QUARANTINED ``status`` to simulate an already-quarantined row.
    """
    row = RegisteredTool(
        tool_def=tool_def,
        def_hash=def_hash if def_hash is not None else compute_tool_def_hash(tool_def),
        status=status,
        admitted_by=_ADMITTED_BY,
        admitted_at=_ADMITTED_AT,
    )
    registry.admit_tool(row)


# ===========================================================================
# Section 1 — host + connector integration mechanics (#174)
# ===========================================================================


# -- no snapshot fails closed -----------------------------------------------


def test_no_refresh_everything_uncallable():
    """With no refresh (no snapshot), the host refuses every call — fail closed,
    reason=None (never an auto-gain before discovery ran)."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            assert host.snapshot is None
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("add", {"a": 1, "b": 2})
            return exc.value

    err = _run(scenario())
    assert err.reason is None
    assert err.server_id == _SERVER_ID
    assert err.tool_name == "add"


# -- ACTIVE tool calls through ----------------------------------------------


def test_active_tool_calls_through():
    """An admitted tool whose live hash matches is ACTIVE and delegates to the
    client, returning the SDK result verbatim."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"])
            result = await host.refresh()
            assert result.is_callable(_SERVER_ID, "add")
            return await host.call("add", {"a": 2, "b": 3})

    call_result = _run(scenario())
    assert call_result.isError is False
    assert call_result.content[0].text == "5"


# -- each failed-closed state -> typed refusal with the right reason ---------


def test_declared_but_unadmitted_is_uncallable_declared():
    """Declared in the manifest but no admitted row -> DECLARED, uncallable, and
    (per the gate) NOT a finding."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            result = await host.refresh()
            assert result.findings == []  # DECLARED is silent
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("add", {"a": 1, "b": 2})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.DECLARED


def test_drifted_tool_refused_with_drift_reason():
    """An admitted row whose def_hash differs from the live hash -> DRIFTED."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"], def_hash="0" * 64)  # wrong hash -> drift
            await host.refresh()
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("add", {"a": 1, "b": 2})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.DRIFTED


def test_unlisted_tool_refused_with_unlisted_reason():
    """A tool the server advertises that the manifest never declared -> UNLISTED,
    uncallable even if the server offers it."""
    registry = MemoryToolRegistry()
    decl = McpServerDecl(tools=[McpToolDecl(tool_name="add")])  # echo_no_doc undeclared

    async def scenario():
        async with _host_ctx(_fake_server(), decl, registry) as host:
            await host.refresh()
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("echo_no_doc", {"text": "hi"})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.UNLISTED


def test_quarantined_row_refused_with_quarantined_reason():
    """An admitted row whose status is QUARANTINED -> QUARANTINED, uncallable."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"], status=RegistryStatus.QUARANTINED)
            await host.refresh()
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("add", {"a": 1, "b": 2})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.QUARANTINED


def test_withdrawn_tool_refused_with_withdrawn_reason():
    """An admitted tool the server STOPPED advertising -> WITHDRAWN. The manifest
    declares 'gone' and a row admits it, but the server never advertises it."""
    registry = MemoryToolRegistry()
    decl = McpServerDecl(
        tools=[McpToolDecl(tool_name="add"), McpToolDecl(tool_name="gone")]
    )
    # A row for a tool the server does not advertise -> pass 2 sees it withdrawn.
    _admit(
        registry,
        McpToolDef(
            server_id=_SERVER_ID,
            tool_name="gone",
            input_schema={"type": "object"},
            description="a tool the server no longer serves",
        ),
    )

    async def scenario():
        async with _host_ctx(_fake_server(), decl, registry) as host:
            result = await host.refresh()
            assert any(
                v.tool_name == "gone" and v.state is ToolState.WITHDRAWN
                for v in result.verdicts
            )
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("gone", {})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.WITHDRAWN


# -- findings surfaced loudly, exactly once per refresh ----------------------


def test_findings_logged_exactly_once_per_refresh(caplog):
    """Each failed-closed finding logs exactly one ERROR per refresh (M5 shape).

    UNLISTED echo_no_doc + WITHDRAWN gone -> exactly two findings, two ERRORs.
    """
    registry = MemoryToolRegistry()
    decl = McpServerDecl(
        tools=[McpToolDecl(tool_name="add"), McpToolDecl(tool_name="gone")]
    )  # echo_no_doc is advertised but undeclared -> UNLISTED
    _admit(
        registry,
        McpToolDef(
            server_id=_SERVER_ID,
            tool_name="gone",
            input_schema={"type": "object"},
            description="withdrawn",
        ),
    )

    async def scenario():
        async with _host_ctx(_fake_server(), decl, registry) as host:
            return await host.refresh()

    with caplog.at_level(logging.ERROR, logger=_HOST_LOGGER):
        result = _run(scenario())

    reasons = {(f.tool_name, f.reason) for f in result.findings}
    assert reasons == {("echo_no_doc", ToolState.UNLISTED), ("gone", ToolState.WITHDRAWN)}
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == len(result.findings) == 2
    joined = " ".join(r.getMessage() for r in errors)
    assert "echo_no_doc" in joined and "gone" in joined


def test_all_active_refresh_logs_nothing(caplog):
    """A clean all-ACTIVE discovery surfaces zero findings and zero ERROR logs."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"])
            _admit(registry, defs["echo_no_doc"])
            return await host.refresh()

    with caplog.at_level(logging.ERROR, logger=_HOST_LOGGER):
        result = _run(scenario())

    assert result.findings == []
    assert [r for r in caplog.records if r.levelno == logging.ERROR] == []


# -- connector dispatch -> host verdict enforced -----------------------------


def test_connector_refuses_when_host_verdict_not_active():
    """The connector enforces the host's verdict end-to-end: a DRIFTED tool driven
    through the sync ``McpConnector.execute`` raises ``ToolNotCallableError``. The
    refusal precedes any transport, so it holds even after the session closed."""
    registry = MemoryToolRegistry()

    async def build_refreshed_host():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"], def_hash="0" * 64)  # drift
            await host.refresh()
            return host

    host = _run(build_refreshed_host())
    connector = McpConnector(host)

    with pytest.raises(ToolNotCallableError) as exc:
        connector.execute(_SERVER_ID, "add", {"a": 1, "b": 2}, credential="")
    assert exc.value.reason is ToolState.DRIFTED


def test_connector_maps_coordinates_and_returns_result():
    """The connector maps (tool=server_id, op=tool_name, args) onto ``host.call``
    and returns its result verbatim — proven against a recording fake host so the
    dispatch wiring is isolated from transport."""

    class _FakeHost:
        def __init__(self) -> None:
            self.server_id = _SERVER_ID
            self.calls: list[tuple[str, dict]] = []

        async def call(self, tool_name, arguments=None):
            self.calls.append((tool_name, arguments or {}))
            return {"echoed": tool_name, "args": arguments}

    fake = _FakeHost()
    connector = McpConnector(fake)  # type: ignore[arg-type]

    result = connector.execute(_SERVER_ID, "add", {"a": 7}, credential="ignored")

    assert fake.calls == [("add", {"a": 7})]
    assert result == {"echoed": "add", "args": {"a": 7}}


def test_connector_rejects_mismatched_server_tool():
    """A BrokeredCall whose ``tool`` is not the bound server_id is a wiring error."""

    class _FakeHost:
        server_id = _SERVER_ID

        async def call(self, tool_name, arguments=None):  # pragma: no cover
            raise AssertionError("must not be reached")

    connector = McpConnector(_FakeHost())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="bound to server"):
        connector.execute("other-server", "add", {}, credential="")


# -- loop-affine real session via the async factory (finding 1 regression) ---


def test_connector_real_session_via_factory_repeat_calls_and_clean_close():
    """A REAL in-memory MCP session, created via the async factory ON the
    connector's own loop, is callable REPEATEDLY through the sync
    ``McpConnector.execute()`` from sync test code — the loop-affine session the old
    per-call ``asyncio.run`` design could not drive (its background reader tasks live
    on the loop that opened the session, so a fresh per-call loop would raise/hang).
    ``close()`` then tears the loop AND the live session down cleanly.

    The factory holds the session's async-context open inside ONE long-lived driver
    task, so the SDK's anyio task-group / cancel-scope is entered and exited in the
    same task; teardown happens when ``close()`` cancels that task."""
    registry = MemoryToolRegistry()

    async def factory() -> McpHost:
        loop = asyncio.get_running_loop()
        ready: asyncio.Future = loop.create_future()

        async def _driver() -> None:
            async with create_connected_server_and_client_session(
                _fake_server()._mcp_server
            ) as session:
                host = McpHost(_full_decl(), registry, McpClient(_SERVER_ID, session))
                defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
                _admit(registry, defs["add"])
                await host.refresh()
                ready.set_result(host)
                await asyncio.Event().wait()  # hold the session live until cancelled

        asyncio.ensure_future(_driver())
        return await ready

    connector = McpConnector(factory)
    try:
        first = connector.execute(_SERVER_ID, "add", {"a": 2, "b": 3}, credential="")
        second = connector.execute(_SERVER_ID, "add", {"a": 10, "b": 20}, credential="")
        assert first.isError is False and second.isError is False
        assert first.content[0].text == "5"
        assert second.content[0].text == "30"
    finally:
        connector.close()
    connector.close()  # idempotent — a second close is a no-op


# -- non-dict args fail closed (finding 2 regression) ------------------------


def test_connector_non_dict_args_fail_closed():
    """A non-dict ``args`` (str, list) raises a ``ValueError`` naming the type
    rather than being silently coerced to ``{}`` — silent coercion would run the
    external call with EMPTY arguments while the PDP/audit recorded the ORIGINAL
    args (an audit/egress divergence). ``None`` still maps to ``{}``."""

    class _FakeHost:
        def __init__(self) -> None:
            self.server_id = _SERVER_ID
            self.calls: list[dict] = []

        async def call(self, tool_name, arguments=None):
            self.calls.append(arguments)
            return {"args": arguments}

    fake = _FakeHost()
    connector = McpConnector(fake)  # type: ignore[arg-type]
    try:
        with pytest.raises(ValueError, match="must be a dict or None"):
            connector.execute(_SERVER_ID, "add", "not-a-dict", credential="")
        with pytest.raises(ValueError, match="got list"):
            connector.execute(_SERVER_ID, "add", ["a", "b"], credential="")
        # None -> {} still works and reaches the host as empty args.
        assert connector.execute(_SERVER_ID, "add", None, credential="") == {"args": {}}
        assert fake.calls == [{}]
    finally:
        connector.close()


# ===========================================================================
# Section 2 — M2-M5, M13(live) conformance (#174)
#
# One test (or small group) per clause in MCP-HOST.md §"Conformance clauses";
# every docstring names its clause sentence. Each test would FAIL if its
# mechanism regressed. Section 1 above already covers the integration mechanics;
# these are the clause-named teeth, exercising the seam each clause names.
#
# NB: this file requires the `mcp` extra (Section 1's in-memory FastMCP server
# imports it at module load, gated by the top-of-file importorskip), so it only
# holds the clauses that genuinely need a live session — M2/M3/M4/M5 use the
# live in-memory server, and the live half of M13 exercises the host gate
# end-to-end. The SDK-free clauses (M1, M6-M12, and M13's pure-gate half) live
# in `test_mcp_conformance_no_sdk.py` and run without the `mcp` extra.
# ===========================================================================


# ---------------------------------------------------------------------------
# M2 — description change alone is drift.
# ---------------------------------------------------------------------------


def test_m2_description_change_alone_is_drift():
    """M2: changing only a tool's description, with server_id/tool_name/
    input_schema unchanged, changes the hash and moves the tool to a fail-closed,
    surfaced drift state (reference: ToolState.DRIFTED — uncallable, surfaced)."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            live = {d.tool_name: d for d in await host._client.list_tool_defs()}["add"]
            # Same four fields EXCEPT description — only the description differs.
            other = live.model_copy(update={"description": live.description + " (changed)"})
            assert other.server_id == live.server_id
            assert other.tool_name == live.tool_name
            assert other.input_schema == live.input_schema
            assert other.description != live.description
            # Description-only change breaks the hash...
            assert compute_tool_def_hash(other) != compute_tool_def_hash(live)
            # ...so admitting the OTHER-description hash makes the live tool drift.
            _admit(registry, other, def_hash=compute_tool_def_hash(other))
            result = await host.refresh()
            verdict = next(v for v in result.verdicts if v.tool_name == "add")
            assert verdict.state is ToolState.DRIFTED
            assert not result.is_callable(_SERVER_ID, "add")
            assert any(f.tool_name == "add" and f.reason is ToolState.DRIFTED
                       for f in result.findings)
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("add", {"a": 1, "b": 2})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.DRIFTED


# ---------------------------------------------------------------------------
# M3 — unlisted discovered tool is uncallable.
# ---------------------------------------------------------------------------


def test_m3_unlisted_discovered_tool_is_uncallable_and_surfaced():
    """M3: a tool advertised at discovery but absent from the admitted registry
    is never callable and surfaces as a quarantine-class finding."""
    registry = MemoryToolRegistry()
    decl = McpServerDecl(tools=[McpToolDecl(tool_name="add")])  # echo_no_doc undeclared

    async def scenario():
        async with _host_ctx(_fake_server(), decl, registry) as host:
            result = await host.refresh()
            # Advertised but neither declared nor admitted -> uncallable + surfaced.
            assert not result.is_callable(_SERVER_ID, "echo_no_doc")
            assert any(f.tool_name == "echo_no_doc" and f.reason is ToolState.UNLISTED
                       for f in result.findings)
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("echo_no_doc", {"text": "hi"})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.UNLISTED


# ---------------------------------------------------------------------------
# M4 — undeclared-in-manifest tool is uncallable even with a store row.
# ---------------------------------------------------------------------------


def test_m4_undeclared_tool_uncallable_even_with_store_row():
    """M4: a (server_id, tool_name) the image-baked AgentManifest never declared
    is uncallable even if a store row names it; admission requires the Layer-1
    declaration — a store row cannot mint a callable."""
    registry = MemoryToolRegistry()
    decl = McpServerDecl(tools=[McpToolDecl(tool_name="add")])  # echo_no_doc undeclared

    async def scenario():
        async with _host_ctx(_fake_server(), decl, registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            # A store row that NAMES the undeclared tool, with a matching hash —
            # the Layer-2 key present, the Layer-1 key absent.
            _admit(registry, defs["echo_no_doc"])
            assert registry.get_tool(_SERVER_ID, "echo_no_doc").tool is not None
            result = await host.refresh()
            # The row does not mint a callable: still UNLISTED (no declaration).
            assert not result.is_callable(_SERVER_ID, "echo_no_doc")
            verdict = next(v for v in result.verdicts if v.tool_name == "echo_no_doc")
            assert verdict.state is ToolState.UNLISTED
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("echo_no_doc", {"text": "hi"})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.UNLISTED


# ---------------------------------------------------------------------------
# M5 — drift quarantines and surfaces exactly once (no per-call flood).
# ---------------------------------------------------------------------------


def test_m5_drift_surfaces_exactly_once_not_per_call(caplog):
    """M5: a live/admitted hash mismatch drops the tool to uncallable and emits
    exactly one distinctive audit surface (one ERROR log) per refresh — repeated
    call attempts do NOT re-log (not a per-call flood)."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"], def_hash="0" * 64)  # wrong hash -> drift
            with caplog.at_level(_logging.ERROR, logger=_HOST_LOGGER):
                result = await host.refresh()
                errors_after_refresh = [
                    r for r in caplog.records if r.levelno == _logging.ERROR
                ]
                # Exactly one distinctive surface for the one drifted tool.
                drift_findings = [f for f in result.findings if f.tool_name == "add"]
                assert len(drift_findings) == 1
                assert drift_findings[0].reason is ToolState.DRIFTED
                assert len(errors_after_refresh) == 1
                # Three call attempts: each refuses, none re-logs (no flood).
                for _ in range(3):
                    with pytest.raises(ToolNotCallableError):
                        await host.call("add", {"a": 1, "b": 2})
                total_errors = [r for r in caplog.records if r.levelno == _logging.ERROR]
                assert len(total_errors) == 1  # still one — refusal never re-surfaces

    _run(scenario())


# ---------------------------------------------------------------------------
# M13 — registry rows are HMAC-integrity-protected.
# ---------------------------------------------------------------------------


def test_m13_registry_rows_are_hmac_integrity_protected():
    """M13: a registry item carries an item-level rowHash over its STORED bytes
    (#246); a tampered item is served quarantined with tool=None — tampered
    bytes are evidence, never parsed — and the host gate therefore renders the
    coordinate uncallable."""
    registry = MemoryToolRegistry()

    async def scenario():
        async with _host_ctx(_fake_server(), _full_decl(), registry) as host:
            defs = {d.tool_name: d for d in await host._client.list_tool_defs()}
            _admit(registry, defs["add"])  # a clean ACTIVE row (valid HMAC)
            # Clean read: not quarantined, item-level rowHash matches the stored bytes.
            clean = registry.get_tool(_SERVER_ID, "add")
            assert not clean.quarantined
            assert clean.stored_hash == compute_row_hmac(clean.tool, registry._hmac_key)
            # Tamper the item-level rowHash -> served quarantined; the bytes ride
            # as raw_data for audit but are never parsed (#246: tool is None).
            registry._rows[(_SERVER_ID, "add")]["rowHash"] = "tampered-hmac"
            tampered = registry.get_tool(_SERVER_ID, "add")
            assert tampered.quarantined is True
            assert tampered.tool is None
            assert tampered.raw_data is not None  # audit-visible, never suppressed
            # The host gate treats a quarantined row as non-authoritative -> uncallable.
            result = await host.refresh()
            verdict = next(v for v in result.verdicts if v.tool_name == "add")
            assert verdict.state is ToolState.QUARANTINED
            assert not result.is_callable(_SERVER_ID, "add")
            with pytest.raises(ToolNotCallableError) as exc:
                await host.call("add", {"a": 1, "b": 2})
            return exc.value

    err = _run(scenario())
    assert err.reason is ToolState.QUARANTINED
