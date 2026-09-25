"""Remote MCP credential delivery over a REAL wire (#237, MCP-HOST.md M25,
CONNECTOR-AUTH C10).

The definition-of-done proof for remote credential delivery, run against the
toy remote OAuth server (`fixtures/oauth_remote_toy_server.py`) rather than a
vendor — this lane's toy-first discipline, which has twice caught transport
bugs a live-first run would have paid for.

What makes these proofs non-vacuous, in order of how easily each could have
been faked:

  * the toy **401s** an unauthenticated request, so "the call succeeded" can
    only mean the credential was really delivered (`test_no_header_map_...`
    pins that the refusal is real);
  * the token is minted by a **real refresh-grant POST** through
    `OAuthRefresh`'s DEFAULT urllib fetcher — no injected fake — so the whole
    strategy path runs, not just the header plumbing;
  * the toy's `whoami` reports the bearer **the server received**, so delivery
    is proven at the far end rather than at the client;
  * every minted token carries the server's pid, so a restart invalidates the
    old one and `test_reconnect_remints_...` cannot pass by replay.

No custom pytest marker: pyproject registers only `stdio`, and an unregistered
marker warns on every run — select this suite by file path.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip(
    "mcp", reason="the streamable-http transport needs the optional `mcp` extra"
)

from safe_agents.broker.mcp.client import connect_streamable_http
from safe_agents.broker.mcp.factory import McpChildDeathError
from safe_agents.broker.mcp.registry import MemoryToolRegistry
from safe_agents.broker.prototype import mcp_construction as _mcpc
from safe_agents.broker.runtime import FakeSecretsProvider
from safe_agents.broker.runtime.credentials import (
    CredentialStrategyError,
    build_credential_strategies,
)
from safe_agents.broker.schemas import AgentManifest
from safe_agents.broker.schemas.mcp_registry import (
    McpRespawnPolicy,
    RegisteredTool,
    RegistryStatus,
    compute_tool_def_hash,
)
from safe_agents.broker.tests.platform_marks import requires_pgrep

pytestmark = requires_pgrep

# One attempt is enough: the reconnect target is already listening again.
_RESPAWN = McpRespawnPolicy(max_attempts=1, backoff_seconds=0.0)

_SERVER_ID = "toyoauth"
_FIXTURE = str(
    Path(__file__).resolve().parent / "fixtures" / "oauth_remote_toy_server.py"
)
_SERVER_NEEDLE = "oauth_remote_toy_server.py"
_TOOLS = ["whoami", "echo", "ping"]
# Must match the fixture's accepted grant.
_REFRESH_TOKEN = "toy-refresh-token"
_CLIENT_ID = "toy-client"
_REFRESH_LEAF = "toy-refresh-leaf"
_PROMPT_S = 10.0
_READY_S = 30.0


def _url(port: int) -> str:
    return f"http://127.0.0.1:{port}/mcp"


def _token_url(port: int) -> str:
    return f"http://127.0.0.1:{port}/token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _server_pids() -> list[int]:
    out = subprocess.run(
        ["pgrep", "-f", _SERVER_NEEDLE], capture_output=True, text=True
    )
    return [int(line) for line in out.stdout.split()] if out.returncode == 0 else []


class _ToyServer:
    """One toy-server subprocess on a fixed port, restartable on that port —
    the reconnect leg needs death and rebirth at the SAME url, and (because
    tokens carry the pid) rebirth is also what invalidates the old token."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, _FIXTURE, str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + _READY_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"toy server exited at startup (code {self.proc.returncode})"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.05)  # no-op under the suite fixture; deadline bounds
        raise RuntimeError(f"toy server never listened on port {self.port}")

    def kill(self) -> None:
        assert self.proc is not None
        self.proc.kill()
        self.proc.wait(timeout=_PROMPT_S)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.kill()


@pytest.fixture(autouse=True)
def _no_stray_servers():
    assert _server_pids() == [], "stray toy server before test"
    yield
    deadline = time.monotonic() + _PROMPT_S
    while time.monotonic() < deadline and _server_pids():
        time.sleep(0.05)
    assert _server_pids() == [], f"toy server leaked: pids {_server_pids()}"


@pytest.fixture()
def toy_server():
    server = _ToyServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _mint_directly(port: int) -> str:
    """Mint one access token the way the strategy does — used to PRIME the
    registry, since discovery itself needs auth on this server."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": _REFRESH_TOKEN,
            "client_id": _CLIENT_ID,
        }
    ).encode()
    request = urllib.request.Request(  # noqa: S310 — loopback test fixture
        _token_url(port), data=body, method="POST"
    )
    with urllib.request.urlopen(request, timeout=_PROMPT_S) as response:  # noqa: S310
        return json.loads(response.read().decode())["access_token"]


def _manifest(port: int, *, header_map: dict | None, strategy: str = "oauth_refresh"):
    """A manifest whose one MCP server is REMOTE and (optionally) declares the
    header-delivery half."""
    manifest: dict = {
        "envelope": {"polarity": "abstain"},
        "connectors": [_SERVER_ID],
        "tool_ops": [
            {"tool": _SERVER_ID, "op": t, "effect": "read", "external": True}
            for t in _TOOLS
        ],
        "mcp_servers": {
            _SERVER_ID: {
                "tools": [
                    {"tool_name": t, "structured_output": True} for t in _TOOLS
                ],
                "transport": "streamable-http",
                "url": _url(port),
            }
        },
    }
    if header_map is not None:
        manifest["connector_auth"] = {
            _SERVER_ID: {
                "strategy": strategy,
                "params": {
                    "token_url": _token_url(port),
                    "client_id": _CLIENT_ID,
                    "refresh_token_leaf": _REFRESH_LEAF,
                },
                "header_map": header_map,
            }
        }
    return AgentManifest.model_validate(manifest)


def _prefetched_registry(port: int) -> MemoryToolRegistry:
    """Admit the server's live defs — the ceremony's result, minus the ceremony.

    Discovery on this server needs a bearer too, so this mints one first: the
    same chicken-and-egg a real operator's `snapshot` faces before any row
    exists.
    """
    registry = MemoryToolRegistry()
    token = _mint_directly(port)

    async def fetch():
        async with connect_streamable_http(
            _SERVER_ID, _url(port), headers={"Authorization": f"Bearer {token}"}
        ) as client:
            return await client.list_tool_defs()

    for tool_def in asyncio.run(fetch()):
        registry.admit_tool(
            RegisteredTool(
                tool_def=tool_def,
                def_hash=compute_tool_def_hash(tool_def),
                status=RegistryStatus.ACTIVE,
                admitted_by="arn:aws:sts::000000000000:assumed-role/Admitter/test",
                admitted_at="2026-07-26T00:00:00Z",
            )
        )
    return registry


def _connectors(manifest: AgentManifest, registry: MemoryToolRegistry, monkeypatch):
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "unused-memory-registry")
    monkeypatch.setattr(
        _mcpc, "DynamoToolRegistry", lambda hmac_key, table_name: registry
    )
    return _mcpc.build_mcp_connectors(
        manifest,
        secrets=FakeSecretsProvider({_REFRESH_LEAF: _REFRESH_TOKEN}),
        credential_strategies=build_credential_strategies(manifest.connector_auth),
        secret_name_for=lambda tool: tool,
    )


_BEARER_HEADER = {"Authorization": {"scheme": "Bearer"}}


def _chain_text(exc: BaseException) -> str:
    """Every exception in a raised chain, rendered.

    A transport failure arrives WRAPPED — the broker's job is to surface a
    typed `McpChildDeathError` (M17) while keeping the real cause on
    `__cause__` — so asserting on `str(exc)` alone would test the wrapper and
    miss whether the underlying error survived. Walks causes/contexts and
    flattens exception groups, which the SDK's task groups raise.
    """
    seen: list[str] = []
    stack: list[BaseException | None] = [exc]
    while stack:
        current = stack.pop()
        if current is None or repr(current) in seen:
            continue
        seen.append(repr(current))
        stack.append(current.__cause__)
        stack.append(current.__context__)
        if isinstance(current, BaseExceptionGroup):
            stack.extend(current.exceptions)
    return "\n".join(seen)


# -- the definition of done --------------------------------------------------


def test_oauth_bearer_is_minted_broker_side_and_reaches_the_server(
    toy_server, monkeypatch
):
    """The DoD: a remote MCP server requiring bearer auth is discovered and
    called through the broker, with the credential resolved broker-side.

    The bearer the SERVER saw is asserted, not the one the client built — and
    it is a token the toy's own /token endpoint minted, so the whole
    OAuthRefresh path (secrets fetch → refresh grant → header) really ran.
    """
    registry = _prefetched_registry(toy_server.port)
    manifest = _manifest(toy_server.port, header_map=_BEARER_HEADER)
    connector = _connectors(manifest, registry, monkeypatch)[_SERVER_ID]
    try:
        result = connector.execute(_SERVER_ID, "whoami", {}, credential="")
        assert result.isError is False
        bearer = result.structuredContent["bearer"]
    finally:
        connector.close()
    assert bearer.startswith("toy-access-"), (
        f"the server saw {bearer!r}; it must be a token its own /token endpoint "
        "minted, which is what proves the refresh grant ran broker-side"
    )


def test_no_header_map_means_the_server_refuses_the_connect(toy_server, monkeypatch):
    """Non-vacuity: with no header_map no credential is resolved, and this
    server genuinely rejects that — so the success above is delivery, not a
    server that would have answered anyone.

    The refusal arrives as a typed `McpChildDeathError` (M17): an unauthorized
    connect IS a failed connect. The 401 itself must survive on the cause
    chain, because a death whose reason was swallowed is undiagnosable.
    """
    registry = _prefetched_registry(toy_server.port)
    manifest = _manifest(toy_server.port, header_map=None)
    connector = _connectors(manifest, registry, monkeypatch)[_SERVER_ID]
    try:
        with pytest.raises(McpChildDeathError) as excinfo:
            connector.execute(_SERVER_ID, "whoami", {}, credential="")
    finally:
        connector.close()
    chain = _chain_text(excinfo.value)
    assert "401" in chain or "Unauthorized" in chain, (
        f"expected the toy's 401 on the cause chain; got:\n{chain}"
    )


def test_reconnect_remints_the_access_token(toy_server, monkeypatch):
    """M25/M18: reconnect IS the re-auth path.

    The server is killed and restarted on the same port. Because every minted
    token carries the minting process's pid, every token from the first
    process is now invalid — so a broker that replayed its cached bearer would
    401 forever. The second call succeeding, with a DIFFERENT bearer observed
    server-side, is the proof that the credential re-resolved per connect.
    """
    registry = _prefetched_registry(toy_server.port)
    manifest = _manifest(toy_server.port, header_map=_BEARER_HEADER)
    # respawn ON: an expired token surfaces as a transport death, so without a
    # policy the M19 fork leaves the session dead and re-auth never happens.
    manifest.mcp_servers[_SERVER_ID].respawn = _RESPAWN
    connector = _connectors(manifest, registry, monkeypatch)[_SERVER_ID]
    try:
        first = connector.execute(_SERVER_ID, "whoami", {}, credential="")
        assert first.isError is False
        first_bearer = first.structuredContent["bearer"]

        toy_server.kill()
        toy_server.start()  # same port, fresh pid ⇒ every old token is dead

        # The first post-death dispatch surfaces the death typed (M17); the
        # respawn policy then reconnects, re-minting on the way.
        with pytest.raises(Exception):
            connector.execute(_SERVER_ID, "whoami", {}, credential="")
        second = connector.execute(_SERVER_ID, "whoami", {}, credential="")
        assert second.isError is False
        second_bearer = second.structuredContent["bearer"]
    finally:
        connector.close()
    assert second_bearer != first_bearer, (
        "the reconnect replayed the dead token instead of re-minting it"
    )


def test_credential_never_reaches_the_agent_surface_or_the_logs(
    toy_server, monkeypatch, caplog
):
    """Doctrine 1 on the REMOTE path: the stdio equivalent (C9, the merged env
    is never logged) does not transfer, because headers are a different
    surface — so it is proven separately here.

    The call is `ping`, whose response mentions no credential — deliberately
    NOT `whoami`/`echo`, which report the bearer back by design and would put
    it in the logs themselves, making this assertion pass or fail for reasons
    having nothing to do with the broker. With `ping`, any minted token in the
    logs is a real leak by the broker or its transport.
    """
    registry = _prefetched_registry(toy_server.port)
    manifest = _manifest(toy_server.port, header_map=_BEARER_HEADER)
    connector = _connectors(manifest, registry, monkeypatch)[_SERVER_ID]
    with caplog.at_level(logging.DEBUG):
        try:
            result = connector.execute(_SERVER_ID, "ping", {}, credential="")
            assert result.isError is False
        finally:
            connector.close()
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert _REFRESH_TOKEN not in logged, "the long-lived refresh token was logged"
    assert "toy-access-" not in logged, "the minted bearer was logged"
    # The connector object itself must not carry the credential into a repr —
    # an exception rendering it is the realistic leak path.
    assert _REFRESH_TOKEN not in repr(connector)
    assert "toy-access-" not in repr(connector)


def test_wrong_refresh_token_refuses_before_any_connect(toy_server, monkeypatch):
    """Fail-closed: a refresh token the authorization server rejects prevents
    the connect, and nothing renders the rejected credential.

    Note where the error lands. Credential resolution runs INSIDE the connect,
    so a strategy failure reaches the caller wrapped as the transport's typed
    death rather than as itself — the same shape the stdio `env_provider` path
    has. What must survive is the `CredentialStrategyError` on the cause chain:
    a failed connect whose real reason was swallowed is indistinguishable from
    an unreachable vendor, and those two want opposite fixes.
    """
    registry = _prefetched_registry(toy_server.port)
    manifest = _manifest(toy_server.port, header_map=_BEARER_HEADER)
    monkeypatch.setenv("MCP_REGISTRY_TABLE_NAME", "unused-memory-registry")
    monkeypatch.setattr(
        _mcpc, "DynamoToolRegistry", lambda hmac_key, table_name: registry
    )
    connectors = _mcpc.build_mcp_connectors(
        manifest,
        secrets=FakeSecretsProvider({_REFRESH_LEAF: "not-the-refresh-token"}),
        credential_strategies=build_credential_strategies(manifest.connector_auth),
        secret_name_for=lambda tool: tool,
    )
    connector = connectors[_SERVER_ID]
    try:
        with pytest.raises(Exception) as excinfo:
            connector.execute(_SERVER_ID, "whoami", {}, credential="")
    finally:
        connector.close()
    chain = _chain_text(excinfo.value)
    assert CredentialStrategyError.__name__ in chain, (
        f"the strategy failure must stay diagnosable on the chain; got:\n{chain}"
    )
    assert "not-the-refresh-token" not in chain, "the rejected credential was rendered"


# -- the OPERATOR path: `snapshot` against an authenticated remote server -----


def _write_manifest_yaml(tmp_path, port: int, *, header_map: dict | None) -> str:
    """The drill manifest as a FILE, because the operator command surface loads
    an image-baked manifest from a path rather than taking an object."""
    import yaml as _yaml

    manifest = _manifest(port, header_map=header_map)
    path = tmp_path / "manifest.yaml"
    path.write_text(_yaml.safe_dump(manifest.model_dump(mode="json", exclude_none=True)), encoding="utf-8")
    return str(path)


def _dir_secrets(tmp_path, monkeypatch, refresh_token: str) -> None:
    """Serve the refresh token through the `dir` arm — one file per leaf, the
    shape a K8s Secret / CSI volume projects and the shape an operator running
    a ceremony on a laptop actually has."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / _REFRESH_LEAF).write_text(refresh_token, encoding="utf-8")
    monkeypatch.setenv("BROKER_SECRETS", "dir")
    monkeypatch.setenv("BROKER_SECRETS_DIR", str(secrets_dir))
    monkeypatch.delenv("BROKER_SECRET_PREFIX", raising=False)


def test_snapshot_authenticates_to_a_remote_server(toy_server, tmp_path, monkeypatch):
    """The operator ceremony's FIRST step works against an authenticated
    vendor-hosted server.

    Regression pin for a real gap: #237 shipped `header_map` into the RUNTIME
    (`SupervisedStreamableHttpHost._open_client`) but left the operator command
    surface's `_discover_tool_defs` connecting to a remote decl with no headers
    at all. Since `snapshot` is pre-admission and every later remote ceremony
    step consumes its artifact (`show`, `diff`, `admit-propose --from-snapshot`),
    that made the whole admission ceremony unreachable for any remote server
    requiring auth — i.e. every real vendor.

    Non-vacuous because the toy genuinely 401s: a written snapshot can only mean
    the credential was really resolved and delivered. The companion test below
    pins that the unauthenticated case still fails.
    """
    from safe_agents.broker.mcp.commands import _parse_args, snapshot_command

    _dir_secrets(tmp_path, monkeypatch, _REFRESH_TOKEN)
    manifest_path = _write_manifest_yaml(tmp_path, toy_server.port, header_map=_BEARER_HEADER)
    out = tmp_path / "snapshot.json"

    assert snapshot_command(
        _parse_args(
            ["snapshot", "--manifest", manifest_path,
             "--server-id", _SERVER_ID, "--out", str(out)]
        )
    ) == 0

    captured = json.loads(out.read_text(encoding="utf-8"))
    assert captured["server_id"] == _SERVER_ID
    assert captured["transport"] == "streamable-http"
    assert sorted(e["tool_def"]["tool_name"] for e in captured["entries"]) == sorted(_TOOLS)
    # Every entry carries the hash the ceremony will bind — the artifact is
    # directly consumable by `admit-propose --from-snapshot`.
    assert all(e["def_hash"] for e in captured["entries"])
    # And nothing credential-shaped reached the artifact.
    assert _REFRESH_TOKEN not in out.read_text(encoding="utf-8")


def test_snapshot_without_header_map_still_fails_closed(
    toy_server, tmp_path, monkeypatch, capsys
):
    """The non-vacuity companion: with no `header_map` the snapshot cannot
    authenticate, so it refuses and writes nothing.

    Without this, the test above would pass just as happily against a server
    that never required auth at all.
    """
    from safe_agents.broker.mcp.commands import _parse_args, snapshot_command

    _dir_secrets(tmp_path, monkeypatch, _REFRESH_TOKEN)
    manifest_path = _write_manifest_yaml(tmp_path, toy_server.port, header_map=None)
    out = tmp_path / "snapshot.json"

    assert snapshot_command(
        _parse_args(
            ["snapshot", "--manifest", manifest_path,
             "--server-id", _SERVER_ID, "--out", str(out)]
        )
    ) == 1
    assert "could not discover tools" in capsys.readouterr().out
    assert not out.exists(), "a failed discovery must not leave a snapshot artifact"


# -- one-time-use credentials: the Doer must not spend the connect's grant ----


def _brokered_read(tool: str, op: str):
    """A minimal external-read BrokeredCall (the shape these Doer legs need)."""
    from safe_agents.broker.schemas import BrokeredCall

    return BrokeredCall.model_validate(
        {
            "principal": {
                "agentId": "doer-pin",
                "skill": "reader",
                "user": "test",
                "tier": "B",
            },
            "tool": tool,
            "op": op,
            "args": {},
            "manifest": {"tool": tool, "op": op, "effect": "read", "external": True},
            "taint": {"tainted": False, "sources": []},
            "session": {"turnId": "t-1", "ingestedSources": []},
            "ts": "2026-07-27T00:00:00Z",
        }
    )


def test_doer_does_not_resolve_a_credential_for_a_connector_that_takes_none():
    """Regression pin for #238, found live against a real brokerage.

    A single brokered MCP call used to resolve the credential TWICE: once in
    `Doer.execute` for every tool it runs, and again in the host's per-CONNECT
    header resolution (M25). The MCP connector documents `credential` as unused
    — its session is already authenticated — so the Doer's resolution was pure
    waste against a static secret and therefore invisible to every prior proof.

    Against a vendor issuing ONE-TIME-USE refresh tokens (OAuth 2.1's
    recommendation for public clients, and what a real brokerage actually does) the
    waste becomes fatal: the Doer SPENDS the grant, and the connect that needs
    it gets `invalid_grant`. The brokered path could not complete a single call.

    Non-vacuous by construction: the strategy below raises on its SECOND
    resolution, so the assertion is not merely "resolve was called once" but
    "the call path survived a credential that only works once".
    """
    from safe_agents.broker.runtime.doer import Doer
    from safe_agents.broker.schemas.decision import Allow

    resolutions: list[str] = []

    class OneTimeUseStrategy:
        def resolve(self, *, secrets, secret_name):
            resolutions.append(secret_name)
            if len(resolutions) > 1:
                raise CredentialStrategyError(
                    "refresh token already spent — one-time use"
                )
            return "the-only-grant"

    class AlreadyAuthenticatedConnector:
        uses_credential = False

        def execute(self, tool, op, args, credential):
            # What the real McpConnector asserts by ignoring the argument.
            assert credential == "", "the Doer handed over a credential anyway"
            return {"ok": True}

    doer = Doer(
        connectors={"vendor": AlreadyAuthenticatedConnector()},
        secrets=FakeSecretsProvider({"vendor": "unused"}),
        credential_strategies={"vendor": OneTimeUseStrategy()},
    )
    result = doer.execute(_brokered_read("vendor", "read_thing"), Allow(kind="allow"))
    assert result.result == {"ok": True}
    assert resolutions == [], (
        "the Doer resolved a credential for a connector that declares it takes "
        f"none; against a one-time-use grant that is the whole bug. Got: {resolutions}"
    )


def test_doer_still_resolves_for_a_connector_that_does_take_a_credential():
    """The counterfactual: the skip is driven by the connector's declaration,
    not by a blanket change. A connector that says nothing still gets one."""
    from safe_agents.broker.runtime.doer import Doer
    from safe_agents.broker.schemas.decision import Allow

    seen: list[str] = []

    class OrdinaryConnector:  # declares nothing -> default True
        def execute(self, tool, op, args, credential):
            seen.append(credential)
            return {"ok": True}

    doer = Doer(
        connectors={"api": OrdinaryConnector()},
        secrets=FakeSecretsProvider({"api": "s3cret-leaf-value"}),
    )
    doer.execute(_brokered_read("api", "read"), Allow(kind="allow"))
    assert seen == ["s3cret-leaf-value"], (
        f"an ordinary connector must still receive its credential; got {seen}"
    )
