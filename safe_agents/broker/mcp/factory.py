"""factory.py — the supervised host factories for ``McpConnector`` (#219, #221 P3).

The loop-affinity contract (``connectors/mcp_connector.py``) requires a real
session-backed ``McpHost`` to arrive as an async FACTORY invoked on the
connector's own loop, with the session's async context held open inside one
long-lived driver task — the SDK's anyio task-group / cancel-scope must be
entered and exited in the same task. Until #219 that driver-task idiom lived
only in the test suite; this module is the packaged reference a manifest's
native construction composes.

Since #221 Phase 3 the factory yields a **supervised** host that owns the
session's whole lifecycle per the MCP-HOST.md lifecycle clauses:

  * **M17 — typed death.** Death of the child/session or its transport — at
    spawn, mid-call, or between calls — surfaces as ``McpChildDeathError``
    carrying the server id and the real cause (``__cause__``), promptly.
    Never the connector's generous call-timeout backstop (the naive idiom
    surfaced every spawn failure as a bare 30s ``TimeoutError`` with the
    cause lost — the #219 Leg-1 finding), and never a raw transport internal
    as the API.
  * **M18 — a reconnect is a new discovery.** Every spawn constructs a fresh
    ``McpHost`` and runs ``refresh()`` before the host is served, so a
    respawned child re-runs the pure discovery evaluator with fresh registry
    reads; no verdict or snapshot ever crosses a session death. The transport
    context is re-entered per spawn, so any per-spawn resolution (the stdio
    ``env_provider`` credential half) re-runs the same way.
  * **M19 — respawn is data and ships OFF.** With no ``McpRespawnPolicy`` a
    dead host stays dead-but-typed (byte-for-byte the pre-knob behavior);
    with one, each death grants ``max_attempts`` respawns with
    ``backoff_seconds`` between them, and an exhausted policy degrades to
    exactly the OFF behavior — sticky typed failure, no retry storm.
  * **M20 — reap before the loop closes.** ``aclose()`` cancels the driver
    task and AWAITS it, so the SDK context unwinds and the child is reaped
    (or the remote session disconnected) while the loop is still running;
    the connector drives it before its own loop teardown.

Supervision is transport-agnostic (``SupervisedMcpHost``): the lifecycle
clauses govern the *session*, not the process behind it. ``SupervisedStdioHost``
is the spawned-child stdio transport; ``SupervisedStreamableHttpHost`` (the
remote clause, **M21**) supervises a streamable-HTTP MCP server through the
SAME shared body — nothing about generation scoping, the respawn burst, the
deadline, or the M20 reap is duplicated per transport. Each transport supplies
its own per-connect credential half through the same shape: ``env_provider``
for a spawned child's environment (C9), ``headers_provider`` for a remote
session's request headers (C10/M25). Both resolve INSIDE ``_open_client``, so
a reconnect re-resolves rather than replaying — which is what makes reconnect
the re-auth path for an expired token. Credential values are never logged or
repr'd.

A *construction refusal* (e.g. ``McpConstructionError`` out of the
``env_provider`` on first spawn) is not a session death — no session ever
ran — and propagates as itself; only spawn/connect/transport failures wrap.

No ``mcp`` SDK import happens at module load (``connect_stdio`` and
``connect_streamable_http`` import it lazily), preserving the base package's
SDK-free import discipline.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import (
    Any,
    AsyncContextManager,
    AsyncIterator,
    Awaitable,
    Callable,
    Optional,
    Sequence,
)

from safe_agents.broker.mcp import client as _client_mod
from safe_agents.broker.mcp.client import McpClient
from safe_agents.broker.mcp.host import McpHost, ToolNotCallableError
from safe_agents.broker.mcp.registry import ToolRegistryStore
from safe_agents.broker.schemas.mcp_registry import McpRespawnPolicy, McpServerDecl

logger = logging.getLogger(__name__)

# Per-spawn env resolver — invoked once per child spawn on the connector's loop,
# so the credential half is re-resolved fresh across a respawn (M18). Stdio-only:
# a remote server has no child whose environment to set.
EnvProvider = Callable[[], Awaitable[Optional[dict]]]

# The remote dual (#237, M25) — invoked once per CONNECT on the connector's
# loop, so the credential half is re-resolved fresh on every reconnect. That
# re-resolution is not a convenience: an expired access token surfaces as an
# httpx-family death, so reconnect IS how re-auth happens, and a provider (not
# a static dict) is what makes the second connect carry a new token.
HeadersProvider = Callable[[], Awaitable[Optional[dict]]]

# How long a mid-call failure waits for the driver task to settle before
# deciding whether the exception was a session death (wrap, M17) or a genuine
# call error (re-raise). The driver unwinds in the same loop, so this is a
# scheduling grace, not a liveness bound.
_DRIVER_SETTLE_S = 1.0

# Hard deadline on one death's whole respawn burst (sleeps + spawn attempts).
# The schema bounds only max_attempts × backoff; real spawn time is unbounded
# (a cold uvx spawn is slow — the #219 drill pre-warmed the cache for exactly
# this reason), and a burst that outlives the connector's 30s backstop would
# surface as the bare TimeoutError M17 exists to kill. Kept under that
# backstop; on expiry the burst is cancelled and the failure is typed.
_BURST_DEADLINE_S = 25.0

# Exception families that ARE the transport reporting a dead peer/stream,
# matched by the top-level module of the exception type (SDK-free): anyio for
# in-process stream closures (both transports ride anyio streams), httpx /
# httpcore for the streamable-HTTP client's connect/read failures (M21).
_TRANSPORT_DEATH_MODULES = frozenset({"anyio", "httpx", "httpcore"})


class McpChildDeathError(Exception):
    """Typed failure: the MCP child/session (or its transport) is dead (M17).

    One typed death for every transport — a spawned stdio child and a remote
    streamable-HTTP session die the same way at this API. ``server_id`` names
    the server; ``detail`` says when it died (spawn / mid-session / respawn
    exhausted); the real cause rides ``__cause__`` so nothing about the death
    is less diagnosable than the raw exception was.
    """

    def __init__(self, server_id: str, detail: str) -> None:
        self.server_id = server_id
        self.detail = detail
        super().__init__(f"MCP server {server_id!r} child is dead: {detail}")


class SupervisedMcpHost:
    """Host-protocol wrapper owning one MCP session's spawn/respawn lifecycle.

    The transport-agnostic supervision core: subclasses supply exactly ONE
    seam — ``_open_client``, an async context manager that connects the
    transport and yields a connected ``McpClient`` — and every lifecycle
    clause (M17 typed death, M18 reconnect-as-new-discovery, M19 ships-OFF
    respawn with its burst deadline, M20 reap-before-loop-close, generation
    scoping) lives HERE once, shared verbatim across transports.

    Serves the ``McpConnector`` host protocol (``server_id`` + async ``call``,
    plus ``aclose`` for ordered teardown). The current inner ``McpHost`` is
    replaced wholesale on every spawn — snapshot, session, and child are one
    unit and die together (M18).
    """

    def __init__(
        self,
        server_id: str,
        *,
        server_decl: McpServerDecl,
        registry: ToolRegistryStore,
        respawn: Optional[McpRespawnPolicy] = None,
    ) -> None:
        self._server_id = server_id
        self._server_decl = server_decl
        self._registry = registry
        self._respawn = respawn
        self._host: Optional[McpHost] = None
        self._driver: Optional[asyncio.Task] = None
        self._death_exc: Optional[BaseException] = None
        # False until ONE spawn has connected successfully. A never-connected
        # server may be re-attempted on a later dispatch (the pre-knob
        # connector retried its factory the same way); death AFTER a
        # successful connect is what the respawn policy governs (M19).
        self._connected_once = False
        self._exhausted = False
        self._closing = False
        self._lock: Optional[asyncio.Lock] = None  # created lazily on our loop

    @property
    def server_id(self) -> str:
        return self._server_id

    @property
    def inner(self) -> Optional[McpHost]:
        """The current live inner host (None before first spawn / after death).

        Reference/test convenience — production dispatch goes through
        ``call()`` so the lifecycle gate cannot be skipped.
        """
        if self._driver is not None and not self._driver.done():
            return self._host
        return None

    def _open_client(self) -> AsyncContextManager[McpClient]:
        """The one transport seam: a FRESH async context manager that connects
        and yields a connected ``McpClient``. Entered once per spawn INSIDE
        the driver task — so per-spawn resolution (the stdio credential half)
        re-runs on every respawn (M18) — and exited to reap/disconnect (M20).
        """
        raise NotImplementedError("transport subclasses supply _open_client")

    async def start(self) -> "SupervisedMcpHost":
        """First spawn, single-shot: a spawn/connect failure here is delivered
        typed immediately (M17) — the respawn policy governs re-spawn after a
        successful connect, never a first spawn that could mask bad config."""
        await self._ensure_live()
        return self

    async def refresh(self) -> Any:
        """Delegate to the live inner host (reference/test convenience)."""
        host = await self._ensure_live()
        return await host.refresh()

    async def call(self, tool_name: str, arguments: Optional[dict] = None) -> Any:
        """Dispatch one call through the lifecycle gate.

        A dead session either respawns per policy (fresh discovery before any
        call — M18) or raises ``McpChildDeathError`` (M17/M19).

        The in-flight call is RACED against its generation's driver task. The
        two transports die facing opposite directions: over stdio the death
        surfaces IN the call (an anyio closure out of the stream read) while
        the driver may stay parked; over streamable-http the death is
        typically delivered TO the driver (the SDK routes the next POST's
        failure into the transport task group) while the dispatching caller
        stays parked on its response stream forever — so without the race,
        the FIRST post-death http dispatch rode the connector's bare 30s
        backstop, the exact untyped failure M17 forbids (observed live, the
        test_mcp_streamable_http.py finding). Which direction a given http
        death takes is SDK-version-dependent: on 1.25.0 a restarted server's
        stale-session answer rides the task group (httpx.HTTPStatusError
        400); on 1.28.x the SDK raises it to the CALLER as
        ``McpError("Session terminated")`` with the driver healthy — the
        race covers the driver direction, ``_is_transport_death``'s McpError
        branch the caller direction. A finished driver therefore retires the
        parked call promptly; a call that finishes keeps the original
        classification exactly — a genuine call error (including
        ``ToolNotCallableError``) passes through untouched, and only a
        transport-family exception or an actually-dead driver wraps typed.
        """
        host = await self._ensure_live()
        driver = self._driver  # the generation this call rides (set with host)
        call_task = asyncio.ensure_future(host.call(tool_name, arguments))
        waiters = {call_task, driver} if driver is not None else {call_task}
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            # OUR caller was cancelled: reap the in-flight call, then propagate.
            call_task.cancel()
            await asyncio.gather(call_task, return_exceptions=True)
            raise
        if not call_task.done():
            # The DRIVER finished first while the call stayed parked (the
            # http death direction). Retire the parked call ourselves and
            # surface the death typed NOW — never the 30s backstop.
            call_task.cancel()
            await asyncio.gather(call_task, return_exceptions=True)
            if self._closing:
                raise McpChildDeathError(self._server_id, "connector is closing")
            cause = self._driver_death_cause(driver)
            await self._mark_dead(cause, generation=host)
            raise McpChildDeathError(
                self._server_id, f"child/session died mid-call to {tool_name!r}"
            ) from cause
        try:
            return call_task.result()
        except (asyncio.CancelledError, ToolNotCallableError):
            raise
        except BaseException as exc:
            # A dead child does NOT reliably wake the parked driver task (a
            # SIGKILL'd child just closes the streams; the SDK's readers treat
            # EOF as normal), so death shows up here as a transport-family
            # exception out of the call. Either signal — transport closure or
            # an actually finished driver — is a death (M17): reap the stale
            # driver so the next call takes the M19 fork, and raise typed with
            # the cause. Death handling is GENERATION-SCOPED to the host/driver
            # this call actually used: a stale in-flight call whose child was
            # already replaced must never retire the fresh generation.
            if _is_transport_death(exc) or await self._driver_died(
                driver, within=_DRIVER_SETTLE_S
            ):
                await self._mark_dead(exc, generation=host)
                raise McpChildDeathError(
                    self._server_id, f"child/session died mid-call to {tool_name!r}"
                ) from exc
            raise

    async def aclose(self) -> None:
        """Cancel the driver and AWAIT the unwind — the child is reaped (the
        connect context exited) before this returns, while the loop is still
        alive (M20). Idempotent.

        Takes the lifecycle lock so an in-progress spawn/respawn (which runs
        under it, deadline-bounded) completes or cancels FIRST — otherwise a
        mid-burst aclose would see no driver, return early, and let the burst
        park a live child nothing will ever reap.
        """
        self._closing = True  # set before the lock: an in-burst spawn's next
        # _ensure_live re-entry refuses, and post-lock we reap whatever landed.
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            driver, self._driver = self._driver, None
            self._host = None
            if driver is None:
                return
            driver.cancel()
            await asyncio.gather(driver, return_exceptions=True)

    # -- internals ----------------------------------------------------------

    async def _ensure_live(self) -> McpHost:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._closing:
                raise McpChildDeathError(self._server_id, "connector is closing")
            if self._driver is not None and not self._driver.done():
                assert self._host is not None
                return self._host
            if self._exhausted:
                raise McpChildDeathError(
                    self._server_id,
                    "respawn policy exhausted; child stays dead until the "
                    "service restarts (M19)",
                ) from self._death_exc
            if not self._connected_once:
                # Never connected: (re-)attempt the first spawn. A failure is
                # typed but NOT sticky — the pre-knob connector re-invoked its
                # factory on the next dispatch the same way, and a first-spawn
                # failure (bad command, cold cache, unreachable peer) is
                # config/transient, not a session death the respawn policy
                # governs.
                try:
                    host = await self._spawn_once()
                except (asyncio.CancelledError, McpChildDeathError):
                    raise
                except BaseException as exc:
                    if _is_construction_refusal(exc):
                        raise  # a refusal, not a death — no session ever ran
                    raise McpChildDeathError(
                        self._server_id, "child/session failed to spawn"
                    ) from exc
                self._connected_once = True
                return host
            # Death after a successful connect — the M19 fork.
            self._record_death()
            if self._respawn is None:
                self._exhausted = True
                raise McpChildDeathError(
                    self._server_id,
                    "child/session died and no respawn policy is declared "
                    "(MCP-HOST.md M19: absent block = no respawn)",
                ) from self._death_exc
            # The burst rides a hard deadline UNDER the connector's liveness
            # backstop: the schema bounds sleeps, but spawn time is unbounded,
            # and a burst that outlived the backstop would surface as the bare
            # TimeoutError M17 exists to kill. Expiry cancels the in-flight
            # attempt (whose reap runs in _spawn_once) and degrades to the
            # exhausted OFF behavior — typed, sticky.
            try:
                return await asyncio.wait_for(
                    self._respawn_burst(), timeout=_BURST_DEADLINE_S
                )
            except asyncio.TimeoutError:
                self._exhausted = True
                raise McpChildDeathError(
                    self._server_id,
                    f"respawn burst exceeded its {_BURST_DEADLINE_S:.0f}s "
                    "deadline; child stays dead until the service restarts "
                    "(M19 degradation)",
                ) from self._death_exc

    async def _respawn_burst(self) -> McpHost:
        """One death's worth of respawn attempts (M19). Runs under the lock."""
        assert self._respawn is not None
        last_exc: Optional[BaseException] = self._death_exc
        for attempt in range(1, self._respawn.max_attempts + 1):
            if self._closing:
                raise McpChildDeathError(self._server_id, "connector is closing")
            if self._respawn.backoff_seconds:
                await asyncio.sleep(self._respawn.backoff_seconds)
            try:
                host = await self._spawn_once()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                last_exc = exc
                logger.warning(
                    "MCP server %r respawn attempt %d/%d failed: %r",
                    self._server_id,
                    attempt,
                    self._respawn.max_attempts,
                    exc,
                )
                continue
            logger.info(
                "MCP server %r respawned (attempt %d/%d); discovery re-evaluated",
                self._server_id,
                attempt,
                self._respawn.max_attempts,
            )
            return host
        self._exhausted = True
        raise McpChildDeathError(
            self._server_id,
            f"respawn exhausted after {self._respawn.max_attempts} attempt(s); "
            "child stays dead until the service restarts (M19)",
        ) from last_exc

    async def _spawn_once(self) -> McpHost:
        """Open the transport and hold its session open in a fresh driver task.

        The fresh ``McpHost`` runs ``refresh()`` BEFORE the ready future
        resolves, so every spawn — first or re — serves only a host holding a
        brand-new discovery snapshot (M18). ``_open_client`` is entered inside
        the driver, so whatever per-spawn resolution it performs re-runs on
        every spawn. A connect/refresh failure is delivered to the awaiting
        caller immediately as the real exception (the #219 Leg-1 hardening);
        a death AFTER ready is recorded for the next call to surface typed.
        """
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[McpHost] = loop.create_future()

        async def _driver() -> None:
            try:
                async with self._open_client() as client:
                    host = McpHost(self._server_decl, self._registry, client)
                    await host.refresh()
                    ready.set_result(host)
                    # Hold the session (and the child) until cancel or death.
                    await asyncio.Event().wait()
            except asyncio.CancelledError:
                raise
            except BaseException as exc:
                if not ready.done():
                    # Connect/refresh failed: deliver the REAL error now, not
                    # a timeout later.
                    ready.set_exception(exc)
                else:
                    # Post-connect death: the next call surfaces it typed
                    # (M17); log once so the cause is never silently lost.
                    logger.error(
                        "MCP session driver for server %r died after connect: %r",
                        self._server_id,
                        exc,
                    )
                    raise

        driver = asyncio.ensure_future(_driver())
        try:
            host = await ready
        except BaseException:
            # The driver is finished or finishing; reap it so nothing leaks.
            driver.cancel()
            await asyncio.gather(driver, return_exceptions=True)
            raise
        self._driver = driver
        self._host = host
        return host

    @staticmethod
    def _driver_death_cause(driver: Optional[asyncio.Task]) -> BaseException:
        """The chainable cause for a driver that finished under a parked call.

        Normally the driver's own exception (over streamable-http, an
        ``ExceptionGroup`` wrapping the real httpx/httpcore failure — the SDK
        re-raises its transport task group's error out of the connect
        context). A driver cancelled externally (a concurrent ``_mark_dead``
        from another call on the same generation, or a raced ``aclose``) has
        no exception to retrieve — synthesize one so ``__cause__`` is never
        None and the death stays diagnosable.
        """
        if driver is not None and not driver.cancelled():
            exc = driver.exception()
            if exc is not None:
                return exc
        return asyncio.CancelledError(
            "session driver task was cancelled/retired externally"
        )

    async def _driver_died(
        self, driver: Optional[asyncio.Task], within: float
    ) -> bool:
        """Did THIS generation's driver task die? Poll-with-deadline rather
        than awaiting the task — awaiting would conflate the driver's
        cancellation with our own."""
        if driver is None:
            return self._death_exc is not None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + within
        while not driver.done() and loop.time() < deadline:
            await asyncio.sleep(0.02)
        return driver.done() and not self._closing

    def _record_death(self) -> None:
        driver = self._driver
        if driver is None or not driver.done():
            return
        if not driver.cancelled():
            self._death_exc = driver.exception()
        self._driver = None
        self._host = None

    async def _mark_dead(self, cause: BaseException, generation: McpHost) -> None:
        """Force-retire ONE spawn generation after an observed transport death.

        No-ops unless ``generation`` is still the installed host — a stale
        observer (an in-flight call from before a respawn) must never cancel
        the fresh generation's driver. The driver may still be parked on its
        hold (a killed child closes the streams without raising into it) —
        cancel it and AWAIT the unwind so the SDK context releases its
        resources, then record the death for the M19 fork on the next dispatch.
        """
        if self._host is not generation:
            return
        driver, self._driver = self._driver, None
        self._host = None
        self._death_exc = cause
        if driver is not None and not driver.done():
            driver.cancel()
            await asyncio.gather(driver, return_exceptions=True)


class SupervisedStdioHost(SupervisedMcpHost):
    """The stdio transport's supervised host: one spawned child per generation.

    Name-stable entry point for the pre-M21 API — the ``__init__`` signature
    is unchanged and every lifecycle behavior lives in ``SupervisedMcpHost``.
    The per-spawn ``env_provider`` (the credential half, CONNECTOR-AUTH C9)
    resolves inside ``_open_client`` on every spawn, so a respawn never reuses
    a previous child's environment (M18).
    """

    def __init__(
        self,
        server_id: str,
        command: str,
        args: Sequence[str],
        *,
        server_decl: McpServerDecl,
        registry: ToolRegistryStore,
        cwd: Optional[str] = None,
        env_provider: Optional[EnvProvider] = None,
        respawn: Optional[McpRespawnPolicy] = None,
    ) -> None:
        super().__init__(
            server_id, server_decl=server_decl, registry=registry, respawn=respawn
        )
        self._command = command
        self._args = list(args)
        self._cwd = cwd
        self._env_provider = env_provider

    @asynccontextmanager
    async def _open_client(self) -> AsyncIterator[McpClient]:
        # Per-spawn env resolution (M18): the credential half is re-resolved
        # fresh on every spawn, never carried across a child death.
        env = await self._env_provider() if self._env_provider else None
        # Module attribute (not a from-import) so tests can fake the
        # transport SDK-free by patching client.connect_stdio.
        async with _client_mod.connect_stdio(
            self._server_id,
            self._command,
            self._args,
            cwd=self._cwd,
            env=env,
        ) as client:
            yield client


class SupervisedStreamableHttpHost(SupervisedMcpHost):
    """The streamable-HTTP transport's supervised host (M21).

    Supervises a REMOTE MCP server with the same lifecycle the stdio child
    gets: there is no process to reap, but the session is still one
    generation — a dead peer surfaces typed (M17), a reconnect re-enters the
    connect context and re-runs discovery fresh (M18), reconnect policy is
    the same ships-OFF ``McpRespawnPolicy`` (M19), and ``aclose`` exits the
    connect context before the loop closes (M20).

    The per-connect ``headers_provider`` is the credential half (M25,
    CONNECTOR-AUTH C10) — the exact mirror of ``SupervisedStdioHost``'s
    ``env_provider``, resolved inside ``_open_client`` on every connect so a
    reconnect never reuses a previous session's token (M18). Header VALUES are
    secret-adjacent by design: never logged or repr'd, here or downstream.
    """

    def __init__(
        self,
        server_id: str,
        url: str,
        *,
        server_decl: McpServerDecl,
        registry: ToolRegistryStore,
        headers_provider: Optional[HeadersProvider] = None,
        respawn: Optional[McpRespawnPolicy] = None,
    ) -> None:
        super().__init__(
            server_id, server_decl=server_decl, registry=registry, respawn=respawn
        )
        self._url = url
        self._headers_provider = headers_provider

    @asynccontextmanager
    async def _open_client(self) -> AsyncIterator[McpClient]:
        # Per-connect header resolution (M18/M25): the credential half is
        # re-resolved fresh on every connect, so an access token that expired
        # under the previous session is re-minted for this one rather than
        # replayed dead.
        headers = await self._headers_provider() if self._headers_provider else None
        # Module attribute (not a from-import) so tests can fake the transport
        # SDK-free by patching client.connect_streamable_http. Re-entered per
        # spawn: a reconnect is a fresh connect context, never a resumed
        # session (M18).
        async with _client_mod.connect_streamable_http(
            self._server_id, self._url, headers=headers
        ) as client:
            yield client


def _is_transport_death(exc: BaseException) -> bool:
    """Is this exception the transport reporting a dead peer/stream?

    Three shapes, all observed or SDK-documented against real servers (never
    tool-semantic — tool failures ride ``CallToolResult.isError`` and
    admission refusals are ``ToolNotCallableError`` before any transport):

      * anyio's stream-closure family (``ClosedResourceError`` /
        ``BrokenResourceError`` / ``EndOfStream``) — the toy-server SIGKILL
        shape, and the in-process half of every SDK transport;
      * httpx/httpcore's connect/read error family — how the streamable-HTTP
        client surfaces a dead or unreachable remote peer (M21);
      * the SDK's ``McpError`` in one of two death messages: a
        connection-closed message — how a real session's request machinery
        reports the dead child when its reader noticed EOF first (observed
        live against ``alpaca-mcp-server``) — or a session-terminated
        message — how the streamable-http client reports a restarted remote
        answering a stale ``mcp-session-id`` POST, raised to the CALLER while
        the transport task group and driver stay healthy (SDK
        version-dependent: 1.25.0 surfaces the same bounce as an httpx 400
        into the task group; 1.28.x takes this caller-direction shape).
        The session-terminated error is client-SYNTHESIZED with the
        distinctive sign-bugged ``ErrorData(code=32600, ...)`` (the JSON-RPC
        standard INVALID_REQUEST is -32600), so that exact positive code is
        accepted as a rewording-resilient secondary key — but NEVER -32600
        itself, which a live server can legitimately send for a malformed
        request that is not a death.

    An ``ExceptionGroup``'s own module is ``builtins`` — the SDK's transports
    re-raise their anyio task group's failure as a group, so the LEAVES must
    be examined: a group is a death iff ANY leaf exception (recursively)
    matches the families or the McpError branch above.

    Matched by module/name to keep this file SDK-free. Deliberately NARROW on
    McpError: any other protocol error stays a call error, not a death.
    Known trade: message-keying drifts when the SDK rewords — and that drift
    CLASS has materialized once already (the session-terminated shape arrived
    on newer SDKs and was missed until reviewed, leaving M19 inert for a
    server deploy bounce). A future rewording degrades a dead session to a
    STICKY RAW McpError (never typed, never the M19 fork) — the live legs
    (the alpaca lifecycle leg in test_alpaca_drill_live.py and the
    toy-server death legs in test_mcp_streamable_http.py) are the canary
    for the next one.
    """
    if isinstance(exc, BaseExceptionGroup):
        return any(_is_transport_death(leaf) for leaf in exc.exceptions)
    if type(exc).__module__.split(".")[0] in _TRANSPORT_DEATH_MODULES:
        return True
    if type(exc).__name__ != "McpError":
        return False
    message = str(exc).lower()
    if "connection closed" in message or "session terminated" in message:
        return True
    # Duck-typed (SDK-free): McpError carries a structured `error: ErrorData`.
    return getattr(getattr(exc, "error", None), "code", None) == 32600


def _is_construction_refusal(exc: BaseException) -> bool:
    """A boot-time wiring refusal is not a child death — keep it unwrapped.

    Matched by name to avoid a circular import with the construction module
    (which imports this one).
    """
    return type(exc).__name__ == "McpConstructionError"


def stdio_host_factory(
    server_id: str,
    command: str,
    args: Optional[Sequence[str]] = None,
    *,
    server_decl: McpServerDecl,
    registry: ToolRegistryStore,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    env_provider: Optional[EnvProvider] = None,
    respawn: Optional[McpRespawnPolicy] = None,
) -> Callable[[], Awaitable[SupervisedStdioHost]]:
    """Build the async host factory ``McpConnector`` expects for a stdio server.

    The returned factory must be invoked on the connector's own loop (the
    connector does this itself — pass the factory straight to
    ``McpConnector(...)``). It yields a started ``SupervisedStdioHost``: the
    first child is spawned eagerly so a spawn failure surfaces at first
    dispatch, typed, with the real cause (M17).

    ``env`` is a static child environment; ``env_provider`` re-resolves it per
    spawn (the credential-half seam, M18) — pass at most one of the two.
    """
    if env is not None and env_provider is not None:
        raise ValueError(
            "stdio_host_factory takes env OR env_provider, not both — a static "
            "env cannot also be per-spawn resolved"
        )
    if env is not None:
        static_env = dict(env)

        async def _static_provider() -> Optional[dict]:
            return dict(static_env)

        env_provider = _static_provider

    async def factory() -> SupervisedStdioHost:
        supervised = SupervisedStdioHost(
            server_id,
            command,
            args or [],
            server_decl=server_decl,
            registry=registry,
            cwd=cwd,
            env_provider=env_provider,
            respawn=respawn,
        )
        await supervised.start()
        return supervised

    return factory


def streamable_http_host_factory(
    server_id: str,
    url: str,
    *,
    server_decl: McpServerDecl,
    registry: ToolRegistryStore,
    headers: Optional[dict[str, str]] = None,
    headers_provider: Optional[HeadersProvider] = None,
    respawn: Optional[McpRespawnPolicy] = None,
) -> Callable[[], Awaitable[SupervisedStreamableHttpHost]]:
    """Build the async host factory ``McpConnector`` expects for a remote
    streamable-HTTP server (M21).

    Mirrors ``stdio_host_factory``: the returned factory must be invoked on
    the connector's own loop, and it yields a started
    ``SupervisedStreamableHttpHost`` — the first connect happens eagerly so a
    connect failure surfaces at first dispatch, typed, with the real cause
    (M17).

    ``headers`` is a static header set; ``headers_provider`` re-resolves it per
    connect (the credential-half seam, M25/M18) — pass at most one of the two,
    exactly as ``stdio_host_factory`` takes ``env`` OR ``env_provider``. Header
    values must never be logged or repr'd anywhere.
    """
    if headers is not None and headers_provider is not None:
        raise ValueError(
            "streamable_http_host_factory takes headers OR headers_provider, "
            "not both — a static header set cannot also be per-connect resolved"
        )
    if headers is not None:
        static_headers = dict(headers)

        async def _static_provider() -> Optional[dict]:
            return dict(static_headers)

        headers_provider = _static_provider

    async def factory() -> SupervisedStreamableHttpHost:
        supervised = SupervisedStreamableHttpHost(
            server_id,
            url,
            server_decl=server_decl,
            registry=registry,
            headers_provider=headers_provider,
            respawn=respawn,
        )
        await supervised.start()
        return supervised

    return factory
