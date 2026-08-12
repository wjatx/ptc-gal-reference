"""mcp_connector.py — the base connector that binds an ``McpHost`` (#174).

An MCP server is a connector; this is the base-connector-shaped wrapper a consumer
names in ``connector_providers`` for one MCP server. It satisfies the ``Connector``
protocol (``execute(tool, op, args, credential)``) the Doer dispatches to, and does
exactly one thing: map the brokered op onto ``McpHost.call`` so the host's ACTIVE
gate is enforced at execute time.

The coordinate mapping is the load-bearing detail: for an MCP connector the
BrokeredCall's ``tool`` IS the ``server_id`` and its ``op`` IS the ``tool_name``.
That is what makes the response taint correctly with ZERO PEP changes — the sa#134
self-ingestion hook stamps a successful ``external=True, effect="read"`` op as
``connector:<tool>.<op>``, which for this connector is exactly
``connector:<server_id>.<tool_name>`` (MCP-HOST.md M9). Admission is the host's
job; taint is the broker's; this connector is pure dispatch.

Loop-affinity contract (why this is not a one-liner): a REAL connected MCP
``ClientSession`` is bound to the event loop that opened it — its anyio background
reader tasks and memory streams live on that loop — so a per-call ``asyncio.run``
(a fresh loop each call, or a worker-thread loop when one is already running) would
drive ``host.call`` on a loop the session was never bound to and raise / hang. This
connector therefore owns ONE long-lived background event loop for its lifetime (a
daemon thread running ``run_forever``), and ALL host coroutine work — the lazy host
build, ``refresh()`` inside the factory, and every ``call()`` — is driven on that
one loop via ``run_coroutine_threadsafe(...).result(timeout=...)``. To make the
session live on that loop, a real session-backed host MUST arrive as an async
FACTORY (``Callable[[], Awaitable[McpHost]]``) invoked lazily on the connector's
loop at first use; a pre-built ``McpHost`` instance is still accepted for
fakes/tests, whose coroutines are not loop-affine. ``close()`` stops the loop
cleanly (cancel pending tasks, stop, join, close).

The host wraps an already-connected client (transport lifecycle is out of scope
here — the credential/session binding is established when the client is built),
so ``execute`` does not read ``credential``; it is accepted to satisfy the
protocol. The ``mcp`` SDK is never imported here (nor transitively at module load,
matching client.py's lazy-import discipline).
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Awaitable, Callable, Optional, Protocol, Union

from safe_agents.broker.runtime.connector import Connector, Credential

# A single generous liveness bound so a wedged MCP call fails loudly instead of
# hanging the synchronous Doer forever. Not a per-tool policy — just a backstop.
_CALL_TIMEOUT_S = 30.0


class McpHostLike(Protocol):
    """What the connector needs from a host: a name and an async call gate.

    Satisfied by ``McpHost`` (fakes/tests) and by the supervised lifecycle
    wrapper ``SupervisedStdioHost`` (#221 P3) — the connector never cares which;
    admission and lifecycle both live behind ``call``. A host MAY additionally
    expose ``aclose()``; if it does, ``close()`` drives it on the loop BEFORE
    the loop is torn down, so children are reaped while their cancel scopes can
    still run (MCP-HOST.md M20).
    """

    @property
    def server_id(self) -> str: ...

    def call(self, tool_name: str, arguments: Optional[dict] = None) -> Awaitable[Any]: ...


# A zero-arg async factory that builds the host ON the connector's loop; used for a
# real, loop-affine session-backed host (see the module docstring).
HostFactory = Callable[[], Awaitable[McpHostLike]]


class McpConnector:
    """Base connector binding one ``McpHost``; dispatches op → ``host.call``.

    Zero admission logic of its own — the host's cached ACTIVE gate decides
    callability, and a non-ACTIVE tool raises ``ToolNotCallableError`` out of
    ``host.call`` before any transport. Satisfies the ``Connector`` protocol.

    Construct with either a pre-built ``McpHost`` instance (fakes/tests; its
    coroutines are not loop-affine) or an async factory that builds the host on the
    connector's own loop (the ONLY correct way to bind a real MCP session — see the
    module docstring). Whichever is supplied, every host coroutine runs on the one
    long-lived background loop this connector owns.
    """

    def __init__(self, host: Union[McpHostLike, HostFactory]) -> None:
        # A callable is an async factory built lazily ON our loop; anything else is a
        # pre-built host instance. McpHost (and the test fakes) are not callable, so
        # ``callable`` cleanly distinguishes the two paths.
        if callable(host):
            self._factory: Optional[HostFactory] = host
            self._host: Optional[McpHostLike] = None
        else:
            self._factory = None
            self._host = host
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._loop_lock = threading.Lock()
        self._host_lock = threading.Lock()

    #: This connector takes NO Doer-resolved credential — its session is already
    #: authenticated, and a remote host resolves its own credential per CONNECT
    #: (M25). The Doer reads this to skip resolution entirely. It is not an
    #: optimisation: against a vendor issuing one-time-use refresh tokens, a
    #: resolution here spends the grant the connect then needs (#238).
    uses_credential = False

    def execute(self, tool: str, op: str, args: Any, credential: Credential) -> Any:
        """Dispatch one brokered call onto the host: ``op`` is the MCP tool name.

        ``tool`` is the ``server_id`` (it must match the host's server) and ``op``
        is the ``tool_name`` handed to ``host.call``, driven on the connector's own
        loop. ``credential`` is unused — the host's client is already connected,
        and ``uses_credential = False`` above stops the Doer resolving one at all.
        The host enforces the ACTIVE gate; a refused tool propagates its
        ``ToolNotCallableError``.
        """
        host = self._ensure_host()
        if tool != host.server_id:
            raise ValueError(
                f"McpConnector bound to server {host.server_id!r} but "
                f"dispatched tool {tool!r}"
            )
        arguments = self._coerce_args(args)
        return self._drive(host.call(op, arguments))

    def close(self) -> None:
        """Stop the background loop cleanly (idempotent).

        Ordering is the M20 clause: if the host exposes ``aclose()`` (the
        supervised lifecycle wrapper does), drive it FIRST — it cancels the
        session driver and awaits the unwind, so the child process is reaped
        while the loop is still running. Only then cancel whatever remains,
        stop and close the loop, and join its thread. A loop torn down first
        would strand the SDK's cancel scopes and could leak the child. Safe to
        call when the loop never started (nothing to do).
        """
        with self._loop_lock:
            loop, thread = self._loop, self._thread
            self._loop = self._thread = None
        if loop is None:
            return

        host = self._host
        aclose = getattr(host, "aclose", None)
        if aclose is not None:
            try:
                asyncio.run_coroutine_threadsafe(aclose(), loop).result(
                    timeout=_CALL_TIMEOUT_S
                )
            except Exception:  # best-effort — the generic cancel below still runs
                pass

        async def _cancel_pending() -> None:
            pending = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        try:
            asyncio.run_coroutine_threadsafe(_cancel_pending(), loop).result(
                timeout=_CALL_TIMEOUT_S
            )
        except Exception:  # best-effort teardown — never raise out of close()
            pass
        loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=_CALL_TIMEOUT_S)
        loop.close()

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _coerce_args(args: Any) -> dict:
        """``None`` → ``{}``; a dict passes through; anything else fails closed.

        Silently coercing a non-dict to ``{}`` would run the external call with
        EMPTY arguments while the PDP/audit recorded the ORIGINAL args — an audit /
        egress divergence. Raise (the Doer surfaces connector exceptions).
        """
        if args is None:
            return {}
        if isinstance(args, dict):
            return args
        raise ValueError(
            f"McpConnector arguments must be a dict or None, got {type(args).__name__}"
        )

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """Start (once) the daemon thread running the connector's long-lived loop."""
        with self._loop_lock:
            if self._loop is not None:
                return self._loop
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=self._run_loop,
                args=(loop,),
                name="mcp-connector-loop",
                daemon=True,
            )
            thread.start()
            self._loop = loop
            self._thread = thread
            return loop

    @staticmethod
    def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def _drive(self, coro: Awaitable[Any]) -> Any:
        """Run a host coroutine to completion ON the connector's loop from sync code."""
        loop = self._ensure_loop()
        return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=_CALL_TIMEOUT_S)

    def _ensure_host(self) -> McpHostLike:
        """Return the host, building it from the factory on our loop at first use.

        The factory is invoked ON the connector's loop so the session it opens (and
        the anyio reader tasks bound to that loop) is the same loop every subsequent
        ``call`` runs on — the loop-affinity contract in the module docstring.
        """
        if self._host is not None:
            return self._host
        with self._host_lock:
            if self._host is not None:
                return self._host
            assert self._factory is not None  # instance path already returned above
            self._host = self._drive(self._factory())
            return self._host


# Structural conformance, checked at import time so a drift from the protocol fails
# HERE rather than at first dispatch (mirrors PeerConnector's import-time assert).
assert issubclass(McpConnector, Connector)
