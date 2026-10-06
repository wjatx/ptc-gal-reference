"""Launch the broker's MCP gateway: over stdio, or over the network.

    python -m safe_agents.broker.gateway

By default this is what a wrapped harness spawns: one process holding one
`BrokerRuntime`, speaking MCP on stdin/stdout. The harness's MCP config points
here, and every tool call it makes is decided and recorded before it executes.

Configuration comes from the environment exactly as the HTTP mouth's does — the
manifest from `BROKER_MANIFEST`, the backends from `BROKER_STORE` / `BROKER_SECRETS`
/ the audit variables — so the gateway introduces no second config surface. On a
durable store arm an unnamed manifest REFUSES rather than falling back to the
checked-in example (`boot_config.resolve_manifest_path`): a defaulted
manifest silently substitutes another agent's principal, grants and envelope, and
`docs/config-provenance.md` is why that must fail loudly.

**stdout belongs to the protocol.** MCP over stdio puts JSON-RPC frames on stdout,
so anything else printed there corrupts the stream. `build_runtime` prints its
backend banner (`[broker] store backend: ...`), which is useful and must not be
lost — so it is redirected to stderr for the duration of the build. This is the
kind of thing that works in every test and breaks the moment a real client
connects, which is why it is handled here rather than discovered later.

## The network MCP mouth

`BROKER_GATEWAY_TRANSPORT=streamable-http` serves the same surface over
streamable HTTP, for an agent that cannot be this process's parent (one inside a
sandbox, with the gateway outside it). Four more settings, all from the
environment (`broker/GATEWAY.md` G19):

    BROKER_GATEWAY_AUTH         the authenticator, by name. Unset REFUSES.
    BROKER_GATEWAY_TOKEN_FILE   for `launch_token`: the file holding the token.
    BROKER_GATEWAY_PORT         the port. 0 = any free port, reported on stderr.
    BROKER_GATEWAY_HOST         the bind address. Default 127.0.0.1.

Every one of them is checked, and the address is bound, BEFORE the runtime is
built, so a mouth that would refuse to start (a typo, a missing token, a port
already taken) has touched no store. Diagnostics stay on stderr on this
transport too, so one launcher reads both mouths the same way.

A stop signal is honoured from the moment the address is announced: a launcher
that reads the listening line and stops the gateway at once stops it with that
one signal.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from functools import partial
from typing import Iterator

from safe_agents.broker.api import build_runtime
from safe_agents.broker.gateway.authn import GatewayConfigError
from safe_agents.broker.gateway.network import (
    MOUTH_CODE,
    TRANSPORT_STDIO,
    NetworkMouthSettings,
    bind_listener,
    is_loopback,
    listener_url,
    resolve_network_mouth,
    resolve_transport,
)
from safe_agents.broker.gateway.surface import GatewaySurface
from safe_agents.broker.gateway.server import NetworkMouth, serve_stdio
from safe_agents.broker.prototype.boot_config import load_named_manifest


def _record_refusals(runtime, causes) -> None:
    runtime.record_refused_connections(mouth=MOUTH_CODE, causes=causes)


@contextlib.contextmanager
def _stop_signals_reach(mouth: NetworkMouth) -> Iterator[None]:
    """Route SIGINT and SIGTERM to `mouth.request_stop()` for the block.

    The server loop takes both signals for itself once it is serving, so this
    handler is the one in place at two other moments, and it is right for both.

    BEFORE the server has taken them. Importing the server and starting it takes
    a moment, and the listening address has been announced by then. A stop that
    lands in that gap must not be lost: `request_stop` remembers it, and the
    mouth starts, sees it, and shuts down. A handler that only absorbed the
    signal would leave a gateway serving after its launcher had stopped it.

    AFTER the server has shut down. It puts this handler back and raises the
    signal again. Were the default handler in place, SIGTERM would end the
    process on the spot: after the graceful stop and BEFORE the `finally` blocks
    that write out the last refusal counts and reap connector children
    (MCP-HOST.md M20). Here the re-raised signal asks an already-stopped mouth to
    stop, which does nothing, and the process leaves by returning.
    """

    def stop(_signum, _frame) -> None:
        mouth.request_stop()

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _announce(settings: NetworkMouthSettings, url: str) -> None:
    """Tell the launcher, on stderr, where the mouth listens and what that exposes."""
    print(
        f"[broker] network MCP mouth on {url} "
        f"(authenticator: {settings.authenticator.name.value})",
        file=sys.stderr,
    )
    if not is_loopback(settings.host):
        print(
            f"[broker] WARNING: bound to {settings.host}, which is not loopback. "
            "This mouth speaks plain HTTP, so the bearer token crosses that "
            "network in the clear; it is only as private as that network is.",
            file=sys.stderr,
        )


def main() -> None:
    try:
        transport = resolve_transport(os.environ)
        settings = None if transport == TRANSPORT_STDIO else resolve_network_mouth(os.environ)
        # Bound here, with the other launch settings and before the runtime
        # exists: an address this machine cannot bind, or a port already taken,
        # is a refusal to start like any other and must not have opened a store.
        listener = None if settings is None else bind_listener(settings.host, settings.port)
    except GatewayConfigError as exc:
        sys.exit(f"[broker] refusing to start the MCP gateway: {exc}")

    with contextlib.ExitStack() as held:
        if listener is not None:
            held.callback(listener.close)
        manifest = load_named_manifest()

        # Compose with stdout redirected to stderr: the banner is diagnostics, and the
        # protocol owns stdout from here on.
        with contextlib.redirect_stdout(sys.stderr):
            runtime, _sink = build_runtime(manifest)
            # MCP-HOST.md M20: reap any connector-held child before the process exits.
            held.callback(runtime.close)
            surface = GatewaySurface(runtime)
            print(
                f"[broker] MCP gateway ready: {len(surface.tools())} tool(s) "
                f"for {manifest.principal.agentId if manifest.principal else '?'}",
                file=sys.stderr,
            )

        if settings is None or listener is None:
            asyncio.run(serve_stdio(surface))
            return
        # The runtime was built on this thread and is called on this thread: the
        # event loop runs here, and the handlers enter the runtime synchronously.
        mouth = NetworkMouth(
            surface,
            authenticator=settings.authenticator,
            # The mouth is handed a way to say "this many were refused, for
            # these causes" and nothing else. It never holds the sink.
            record_refusals=partial(_record_refusals, runtime),
            listener=listener,
        )
        # The stop handler goes in BEFORE the address is announced, so there is no
        # moment at which a launcher knows the address and cannot stop the mouth.
        with _stop_signals_reach(mouth):
            _announce(settings, listener_url(listener))
            asyncio.run(mouth.serve())


if __name__ == "__main__":
    main()
