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

## Stopping

Every mouth this process opens runs on one event loop on this thread, and one
signal handler, in place from the moment an address is announced until the
loop has finished, stops all of them: one `SIGTERM` or `SIGINT`, and each mouth
returns, writes its last refusal counts, and the process leaves by returning,
so connector children are reaped (MCP-HOST.md M20). That holds over stdio too.
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
    SerializedSurface,
    bind_listener,
    is_loopback,
    listener_url,
    resolve_network_mouth,
    resolve_transport,
)
from safe_agents.broker.gateway.surface import GatewaySurface
from safe_agents.broker.gateway.server import (
    NetworkMouth,
    StdioMouth,
    serve_until_any_stops,
)
from safe_agents.broker.prototype.boot_config import load_named_manifest


def _record_refusals(runtime, mouth: str, causes) -> None:
    runtime.record_refused_connections(mouth=mouth, causes=causes)


@contextlib.contextmanager
def _stop_signals_reach(*mouths) -> Iterator[None]:
    """Route SIGINT and SIGTERM to every mouth's `request_stop()` for the block.

    No server underneath takes the signals for itself (`server.py`,
    `_server_without_signal_capture`), so this handler is the one in place from
    before the first address is announced until every mouth has returned. That
    is what lets one signal stop every mouth that shares the loop.

    BEFORE a mouth has begun serving. Importing the server and starting it takes
    a moment, and the listening address has been announced by then. A stop that
    lands in that gap must not be lost: `request_stop` remembers it, and the
    mouth starts, sees it, and shuts down. A handler that only absorbed the
    signal would leave a gateway serving after its launcher had stopped it.

    WHILE serving, and AFTER. The default handler would end the process on the
    spot, BEFORE the `finally` blocks that write out the last refusal counts and
    reap connector children (MCP-HOST.md M20). Here a stop asks each mouth to
    return, which a mouth already stopped ignores, and the process leaves by
    returning. Over stdio there was no handler at all before this, and `SIGTERM`
    ended the gateway that way.
    """

    def stop(_signum, _frame) -> None:
        for mouth in mouths:
            mouth.request_stop()

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _announce(settings, url: str, *, mouth_name: str = "network MCP mouth") -> None:
    """Tell the launcher, on stderr, where a mouth listens and what that exposes."""
    print(
        f"[broker] {mouth_name} on {url} "
        f"(authenticator: {settings.authenticator.name.value})",
        file=sys.stderr,
    )
    _warn_unless_loopback(settings.host)


def _warn_unless_loopback(host: str) -> None:
    if not is_loopback(host):
        print(
            f"[broker] WARNING: bound to {host}, which is not loopback. "
            "This mouth speaks plain HTTP, so the bearer token crosses that "
            "network in the clear; it is only as private as that network is.",
            file=sys.stderr,
        )


def main() -> None:
    with contextlib.ExitStack() as held:
        try:
            transport = resolve_transport(os.environ)
            settings = None if transport == TRANSPORT_STDIO else resolve_network_mouth(os.environ)
            # Bound here, with the other launch settings and before the runtime
            # exists: an address this machine cannot bind, or a port already taken,
            # is a refusal to start like any other and must not have opened a store.
            listener = None
            if settings is not None:
                listener = bind_listener(settings.host, settings.port)
                held.callback(listener.close)
        except GatewayConfigError as exc:
            sys.exit(f"[broker] refusing to start the MCP gateway: {exc}")

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

        # The runtime was built on this thread and is called on this thread: the
        # event loop runs here, and the handlers enter the runtime synchronously.
        # ONE serialized surface for every mouth, so its rules hold across them.
        serialized = SerializedSurface(surface)
        mouths: list = []
        if settings is not None and listener is not None:
            mouths.append(NetworkMouth(
                serialized,
                authenticator=settings.authenticator,
                # The mouth is handed a way to say "this many were refused, for
                # these causes" and nothing else. It never holds the sink.
                record_refusals=partial(_record_refusals, runtime, MOUTH_CODE),
                listener=listener,
            ))
        else:
            mouths.append(StdioMouth(serialized))
        # The stop handler goes in BEFORE any address is announced, so there is no
        # moment at which a launcher knows an address and cannot stop the gateway.
        with _stop_signals_reach(*mouths):
            if settings is not None and listener is not None:
                _announce(settings, listener_url(listener))
            asyncio.run(serve_until_any_stops(mouths))


if __name__ == "__main__":
    main()
