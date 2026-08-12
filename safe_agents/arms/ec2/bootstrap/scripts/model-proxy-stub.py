#!/usr/bin/env python3
"""model-proxy-stub.py — broker model-inference forward proxy (STUB, safe-agents sa#97).

The broker's model-egress surface, stubbed until the broker build (sa#12) owns it.
A minimal HTTP CONNECT proxy that allowlists ONLY the model-inference host(s) and
refuses everything else with 403. It runs in the host root netns (which has NAT),
binds the broker side of the agent veth, and performs the actual TLS to
api.anthropic.com on the agent's behalf — so the confined agent (docs/model-egress.md)
reaches its model via HTTPS_PROXY without any direct internet route, and a
compromised agent still cannot reach a connector host: this proxy won't CONNECT to one.

Re-derived from the live-proven rhel-openshell copy (sa#35). The proxy is arm-agnostic;
the constants below MUST match every arm so the committed egress snapshot stays valid.

The allowlist is matched by hostname (the CONNECT target), NOT by IP — api.anthropic.com
is Cloudflare-fronted with rotating IPs, so an IP/SG rule cannot express it. That is the
whole reason the model allowlist lives here at the proxy rather than in a security group.

Stdlib only (no third-party deps); the AL2023 base AMI ships python3.

Usage:
    model-proxy-stub.py [--host H] [--port P] [--allow host1,host2]
Env overrides: SA_BROKER_VETH_IP, SA_MODEL_PROXY_PORT, SA_MODEL_ALLOWLIST.
"""
from __future__ import annotations

import argparse
import os
import selectors
import socket
import sys
import threading

DEFAULT_HOST = os.environ.get("SA_BROKER_VETH_IP", "10.255.255.1")
DEFAULT_PORT = int(os.environ.get("SA_MODEL_PROXY_PORT", "8443"))
# Only the model-inference endpoint(s). NO connector hosts — those are broker-mediated.
DEFAULT_ALLOWLIST = os.environ.get("SA_MODEL_ALLOWLIST", "api.anthropic.com")

_CONNECT_TIMEOUT_S = 10
_IDLE_TIMEOUT_S = 300
_BUF = 65536


def _send(conn: socket.socket, status: str) -> None:
    conn.sendall(f"HTTP/1.1 {status}\r\n\r\n".encode())


def _tunnel(a: socket.socket, b: socket.socket) -> None:
    """Bidirectionally pipe two sockets until either closes or goes idle.

    The sockets stay BLOCKING: the selector only signals read-readiness, the recv after that
    never blocks, and a blocking `sendall` correctly waits when the peer's send buffer is full.
    With non-blocking sockets, `sendall` raises BlockingIOError (an OSError) the instant the
    destination buffer fills — which the OSError handler below swallows, tearing the tunnel down
    and surfacing to the client as ECONNRESET. curl's small writes never hit it; claude's bursty
    TLS does (and small-instance/arm64 socket buffers fill sooner — why RHEL/m7i passed and this
    t4g.small did not).
    """
    sel = selectors.DefaultSelector()
    a.settimeout(None)
    b.settimeout(None)
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    try:
        while True:
            events = sel.select(timeout=_IDLE_TIMEOUT_S)
            if not events:
                return  # idle timeout
            for key, _ in events:
                src: socket.socket = key.fileobj  # type: ignore[assignment]
                dst: socket.socket = key.data
                try:
                    data = src.recv(_BUF)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if not data:
                    return  # peer closed
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        sel.close()


class ModelProxy:
    def __init__(self, host: str, port: int, allowlist: set[str]) -> None:
        self.host = host
        self.port = port
        self.allowlist = allowlist  # set of "host:port" the proxy will CONNECT to

    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(64)
        print(
            f"[model-proxy-stub] listening on {self.host}:{self.port}; "
            f"allowlist={sorted(self.allowlist)}",
            flush=True,
        )
        while True:
            client, _ = srv.accept()
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(_CONNECT_TIMEOUT_S)
            # Read the full CONNECT header block (through CRLFCRLF), not just the first line:
            # clients (e.g. Node/claude) pipeline the TLS ClientHello immediately after the
            # headers, and on a fast link those bytes land in the SAME recv. Splitting on the
            # first "\r\n" and tunnelling only fresh reads silently DROPS that ClientHello, so the
            # upstream handshake never starts and the peer resets (ECONNRESET). Preserve the
            # leftover and forward it before tunnelling.
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = client.recv(_BUF)
                if not chunk:
                    return
                request += chunk
                if len(request) > _BUF:
                    _send(client, "400 Bad Request")
                    return
            header_block, _, leftover = request.partition(b"\r\n\r\n")
            line = header_block.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            # Only the CONNECT (HTTPS tunnel) method is supported — claude uses it.
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                _send(client, "405 Method Not Allowed")
                return
            target = parts[1]
            host, _, port = target.partition(":")
            port = port or "443"
            if f"{host}:{port}" not in self.allowlist:
                # The load-bearing line: anything not the model endpoint is refused.
                print(f"[model-proxy-stub] DENY {target}", flush=True)
                _send(client, "403 Forbidden")
                return
            upstream = socket.create_connection((host, int(port)), timeout=_CONNECT_TIMEOUT_S)
            _send(client, "200 Connection Established")
            client.settimeout(None)
            # Forward any bytes the client pipelined after the CONNECT headers (e.g. the TLS
            # ClientHello) before entering the bidirectional tunnel — else the handshake stalls.
            if leftover:
                upstream.sendall(leftover)
            _tunnel(client, upstream)
        except OSError as exc:
            try:
                _send(client, "502 Bad Gateway")
            except OSError:
                pass
            print(f"[model-proxy-stub] error: {exc}", flush=True)
        finally:
            client.close()
            if upstream is not None:
                upstream.close()


def _parse_allowlist(raw: str) -> set[str]:
    """Normalise a comma list of hosts (or host:port) to a set of host:port (default :443)."""
    out: set[str] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        host, _, port = item.partition(":")
        out.add(f"{host}:{port or '443'}")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="safe-agents broker model-proxy stub (sa#97)")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--allow", default=DEFAULT_ALLOWLIST,
                    help="comma-separated model hosts (default: api.anthropic.com)")
    args = ap.parse_args(argv)
    ModelProxy(args.host, args.port, _parse_allowlist(args.allow)).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
