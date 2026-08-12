"""oauth_remote_toy_server — a test-only REMOTE MCP server that REQUIRES bearer
auth, plus the OAuth token endpoint that issues the bearer (#237).

The toy the remote-credential-delivery slice is built against, per this lane's
build-toy-first discipline (the Phase 4 toy suite caught the parked-caller M17
gap; adversarial review caught the stale-session case that left M19 inert).
Two halves in one process, because the point is to exercise BOTH ends of the
`oauth_refresh` strategy over a real wire:

  * ``POST /token`` — an RFC 6749 refresh-grant endpoint. It validates the
    posted ``grant_type``/``refresh_token``/``client_id`` and mints a NEW
    access token on every call (``toy-access-<n>``), so a test can prove that
    a reconnect re-minted rather than replayed. A public client is assumed
    (no ``client_secret``), which is the shape
    ``token_endpoint_auth_methods_supported: ["none"]`` describes and the one
    `OAuthRefresh` already supports with `client_secret_leaf` omitted.
  * ``/mcp`` — the MCP endpoint, behind middleware that 401s any request whose
    ``Authorization`` header is not ``Bearer <a token this server minted>``.
    The rejection is real: an unauthenticated broker gets a transport failure,
    not a polite tool error, which is what makes "the credential was actually
    delivered" provable rather than asserted.

The ``whoami`` tool reports back the bearer the request carried, so a test can
prove the delivered header reached the SERVER — not merely that the client was
handed one. Loopback plain-http is the sanctioned M21 carve-out; this binds
127.0.0.1 only, on the port given as argv[1].

Run:  python safe_agents/broker/tests/fixtures/oauth_remote_toy_server.py <port>
"""
from __future__ import annotations

import os
import sys
from contextvars import ContextVar

import uvicorn
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# The refresh token this toy accepts; anything else is `invalid_grant`. The
# broker reads its copy from the secrets store, so a mismatch here proves the
# refresh token really did travel from the secrets provider to the endpoint.
REFRESH_TOKEN = "toy-refresh-token"
CLIENT_ID = "toy-client"

# Every access token this server has minted. Membership IS the auth check, so a
# token minted by a previous connect keeps working — this toy never expires one
# on its own, leaving expiry to the test that wants to simulate it.
_MINTED: set[str] = set()
_MINT_COUNT = 0

# The bearer the in-flight request carried, so a tool can report it back. A
# ContextVar (not an attribute) because the MCP session outlives any one
# request and several requests may be in flight on one session.
_CURRENT_BEARER: ContextVar[str] = ContextVar("current_bearer", default="")


class WhoAmI(BaseModel):
    """The bearer the calling request presented — structured output."""

    bearer: str


class Pong(BaseModel):
    """A credential-free answer — structured output."""

    ok: bool


async def token_endpoint(request: Request) -> JSONResponse:
    """The refresh-grant exchange. Mints a fresh access token per call."""
    global _MINT_COUNT
    form = await request.form()
    if form.get("grant_type") != "refresh_token":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if form.get("refresh_token") != REFRESH_TOKEN:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if form.get("client_id") != CLIENT_ID:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    _MINT_COUNT += 1
    # The pid makes every token unique to THIS process, so a restart on the
    # same port invalidates every previously minted token — the honest local
    # stand-in for expiry. Without it a restarted toy would re-mint the same
    # counter values and a replayed dead token would silently still work,
    # making the reconnect-re-mints-the-token proof vacuous.
    access_token = f"toy-access-{os.getpid()}-{_MINT_COUNT}"
    _MINTED.add(access_token)
    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}
    )


class RequireBearer(BaseHTTPMiddleware):
    """401 anything reaching the MCP endpoint without a minted bearer.

    The token endpoint is deliberately exempt — it is how a client GETS a
    bearer, so requiring one there would be circular.
    """

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/token"):
            return await call_next(request)
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or token not in _MINTED:
            return JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        reset = _CURRENT_BEARER.set(token)
        try:
            return await call_next(request)
        finally:
            _CURRENT_BEARER.reset(reset)


def build_app(port: int):
    server = FastMCP("toyoauth", host="127.0.0.1", port=port)

    @server.tool()
    def whoami() -> WhoAmI:
        """Report the bearer token the calling request presented."""
        return WhoAmI(bearer=_CURRENT_BEARER.get())

    @server.tool()
    def echo(text: str) -> WhoAmI:
        """Echo the caller's bearer alongside nothing else (declared, admitted)."""
        return WhoAmI(bearer=_CURRENT_BEARER.get() + ":" + text)

    @server.tool()
    def ping() -> Pong:
        """Answer a constant, mentioning no credential.

        The leak-detection tool: because nothing about the bearer is in this
        response, any appearance of a minted token in the logs of a `ping` call
        is a real leak by the broker or its transport — whereas `whoami` would
        put one there by design and make the same assertion vacuous.
        """
        return Pong(ok=True)

    app = server.streamable_http_app()
    app.router.routes.append(Route("/token", token_endpoint, methods=["POST"]))
    app.add_middleware(RequireBearer)
    return app


if __name__ == "__main__":
    _port = int(sys.argv[1])
    uvicorn.run(build_app(_port), host="127.0.0.1", port=_port, log_level="critical")
