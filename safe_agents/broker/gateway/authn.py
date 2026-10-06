"""authn.py — who may speak on the network MCP mouth, as pure logic.

One runtime serves one principal, taken from its manifest. A network mouth
therefore never has to learn WHO is calling. It has to decide whether this
connection may speak as the runtime's one principal, and it has to decide that
before it serves a single MCP frame (`broker/GATEWAY.md` G12).

This module is the catalog and the check. It imports nothing but the standard
library: no `mcp` SDK, no socket, no ASGI, no broker runtime. `network.py` puts the
check in front of a request; `server.py` binds it to the SDK.

## The catalog is closed

The authenticator is selected by NAME from `MouthAuthenticator`, the way a
connector's credential strategy is selected from `AuthStrategy`
(`broker/CONNECTOR-AUTH.md`). It is never an import path, so no configuration
surface can supply one (`docs/config-provenance.md`, decision test 1). An unnamed
authenticator refuses to start. There is no unauthenticated default, on loopback
or anywhere else. A name the base reserves and has not built refuses to start
saying so.

## What the one built arm does not buy

`launch_token` is a bearer secret the launcher hands to the gateway and to the one
agent it launches. Anything that can read it can ask as that principal. It buys
the right to ASK; the broker still decides every call. Its exposure is bounded only
by whatever boundary the agent sits in.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Protocol
from urllib.parse import parse_qsl

logger = logging.getLogger(__name__)

#: Names the authenticator. Unset refuses (`resolve_authenticator`).
AUTH_ENV = "BROKER_GATEWAY_AUTH"

#: Names the FILE the launch token is read from. A pointer, never the value: the
#: secret is a bare leaf its launcher supplies (`docs/config-provenance.md`, layer
#: 4), and a value in the environment would be inherited by every child the broker
#: spawns for a connector.
TOKEN_FILE_ENV = "BROKER_GATEWAY_TOKEN_FILE"

#: The floor on a launch token's length. A launcher generates this value, so the
#: floor costs it nothing (`secrets.token_urlsafe(32)` is 43 characters), and it
#: is what makes guessing over a socket hopeless without a rate limit.
MIN_TOKEN_CHARS = 32

#: The most a token file may hold. Read with a bound so a mis-pointed path (a log,
#: a device) is refused in words and not slurped.
_MAX_TOKEN_FILE_BYTES = 4096

#: RFC 6750 §2.1 `b64token`: what a bearer credential may be spelled with. A token
#: outside it could not be carried in an `Authorization` header unambiguously.
_B64TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")

#: Query parameter names that carry a credential (RFC 6750 §2.3 names the first).
#: The mouth never accepts a credential from a URL, because URLs are logged.
_QUERY_CREDENTIAL_KEYS = frozenset({"access_token", "token"})

_BEARER = b"bearer"


class GatewayConfigError(ValueError):
    """A network-mouth launch setting is missing or unusable.

    Raised at startup, before a socket is bound or a runtime is built. Every case
    fails toward serving nothing.
    """


class GatewayAuthConfigError(GatewayConfigError):
    """The network MCP mouth was not told, validly, how to authenticate callers."""


class MouthAuthenticator(str, Enum):
    """The closed catalog of ways the network MCP mouth authenticates a connection.

    Only `launch_token` is implemented. The other two names are RESERVED: they are
    the arms for a gateway reached from another machine, each needs an issuer the
    single-machine case does not have, and selecting either refuses to start.
    """

    LAUNCH_TOKEN = "launch_token"
    #: The MCP specification's own authorization for HTTP transports (OAuth 2.1
    #: bearer tokens). Reserved, not implemented.
    OAUTH_BEARER = "oauth_bearer"
    #: Mutual TLS with workload identity. Reserved, not implemented.
    MTLS_WORKLOAD_IDENTITY = "mtls_workload_identity"


class RefusalCause(str, Enum):
    """Why a connection was refused: the closed vocabulary that reaches the tape.

    A refusal record carries one of these codes and a count. It never carries a
    header, a token, an address or any other byte the refused party chose.
    """

    MISSING_CREDENTIAL = "missing_credential"
    WRONG_SCHEME = "wrong_scheme"
    MALFORMED_CREDENTIAL = "malformed_credential"
    CREDENTIAL_IN_QUERY = "credential_in_query"
    WRONG_TOKEN = "wrong_token"
    #: Not HTTP at all (a WebSocket upgrade). The mouth serves one transport.
    UNSUPPORTED_SCOPE = "unsupported_scope"
    #: The check itself raised. Refused, never admitted.
    AUTHENTICATOR_ERROR = "authenticator_error"


class _Admitted:
    """The one value that admits a connection. See `ADMITTED`."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "ADMITTED"


#: The sole admitting verdict, compared by IDENTITY. A check that returns anything
#: else, including None, refuses: admission is something a check has to say, never
#: something it reaches by falling off the end.
ADMITTED = _Admitted()


@dataclass(frozen=True)
class ConnectionFacts:
    """What the mouth lets an authenticator see of one request.

    Deliberately two fields. An authenticator has no reason to read a body, a
    path or a session id, and none of those may stand in for a credential.
    """

    #: Every `Authorization` header value, raw. More than one is malformed.
    authorization: tuple[bytes, ...] = ()
    query_string: bytes = b""


class Authenticator(Protocol):
    """One arm of the catalog: decide whether a connection may speak."""

    name: MouthAuthenticator

    def check(self, facts: ConnectionFacts) -> RefusalCause | _Admitted:
        ...


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


class LaunchToken:
    """The token-bound-at-launch arm: one bearer secret, compared in constant time.

    Holds a SHA-256 digest of the token and not the token. The comparison is
    between two digests, so it runs in time independent of where the presented
    value first differs and of how long it is.
    """

    name = MouthAuthenticator.LAUNCH_TOKEN

    def __init__(self, token: str) -> None:
        if not token:
            raise GatewayAuthConfigError("the launch token is empty")
        if not _B64TOKEN.fullmatch(token):
            raise GatewayAuthConfigError(
                "the launch token contains a character a bearer credential cannot "
                "carry (RFC 6750 b64token: letters, digits, and - . _ ~ + /, with "
                "optional trailing =)"
            )
        if len(token) < MIN_TOKEN_CHARS:
            raise GatewayAuthConfigError(
                f"the launch token is {len(token)} characters; at least "
                f"{MIN_TOKEN_CHARS} are required. Generate one, for example with "
                "`python -c 'import secrets; print(secrets.token_urlsafe(32))'`"
            )
        self._token_digest = _digest(token.encode("ascii"))

    def __repr__(self) -> str:
        return "LaunchToken(<redacted>)"

    def check(self, facts: ConnectionFacts) -> RefusalCause | _Admitted:
        # A credential in the URL is refused even beside a valid header: the URL
        # is the part of a request that gets logged, and admitting the request
        # would teach a client that putting it there works.
        if _query_carries_credential(facts.query_string):
            return RefusalCause.CREDENTIAL_IN_QUERY
        if not facts.authorization:
            return RefusalCause.MISSING_CREDENTIAL
        if len(facts.authorization) > 1:
            return RefusalCause.MALFORMED_CREDENTIAL
        scheme, _, presented = facts.authorization[0].strip().partition(b" ")
        if scheme.lower() != _BEARER:
            return RefusalCause.WRONG_SCHEME
        presented = presented.strip()
        if not presented or b" " in presented or b"\t" in presented:
            return RefusalCause.MALFORMED_CREDENTIAL
        if hmac.compare_digest(_digest(presented), self._token_digest):
            return ADMITTED
        return RefusalCause.WRONG_TOKEN


def _query_carries_credential(query_string: bytes) -> bool:
    if not query_string:
        return False
    pairs = parse_qsl(query_string.decode("latin-1"), keep_blank_values=True)
    return any(key.lower() in _QUERY_CREDENTIAL_KEYS for key, _ in pairs)


def read_launch_token(path: str) -> str:
    """Read the launch token from the file its launcher named.

    Refuses, in words, a file that cannot be read, is not a regular file, is
    readable beyond its owner, is oversized, or does not hold a usable token. One
    trailing newline is dropped, because that is what writing a value with a shell
    leaves behind; nothing else is trimmed.

    The mode rule follows the issuer signing key's (`grants/issuer_keys.py`)
    and not the connector-credential directory's: this file sits on the launcher's
    own machine, where the mode bits ARE the boundary, and a bearer secret every
    local user can read authenticates nobody. Windows has no mode bits to check, so
    the rule is not applied there and the file's ACL is the launcher's to set.
    """
    token_path = Path(path)
    try:
        info = token_path.stat()
    except OSError as exc:
        raise GatewayAuthConfigError(
            f"{TOKEN_FILE_ENV}={path} could not be read ({exc})"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise GatewayAuthConfigError(f"{TOKEN_FILE_ENV}={path} is not a regular file")
    if sys.platform != "win32" and info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise GatewayAuthConfigError(
            f"{TOKEN_FILE_ENV}={path} is mode {stat.S_IMODE(info.st_mode):04o}; "
            "refusing a launch token readable beyond its owner (anything that can "
            f"read it can ask as this gateway's principal). Run: chmod 600 {path}"
        )
    try:
        with token_path.open("rb") as handle:
            raw = handle.read(_MAX_TOKEN_FILE_BYTES + 1)
    except OSError as exc:
        raise GatewayAuthConfigError(
            f"{TOKEN_FILE_ENV}={path} could not be read ({exc})"
        ) from exc
    if len(raw) > _MAX_TOKEN_FILE_BYTES:
        raise GatewayAuthConfigError(
            f"{TOKEN_FILE_ENV}={path} is larger than {_MAX_TOKEN_FILE_BYTES} bytes; "
            "it does not look like a token file"
        )
    for ending in (b"\r\n", b"\n"):
        if raw.endswith(ending):
            raw = raw[: -len(ending)]
            break
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GatewayAuthConfigError(
            f"{TOKEN_FILE_ENV}={path} does not hold an ASCII token"
        ) from exc
    try:
        LaunchToken(token)
    except GatewayAuthConfigError as exc:
        raise GatewayAuthConfigError(f"{TOKEN_FILE_ENV}={path}: {exc}") from exc
    return token


def _launch_token_from_env(env: Mapping[str, str]) -> Authenticator:
    path = env.get(TOKEN_FILE_ENV, "")
    if not path:
        raise GatewayAuthConfigError(
            f"{AUTH_ENV}={MouthAuthenticator.LAUNCH_TOKEN.value} but {TOKEN_FILE_ENV} "
            "is unset; refusing to start: the launch-token arm needs the file its "
            "launcher wrote the token to. The token is never read from an "
            "environment value, a manifest or a store."
        )
    return LaunchToken(read_launch_token(path))


# The base-owned, closed catalog. A name in `MouthAuthenticator` and absent here is
# one the base reserves and has not implemented; selecting it refuses to start.
# Mirrors `_STRATEGY_FACTORIES` in `runtime/credentials.py`.
_AUTHENTICATOR_FACTORIES: dict[
    MouthAuthenticator, Callable[[Mapping[str, str]], Authenticator]
] = {
    MouthAuthenticator.LAUNCH_TOKEN: _launch_token_from_env,
}


def resolve_authenticator(env: Mapping[str, str] | None = None) -> Authenticator:
    """Build the authenticator the environment NAMES, or refuse to start.

    Unnamed refuses. Unknown refuses. Reserved refuses. Named and misconfigured
    refuses. There is no path through this function that yields an authenticator
    nobody asked for.
    """
    source = os.environ if env is None else env
    named = source.get(AUTH_ENV, "")
    valid = ", ".join(repr(member.value) for member in _AUTHENTICATOR_FACTORIES)
    if not named:
        raise GatewayAuthConfigError(
            f"{AUTH_ENV} is unset; refusing to start the network MCP mouth: it "
            "serves no connection it has not authenticated, and there is no "
            f"unauthenticated default, on loopback or anywhere else. Set {AUTH_ENV} "
            f"to one of: {valid}."
        )
    try:
        selected = MouthAuthenticator(named)
    except ValueError:
        raise GatewayAuthConfigError(
            f"{AUTH_ENV}={named!r} is not a recognized authenticator; refusing to "
            "start. The catalog is closed and base-owned; a name selects from it "
            f"and nothing can add to it. Implemented: {valid}."
        ) from None
    factory = _AUTHENTICATOR_FACTORIES.get(selected)
    if factory is None:
        raise GatewayAuthConfigError(
            f"{AUTH_ENV}={selected.value!r} is a reserved name and is NOT YET "
            "IMPLEMENTED in the reference implementation; refusing to start. "
            f"Implemented: {valid}."
        )
    return factory(source)


class RefusalLedger:
    """Counts every refused connection and records them a bounded number of times.

    The refused party is unauthenticated, so it must not be able to grow the audit
    tape one record per attempt. Every refusal is COUNTED, by cause, in a table
    whose size is fixed by `RefusalCause`. At most one record is written per
    `window_s`: the first refusal after a quiet window is recorded at once, and
    the refusals that follow inside the window ride the next record as counts.
    Nothing is dropped; what coalescing costs is each later refusal's own
    timestamp.

    `record` is the only thing this class can do to the outside world, and the
    only argument it passes is `{cause code: count}`. It is handed no sink.

    A failed `record` never becomes an admission: the refusal has already been
    decided by the time the ledger hears of it. The counts are kept and the write
    is retried at the next window, so a broken tape is retried at the same bounded
    rate it is written at.
    """

    def __init__(
        self,
        record: Callable[[Mapping[str, int]], None],
        *,
        window_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self._record = record
        self._window_s = window_s
        self._clock = clock
        self._pending: dict[RefusalCause, int] = {}
        self._last_attempt: float | None = None

    @property
    def pending(self) -> dict[str, int]:
        """Refusals counted and not yet on the tape, by cause code."""
        return {cause.value: count for cause, count in self._pending.items()}

    def refuse(self, cause: RefusalCause) -> None:
        """Count one refusal, and record if the window allows."""
        self._pending[cause] = self._pending.get(cause, 0) + 1
        self.flush_if_due()

    def flush_if_due(self) -> None:
        """Record what is pending if a window has passed since the last record."""
        if not self._pending:
            return
        now = self._clock()
        if self._last_attempt is not None and now - self._last_attempt < self._window_s:
            return
        self._flush(now)

    def close(self) -> None:
        """Record what is pending now, window or not. Called once, at shutdown."""
        if self._pending:
            self._flush(self._clock())

    def _flush(self, now: float) -> None:
        self._last_attempt = now
        counts = {
            cause.value: self._pending[cause]
            for cause in sorted(self._pending, key=lambda c: c.value)
        }
        try:
            self._record(counts)
        except Exception as exc:  # noqa: BLE001 — a failed record must not propagate
            logger.error(
                "could not record %d refused connection(s) (%s: %s); the counts are "
                "kept and the write is retried",
                sum(counts.values()), type(exc).__name__, exc,
            )
            return
        self._pending.clear()
