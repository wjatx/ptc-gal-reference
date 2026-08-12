"""Connector auth-strategy config — the consumer-facing declaration of HOW the
broker resolves a connector's live credential at execute time (#173).

Historically a connector's credential was a single static Secrets Manager leaf; the
Doer fetched the string and handed it to the connector. Real backends need more —
an OAuth access token minted from a broker-held refresh token, an STS-assumed role,
the broker's own ambient identity. This block lets a consumer *declare* which
resolution strategy a connector tool uses, without ever seeing the credential:
the broker resolves it (`safe_agents.broker.runtime.credentials`), the agent never
does. "agent holds no credentials" holds while "a credential" generalizes.

The strategy CATALOG is base-owned and CLOSED — a tool picks one by the `strategy`
discriminator (a fixed enum), never by an import path. Unlike `connector_providers`
(a dotted class path), nothing store-loaded can inject a new resolution strategy;
the base ships every strategy it supports and the manifest only *selects + configures*
one. Strategy-specific `params` (token URL, client id, secret leaves) are validated
by the strategy at build time, not here — this schema only fixes the shape.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


class AuthStrategy(str, Enum):
    """The closed catalog of base-owned credential-resolution strategies.

    ``static_secret`` is the default and is byte-for-byte the pre-#173 behavior
    (fetch a single secret leaf and hand it to the connector). The non-static
    strategies resolve a *live* credential broker-side at execute time. Only
    ``static_secret`` and ``oauth_refresh`` are implemented today; ``assumed_role``
    and ``ambient_identity`` are reserved names (a manifest selecting an
    unimplemented strategy fails loudly at broker build, never silently).
    """

    STATIC_SECRET = "static_secret"
    OAUTH_REFRESH = "oauth_refresh"
    ASSUMED_ROLE = "assumed_role"
    AMBIENT_IDENTITY = "ambient_identity"


# RFC 7230 `token` — the grammar an HTTP field-name and an RFC 7235 auth-scheme
# both use. Anything outside it cannot be a header name or a scheme, so it is
# refused at load rather than smuggled into a request line.
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Headers the streamable-HTTP transport sets ITSELF, per request, and which
# therefore take precedence over the client's defaults (the SDK's
# `_prepare_headers`). A `header_map` naming one of these would be silently
# ignored — and dead config is a masked misconfiguration (the `capability_iam`
# posture), so refuse it instead of dropping it. `host` is httpx's to compute.
_TRANSPORT_OWNED_HEADERS = frozenset(
    {
        "accept",
        "content-type",
        "host",
        "last-event-id",
        "mcp-protocol-version",
        "mcp-session-id",
    }
)


class HeaderSource(BaseModel):
    """WHERE one resolved credential goes in one outbound HTTP header (#237).

    The remote dual of ``env_map``'s value half: it names how a credential is
    *framed*, and never carries one. Two shapes, and a server uses exactly one:

      * ``scheme`` only — the credential is a BARE string (an ``oauth_refresh``
        access token, a single static API key) and the header value is
        ``"<scheme> <credential>"``, or the credential verbatim when ``scheme``
        is omitted;
      * ``field`` — the credential is a flat JSON string map (the #221
        credential-leaf shape) and this header carries that one field, so a
        multi-key server (``X-API-Key`` + ``X-Client-Id``) needs no consumer
        code. Exactly the ``env_map`` semantics, with a header as the target.

    ``scheme`` is deliberately NOT a template: it is validated as a single
    RFC 7235 auth-scheme token, so nothing interpolates arbitrary text into a
    header value. Mixing the two shapes within one server is refused at load
    (one credential cannot be both a bare string and a map).
    """

    model_config = ConfigDict(extra="forbid")

    scheme: Optional[str] = None
    field: Optional[str] = None

    @field_validator("scheme")
    @classmethod
    def _scheme_is_one_token(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _HTTP_TOKEN.match(value):
            raise ValueError(
                f"scheme {value!r} is not a single RFC 7235 auth-scheme token "
                '(e.g. "Bearer"); a scheme frames the credential, it is not a '
                "template"
            )
        return value

    @field_validator("field")
    @classmethod
    def _field_is_non_empty(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not value:
            raise ValueError("field must be a non-empty credential field name")
        return value


class ConnectorAuth(BaseModel):
    """How the broker resolves ONE connector tool's credential.

    Keyed by connector tool name in ``AgentManifest.connector_auth``. An absent
    entry means ``static_secret`` — so the empty block preserves the pre-#173
    behavior exactly.

    ``params`` is a strategy-specific string map (never secret VALUES — only leaf
    NAMES, URLs, client ids). For ``oauth_refresh`` the broker reads the refresh
    token from the named secret leaf and mints an access token at execute time; the
    refresh token never leaves the broker. Required/optional keys are the strategy's
    concern, validated when the broker compiles the strategy (fail at build, not at
    the wire).

    ``env_map`` (#221) declares HOW a resolved credential is DELIVERED to a
    spawned MCP child process: child env var name → field name inside the
    resolved credential (which must be a flat JSON string map). It is the
    mapping-as-data seam — e.g. ``{ALPACA_API_KEY: ALPACA_KEY}`` renames a
    stored field to the env var the server expects, with no consumer code. The
    map is an explicit allowlist: an unmapped credential field NEVER reaches the
    child. Legal only for a tool that is a spawnable ``mcp_servers`` entry
    (enforced by the manifest validator — for any other tool it is dead config);
    resolution happens at child spawn on the connector's own loop, the merged
    env is never logged, and the agent never sees it (CONNECTOR-AUTH.md).

    ``header_map`` (#237) is the REMOTE dual of ``env_map``: outbound header
    name → ``HeaderSource``, declaring how a resolved credential reaches a
    streamable-HTTP MCP server that needs bearer auth. Same mapping-as-data
    seam and the same allowlist discipline — a credential field no header
    names never leaves the broker. Resolution happens broker-side per CONNECT
    (so a reconnect re-mints an expired token, MCP-HOST.md M18/M25), header
    values are never logged or repr'd, and the agent never sees them. Legal
    only for a tool that is a REMOTE ``mcp_servers`` entry — the manifest
    validator refuses it on a stdio decl exactly as it refuses ``env_map`` on
    a remote one; the two are duals and neither is silently ignored on the
    wrong transport.
    """

    model_config = ConfigDict(extra="forbid")

    strategy: AuthStrategy = AuthStrategy.STATIC_SECRET
    params: dict[str, str] = {}
    env_map: dict[str, str] = {}
    header_map: dict[str, HeaderSource] = {}

    @field_validator("header_map")
    @classmethod
    def _header_map_is_well_formed(
        cls, value: dict[str, HeaderSource]
    ) -> dict[str, HeaderSource]:
        """Refuse a header_map that could not be delivered as declared.

        Four ways a map is unsatisfiable, all statically checkable and so all
        refused at load rather than at the wire: a name that is not an HTTP
        token; two entries differing only by case (field names are
        case-insensitive, so which one wins is ambiguous); a name the
        transport sets itself (declared-but-ignored dead config); and a mix of
        the bare-string and JSON-map shapes, since one resolved credential
        cannot be both.
        """
        seen: dict[str, str] = {}
        for name in value:
            if not _HTTP_TOKEN.match(name):
                raise ValueError(
                    f"header_map name {name!r} is not a valid HTTP field name "
                    "(RFC 7230 token)"
                )
            lowered = name.lower()
            if lowered in _TRANSPORT_OWNED_HEADERS:
                raise ValueError(
                    f"header_map declares {name!r}, which the streamable-HTTP "
                    "transport sets on every request and which therefore "
                    "overrides it; a header that can never be delivered is "
                    "dead config — drop it"
                )
            if lowered in seen:
                raise ValueError(
                    f"header_map declares both {seen[lowered]!r} and {name!r}; "
                    "HTTP field names are case-insensitive, so which value "
                    "wins is ambiguous — declare one"
                )
            seen[lowered] = name
        with_field = sorted(name for name, src in value.items() if src.field is not None)
        without = sorted(name for name, src in value.items() if src.field is None)
        if with_field and without:
            raise ValueError(
                f"header_map mixes credential shapes: {with_field!r} name a "
                f"'field' (a flat JSON string map credential) while {without!r} "
                "do not (a bare string credential); one resolved credential "
                "cannot be both — pick one shape"
            )
        return value
