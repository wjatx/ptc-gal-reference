"""mcp_construction.py — native MCP connector construction from the manifest (#221).

Before #221 an MCP server reached the runtime only through the ``connector_providers``
seam: a consumer wrote a zero-arg ``McpConnector`` subclass that re-derived the
manifest, registry table, and HMAC key from env (``examples/restricted_mcp_server/
provider.py``, retired with this module). That worked, but it put twenty lines of
security-critical wiring in every consumer and forced the consumer-boundary guard
open (``{schemas, mcp}``). Native construction moves the wiring into the ONE
composition root: a manifest ``mcp_servers`` entry that declares spawn config
(``command`` + friends, ``McpServerDecl``) is composed by ``build_runtime`` itself —
child process, host factory, admitted-tool registry, and spawn-time credential
env — with no consumer class in between.

Injection-power lattice (docs/config-provenance.md): the spawn block names code to
run, so it is honored ONLY from the image-baked manifest — structurally guaranteed
because the envelope store loads an ``Envelope``, which has no ``mcp_servers``
field. Nothing store-loaded reaches this module.

For a STDIO (spawned-child) declaration, the child environment has exactly TWO
manifest-governed halves, disjoint by construction (the manifest validator
refuses overlap at load):

  * the STATIC half — ``McpServerDecl.env``, plain config pinned in the image
    (e.g. ``ALPACA_PAPER_TRADE: "true"``); never credential material;
  * the CREDENTIAL half — resolved broker-side at CHILD SPAWN time on the
    connector's own loop via the #173 CredentialProvider catalog, then mapped
    field-by-field through ``connector_auth.env_map`` (child env var name →
    credential field name). The map is an explicit allowlist: an unmapped
    credential field NEVER reaches the child. With ``env_map`` empty, no
    credential is resolved at all (a credential-less server costs nothing).

Both halves overlay the SDK's minimal default environment (``connect_stdio``),
never the broker's full environment. The merged env is never logged and never
crosses to the agent — the agent still only asks.

A REMOTE (streamable-http, ``url``) declaration is natively constructed the
same way — same registry and HMAC wiring, connected instead of spawned — with
the credential half delivered as request HEADERS (#237, MCP-HOST.md M25)
rather than as a child environment. The two transports' delivery declarations
are duals and each is refused on the other's transport: ``env_map`` on a
remote decl and ``header_map`` on a stdio one both fail at manifest load (and
``env_map`` again here, belt-wise), so neither is ever silently dropped.

Header resolution happens per CONNECT, not per call and not at boot — the
mirror of the stdio env_provider. That timing is load-bearing rather than
incidental: an expired access token surfaces as a transport death, so the M18
reconnect re-runs resolution and re-mints. With an empty ``header_map`` no
credential is resolved at all, so an unauthenticated remote server costs
nothing.
"""

from __future__ import annotations

import json
import os
from typing import Callable, Mapping

from safe_agents.broker.mcp import (
    DynamoToolRegistry,
    ToolRegistryStore,
    stdio_host_factory,
    streamable_http_host_factory,
)
from safe_agents.broker.mcp.sqlite_stores import SqliteToolRegistry
from safe_agents.broker.runtime.connector import Connector
from safe_agents.broker.runtime.credentials import CredentialProvider, StaticSecret
from safe_agents.broker.runtime.secrets import SecretsProvider
from safe_agents.broker.schemas import AgentManifest, HeaderSource, McpServerDecl
from safe_agents.connectors import McpConnector

from .boot_config import (
    resolve_hmac_key,
    resolve_store_arm,
    sqlite_grants_open_options,
)


class McpConstructionError(Exception):
    """Raised when the native MCP construction path cannot be wired safely.

    Always a boot-time (or first-spawn) refusal, never a silent fallback: a
    spawnable server without a named registry table, a credential that cannot
    satisfy the declared ``env_map``, or an env collision the manifest validator
    should have caught. Messages name field/leaf/table NAMES only — never a
    credential value.
    """


def native_mcp_server_ids(manifest: AgentManifest) -> frozenset[str]:
    """The server_ids ``build_runtime`` constructs natively.

    Native means construction config is declared: a stdio spawn block
    (``command``) or a remote streamable-http endpoint (``url``). A
    namespace-only declaration (neither ``command`` nor ``url``) is NOT
    native — its construction remains the consumer's concern, byte-for-byte
    the pre-#221 behavior.
    """
    return frozenset(
        server_id
        for server_id, decl in manifest.mcp_servers.items()
        if decl.command is not None or decl.url is not None
    )


def compose_child_env(
    server_id: str,
    static_env: Mapping[str, str],
    env_map: Mapping[str, str],
    credential: object,
) -> dict[str, str]:
    """Merge the static and credential halves of one child environment. Pure.

    ``credential`` is the value the CredentialProvider resolved; with a non-empty
    ``env_map`` it MUST be a flat JSON string map (the #221 credential-leaf
    shape) — each mapped field is copied to its declared child env var. Refusals
    fail toward NOT spawning: a missing field, a non-JSON credential, or a
    collision with the static half (belt — the manifest validator refuses the
    statically-checkable case at load) all raise rather than spawn a child with
    a partial or ambiguous environment. Error messages carry field NAMES only.
    """
    env = dict(static_env)
    if not env_map:
        return env
    if not isinstance(credential, str):
        raise McpConstructionError(
            f"mcp server {server_id!r}: connector_auth.env_map requires a string "
            f"credential (a flat JSON string map), got {type(credential).__name__} "
            "— the assumed_role bundle has no env-injection shape"
        )
    try:
        fields = json.loads(credential)
    except ValueError:
        raise McpConstructionError(
            f"mcp server {server_id!r}: resolved credential is not valid JSON; "
            "env_map requires the credential leaf to be a flat JSON string map "
            '(e.g. {"ALPACA_KEY": "...", "ALPACA_SECRET": "..."})'
        ) from None
    if not isinstance(fields, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in fields.items()
    ):
        raise McpConstructionError(
            f"mcp server {server_id!r}: resolved credential must be a FLAT JSON "
            "string map for env_map delivery; got a non-flat or non-string shape"
        )
    for child_var, field_name in sorted(env_map.items()):
        if child_var in env:
            raise McpConstructionError(
                f"mcp server {server_id!r}: env_map target {child_var!r} collides "
                "with the static spawn env; the two halves must be disjoint "
                "(manifest validation should have refused this)"
            )
        if field_name not in fields:
            raise McpConstructionError(
                f"mcp server {server_id!r}: credential has no field {field_name!r} "
                f"for env_map target {child_var!r}; credential fields present: "
                f"{sorted(fields)}"
            )
        env[child_var] = fields[field_name]
    return env


def compose_headers(
    server_id: str,
    header_map: Mapping[str, HeaderSource],
    credential: object,
) -> dict[str, str]:
    """Render the declared credential headers for ONE remote connect. Pure.

    The remote mirror of ``compose_child_env`` (#237): each ``header_map``
    entry is a ``HeaderSource`` naming where the resolved credential goes, and
    the credential itself is a bare string or a flat JSON string map — which of
    the two is settled by whether any entry names a ``field`` (the manifest
    validator has already refused a mix, so the entries agree by
    construction). Refusals fail toward NOT connecting: a non-string credential, a
    non-JSON credential under a ``field`` map, or a missing field all raise
    rather than connect with a partial or empty Authorization header, because
    a half-authenticated session fails at the vendor as an opaque 401 instead
    of here as a named misconfiguration. Error messages carry header and field
    NAMES only — never a value, not even a prefix of one.
    """
    if not header_map:
        return {}
    untyped = sorted(
        name
        for name, source in header_map.items()
        if not isinstance(source, HeaderSource)
    )
    if untyped:
        # Belt, mirroring the env_map path's isinstance guards. A plain dict
        # here would satisfy every `getattr(..., None)` read and render the
        # credential with its scheme SILENTLY DROPPED — an Authorization value
        # missing "Bearer " fails at the vendor as an opaque 401, arbitrarily
        # far from the config that caused it. Refuse instead.
        raise McpConstructionError(
            f"mcp server {server_id!r}: header_map entries {untyped!r} are not "
            "HeaderSource values; a raw mapping would deliver the credential "
            "with its scheme dropped rather than refuse"
        )
    if not isinstance(credential, str):
        raise McpConstructionError(
            f"mcp server {server_id!r}: connector_auth.header_map requires a "
            f"string credential, got {type(credential).__name__} — the "
            "assumed_role bundle has no header-injection shape"
        )
    wants_fields = any(source.field is not None for source in header_map.values())
    fields: dict[str, str] = {}
    if wants_fields:
        try:
            parsed = json.loads(credential)
        except ValueError:
            raise McpConstructionError(
                f"mcp server {server_id!r}: resolved credential is not valid "
                "JSON; a header_map naming 'field' requires the credential "
                'leaf to be a flat JSON string map (e.g. {"key": "…"})'
            ) from None
        if not isinstance(parsed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
        ):
            raise McpConstructionError(
                f"mcp server {server_id!r}: resolved credential must be a FLAT "
                "JSON string map for header_map field delivery; got a non-flat "
                "or non-string shape"
            )
        fields = parsed
    headers: dict[str, str] = {}
    for name, source in sorted(header_map.items()):
        field_name = source.field
        if field_name is None:
            value = credential
        elif field_name in fields:
            value = fields[field_name]
        else:
            raise McpConstructionError(
                f"mcp server {server_id!r}: credential has no field "
                f"{field_name!r} for header {name!r}; credential fields "
                f"present: {sorted(fields)}"
            )
        headers[name] = f"{source.scheme} {value}" if source.scheme else value
    return headers


def build_mcp_connectors(
    manifest: AgentManifest,
    *,
    secrets: SecretsProvider,
    credential_strategies: Mapping[str, CredentialProvider],
    secret_name_for: Callable[[str], str],
) -> dict[str, Connector]:
    """Construct one ``McpConnector`` per constructible ``mcp_servers`` declaration.

    The native half of connector resolution: ``build_runtime`` excludes these
    names from ``resolve_connectors`` and merges this dict in afterward (the
    manifest validator has already guaranteed each name is wired in
    ``connectors`` and collides with no ``connector_providers`` entry).

    Both transports get identical registry wiring, on whichever arm
    ``BROKER_STORE`` selects: the admitted-tool table inside the named
    ``broker.db`` on sqlite, the named DynamoDB table otherwise. The registry
    must be operator-NAMED on both — a Dynamo arm with no
    ``MCP_REGISTRY_TABLE_NAME`` refuses at build, and sqlite's name is
    ``BROKER_SQLITE_PATH``, which ``resolve_sqlite_db_path`` refuses when unset
    — because without the admitted-tool registry (key #2 of two-key admission)
    every tool is DECLARED-only and uncallable, so refuse loudly instead of
    serving a dead connector. The HMAC key resolves exactly as the grant
    store's does (``resolve_hmac_key``, #205: the fixed dev key is honored only
    on the local/memory arm).

    Each transport gets the credential half its shape allows, through the same
    per-resolution seam: a stdio (``command``) declaration builds the spawn
    path with its ``env_map`` env_provider (C9), and a remote (``url``) one
    builds ``streamable_http_host_factory`` with a ``header_map``
    headers_provider (C10, MCP-HOST.md M25). Both resolvers run on the
    connector's loop at connect/spawn, not here — so an empty map for either
    resolves no credential at all.

    Construction is cheap and AWS-free (``DynamoToolRegistry`` is lazy; the
    child spawns / session connects at first dispatch on the connector's
    loop), so boot cost does not grow with declared servers.
    """
    constructible = {
        server_id: manifest.mcp_servers[server_id]
        for server_id in sorted(native_mcp_server_ids(manifest))
    }
    if not constructible:
        return {}
    # The registry backend follows the BROKER_STORE profile seam, like every
    # other store: on the sqlite arm it is the admitted-tool table inside the
    # named broker.db, on every other arm the named DynamoDB table. The
    # operator-named requirement holds on BOTH — sqlite's name is
    # BROKER_SQLITE_PATH, which resolve_sqlite_db_path refuses when unset — so
    # this fork relaxes nothing; without it a manifest declaring MCP servers
    # simply could not boot on the local arm at all.
    on_sqlite = resolve_store_arm() == "sqlite"
    table_name = os.environ.get("MCP_REGISTRY_TABLE_NAME")
    if not on_sqlite and not table_name:
        raise McpConstructionError(
            f"MCP_REGISTRY_TABLE_NAME is unset but the manifest declares natively "
            f"constructed mcp server(s) {sorted(constructible)!r} — the admitted-tool "
            "registry (key #2 of two-key admission) must be operator-named; without it "
            "every tool is DECLARED-only and uncallable, so refuse loudly at build "
            "instead of serving a dead connector"
        )
    hmac_key = resolve_hmac_key()
    # TOOLDEF#/TOOLREC# are the checker-writable key space (#203). The serving
    # broker only READS the registry (two-key admission is a read at connect),
    # so it takes the same read-only grant mount the maker does.
    grant_opts = sqlite_grants_open_options() if on_sqlite else {}
    connectors: dict[str, Connector] = {}
    for server_id, decl in constructible.items():
        registry = (
            SqliteToolRegistry(hmac_key, **grant_opts)
            if on_sqlite
            else DynamoToolRegistry(hmac_key=hmac_key, table_name=table_name)
        )
        auth = manifest.connector_auth.get(server_id)
        if decl.url is not None:
            # Belt: the manifest validator refuses an env_map on a remote decl
            # (M21 — no spawn to inject into), so this is unreachable through a
            # validated manifest; construction still must never silently drop
            # declared credential delivery.
            if auth and auth.env_map:
                raise McpConstructionError(
                    f"mcp server {server_id!r} is remote (streamable-http) but "
                    "connector_auth declares env_map; a remote server has no "
                    "spawn to inject into (MCP-HOST.md M21) — the remote "
                    "credential half is header_map"
                )
            header_map = dict(auth.header_map) if auth else {}
            remote_strategy = credential_strategies.get(server_id) or StaticSecret()
            remote_secret_name = secret_name_for(server_id)

            def _make_remote_factory(
                server_id: str = server_id,
                decl: McpServerDecl = decl,
                registry: ToolRegistryStore = registry,
                header_map: dict = header_map,
                strategy: CredentialProvider = remote_strategy,
                secret_name: str = remote_secret_name,
            ) -> Callable[[], "object"]:
                async def headers_provider():
                    # Invoked once per CONNECT on the connector's loop (the
                    # mirror of the stdio env_provider): the credential
                    # resolves lazily per connect — an unused connector fetches
                    # no secret, and a reconnect after session death re-mints,
                    # which is how an expired access token recovers (M18/M25).
                    if not header_map:
                        return None
                    # A strategy may cache its minted credential (#173.2). Drop
                    # that cache HERE, because this closure runs only at connect
                    # and a connect is either the first one (where invalidating
                    # is a no-op) or a RECONNECT — and a reconnect means the last
                    # session died, which is exactly when the credential is
                    # suspect. Serving a cached token across a reconnect would
                    # replay a credential the far end may have revoked before its
                    # stated expiry, reinstating in a narrower window the
                    # "replays a dead credential forever" failure that per-connect
                    # resolution exists to prevent (M25).
                    # Clear the WHOLE cache, not this secret_name's entry: the
                    # strategy caches under its configured refresh_token_leaf,
                    # which need not equal the connector's secret_name (it does
                    # not, whenever connector_auth names refresh_token_leaf
                    # explicitly). A targeted invalidation silently misses in
                    # exactly that case. The strategy instance is per-connector,
                    # so clearing all of it is correctly scoped anyway.
                    invalidate = getattr(strategy, "invalidate", None)
                    if callable(invalidate):
                        invalidate()
                    credential = strategy.resolve(
                        secrets=secrets, secret_name=secret_name
                    )
                    return compose_headers(server_id, header_map, credential) or None

                async def factory():
                    # Yields a started SupervisedStreamableHttpHost — same
                    # M17–M20 lifecycle with "child" read as "session".
                    inner = streamable_http_host_factory(
                        server_id,
                        decl.url,
                        server_decl=decl,
                        registry=registry,
                        headers_provider=headers_provider,
                        respawn=decl.respawn,
                    )
                    return await inner()

                return factory

            connectors[server_id] = McpConnector(_make_remote_factory())
            continue
        env_map = dict(auth.env_map) if auth else {}
        strategy = credential_strategies.get(server_id) or StaticSecret()
        secret_name = secret_name_for(server_id)

        # Default-arg binding: each iteration's values are captured NOW, not at
        # factory-call time (the classic late-binding closure trap would hand
        # every server the LAST loop iteration's decl).
        def _make_factory(
            server_id: str = server_id,
            decl: McpServerDecl = decl,
            registry: ToolRegistryStore = registry,
            env_map: dict[str, str] = env_map,
            strategy: CredentialProvider = strategy,
            secret_name: str = secret_name,
        ) -> Callable[[], "object"]:
            async def env_provider():
                # Invoked once per child SPAWN on the connector's loop (loop-
                # affinity contract): the credential resolves lazily per spawn —
                # an unused connector fetches no secret, and a respawn after
                # child death re-resolves fresh (MCP-HOST.md M18).
                # strategy.resolve is sync on that private loop; nothing else
                # runs on it before the host exists (the Doer's execute-time
                # resolution makes the same trade).
                if env_map:
                    credential = strategy.resolve(
                        secrets=secrets, secret_name=secret_name
                    )
                    env = compose_child_env(server_id, decl.env, env_map, credential)
                else:
                    env = dict(decl.env)
                return env or None

            async def factory():
                # Yields a started SupervisedStdioHost — spawn, typed-death,
                # ships-OFF respawn, and reap-ordering per MCP-HOST.md M17–M20;
                # `decl.respawn` is the image-baked M19 knob (absent = OFF).
                inner = stdio_host_factory(
                    server_id,
                    decl.command,
                    decl.args,
                    server_decl=decl,
                    registry=registry,
                    cwd=decl.cwd,
                    env_provider=env_provider,
                    respawn=decl.respawn,
                )
                return await inner()

            return factory

        connectors[server_id] = McpConnector(_make_factory())
    return connectors
