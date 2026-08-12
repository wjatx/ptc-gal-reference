"""AgentManifest schema — the broker-facing view of an agents/<name>.yaml (sa#113).

The single typed source of truth for the broker-facing half of the manifest —
`core/manifest-schema.md`'s "envelope + broker blocks". Living in `broker.schemas`
lets BOTH the pipeline (which validates it) and the broker (which will consume it)
reach it cleanly: the allowed dependency direction is pipeline → broker.schemas,
never the reverse (the broker must never import `safe_agents.pipeline`).

Only `envelope` is present in real manifests today, so it is the one required
block; the four non-envelope blocks (`principal`, `grant_classes`, `budgets`,
`connectors`) are optional pending broker-debaking P2's `build_runtime(manifest)`,
which will consume and then require them. `connectors` carries connector NAMES
only — registry resolution is P2. The envelope stays authoritative as the typed
`Envelope`; it is not re-flattened here.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .brokered_call import ToolOp
from .budgets import Budgets
from .capability_iam import CapabilityIam
from .common import CounterPeriod, Principal
from .connector_auth import AuthStrategy, ConnectorAuth
from .envelope import Envelope
from .mcp_registry import McpServerDecl


class AgentManifest(BaseModel):
    """The broker-facing blocks of an agents/<name>.yaml manifest.

    `envelope` is the one always-present block; the rest default empty/None until
    P2's build_runtime consumes and then requires them.
    """

    model_config = ConfigDict(extra="forbid")

    # -- Always present in real manifests today -------------------------------
    envelope: Envelope

    # -- Optional pending broker-debaking P2 (build_runtime) ------------------
    principal: Optional[Principal] = None
    grant_classes: list[str] = []  # action classes granted, e.g. ["alpaca.read"]
    budgets: Optional[Budgets] = None
    connectors: list[str] = []  # connector NAMES only, e.g. ["github"]; resolution is P2

    # -- Consumer-owned ToolOp classifications (#171) -------------------------
    # The per-agent tool-operation table: each op's effect/external/reversible/egress_arg
    # classification travels WITH the agent, not in a base global. build_runtime builds a
    # ToolOpTable from this list and the broker resolves every call against it — so a
    # consumer-defined op gates identically regardless of its name (the base owns the
    # ToolOp *schema* + PDP rules, never the op *names*). The base ships a copyable
    # CATALOG of domain-neutral ops (safe_agents.broker.manifest.CATALOG) an author may
    # copy in; it is NEVER consulted at request time. Classifications are code/manifest-
    # resident facts — the model cannot assert its 'send' is really a 'draft'. Duplicate
    # (tool, op) keys are rejected at load (a table with two verdicts for one op is
    # ambiguous). Defaults empty for back-compat with the pre-#171 blocks above.
    tool_ops: list[ToolOp] = []

    # -- Counter period — the time-scale knob (#212) ---------------------------
    # The bucket size every budget cap and evidence counter for this agent is
    # scoped to (enforcement.scoped_counter_key). Default "utc-day" is
    # byte-for-byte the pre-#212 key format. The period is authority-shaping (it
    # scopes budgets and evidence windows), so it lives HERE — image-baked,
    # never store-mutable, and deliberately OUTSIDE Envelope so declaring the
    # default never churns the envelope hash. Ceremony readers name the same
    # period on the command line; a mismatch reads disjoint keys and yields zero
    # evidence — failing toward less authority, never a wrong sum.
    counter_period: CounterPeriod = "utc-day"

    # -- Consumer-supplied connector implementations + secret mapping (sa#141) --
    # connector_providers: connector name → dotted provider path ("pkg.module:ClassName").
    # Honored ONLY from the image-baked manifest file — never from any store-loaded
    # artifact (the Envelope store loads an Envelope, which has no provider field).
    # connector_secrets: connector name → Secrets Manager secret LEAF, overriding the
    # default leaf == tool-name mapping. Leaf names only — never secret VALUES, and
    # never a full secret id. When the broker runs with BROKER_SECRET_PREFIX set, the
    # value is still prefixed to ``<prefix>/connectors/<value>`` (sa#164) — so declare
    # a bare leaf (e.g. "track-feed-token"), not a pre-prefixed path. Keeping it a leaf
    # keeps the manifest env-agnostic and inside the ``<prefix>/connectors/*`` IAM grant.
    connector_providers: dict[str, str] = {}
    connector_secrets: dict[str, str] = {}

    # -- Per-connector credential-resolution strategy (#173) -------------------
    # connector_auth: connector tool name → ConnectorAuth (strategy + params). The
    # broker compiles this into a per-tool CredentialProvider and resolves the LIVE
    # credential at execute time — the agent still never sees it. An absent entry
    # means `static_secret`, so the empty block is byte-for-byte the pre-#173
    # behavior (fetch the `connector_secrets` leaf and hand it to the connector).
    # The strategy catalog is base-owned and closed (an enum discriminator, not an
    # import path) — nothing store-loaded can inject a resolution strategy.
    connector_auth: dict[str, ConnectorAuth] = {}

    # -- Per-capability IAM scoping (#175) -------------------------------------
    # capability_iam: connector tool name → the minimal IAM (actions + resource ARNs)
    # that capability runs with. Consumed by the DEPLOY (infra/lib/, CDK), which
    # provisions a role scoped to exactly this and trusting the broker identity; the
    # `assumed_role` credential strategy then assumes that role at execute time, so a
    # connector's blast radius equals its declared scope (an out-of-scope action is
    # denied by IAM, not the broker). Same key space as connector_auth — a capability's
    # IAM scope and its credential strategy line up one-to-one. Base owns the shape,
    # consumer fills it; nothing store-loaded can inject a role or a scoping.
    capability_iam: dict[str, CapabilityIam] = {}

    # -- MCP tool-registry namespace declarations (#174) -----------------------
    # mcp_servers: server_id → the image-baked declaration of that server's tool
    # namespace and per-tool structured_output trust. This is the FIRST of the
    # two-key admission: it pre-declares which (server_id, tool_name) pairs a
    # later signed registry row may activate. A discovered tool outside this set
    # is never admissible. The manifest half must be COMPLETE — every declared
    # tool also needs its ToolOp classification (external read/write), enforced
    # below — so the base classifies an MCP call by code-resident facts, never by
    # anything the server or model asserts at discovery time.
    mcp_servers: dict[str, McpServerDecl] = {}

    @field_validator("tool_ops")
    @classmethod
    def _tool_ops_have_unique_keys(cls, value: list[ToolOp]) -> list[ToolOp]:
        """Reject duplicate (tool, op) keys — one op must have exactly one verdict.

        Two entries for the same (tool, op) would make request-time resolution
        ambiguous (which classification wins?). Fail at load, not at the wire.
        """
        seen: set[str] = set()
        for entry in value:
            key = f"{entry.tool}.{entry.op}"
            if key in seen:
                raise ValueError(
                    f"tool_ops declares {key!r} more than once; each (tool, op) must "
                    "have exactly one classification"
                )
            seen.add(key)
        return value

    @field_validator("connector_providers")
    @classmethod
    def _provider_paths_are_well_formed(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject malformed provider paths at schema level (fail at load, not at wire).

        A provider path must be ``"pkg.module:ClassName"`` — exactly one ``:`` with
        non-empty module and class parts. Import/type failures are the registry's
        concern (``ConnectorProviderError``); shape failures belong here.
        """
        for name, path in value.items():
            module, colon, klass = path.partition(":")
            if not colon or not module or not klass or ":" in klass or module.startswith("."):
                raise ValueError(
                    f"connector_providers[{name!r}] = {path!r} is not a valid provider "
                    'path; expected "pkg.module:ClassName" (exactly one colon, '
                    "non-empty absolute module and class parts)"
                )
        return value

    @field_validator("connector_secrets")
    @classmethod
    def _secret_names_are_non_empty(cls, value: dict[str, str]) -> dict[str, str]:
        """Reject empty secret names at schema level (fail at load, not at wire)."""
        for name, secret_name in value.items():
            if not secret_name:
                raise ValueError(f"connector_secrets[{name!r}] must be a non-empty secret leaf")
        return value

    @model_validator(mode="after")
    def _capability_iam_pairs_with_assumed_role(self) -> "AgentManifest":
        """A declared IAM scope must be assumed by an `assumed_role` strategy (#175).

        `capability_iam` is inert without the strategy that assumes the provisioned
        role: a scope no credential strategy assumes is dead config, and a silent
        mismatch would deploy a scoped role nothing ever uses. Require every
        `capability_iam` tool to select `assumed_role` in `connector_auth`. (The
        reverse is not required — an `assumed_role` strategy may reference a role
        provisioned outside this manifest.) Fail at load, not at the wire.
        """
        for tool in self.capability_iam:
            auth = self.connector_auth.get(tool)
            if auth is None or auth.strategy is not AuthStrategy.ASSUMED_ROLE:
                selected = auth.strategy.value if auth else "static_secret (no entry)"
                raise ValueError(
                    f"capability_iam[{tool!r}] declares an IAM scope but connector_auth "
                    f"selects {selected!r}; a declared scope must be assumed by the "
                    "'assumed_role' strategy or it is dead config"
                )
        return self

    @model_validator(mode="after")
    def _mcp_spawn_wiring_is_coherent(self) -> "AgentManifest":
        """Enforce the native-construction invariants at load (fail at build, #221).

        (a) A constructible server (one declaring `command` OR `url` — spawned
        stdio child or connected streamable-http session, both natively built
        by `build_runtime`) must be named in `connectors` — construction config
        nothing wires is dead config, and dead config is a masked
        misconfiguration (the `capability_iam` posture).

        (b) A constructible server_id must NOT also appear in
        `connector_providers`: two construction paths for one name is
        ambiguous, and the native block exists to supersede the provider class
        for MCP. Pick one.

        (c) `connector_auth.env_map` is legal ONLY for a stdio (`command`)
        server's tool name: env injection is a spawn-time delivery mechanism —
        a remote (`url`) server has no spawn to inject into, so an env_map on
        one is unsatisfiable config and refuses here (MCP-HOST.md M21; the
        remote transport's delivery mechanism is `header_map`), and for any
        non-mcp tool the map is dead config. For a stdio decl the map's target
        env var names must not collide with the server's static `env` — the
        credential half and the static half of the child environment must be
        disjoint by construction, so neither can silently override the other.

        (d) `connector_auth.header_map` is the exact dual and is legal ONLY for
        a remote (`url`) server's tool name: per-request header injection needs
        a request, and a spawned stdio child has none — its credential half is
        `env_map` (MCP-HOST.md M25). Refusing each map on the other's transport
        keeps the pair symmetric: neither is ever silently ignored on the wrong
        one. For any non-mcp tool the map is dead config.
        """
        stdio = {
            server_id
            for server_id, server in self.mcp_servers.items()
            if server.command is not None
        }
        remote = {
            server_id
            for server_id, server in self.mcp_servers.items()
            if server.url is not None
        }
        constructible = stdio | remote
        for server_id in sorted(constructible):
            if server_id not in self.connectors:
                raise ValueError(
                    f"mcp_servers[{server_id!r}] declares construction config "
                    f"(command/url) but {server_id!r} is not named in "
                    "'connectors'; a constructible server nothing wires is dead "
                    "config — add it to connectors or drop the construction block"
                )
            if server_id in self.connector_providers:
                raise ValueError(
                    f"mcp_servers[{server_id!r}] declares construction config AND "
                    f"connector_providers[{server_id!r}] names a provider class; "
                    "two construction paths for one connector is ambiguous — "
                    "native construction config supersedes the provider, pick one"
                )
        for tool, auth in self.connector_auth.items():
            if auth.header_map:
                if tool in stdio:
                    raise ValueError(
                        f"connector_auth[{tool!r}] declares header_map but "
                        f"mcp_servers[{tool!r}] is a spawned (stdio) server; a "
                        "child process has no request to put a header on — its "
                        "credential half is env_map (MCP-HOST.md M25)"
                    )
                if tool not in remote:
                    raise ValueError(
                        f"connector_auth[{tool!r}] declares header_map but "
                        f"{tool!r} is not a remote mcp_servers entry; header "
                        "injection is the streamable-HTTP delivery mechanism, "
                        "so for any other tool the map is dead config — drop it "
                        "or declare the remote block"
                    )
            if not auth.env_map:
                continue
            if tool in remote:
                raise ValueError(
                    f"connector_auth[{tool!r}] declares env_map but "
                    f"mcp_servers[{tool!r}] is a remote (streamable-http) "
                    "server; a remote server has no spawn to inject into — the "
                    "remote transport's credential half is header_map "
                    "(MCP-HOST.md M25), so declare that instead"
                )
            if tool not in stdio:
                raise ValueError(
                    f"connector_auth[{tool!r}] declares env_map but {tool!r} is "
                    "not a spawnable mcp_servers entry; env injection is a "
                    "spawn-time delivery mechanism, so for any other tool the "
                    "map is dead config — drop it or declare the spawn block"
                )
            static_env = self.mcp_servers[tool].env
            collisions = sorted(set(auth.env_map) & set(static_env))
            if collisions:
                raise ValueError(
                    f"connector_auth[{tool!r}].env_map targets {collisions!r} "
                    f"which mcp_servers[{tool!r}].env also declares; the "
                    "credential half and the static half of the child env must "
                    "be disjoint — neither may override the other"
                )
        return self

    @model_validator(mode="after")
    def _mcp_declarations_are_complete(self) -> "AgentManifest":
        """Enforce the two manifest-side MCP invariants at load (fail at build, #174).

        (a) Two-key completeness: every declared `(server_id, tool_name)` must
        have a matching `ToolOp` in `tool_ops` with `tool == server_id`,
        `op == tool_name`, and `external is True`. A declared MCP tool without
        its ToolOp classification is a half-declared key the broker could not
        classify — refuse rather than admit one at request time.

        (b) Structured-only trust: a declared MCP tool named in
        `envelope.trusted_read_sources` (source id `connector:<server_id>.<tool_name>`)
        is legal ONLY if that tool declares `structured_output: true`. A
        free-text tool's output is injection surface; trusting it is refused
        here. Trusted sources that do NOT point at a declared MCP tool are left
        untouched (they are other connectors' concern).
        """
        op_keys = {(op.tool, op.op): op for op in self.tool_ops}
        trusted = set(self.envelope.trusted_read_sources)
        for server_id, server in self.mcp_servers.items():
            for decl in server.tools:
                op = op_keys.get((server_id, decl.tool_name))
                if op is None or op.external is not True:
                    raise ValueError(
                        f"mcp_servers[{server_id!r}] declares tool {decl.tool_name!r} but "
                        f"tool_ops has no external ToolOp for (tool={server_id!r}, "
                        f"op={decl.tool_name!r}); a declared MCP tool must carry its "
                        "external ToolOp classification"
                    )
                source_id = f"connector:{server_id}.{decl.tool_name}"
                if source_id in trusted and not decl.structured_output:
                    raise ValueError(
                        f"trusted_read_sources names {source_id!r} but mcp_servers"
                        f"[{server_id!r}] declares tool {decl.tool_name!r} with "
                        "structured_output=false; only a structured-output MCP tool may "
                        "be a trusted read source (free-text output is injection surface)"
                    )
        return self
