# CONNECTOR-AUTH — resolving a connector's live credential broker-side (#173/#175, PTC Phase 3a)

> **Status: contract (2026-07-11; extended for #175 IAM scoping, and for #237 remote header
> delivery 2026-07-26).** Contract-tier per `docs/contract-vs-reference.md`: this document
> is the normative words, `safe_agents/broker/schemas/connector_auth.py` (`AuthStrategy`,
> `ConnectorAuth`, `HeaderSource`) is the consumer-facing config surface,
> `safe_agents/broker/runtime/credentials.py`
> (`CredentialProvider`, `StaticSecret`, `OAuthRefresh`, `build_credential_strategies`) is the
> base-owned strategy catalog, and `safe_agents/broker/tests/test_credential_strategies.py` is the
> conformance suite. `examples/oauth_api/` is the reference OAuth consumer and
> `examples/oauth_remote_mcp/` the reference REMOTE-MCP one — instantiations of the non-static seam,
> not the contract. Companion to `broker/SCHEMAS.md` (the `AgentManifest` block this
> extends) and the `connector_providers`/`connector_secrets` seam (sa#141/#164) it sits beside.

## What this is — and what it is not

Before #173 a connector's credential was a single **static secret string**: the Doer computed a leaf
name (`connector_secrets`, or the default leaf == tool name) and did `secrets.fetch_secret(leaf)`,
handing the result to the connector. That is the right shape for a static API key. It is the *wrong*
shape for the credentials real backends actually use — an OAuth access token minted from a refresh
token, an STS-assumed role, the broker's own ambient IAM identity.

Connector-auth generalizes credential resolution from a string into a pluggable **strategy** the
broker invokes **per call, at execute time**. `static_secret` is the degenerate case and is
byte-for-byte the pre-#173 behavior; the non-static strategies resolve a *live* credential.

It is **not** a new grant, a new decision verb, or a taint mechanism. Which strategy resolves a
credential says nothing about whether a call is *allowed* — the PEP has already decided that. This
seam only answers "given an allowed call, what credential does the connector run with, and how is it
obtained without the agent ever seeing it."

## The two doctrines (these ride along with the seam)

**Doctrine 1 — no raw passthrough of long-lived material.** Every strategy resolves the credential
**broker-side**; only the resolved credential crosses into the connector, and the agent never sees
even that. Long-lived material stays inside the strategy: `OAuthRefresh` reads the *refresh token*
from the secrets store and returns a short-lived *access token* — the refresh token never leaves the
broker, never reaches the connector, never reaches the agent. "The agent holds no credentials" is the
floor; #173 widens *what a credential is* (a static string → a rotated token → an assumed role)
without widening *who holds it*. A strategy that handed the agent (or even logged) the long-lived
secret would break the floor.

**Doctrine 2 — the local-exec threat-model note.** A network connector's "egress" is bounded by the
URL it can reach. A **local-exec** connector (a CLI wrapper, an MCP-stdio server, a subprocess)
extends "egress" from *the network* to *any effect the broker identity can cause* on the host or in
the cloud account. Confinement therefore generalizes from URL-scoping to **IAM-scoping + an OS
sandbox** (the IAM-scoping half is `assumed_role` + `capability_iam`, #175 — see below). Two
structural consequences, load-bearing for any
connector regardless of auth strategy:

- **No raw command/query/URL passthrough.** A connector exposes narrow, *classified* capabilities
  (`aws.ec2_terminate`, `db.get_customer(id)`), never `aws.execute(<cmd>)` or `db.query(<sql>)`. A
  free-form-input connector is a broker bypass — it lets the agent smuggle an unclassified effect
  through a classified op. The ToolOp table (#171) classifies the *op*; a passthrough arg defeats that
  classification.
- **The broker identity is the blast radius.** With `ambient_identity`/`assumed_role`, the credential
  *is* an identity, not a secret; scope that identity to exactly the declared capability (#175), never
  the broker's full role.

## The seam

Three parts, each at an existing composition point:

1. **Config (consumer-facing).** `AgentManifest.connector_auth: dict[tool, ConnectorAuth]`, where
   `ConnectorAuth = { strategy: AuthStrategy, params: dict[str,str], env_map: dict[str,str],
   header_map: dict[str, HeaderSource] }`.
   Keyed by connector **tool name**. An absent entry means `static_secret`, so the empty block is
   the pre-#173 behavior exactly. `params` is a string map of **leaf names, URLs, client ids —
   never secret VALUES**. `env_map` (#221) is the spawn-time DELIVERY declaration for MCP child
   processes and `header_map` (#237) the per-connect one for REMOTE MCP servers (see the two
   delivery sections below); each is refused on the other's transport, and on any non-MCP tool, as
   dead config at manifest load.

2. **Catalog (base-owned, closed).** `AuthStrategy` is a fixed enum; `build_credential_strategies`
   compiles each entry into a `CredentialProvider` via a base-owned factory table. There is **no
   import-path seam** (unlike `connector_providers`) — a manifest *selects and configures* a strategy,
   it cannot *inject* one. This is deliberate: nothing store-loaded can introduce a credential-
   resolution path, and the blast radius of a new strategy is a base PR with a conformance test.

3. **Resolution (broker-side, per call).** The Doer holds a `CredentialProvider` per tool and calls
   `resolve(secrets, secret_name)` inside `execute()` — the credential is fetched lazily, used,
   discarded, and (on a connector exception) redacted (`doer.py`). A tool with no strategy falls back
   to `StaticSecret`, so `StaticSecret.resolve == secrets.fetch_secret(secret_name)` — the unchanged
   default path.

### The strategy catalog

| `strategy` | resolves to | long-lived material (stays broker-side) | status |
|---|---|---|---|
| `static_secret` | the secret leaf, verbatim | the leaf value itself | shipped (default, unchanged) |
| `oauth_refresh` | a minted OAuth access token | the refresh token + client secret (secret leaves) | shipped |
| `assumed_role` | STS-assumed role credentials (an `AssumedRoleCredential` bundle) | the role trust / broker identity | **shipped (#175)** |
| `ambient_identity` | the broker's own IAM identity (no secret) | the broker workload identity | **reserved** — not implemented |

A manifest selecting a **reserved** strategy fails loudly at broker build with
`CredentialStrategyError` — a boot-time failure, never a silent per-call surprise. (The reserved names
exist so a consumer can declare intent and a base PR only adds the factory, not the enum.)

#### `oauth_refresh` params

| param | required | meaning |
|---|---|---|
| `token_url` | yes | the OAuth token endpoint |
| `client_id` | yes | the OAuth client id |
| `refresh_token_leaf` | no | secret leaf holding the refresh token (default: the tool→leaf mapping) |
| `client_secret_leaf` | no | secret leaf holding the client secret (omit for a public client) |
| `scope` | no | requested scope |

The token exchange (the refresh-grant HTTP POST) is an **injectable** `TokenFetcher` — the default is
a stdlib urllib POST; conformance tests inject a fake so they run without a network. v1 mints fresh
per call (stateless, always-correct); a TTL-aware cache is a connector-lifecycle follow-on (#173.2,
deferred).

#### `assumed_role` params (#175)

| param | required | meaning |
|---|---|---|
| `role_arn` | yes | the ARN of the per-capability scoped role to assume |
| `session_name` | no | the STS `RoleSessionName` (CloudTrail attribution); default `safe-agents-connector` |
| `duration_seconds` | no | session lifetime; the STS default if omitted |
| `external_id` | no | the `ExternalId` the role's trust policy requires, if any |
| `region` | no | STS regional-endpoint override |

The assume-role call is an **injectable** `RoleAssumer` (the default is a boto3 STS `assume_role`;
conformance tests inject a fake so they run without AWS). `assumed_role` reads **no secret leaf** — the
credential is an assumed *identity*, not a stored string — and resolves an `AssumedRoleCredential`
bundle (`safe_agents.connectors.AssumedRoleCredential`: `access_key_id` + `secret_access_key` +
`session_token` + informational `expiration`). Fresh per call (stateless; a TTL cache is #173.2).

## Per-capability IAM scoping (#175)

`assumed_role` is only half the story. Doctrine 2 says an identity's blast radius is whatever that
identity can do, so the identity must be **scoped to exactly the declared capability**. The scope is a
consumer declaration in a new manifest block, `AgentManifest.capability_iam`:

```yaml
connector_auth:
  s3: { strategy: assumed_role, params: { role_arn: "arn:aws:iam::ACCT:role/agent-s3-read" } }
capability_iam:
  s3: { actions: ["s3:GetObject"], resources: ["arn:aws:s3:::my-bucket/*"] }
```

Three seams, each at an existing composition point:

1. **Declare (consumer config).** `capability_iam: dict[tool, CapabilityIam]`, where
   `CapabilityIam = { actions: list[str], resources: list[str] }` — the minimal IAM the capability
   runs with. Same key space as `connector_auth`, so a capability's credential strategy and its IAM
   scope line up one-to-one. Base owns the *shape*; the consumer fills it; there is **no policy-document
   or import-path seam** — nothing store-loaded can inject a role, a trust policy, or a scoping. A
   `capability_iam` tool MUST select `assumed_role` (a scope nothing assumes is dead config; rejected at
   load).
2. **Provision (the deploy).** The CDK (`infra/lib/`) reads `capability_iam` and provisions **one role
   per capability** scoped to exactly those actions+resources and trusting the broker identity, without
   disturbing the broker's own `<agent>/connectors/*` secret scoping (sa#139).
3. **Assume (broker-side, per call).** The `assumed_role` strategy STS-assumes that role at execute time
   and hands the connector the short-lived bundle — never the broker's own identity, never a long-lived
   key. **An out-of-scope action is denied by IAM, not by the broker.**

`ambient_identity` remains reserved: it is the deliberate *un*-scoped escape hatch (the broker's full
role), the opposite of what #175 is for — so it is not implemented alongside the scoping feature.

## Spawn-time delivery — MCP child env injection (#221)

Execute-time resolution (part 3 above) assumes the connector consumes the credential **per call**.
A natively-constructed MCP server (`McpServerDecl` spawn config, `prototype/mcp_construction.py`)
consumes it differently: the credential must be in the CHILD PROCESS's environment when it spawns,
and the child outlives many calls. So for a spawnable MCP tool the SAME strategy catalog resolves at
**child spawn time** instead — lazily, on the connector's own loop at first dispatch (an unused
connector fetches no secret; a respawn after child death re-resolves fresh), never at broker boot
and never per call.

Delivery is **mapping-as-data**: `env_map` maps child env var name → field name inside the resolved
credential, which must be a **flat JSON string map** (e.g. leaf value
`{"ALPACA_KEY": "…", "ALPACA_SECRET": "…"}` with `env_map: {ALPACA_API_KEY: ALPACA_KEY,
ALPACA_SECRET_KEY: ALPACA_SECRET}` renaming stored fields to the vars the server expects — no
consumer code). The map is an explicit **allowlist**: an unmapped credential field never reaches the
child. The child env has exactly two manifest-governed halves — the static `McpServerDecl.env` and
the `env_map`-delivered credential half — kept **disjoint at manifest load** (overlap refuses), both
overlaying the SDK's minimal default environment. The merged env is never logged; the agent never
sees it; an empty `env_map` resolves no credential at all. A credential that cannot satisfy the map
(missing field, non-JSON, a non-string bundle like `assumed_role`'s) refuses the spawn rather than
spawning a partially-configured child.

## Per-connect delivery — remote MCP header injection (#237)

Spawn-time delivery answers "the credential must be in the child's environment." A **remote**
(streamable-HTTP) MCP server has no child, so the same question has a different answer: the
credential must be on the **request**, as a header. `header_map` is that declaration, and it is the
exact dual of `env_map` — same mapping-as-data seam, same allowlist discipline, same "names where a
credential goes, never a credential."

```yaml
connector_auth:
  vendor_mcp:
    strategy: oauth_refresh
    params: { token_url: "https://auth.vendor/token", client_id: "…", refresh_token_leaf: "vendor-refresh" }
    header_map:
      Authorization: { scheme: Bearer }
```

A `HeaderSource` has two shapes and a server uses one: **`scheme` only**, where the credential is a
bare string (an `oauth_refresh` access token, a single API key) and the header value is
`"<scheme> <credential>"`; or **`field`**, where the credential is a flat JSON string map and each
header carries one named field — `env_map`'s semantics with a header as the target, so a multi-key
server (`X-API-Key` + `X-Client-Id`) still needs no consumer code. Mixing the two under one server
is refused at load, because one resolved credential cannot be both.

`scheme` is deliberately **not a template**. It is validated as a single RFC 7235 auth-scheme token,
so nothing interpolates arbitrary text into a header value; the credential is the token, and the
scheme is transport framing that belongs to delivery rather than to resolution. That split is why
`oauth_refresh` needed no modification to serve this case: it mints a bare access token, as it
always did.

**Resolution happens per CONNECT** — not per call, not at boot. This is the seam's load-bearing
timing rather than an implementation convenience: an expired access token surfaces as a transport
death, so **reconnect is the re-auth path**, and only a per-connect resolver makes the next session
carry a new token. The consequence for consumers is concrete — a remote server on a credential that
expires wants `McpRespawnPolicy` declared (`mcp_servers.<id>.respawn`), which ships OFF; without it
the M19 fork leaves the session dead and no re-mint ever happens.

Three refusals, all failing toward NOT connecting: a header the transport sets itself (declared but
undeliverable, so dead config); a credential that cannot satisfy the map (missing field, non-JSON
under a `field` map, or a non-string bundle like `assumed_role`'s); and `header_map` on a stdio decl
— the mirror of `env_map`'s refusal on a remote one, so neither map is ever silently ignored on the
wrong transport.

## Conformance clauses

- **C1 — static is unchanged.** With an empty or absent `connector_auth`, every tool resolves via
  `StaticSecret`, i.e. `secrets.fetch_secret(secret_name)` — byte-for-byte the pre-#173 path.
- **C2 — no passthrough of long-lived material.** A non-static strategy reads its long-lived material
  from the secrets store and returns only the short-lived resolved credential; the connector receives
  the resolved credential, never the long-lived material.
- **C3 — closed catalog.** A strategy is selected by the `AuthStrategy` enum only; a `connector_auth`
  entry cannot carry an import path. A reserved/unimplemented strategy raises `CredentialStrategyError`
  at build.
- **C4 — fail at build, not at the wire.** Malformed params (missing-required, unknown, or params on
  a param-less strategy) raise `CredentialStrategyError` during `build_credential_strategies`, not on
  the first `/call`.
- **C5 — no raw passthrough (doctrine 1).** No strategy exposes the credential to the agent surface;
  the Doer redaction (`doer.py`) still covers a connector that embeds it in an exception — including
  every sensitive field of a bundle credential, not just a single string.
- **C6 — assumed_role reads no secret + resolves a bundle (#175).** `assumed_role` fetches no secret
  leaf (an identity is not a stored secret); it resolves an `AssumedRoleCredential` via the injected
  `RoleAssumer` and the connector receives that bundle, never the broker's own identity.
- **C7 — a declared scope is assumed (#175).** A `capability_iam` tool MUST select `assumed_role` in
  `connector_auth`; a scope no strategy assumes is dead config and is rejected at manifest load.
- **C8 — the scoped role bounds the blast radius (#175).** The deploy provisions a role scoped to
  exactly `capability_iam[tool]`; an action outside that scope is denied by IAM at execute time, not by
  the broker. (Proven by `examples/scoped_s3/` + the infra synth tests.)
- **C9 — spawn-time env injection is allowlisted, disjoint, and unlogged (#221).** For a spawnable MCP
  tool, the credential resolves at child spawn (lazily, per spawn, broker-side) and reaches the child
  ONLY through the declared `env_map` (unmapped fields never cross); the credential half and the static
  spawn env are disjoint at manifest load; a credential that cannot satisfy the map refuses the spawn;
  the merged environment is never logged and never crosses to the agent. `env_map` on a non-spawnable
  tool is refused at manifest load.
- **C10 — per-connect header injection is allowlisted, re-resolved, and unlogged (#237).** For a
  REMOTE MCP tool, the credential resolves broker-side once per CONNECT and reaches the server ONLY
  through the declared `header_map` (an unmapped credential field never crosses); a credential that
  cannot satisfy the map refuses the connect; header values are never logged and never cross to the
  agent. Re-resolution per connect is required, not optional — it is what makes a reconnect re-mint
  an expired token instead of replaying a dead one. `header_map` is refused at manifest load on a
  stdio decl and on any non-MCP tool, exactly as `env_map` is refused on a remote decl: the two are
  duals and neither is silently dropped on the wrong transport.

## Deferred (this contract's edges)

- **`ambient_identity` — the un-scoped escape hatch.** The broker's own full IAM role (no secret). The
  deliberate opposite of #175's scoping and not implemented alongside it; a reserved enum name that
  fails loudly at build until a base PR adds the factory.
- **#173.2 — connector lifecycle.** `open()`/`close()`/session handling for pooled or stateful
  backends (MCP handshakes, DB pools, subprocesses), and a TTL-aware token cache — now tracked as
  #221 Phase 3 (child-death recovery, shutdown ordering, token cache). (Phase 3b #174 itself landed —
  `broker/MCP-HOST.md`; its spawn-time credential delivery is the C9 clause above.)
