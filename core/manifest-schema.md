# Manifest + envelope schema

One declarative file per agent — `agents/<name>.yaml` — is everything the substrate needs to
provision, deploy, smoke, and *bound* an agent. It has two halves:

- **Manifest** (shape informed by a proven pattern; owned here): `repo`, `policy`, `secrets`, `smoke`, plus the
  new `arm`. The pipeline scripts read these; they hold no per-agent knowledge.
- **Envelope** (net-new, from `../ARCHITECTURE.md`): the domain-specific risk configuration the
  base floor is bent into for this agent — caps, allowlists, reversibility classes, confidence
  bars/error budgets, fallback budgets, the input-trust map, promotion predicates, and the
  re-derived **safe-default polarity**.

The split mirrors the base/per-agent line: the manifest half is plumbing the pipeline consumes;
the envelope half is the values the **broker** consumes to fill in the seven base schemas (Grant,
BrokeredCall, Decision, Intent, Budgets, PromotionRecord — and the broker-emitted AuditRecord).
The base ships the schemas; this file is where a per-agent repo supplies the values.

> **Authority note.** Effect/external/reversible facts about a *tool* come from the tool's static
> manifest entry in `broker/` — from code, never from the model and never re-asserted here. The
> envelope's `reversibility_classes` map **action classes** to handling policy; it does not get to
> relabel a tool the broker's registry calls irreversible.

## Manifest fields (pipeline-facing)

| Field | Meaning |
|---|---|
| `name` | Agent id; keys the run record (`JOB#<name>`), secrets prefix, policy filename. |
| `repo` | Git repo cloned onto the host (read-only worker source), pulled via the deploy key. |
| `deploy_key_secret` | Secrets Manager id of the ed25519 private deploy key (read-only clone; write only if the agent pushes artifacts). |
| `arm` | **New.** Which cloud arm runs this agent: `ec2` · `ec2-woken` · `fargate`. Selects the adapter. |
| `schedule` | **New (sa#115).** Optional `{expression, timezone, state}` block for `arm: fargate`. `state` defaults to `DISABLED` — a provision never auto-enables a production schedule before its first manual proof; the consumer enables explicitly after verifying. Omitted `expression`/`timezone` fall back to the fargate arm's own defaults. |
| `policy` | The agent's network-egress confinement policy file (security-group / netns spec). Under the broker model this allows **only the broker endpoint + `api.anthropic.com`**; enforcement is by confined netns + security group on EC2/Fargate arms. OpenShell egress policies apply only to the dev-box arm. |
| `secrets.runner_keys` | JSON bundle of **non-connector** runtime config (flags, feature config, non-secret env). Connector creds do **not** belong here — they live only in the broker's store. |
| `secrets.broker_connector_keys` | Secrets Manager path for the connector credentials bundle. Seeded exclusively into the **broker's** secret store by `seed-agent`; the agent process never receives these and holds no credentials to any connector. |
| `secrets.oauth_token` | Raw `CLAUDE_CODE_OAUTH_TOKEN` (the model brain; not a connector). |
| `smoke.read_only` / `smoke.prompt` / `smoke.expect_substring` | The deploy-time proof: run the agent read-only with `prompt`, assert the answer contains `expect_substring` and `claude` exited 0. |

`schedule` only takes effect for `arm: fargate`:

```yaml
schedule:
  expression: "cron(15 15 * * ? *)"
  timezone: "America/Chicago"
  state: DISABLED   # default; flip to ENABLED only after a manual proof run
```

## Envelope fields (broker-facing)

The canonical, authoritative definition of the envelope's fields — exact names, types,
and which are strict vs. permissive — is the typed `Envelope` model in
`safe_agents/broker/schemas/envelope.py` (sa#135). In brief: it is the domain-specific
risk configuration the base floor is bent into for a given agent — polarity, caps,
allowlists, reversibility classes, the typed `confidence` bar/error-budget knob (#184,
superseding the former `abstention_thresholds` placeholder), fallback budgets, the
input-trust map, promotion predicates, and which autonomy rungs the agent may occupy.
`polarity`, `caps`, `allowlists`, `high_stakes`, and `confidence` are modeled strictly;
the remaining fields are modeled permissively pending later phases (see the module
docstring). The pipeline validates every manifest's
`envelope:` block against this schema (`safe_agents/pipeline/validate.py`).

The `envelope:` block is one of five **broker-facing** blocks, together typed as the
`AgentManifest` model in `safe_agents/broker/schemas/manifest.py` (sa#113): `envelope`
(required) plus `principal`, `grant_classes`, `budgets`, `connectors`, and (sa#141)
`connector_providers` / `connector_secrets`. The broker's
`build_runtime(manifest)` consumes an `AgentManifest` to construct the runtime —
principal, granted action classes, the per-UTC-day cap (from `envelope.caps.actions_per_utc_day`;
the legacy `actions_per_run` spelling still loads via alias — #163),
and connectors (resolved provider-first via `connector_providers`, else by name against
the base registry; `connector_secrets` maps a connector to its secret leaf, defaulting to
the tool name, resolved under `<prefix>/connectors/` when a secret prefix is set — sa#164)
— so **no agent-specific constant is baked into the broker code**; the
config lives in the manifest artifact (broker-debaking P2). Provider paths are honored
only from the image-baked manifest file — the envelope store carries no provider field. The envelope itself is not yet consumed at decision time — the real
envelope-hash verification is sa#122 (broker-debaking P4).

## Annotated example

```yaml
# agents/my-agent.yaml — manifest + envelope. The pipeline reads the top half;
# the broker reads `envelope`. Adding an agent = drop this + a policy + seed secrets.
name: my-agent

# ── Manifest (pipeline-facing) ────────────────────────────────────────────────
repo: git@github.com:my-org/my-agent.git
deploy_key_secret: my-agent/deploy-key
arm: ec2                      # always-on EC2; broker co-placed as a local sidecar
policy: policies/my-agent.yaml        # egress: broker endpoint + api.anthropic.com ONLY
secrets:
  runner_keys: my-agent/runner-keys                  # non-connector runtime config only
  broker_connector_keys: my-agent/broker-keys        # connector creds → broker store ONLY
  oauth_token: my-agent/claude-oauth-token           # model brain; not a connector
smoke:
  read_only: true
  prompt: "You are read-only. Read strategy.md and portfolio.json. In ONE sentence, what is this agent's single defining constraint?"
  expect_substring: "never"

# ── Envelope (broker-facing; re-derived per domain) ───────────────────────────
envelope:
  polarity: abstain           # silence is safe — trading agent abstains by default
  autonomy_rungs:
    order.place:   [blocked]                       # signals-only: never autonomous
    brief.write:   [autonomous]
    notify.send:   [autonomous]
  caps:
    actions_per_utc_day: 1    # at most one actionable signal per UTC day (#163 rename;
                              # the legacy `actions_per_run` spelling still loads)
    position_usd:    0        # no order surface exists at all today
  allowlists:
    tools: [snapshot.read, research.web, ledger.append, notify.telegram]
    # NOTE: no order-placing tool is in the registry — "signals only" is structural
  reversibility_classes:
    order.place:  { tier: irreversible, handling: blocked }
    ledger.append:{ tier: recoverable,  handling: autonomous }   # append-only, never delete
    notify.send:  { tier: irreversible, handling: autonomous }   # low blast: a message
  confidence:                 # typed bar/error-budget knob (#184); unset = OFF
    min_confidence: 0.9       # below-bar routes to the per-agent safe response
  fallback_budgets:
    degraded_runs_per_week: 2
  input_trust_map:
    snapshot:     trusted          # the data pull is the ground truth
    web_research: untrusted        # tainted; can source a claim, cannot drive an action
    inbound_msg:  untrusted        # the airlock screens these
    memory:       untrusted        # memory is a taint source, never a trusted store
  promotion_predicates:
    # order.place stays blocked until a separate, signed maker-checker promotion;
    # the track record (the ledger) is the evidence that would earn it.
    order.place: "manual; requires blast-contained account + N-day refuted-forecast=0 record"
  high_stakes: false
```

The trading example sits at the conservative end — all order actions `blocked`, polarity `abstain`.
A different agent (an ops agent whose inaction is the hazard) would declare `polarity: act`, real
`caps`, and `reversibility_classes` that route recoverable actions to `autonomous-with-reporting`.
Same schema, different values — which is the whole point of the base/per-agent split.

## Validation (to build)

A `validate-manifest` step (CI + a pipeline pre-flight) should assert: `arm` is a known arm;
`polarity` is present and explicit (no default); every action class named in `autonomy_rungs`,
`reversibility_classes`, and `promotion_predicates` resolves to a tool in the broker registry; and
the `policy` egress allowlist contains the broker endpoint and nothing that bypasses it. See
`PORTING.md` — this is net-new.
