# Reference patterns & re-derivation plan

The base **depends on no other repository**. Two predecessor systems — a development harness that
ran an agent pipeline, and a consumer agent deployed on real substrates — are references only:
proven patterns to learn from, not sources to port files from or link to at runtime. This document
records, per piece: **what proven pattern each mechanism draws on**, **how it is re-derived clean
and generalized**, and **what is net-new** to the broker model. The base must stand alone.

This pass is **design + scaffold + this plan**. No files were copied wholesale; proven mechanisms
are referenced below and re-derived clean here — stubbed only where a small illustration helps.

## Reference patterns table

| core/ target | Reference (proven pattern) | How we re-derive it clean |
|---|---|---|
| `RUNNER-CONTRACT.md` | the harness's runner contract | **Re-derived** (canonical copy lives here). De-coupled: the consumer agent's mechanisms are examples, not the spec; added the broker-co-placement seam invariant + `arm` enum. Done this pass. |
| `manifest-schema.md` + `agents/<name>.yaml` | the harness's per-agent manifest YAML + its `manifest_get` dotted-path reader | **Re-derived + extended.** Manifest re-derived to the same shape; envelope half net-new (from `ARCHITECTURE.md`). `manifest_get` dotted-path reader re-derived (minimal adaptation). |
| `bin/_pipeline-lib.sh` | the harness's pipeline library | **Re-derive from this pattern (minimal adaptation expected).** Generic already: `manifest_get`, `ssm_run_as_dev` (base64-over-SSM + run-as-`dev` + PATH fix), `instance_id_for_stack`. No consumer-specific coupling in the pattern. |
| `bin/seed-agent` | the harness's credential seeder | **Re-derive + generalize.** Splits creds into deploy-key / runner-keys / oauth-token by manifest. Net-new: a **broker-secrets** path — connector creds get seeded into the *broker's* store, not the agent's. |
| `bin/provision-agent-host` | the harness's host provisioner + its dev-box stack | **Re-derive + branch by arm.** Pattern deploys the RHEL+OpenShell box. Re-derive to read `arm:` and provision the right substrate (EC2 box / woken-EC2 / Fargate task). Net-new: provision the **broker sidecar** alongside the agent host. |
| `bin/deploy-agent` | the harness's deployer | **Re-derive from this pattern (minimal adaptation).** Clones repo via deploy key, verifies policy + secrets reachable, idempotent `git pull`. |
| `bin/smoke-agent` | the harness's smoke runner + its confined agent launcher | **Re-derive + tighten.** Runs `smoke.prompt` confined, asserts `expect_substring` + exit 0. Net-new: the smoke must also assert **egress is broker-only** (a connector reached directly = smoke fail). |
| EC2 arm (`arms.md` Arm 1) | the consumer agent's EC2 bootstrap (`user-data.sh` + its README) | **Re-derive + generalize.** Bootstrap parameterized by name/repo/arm from the manifest; add a broker-sidecar bootstrap block. |
| Lambda-woken arm (`arms.md` Arm 2) | the consumer agent's SAM inbound-airlock stack + its runner-ready emitter and systemd unit | **Re-derive + generalize.** Lift Telegram/owner specifics into a manifest-driven inbound config; keep the guardrail→dedupe→screen→wake→drain pattern. (SAM stack noted as reference, not re-read deeply.) |
| Fargate arm (`arms.md` Arm 3) | — | **Net-new.** No reference pattern; designed in `arms.md`. |
| `bin/run-claude-agent` (confinement) | the harness's confined agent launcher | **Re-derive, then adapt.** On **agent arms** (EC2, Fargate): replace OpenShell egress policy with a confined netns whose only outbound route is the broker (network-layer enforcement). OpenShell is **dev-box arm only** — the arm64/x86_64 mismatch makes it impractical on the always-on EC2 arm. See egress confinement decision in §Open questions. |

## What gets de-coupled from the consumer agent (the base must stand alone)

- **Secret names** (`ALPACA_*`, `NOTIFY_TELEGRAM_*`, `TAVILY_KEY`) → become `runner_keys` bundle
  contents, opaque to the base. The base knows "non-connector config bundle," not Alpaca.
- **The Alpaca calendar pre-flight** → stays an *example* of element 3, not part of the contract.
- **`strategy.md` / signals / ledger** → an example of element 4's git-push sink, not a base concept.
- **Telegram / owner `chat_id`** → the notification seam + the inbound config; channel-agnostic.
- **OpenShell connector allowlist** (Anthropic + Alpaca + Telegram + Tavily) → replaced by the
  broker-only egress policy on agent arms (the central net-new change; OpenShell reserved for
  dev-box arm — see egress confinement decision in §Open questions).

## Net-new work (the broker model adds this on top of the reference patterns)

1. **Broker co-placement per arm** — the sidecar process/task, its separate IAM identity, and the
   network-layer route that makes the broker the agent's *only* egress. This is the substrate's
   reason to exist; the reference pipeline patterns assume direct-connector access.
2. **The envelope half of the manifest** — caps/allowlists/reversibility/abstention/fallback/
   input-trust/promotion/polarity, consumed by `broker/`. (Schema designed in `manifest-schema.md`;
   broker-side consumption is `broker/`'s job, not core's.)
3. **`validate-manifest`** — CI + pipeline pre-flight asserting `arm` known, `polarity` explicit,
   action classes resolve to broker tools, egress policy is broker-only.
4. **Broker-only egress assertion in smoke** — prove confinement, don't trust it.
5. **The Fargate arm** end to end.
6. **Two-identity bootstrap** — split today's single instance role into agent-role + broker-role.

## Suggested sequencing

1. **Scaffold (this pass).** Docs + schema + directory shape. ✅
2. **Re-derive the pipeline `bin/` + `_pipeline-lib.sh` + manifest reader** — generic, low-risk,
   gives `core/` a working provision/deploy/smoke against a placeholder agent. (No broker yet.)
3. **Re-derive the EC2 Arm 1 bootstrap, generalized** — manifest-driven, still connector-allowlist
   egress, to prove the generalization without changing the security model.
4. **Land the broker seam (depends on `broker/`)** — the sidecar + two-identity + broker-only
   egress; flip Arm 1 from connector-allowlist to broker-only; tighten smoke.
5. **Re-derive Arm 2 (woken)** generalized; then **build Arm 3 (Fargate)** as the clean
   broker-per-arm reference.
6. **`validate-manifest` + envelope wiring** alongside `broker/` maturing.

Steps 2–3 draw on well-understood reference patterns (low adaptation risk, parallelizable).
Step 4 gates on `broker/` and is where the real substrate value lands.

---

## Open questions worth surfacing

1. **OpenShell sandbox vs the broker model — DECIDED.** Egress confinement on **agent arms**
   (always-on EC2, Lambda-woken EC2, Fargate) is a **confined network namespace (netns) + security-
   group/subnet routing whose only outbound route is the broker**. OpenShell is reserved for the
   **dev-box arm only**.

   Forcing reason: the always-on EC2 agent arm is **arm64 Amazon Linux**; OpenShell requires
   **x86_64 + RHEL** driving rootless podman. They cannot be co-located, so OpenShell cannot serve
   as the agent-arm confinement mechanism.

   The broker is the single egress enforcement point on agent arms. Netns + security-group rules
   live outside agent code; the agent cannot modify them. OpenShell's filesystem default-deny +
   version-pinned confinement remains valuable and is retained on the dev-box arm where the
   x86_64/RHEL environment exists.

   Impact on `bin/run-claude-agent`: the re-derived script targets netns confinement (not OpenShell
   sandbox) for EC2 and Fargate arms; the dev-box arm adapter keeps OpenShell with its egress
   policy rewritten to allow only the broker endpoint + `api.anthropic.com`.

   **How the model is reached under "only route is the broker" — RESOLVED (sa#35, `docs/model-egress.md`):**
   the broker is *also* the model-inference proxy. The agent's single netns route reaches the broker,
   which exposes both the tool-call API and a domain-allowlisted forward proxy for `api.anthropic.com`
   (the agent sets `HTTPS_PROXY` → broker). So "only outbound route is the broker" holds literally,
   even for inference — there is no direct model route and no SG/CIDR rule for the model (it is
   Cloudflare-fronted; the allowlist lives at the proxy). Implemented on the rhel-openshell autonomous
   arm: `agent-netns-setup.sh` + the agent-service `ip netns exec` wrapper + a stub `model-proxy-stub.py`
   (the real proxy surface is the broker build, sa#12). Filesystem isolation for autonomous agents is
   a separate gap tracked in sa#95.

2. **Does the broker need its own arm, or is it always a sidecar?** This pass assumes sidecar
   (same host/task as the agent, separate identity). A shared broker *service* (one broker, many
   agents) is a different topology with its own blast-radius and multi-tenancy questions. Sidecar
   is simpler and matches `ARCHITECTURE.md`'s "ideally a different process/container/task" — but
   worth an explicit decision before Fargate.

3. **Where does the airlock's screening Lambda fit the broker model?** Today the guardrail Lambda
   screens inbound with Bedrock Haiku and is itself a scoped principal. Is the inbound guardrail
   part of `core/` (substrate, every responsive agent needs it) or is screening policy per-agent
   (envelope)? I scaffolded the *plumbing* as substrate (Arm 2) and left the *screening criteria*
   as envelope (`input_trust_map`) — confirm that split.

4. **`arm` granularity.** I modeled `ec2`, `ec2-woken`, `fargate`. Is "woken" really a separate arm
   or a *mode* of the EC2 arm (a box can be both timer-driven and event-woken — the consumer agent is)?
   Leaning toward `arm: ec2` + an optional `inbound:` block rather than a distinct `ec2-woken` arm;
   kept them separate in the schema for now for clarity. Worth collapsing before the pipeline reads
   the field.
