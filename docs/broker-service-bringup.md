# Broker-service bringup runbook

Bringing the persistent broker Fargate service (the #98 two-box topology) up from a torn-down
floor. The floor is `cdk destroy`'d between sessions for cost, and teardown **force-deletes the
per-agent secrets** — so a fresh bringup is a specific ordered sequence, not just `cdk deploy`.
This runbook captures it (learned the hard way; see the "why it bites" notes).

All commands from the repo root unless noted. `us-east-1`, `development`.

> **Environment ownership (sa#111).** This runbook targets `development`, the platform's
> ephemeral floor — the routine teardown it describes is only sanctioned *there*. The same
> sequence works for a durable environment's first bringup (substitute the environment name),
> but `production` is a real consumer's infrastructure: never tear it down or redeploy over it
> without coordinating. See `docs/environments.md`.

> **Network mode.** The deployed default is now **open mode** (`secureNetwork` off): the broker
> task runs in a public subnet with a public IP, no NAT/interface endpoints. This runbook's
> mechanics are unchanged, but the private-subnet/NAT/endpoint assumptions below describe the
> `secureNetwork: true` topology, deployed only when a consumer needs it. See
> `docs/network-security-layer.md`.

## 0. Prereqs

- The infra floor stacks (`SafeAgents-{Network,State,Identity}-development`) deployed:
  `cd infra && npx cdk deploy SafeAgents-Network-development SafeAgents-State-development SafeAgents-Identity-development -c environment=development --require-approval never`
- A broker image buildable locally (podman). arm64 (the Fargate task is arm64).

## 1. Deploy Compute at desiredCount=0 FIRST

The broker task references a Secrets Manager HMAC secret and an ECR image that don't exist yet.
If you deploy Compute at desiredCount≥1 before they exist, the task can't start → the ECS
deployment **circuit breaker** trips → `ROLLBACK_COMPLETE`, and a rolled-back stack can't be
updated (must be deleted first). So:

```
# if a prior attempt left it rolled back:
aws cloudformation delete-stack --stack-name SafeAgents-Compute-development
aws cloudformation wait stack-delete-complete --stack-name SafeAgents-Compute-development

cd infra && npx cdk deploy SafeAgents-Compute-development \
  -c environment=development -c brokerDesiredCount=0 --require-approval never
```

At 0 tasks the service stabilizes immediately and creates the cluster, the ECR repos, and the
Cloud Map namespace (`broker.safe-agents.local`).

## 2. Build + push the broker image

> **Rebuilding onto a live floor picks up merged-but-undeployed PDP changes — check what
> behavior shifts.** e.g. sa#137 (merged 2026-07-07): once a rebuilt broker deploys, reads draw
> the cap budget, an **in-loop**-granted external read escalates instead of allowing (production
> grants are all on-loop today, so nothing gates until a grant is demoted), and the query-egress
> knobs are available (off unless the envelope sets them). Audit the seeded grant levels +
> envelope knobs against the new rule table before redeploying over `production`.

The broker image is identical local/Fargate; build it from `safe_agents/arms/local/Containerfile.broker`
(builds from repo root — it COPYs `broker/` + the model-proxy stub). arm64:

```
podman build --platform linux/arm64 -t safe-agents-broker:dev -f safe_agents/arms/local/Containerfile.broker .

REPO="$(aws ssm get-parameter --name /safe-agents/development/ecr-broker-repo-uri --query Parameter.Value --output text)"
aws ecr get-login-password | podman login --username AWS --password-stdin "${REPO%%/*}"
# NOTE: push via the docker:// transport form. `podman push $REPO:latest` has mangled the tag
# ("latest" -> "atest" in the registry path) — use the explicit destination:
podman push safe-agents-broker:dev "docker://${REPO}:latest"
```

## 3. Seed the secrets + grants (teardown force-deleted them)

The broker needs the HMAC secret to START; the grants + connector token + agent oauth are needed
before a capstone round-trip. The HMAC used to **seed** grants must equal the one the broker
**reads** (else every grant quarantines on read), so capture it:

The broker task runs with `BROKER_ENVELOPE_LOAD=store` (sa#136 Slice B) — it LOADS its in-force
risk envelope from the envelope store (co-located in the grants table), not the manifest. So the
seed order is **`seed_envelope` → `seed_grants` → deploy**: the envelope must exist first, because
`seed_grants` stamps each grant with the loaded envelope's hash, and the broker fails its boot
fast (fail-closed) if no envelope is seeded.

```
HMAC="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
aws secretsmanager create-secret --name safe-agents/development/broker-hmac-key --secret-string "$HMAC"

# envelope — MUST run before seed_grants (grants stamp the loaded envelope's hash). Seeds the
# agents/<name>.yaml `envelope:` block into the store keyed by the broker's principal:
BROKER_GRANTS_TABLE=safe-agents-development-grants \
  BROKER_ENVELOPE_MANIFEST=safe_agents/broker/prototype/example_manifest.yaml \
  broker/.venv/bin/python -m safe_agents.broker.prototype.seed_envelope
# expect "[seed] OK polarity=... written and read back."

# grants — run with the SAME HMAC + the grants table (module moved in the sa#106 SDK
# extraction; run from the REPO ROOT). If the environment's broker task was deployed with a
# -c brokerGrantClasses=... override (development bringups do this so the arm capstones'
# github.whoami is served), set the SAME BROKER_GRANT_CLASSES here or the extra classes
# never seed:
BROKER_GRANTS_TABLE=safe-agents-development-grants BROKER_HMAC_KEY="$HMAC" \
  BROKER_ENVELOPE_LOAD=store \
  broker/.venv/bin/python -m safe_agents.broker.prototype.seed_grants
# expect "all N grants seeded and verified."
# BROKER_ENVELOPE_LOAD=store makes seed_grants stamp grants with the STORE envelope's hash —
# the same one the deployed broker loads — so they verify (not the manifest's, which could diverge).

# github connector credential — the RAW token (used as `Bearer <value>`), NOT json:
aws secretsmanager create-secret --name safe-agents/development/connectors/github \
  --secret-string "$(gh auth token)"

# search connector credential (sa#133) — JSON with provider + key; the endpoint is
# code-resident per provider, so the credential carries no URL to misconfigure. The
# broker task's egress must permit api.tavily.com (the AGENT allowlists don't apply;
# this is the broker's own subnet/proxy posture — verify before seeding the grant).
# read -s keeps the key out of shell history and `ps` output — don't paste it inline:
read -s TAVILY_KEY   # paste the tvly-... key at the (silent) prompt, then Enter
aws secretsmanager create-secret --name safe-agents/development/connectors/search \
  --secret-string "{\"provider\": \"tavily\", \"api_key\": \"$TAVILY_KEY\"}"

# agent oauth (per agent that will run) — sourced from the consumer's own
# `<agent>/claude-oauth-token` secret. Set OAUTH_SRC to it before running this block;
# a base runbook never names one tenant's live secret id.
# TWO naming conventions are read by different paths (found the hard way, 2026-07-01): the
# Fargate task injects safe-agents/{env}/agents/{agent}/oauth-token, while the EC2/RHEL/woken
# boxes resolve the manifest's `{agent}/claude-oauth-token`. Seed BOTH until they converge:
OAUTH_SRC="${OAUTH_SRC:?set OAUTH_SRC to the consumer's <agent>/claude-oauth-token secret id}"
OAUTH="$(aws secretsmanager get-secret-value --secret-id "$OAUTH_SRC" --query SecretString --output text)"
for A in smoke-ec2 smoke-rhel-openshell smoke-fargate smoke-woken; do
  aws secretsmanager create-secret --name "safe-agents/development/agents/$A/oauth-token" --secret-string "$OAUTH"
  aws secretsmanager create-secret --name "$A/claude-oauth-token" --secret-string "$OAUTH"
done
```

## 4. Scale the broker to 1 + verify healthy

```
aws ecs update-service --cluster safe-agents-development-cluster \
  --service safe-agents-development-broker --desired-count 1 --force-new-deployment

# poll runningCount -> 1. If it stays 0, the task is crash-looping: read the reason:
aws logs get-log-events --log-group-name /safe-agents/development/broker \
  --log-stream-name "$(aws logs describe-log-streams --log-group-name /safe-agents/development/broker \
     --order-by LastEventTime --descending --query 'logStreams[0].logStreamName' --output text)" \
  --query 'events[].message' --output text | tail -25
```

The Cloud Map A record is `broker.safe-agents.local`; confirm it resolves to the task IP:
`aws servicediscovery list-instances --service-id <broker svc id> --query 'Instances[].Attributes.AWS_INSTANCE_IPV4'`.

## Gotchas that bite (each cost a debug cycle)

- **brokerRole needs `s3:ListBucket` AND `s3:GetObject` (+`kms:Decrypt`)** on the audit surface,
  not just `PutObject`. The #104 audit resume (`S3ObjectLockSink.resuming`) lists keys to find the
  max sequence number, then READS that record's body to compute the previous hash for the chain
  link (sa#132) — without either grant the broker crash-loops on boot with `AccessDenied`. The
  GetObject case is nastier: it passes on an empty bucket (fresh bringup) and only bites on the
  first restart AFTER real audit records exist. Both fixed in `infra/lib/identity-stack.ts`;
  tamper-evidence rests on Object Lock + the hash chain, not read-denial.
- **desiredCount=0 on the first Compute deploy** (§1) — the #1 cause of a rolled-back stack.
- **Push via `docker://` transport** (§2) — the bare `$REPO:latest` form mangled the tag.
- **Same HMAC to seed and read** (§3) — a mismatch quarantines every grant silently.
- **Teardown force-deletes the 5 per-agent secrets** so their names free up for immediate
  redeploy — always re-seed on a fresh bringup.
