# Broker-service bringup runbook

Bringing the persistent broker Fargate service (the broker in its own box, apart from the agent)
up from a torn-down floor, for the model-driven smoke agents. The floor is `cdk destroy`'d between
sessions for cost. Secrets live outside every stack and the grants table goes with the State
stack, so a fresh bringup is a specific ordered sequence, not just `cdk deploy`. This runbook
captures it (learned the hard way; see the "why it bites" notes).

To see the broker decide calls on AWS without a model or any third-party credential, follow the
AWS tour in `docs/evaluating.md` instead; it is the shorter path and is proven end to end.

All commands from the repo root unless noted, with the repository's virtual environment active
(root `README.md`), against `development` in your AWS CLI's default region. Only the
`secureNetwork: true` topology is region-bound (it is built for `us-east-1`).

> **Environment ownership.** This runbook targets `development`, an ephemeral floor, and the
> routine teardown it describes is sanctioned only there. The same sequence works for a durable
> environment's first bringup (substitute the environment name), but a durable environment may be
> carrying a live consumer: never tear one down or redeploy over it without checking who depends
> on it. See `docs/environments.md`.

> **Network mode.** The deployed default is now **open mode** (`secureNetwork` off): the broker
> task runs in a public subnet with a public IP, no NAT/interface endpoints. This runbook's
> mechanics are unchanged, but the private-subnet/NAT/endpoint assumptions below describe the
> `secureNetwork: true` topology, deployed only when a consumer needs it. See
> `docs/network-security-layer.md`.

## 0. Prereqs

- The infra floor stacks (`SafeAgents-{Network,State,Identity}-development`) deployed:
  `cd infra && npx cdk deploy SafeAgents-Network-development SafeAgents-State-development SafeAgents-Identity-development -c environment=development --require-approval never`
- A broker image buildable locally (podman). arm64 (the Fargate task is arm64).
- The virtual environment from the root `README.md`; its `[dev]` extra carries boto3 for seeding.

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
  -c environment=development -c brokerDesiredCount=0 --require-approval never \
  -c brokerManifestPath=/app/safe_agents/broker/prototype/example_manifest.yaml
```

`brokerManifestPath` is the manifest's path inside the image. The broker runs on the DynamoDB
store, where an unset `BROKER_MANIFEST` refuses to boot rather than fall back to an example, so
the service never becomes healthy without it (`docs/cdk-context-contract.md`). A consumer names
its own manifest from its own image layer here.

At 0 tasks the service stabilizes immediately and creates the cluster, the ECR repos, and the
Cloud Map namespace (`broker.safe-agents.local`).

## 2. Build + push the broker image

> **Rebuilding onto a live floor picks up merged-but-undeployed decision-rule changes.** Before
> redeploying over an environment with grants in force, read the git log for changes to the rule
> table and envelope knobs since the running image was built, and audit the seeded grant levels
> against them. A change to how a grant level escalates can turn an allow into a hold.

The broker image is identical local/Fargate; build it from `safe_agents/arms/local/Containerfile.broker`
(builds from repo root; it copies `pyproject.toml`, `README.md` and `safe_agents/`). arm64:

```
podman build --platform linux/arm64 -t safe-agents-broker:dev -f safe_agents/arms/local/Containerfile.broker .

REPO="$(aws ssm get-parameter --name /safe-agents/development/ecr-broker-repo-uri --query Parameter.Value --output text)"
aws ecr get-login-password | podman login --username AWS --password-stdin "${REPO%%/*}"
# Keep the braces: in zsh, `$REPO:latest` reads `:l` as a history modifier and pushes to a
# repository path ending in "atest".
podman push safe-agents-broker:dev "docker://${REPO}:latest"
```

## 3. Seed the secrets + grants (teardown force-deleted them)

The broker needs the HMAC secret to START; the grants + connector token + agent oauth are needed
before a capstone round-trip. The HMAC used to **seed** grants must equal the one the broker
**reads** (else every grant quarantines on read), so capture it:

The broker task runs with `BROKER_ENVELOPE_LOAD=store`, so it LOADS its in-force
risk envelope from the envelope store (co-located in the grants table), not the manifest. So the
seed order is **`seed_envelope` → `grants.commands seed` → deploy**: the envelope must exist first,
because the seed stamps each grant with the loaded envelope's hash, and the broker fails its boot
fast (fail-closed) if no envelope is seeded.

```
HMAC="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
aws secretsmanager create-secret --name safe-agents/development/broker-hmac-key --secret-string "$HMAC"

# envelope — MUST run before the grant seed (grants stamp the loaded envelope's hash). Seeds the
# agents/<name>.yaml `envelope:` block into the store keyed by the broker's principal:
BROKER_GRANTS_TABLE=safe-agents-development-grants \
  BROKER_ENVELOPE_MANIFEST=safe_agents/broker/prototype/example_manifest.yaml \
  python -m safe_agents.broker.prototype.seed_envelope
# expect "[seed] OK polarity=... written and read back."

# grants — run with the SAME HMAC, the grants table, and the local path of the manifest the
# image bakes. If the broker task was deployed with a -c brokerGrantClasses=... override
# (development bringups do this so the arm capstones' github.whoami is served), set the SAME
# BROKER_GRANT_CLASSES here or the extra classes never seed:
BROKER_GRANTS_TABLE=safe-agents-development-grants BROKER_HMAC_KEY="$HMAC" \
  BROKER_MANIFEST=safe_agents/broker/prototype/example_manifest.yaml BROKER_ENVELOPE_LOAD=store \
  python -m safe_agents.broker.grants.commands seed
# expect "N created, 0 skipped, 0 failed". Bootstrap records are UNSIGNED unless an issuer
# signing key is configured, and the command says so.
# BROKER_ENVELOPE_LOAD=store makes the seed stamp grants with the STORE envelope's hash —
# the same one the deployed broker loads — so they verify (not the manifest's, which could diverge).

# github connector credential — the RAW token (used as `Bearer <value>`), NOT json:
aws secretsmanager create-secret --name safe-agents/development/connectors/github \
  --secret-string "$(gh auth token)"

# search connector credential — JSON with provider + key; the endpoint is
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
  not just `PutObject`. The audit resume (`S3ObjectLockSink.resuming`) lists keys to find the
  max sequence number, then READS that record's body to compute the previous hash for the chain
  link. Without either grant the broker crash-loops on boot with `AccessDenied`. The
  GetObject case is nastier: it passes on an empty bucket (fresh bringup) and only bites on the
  first restart AFTER real audit records exist. Both fixed in `infra/lib/identity-stack.ts`;
  tamper-evidence rests on Object Lock + the hash chain, not read-denial.
- **desiredCount=0 on the first Compute deploy** (§1) — the #1 cause of a rolled-back stack.
- **Brace `${REPO}` when pushing** (§2): in zsh the bare `$REPO:latest` form mangles the tag.
- **Same HMAC to seed and read** (§3) — a mismatch quarantines every grant silently.
- **Secrets outlive the stacks.** `cdk destroy` leaves every secret above in place. Delete them
  with `--force-delete-without-recovery` if you want the names free for the next bringup: a
  secret in its recovery window blocks re-creating the same name. The grants go with the State
  stack, so always re-seed on a fresh bringup.
- **Clear the CDK context after a teardown** (`npx cdk context --clear` in `infra/`). Compute
  looks up the network ids at synth and caches them in `infra/cdk.context.json`, so a stale cache
  fails the next Compute deploy with a Route 53 `InvalidVPCId` on the Cloud Map namespace.
