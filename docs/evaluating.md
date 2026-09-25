# Evaluating the reference implementation

> For anyone who has followed the setup in the root `README.md` and wants to know what to look
> at next. It picks up where the README stops: which deployment path fits what you want to
> check, a laptop tour in order, an AWS tour to a decided call, and the state of the OpenShift path.

What you can check depends on where the broker runs. The strongest claim this implementation
makes, that the enforcement point cannot grant itself authority, is a property of a platform
boundary, and a single machine has no such boundary to show. `docs/posture-ladder.md` names the
three postures; the table below maps them to the three places you can run this.

## Choose a path

| Path | What you can check | What you cannot | Effort |
|---|---|---|---|
| **Laptop** (posture 1) | The test suite, the generated conformance statement, the broker deciding real MCP tool calls, the taint hold, the audit tape, the broker embedded as a library | Any claim that rests on a boundary between the broker and the agent: grant writes denied by the platform, credentials held across a boundary, the agent's own built-in tools being confined | About ten minutes. No account |
| **AWS** (posture 3) | The broker under its own cloud identity, with an out-of-scope action refused by IAM rather than by broker code, and maker≠checker enforced by comparing credential ARNs | The grant ceremony, which the tour seeds past (see [the AWS tour](#the-aws-tour)) | About fifteen minutes after one-time CDK bootstrap, an AWS account you can create IAM roles in, and about $0.54 a day while the broker runs |
| **OpenShift** (posture 2) | The ceremony arc in pods under separate ServiceAccounts, with a leg's writes to grant rows and to another leg's audit records refused by the kernel on read-only mounts, and an agent pod holding no credentials working only through the broker | Anything on vanilla Kubernetes, which the drill does not support today | Cluster admin on an OpenShift cluster, or OpenShift Local on a laptop (a free Red Hat account, about 14 GiB of RAM for the VM); from about 150 s to 19 minutes for a full run, depending on the cluster |

Starting with the laptop is reasonable, and so is stopping there, as long as the conclusions
stay inside posture 1.

## The laptop tour

Every command here runs from the repository root with the virtual environment active, on macOS,
Linux or Windows unless a step says otherwise.

### 1. Run the suite

```
python -m pytest -rs
```

`-rs` lists every skip with its reason. The skips that remain with `spec/` present are opt-in
live checks, each naming the credential or deployed environment it needs. The tests that compare
specification text against the shipped schemas run only when the specifications are cloned into
`spec/`; without them the run is green having checked nothing about conformance.

### 2. Read the conformance statement

```
python -m safe_agents.contract.spec_clauses --summary --spec-dir spec
python -m safe_agents.contract.spec_clauses --pics-ri --spec-dir spec
```

The summary lists every clause with its marker state and ends in self-checks. The second command
prints the completed implementation conformance statement (the PICS, after ISO/IEC 9646-7), one
table per role. A clause answered `N` carries the issue that tracks it.
`docs/lf-reference-implementation.md` explains how to read a marked clause, which matters: most
marked clauses are compound requirements where one part is unbuilt.

### 3. Watch the broker decide

```
python -m safe_agents.broker.gateway.demo --verbose
```

The demo starts the MCP gateway as a child process, connects to it the way any MCP client does,
and makes three calls: a tool the manifest never declared, a declared search, and a declared
notification. The root `README.md` shows the output and what each reply means. `--verbose` adds
the gateway's startup banner, which names the store, the audit sink, the secrets arm and the
grant load mode.

That banner reads `grant load mode: seed`. Seed mode is the default local path, and it is the one
described under "What we would most like challenged" in `docs/lf-reference-implementation.md`: it
writes grants from inside the broker process, with a hardcoded reviewer attribution (#372). You
are looking at the configuration whose weakest leg that document names.

To keep the audit tape rather than hold it in memory, name a file for it:

```bash
export BROKER_AUDIT_PATH="$HOME/.ptc-gal/audit.jsonl"      # macOS, Linux
```

```powershell
$env:BROKER_AUDIT_PATH = "$HOME\.ptc-gal\audit.jsonl"      # Windows
```

Each line is one hash-chained record: the principal, the tool and op, a digest of the arguments,
the decision, its reason, and the outcome. Arguments are recorded only as a digest, and the
connector credential is not one of the fields.

### 4. Use your own Tavily key and see the taint hold

```
python -m safe_agents.broker.gateway.set_search_key
```

The helper reads the key without echoing it, refuses to write it inside the checkout, and stores
it as `~/.ptc-gal/secrets/search`, the file the broker's `dir` secrets arm reads for the `search`
connector. It prints the `BROKER_SECRETS_DIR` line to paste for your shell. `--dir PATH` stores it
somewhere else.

With the variable set, run the demo again. The search now succeeds, and the notification that
follows comes back held for approval rather than executed. That is the taint floor
(`broker/TAINT.md`): a successful read of external content taints the turn, and an external write
in a tainted turn escalates to `require_approval`. The turn is owned by the broker, one per
principal across calls, so an agent cannot declare a fresh turn to shed the taint
(`docs/turn-identity.md`). A failed read taints nothing, which is why the placeholder key does
not produce the hold.

Approving a held call is outside this tour. What the tour shows is that the write did not happen
and that the hold is on the tape.

### 5. Connect a real MCP client

The gateway is an ordinary stdio MCP server, so any MCP client can launch it. Give the client the
absolute path to the virtual environment's Python, so that it runs with the right packages
whatever directory it starts in.

For Claude Code, from the repository root:

```bash
claude mcp add ptc-gal-broker -- "$PWD/.venv/bin/python" -m safe_agents.broker.gateway
```

```powershell
claude mcp add ptc-gal-broker '--' "$PWD\.venv\Scripts\python.exe" -m safe_agents.broker.gateway
```

To pass your key directory, add `-e` before the `--`:

```bash
claude mcp add ptc-gal-broker -e BROKER_SECRETS_DIR="$HOME/.ptc-gal/secrets" -- "$PWD/.venv/bin/python" -m safe_agents.broker.gateway
```

`claude mcp get ptc-gal-broker` should report `Status: ✔ Connected`. The server is added at
Claude Code's default `local` scope, so it is available to sessions started in the directory
where you ran the command. `claude mcp remove ptc-gal-broker -s local` removes it. The syntax is
from `claude mcp add --help` in Claude Code 2.1, and the macOS form was run as written. The
PowerShell form quotes `'--'` so that PowerShell passes it through to `claude`; it has not been
run on Windows.

Other clients take the same three facts in their own configuration file. In the `mcpServers`
shape that Claude Code's project `.mcp.json` uses:

```json
{
  "mcpServers": {
    "ptc-gal-broker": {
      "command": "/absolute/path/to/ptc-gal-reference/.venv/bin/python",
      "args": ["-m", "safe_agents.broker.gateway"],
      "env": { "BROKER_SECRETS_DIR": "/absolute/path/to/home/.ptc-gal/secrets" }
    }
  }
}
```

On Windows the command is `C:\\path\\to\\ptc-gal-reference\\.venv\\Scripts\\python.exe`, with
backslashes doubled inside JSON.

Then ask the agent to search for something and to send a notification about what it found. The
search tool is `search__query` and the notification tool is `notify__send`. With your own key, the
notification is held, as in step 4.

Keep in mind what this does not cover. The broker decides the calls the client makes through this
server. Claude Code's own built-in tools (its shell, file edits and web fetch) are not MCP servers,
and nothing here gates them. `docs/posture-ladder.md` calls this out as the defining limit of
posture 1, and the fix it names is a sandbox around the agent, which is posture 2.

### 6. Embed the broker as a library

```
python -m examples.embedded_agent.agent
```

The same broker, imported into a plain Python program through the public `safe_agents.broker.api`
surface instead of reached over MCP. One call is allowed and one is refused because the tool is
classified but not granted, and the audit tape is printed at the end.
`examples/embedded_agent/README.md` walks through it.

### What a laptop cannot show

On a laptop the broker, the agent and the grant store run as the same OS user. The deterministic
gate, taint, two-key tool admission and an honest audit tape all hold there. What does not hold is
anything that depends on the agent being unable to reach what the broker holds: an adversary with
the agent's user can edit the grant store or read the credentials directly.
`docs/posture-ladder.md` states what each posture holds and what it does not, and
"What we would most like challenged" in `docs/lf-reference-implementation.md` explains why the
self-authorization leg can only be attacked where a boundary exists.

## The AWS tour

This tour deploys the broker as an ECS Fargate service under its own IAM role, sends it one call
it allows and one it refuses, and reads both audit records back from S3. No model and no
third-party credential is involved. The agent side is a one-shot task that runs
`call_client` under the agent role, which holds no permissions at all, and the manifest is
`examples/embedded_agent/manifest.yaml`: `search.query` is granted and answered from an in-process
corpus, and `notify.send` is classified but not granted.

It takes about fifteen minutes of commands and waiting. Every step below was run as written, from
an account with no `SafeAgents-*` stacks, on 2026-09-25; the transcript is attached to the issue
that asked for this tour (#42).

### Before you start

You need:

- an AWS account and credentials that can create IAM roles, KMS keys, VPCs and ECS services
  (an administrator profile is the simple case);
- the account bootstrapped for CDK in the region you will use: `npx cdk bootstrap
  aws://<account>/<region>` from `infra/`, once;
- Node.js (for CDK), the AWS CLI v2, and `podman` or `docker`;
- the repository's virtual environment from the root `README.md`, active in your shell. The
  `[dev]` extra includes boto3, which the seeding and audit commands use.

Nothing else has to exist in the account. The Identity stack names a GitHub Actions OIDC provider
in the trust policy of two read-only watcher roles; IAM accepts that trust policy whether or not
the provider exists, so an account without one deploys, and those two roles trust nobody until you
pass `-c githubOidcSubjects=...`.

The commands are for bash or zsh on macOS or Linux; on Windows, use WSL. Keep variables braced as
shown (`"${REPO}:latest"`): in zsh, `$REPO:latest` is read as a history modifier and names a
repository that does not exist.

Stay on `development`. `staging` and `production` keep their resources on teardown and put a
seven-year GOVERNANCE-mode Object Lock on the audit bucket. Leave the network-security layer off
(the default); it adds a NAT gateway and interface endpoints and is only built for `us-east-1`.

```bash
export AWS_REGION=us-east-1        # any region; this tour was run in us-east-1
export ENV=development
```

### 1. Deploy the foundation and the compute stack

From `infra/`, deploy the four stacks the broker needs, by name. Do not use `cdk deploy --all`:
the Channels stack is not needed here and expects an airlock image you have not built.

```bash
cd infra
npm ci
npx cdk deploy SafeAgents-Network-${ENV} SafeAgents-State-${ENV} SafeAgents-Identity-${ENV} \
  -c environment=${ENV}
npx cdk deploy SafeAgents-Compute-${ENV} -c environment=${ENV} -c brokerDesiredCount=0 \
  -c brokerManifestPath=/app/examples/embedded_agent/manifest.yaml
cd ..
```

CDK asks you to approve the IAM changes; read them, since they are the broker's and the agent's
identities. The broker service is created with no running task, because its image does not exist
yet. `brokerManifestPath` is required: on the DynamoDB store the broker refuses to boot without a
named manifest rather than fall back to an example (`docs/cdk-context-contract.md`).

### 2. Build and push the broker image

The broker image is the base image plus a thin layer that bakes in the example's manifest and its
local search connector. The broker honours a connector provider only from a manifest baked into
the image, so the layer is how a consumer ships one.

```bash
podman build --platform linux/arm64 -f safe_agents/arms/local/Containerfile.broker \
  -t safe-agents-broker:base .
podman build --platform linux/arm64 -f examples/embedded_agent/Containerfile.broker \
  --build-arg BASE_IMAGE=safe-agents-broker:base -t safe-agents-broker:embedded .

REPO=$(aws ssm get-parameter --name "/safe-agents/${ENV}/ecr-broker-repo-uri" \
  --query Parameter.Value --output text)
aws ecr get-login-password | podman login --username AWS --password-stdin "${REPO%%/*}"
podman tag safe-agents-broker:embedded "${REPO}:latest"
podman push "${REPO}:latest"
```

The tasks run on arm64. On an x86 machine the build goes through emulation and is slower.

### 3. Create the two secrets and seed the grant

The broker needs an HMAC key to verify its grant rows, and the key used to seed them must be the
key the broker reads. It also fetches a credential for every tool it executes, so the search
connector needs a secret even though the local corpus ignores its value.

```bash
HMAC="$(python -c 'import secrets; print(secrets.token_hex(32))')"
aws secretsmanager create-secret --name "safe-agents/${ENV}/broker-hmac-key" --secret-string "${HMAC}"
aws secretsmanager create-secret --name "safe-agents/${ENV}/connectors/search" \
  --secret-string placeholder-local-search-needs-no-credential

M=examples/embedded_agent/manifest.yaml
BROKER_GRANTS_TABLE="safe-agents-${ENV}-grants" BROKER_ENVELOPE_MANIFEST=${M} \
  python -m safe_agents.broker.prototype.seed_envelope
BROKER_GRANTS_TABLE="safe-agents-${ENV}-grants" BROKER_HMAC_KEY="${HMAC}" BROKER_MANIFEST=${M} \
  BROKER_ENVELOPE_LOAD=store python -m safe_agents.broker.grants.commands seed
```

The envelope goes first, because each grant is stamped with the hash of the envelope the broker
will load. Expect `1 created, 0 skipped, 0 failed` and a note that the bootstrap record is
unsigned: no issuer signing key is configured on this path, and the seed says so rather than
signing with something it does not have. Without the `connectors/search` secret the allowed call
in step 5 is recorded as `allow/failed` and the agent receives a deny.

### 4. Start the broker

```bash
aws ecs update-service --cluster "safe-agents-${ENV}-cluster" \
  --service "safe-agents-${ENV}-broker" --desired-count 1
aws ecs wait services-stable --cluster "safe-agents-${ENV}-cluster" \
  --services "safe-agents-${ENV}-broker"
aws logs tail "/safe-agents/${ENV}/broker" --since 10m
```

The wait took about a minute. The log should end with the broker naming its stores (DynamoDB, the
S3 audit bucket, Secrets Manager) and `tool-call API on http://0.0.0.0:8080 (registry: 1 ops)`.

### 5. Send one allowed and one refused call

The broker's security group admits only the agent security group, so the call comes from a task
inside the VPC. The Compute stack defines that task as `safe-agents-<env>-client`: the broker
image with `call_client` as its entry point, the agent role as its task role, and no secrets.

```bash
p() { aws ssm get-parameter --name "/safe-agents/${ENV}/$1" --query Parameter.Value --output text; }
SUBNETS=$(p agent-subnet-ids); SG=$(p agent-sg-id); FAMILY=$(p client-task-family)

cat > /tmp/calls.json <<'JSON'
{"containerOverrides": [{"name": "client", "command": [
  "--call", "search.query", "{\"query\": \"broker\"}",
  "--call", "notify.send", "{\"text\": \"hello\"}"]}]}
JSON

TASK=$(aws ecs run-task --cluster "safe-agents-${ENV}-cluster" --launch-type FARGATE \
  --task-definition "${FAMILY}" --overrides file:///tmp/calls.json \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SG}],assignPublicIp=ENABLED}" \
  --query 'tasks[0].taskArn' --output text)
aws ecs wait tasks-stopped --cluster "safe-agents-${ENV}-cluster" --tasks "${TASK}"
aws logs tail "/safe-agents/${ENV}/client" --since 10m --format short
```

`assignPublicIp=ENABLED` is needed with the network-security layer off, because the task pulls
its image over the internet gateway. The log shows the registry and one line per decision:

```
{"broker_url": "http://broker.safe-agents.local:8080", "registry": [{"tool": "search", "op": "query"}]}
{"call": "search.query", "decision_kind": "allow", "result": {"query": "broker", "hits": [{"topic": "broker", "text": "The agent holds no connector credentials. Its only egress is the broker."}]}, "reason": null, "intent_id": null, "idempotent": false}
{"call": "notify.send", "decision_kind": "deny", "result": null, "reason": "tool not granted to this principal", "intent_id": null, "idempotent": false}
```

The registry is what the agent may see, and `notify.send` is not in it. The agent asked anyway,
and the broker refused on the record.

### 6. Read the audit records back from S3

```bash
python -m safe_agents.broker.auditor.tape_cli --s3-bucket "safe-agents-${ENV}-audit" --verify
```

```
  [   0] 2026-09-25T12:13:13.159476+00:00  search.query  allow/executed
  [   1] 2026-09-25T12:13:13.441839+00:00  notify.send  deny/denied
         why  tool not granted to this principal

CHAIN CONSISTENT — 2 records, seq 0..1
```

The command prints what the check does not prove, and it is worth reading: the chain is unkeyed
SHA-256, so a consistent chain shows the tape was not edited in place, while anyone who can write
the prefix could rewrite it whole. On `development` the audit bucket has Object Lock enabled with
no default retention, so nothing refuses that rewrite here.

### 7. Stop the broker, or tear it all down

Between sessions, scale the broker to zero; the rest costs cents a day.

```bash
aws ecs update-service --cluster "safe-agents-${ENV}-cluster" \
  --service "safe-agents-${ENV}-broker" --desired-count 0
```

To remove everything the tour created, destroy the stacks in reverse order, then delete the two
secrets, which no stack owns:

```bash
cd infra
npx cdk destroy SafeAgents-Compute-${ENV} SafeAgents-Identity-${ENV} SafeAgents-State-${ENV} \
  SafeAgents-Network-${ENV} -c environment=${ENV}
cd ..
for s in broker-hmac-key connectors/search; do
  aws secretsmanager delete-secret --secret-id "safe-agents/${ENV}/${s}" \
    --force-delete-without-recovery
done
```

On `development` the buckets, tables, repositories and log groups are deleted with their stacks,
including their contents. The four KMS keys enter AWS's minimum seven-day pending-deletion window,
during which they are not billed. The secrets are deleted without a recovery window so that a
second run can create them again under the same names. The CDK bootstrap stack is yours and stays.

### What this costs

Taken from the resource list of the four deployed stacks, at `us-east-1` list prices as of
September 2026; check the current prices for your region. Idle, with the broker scaled to zero:
four KMS keys ($4 a month), the Cloud Map private DNS zone ($0.50 a month) and two secrets ($0.80
a month), about $0.18 a day. The VPC endpoints are the free gateway type for DynamoDB and S3, and
there is no NAT gateway. DynamoDB, S3, ECR and CloudWatch Logs charge for use, which this tour
keeps to fractions of a cent. With the broker running add about $0.24 a day for the Fargate task
(0.25 vCPU, 0.5 GB, arm64) and $0.12 a day for its public IPv4 address, about $0.54 a day in all.
Each client run costs well under a cent. The network-security layer, if you turn it on, adds about
$6 a day for the NAT gateway and interface endpoints (`docs/network-security-layer.md`).

### What the AWS tour does not show

It shows a broker on AWS deciding under its own IAM role for a caller with no permissions. It does
not exercise the grant ceremony: the single grant here is the sanctioned bootstrap seed, run by
you with your own credentials. The ceremony roles (maker, checker, auditor) are created only when
you pass their `<x>TrustedPrincipals` contexts, and `docs/operator-identities.md` covers them.
The broker's `/call` endpoint does not authenticate its caller; the security group is the only
gate, and every caller inside it is the manifest's one principal.

The other runbooks: `docs/broker-service-bringup.md` for the broker service with the model-driven
smoke agents, `docs/operator-identities.md` for the ceremony roles (read it before any Identity
redeploy), `docs/environments.md` for what each environment is for, and the two airlock runbooks
listed in `docs/README.md`.

## OpenShift

The OpenShift arm (`safe_agents/arms/openshift/README.md`) is where posture 2 is demonstrated. It
deploys the broker and runs the same ceremony arc the laptop runs, then shows what a workload on
the other side of a boundary cannot reach. The maker cannot complete a grant ceremony alone: it is
refused the signing key, and its attempt to write a grant row is refused by the kernel on a
read-only mount. A ceremony leg cannot forge or erase another leg's audit records, for the same
reason. An agent pod holding no credentials gets work done through the broker and only through
it, inside a pod sandbox of SCC and NetworkPolicy. Read `safe_agents/arms/openshift/BRIEF.md`
first; it states each claim beside its limits, including that the broker can still rewrite its
own tape.

It needs cluster admin, `oc`, BuildConfigs, the internal image registry and the `restricted-v2`
SCC, so vanilla Kubernetes is not supported today. It was verified on OpenShift 4.20, and on
OpenShift Local (CRC 2.51, OpenShift 4.18.2) on an arm64 Apple silicon laptop on 2026-09-24,
unchanged apart from one setting: the VM's memory raised to 14336 MiB, because the default
cannot schedule the 2Gi build pod. The cost of the laptop path is a free Red Hat account for the
pull secret, about 14 GiB of RAM and 35 GB of disk for the VM, and a first `crc start` of about
25 minutes (about 3 when warm); the drill itself then took about 150 s with builds. The exact
sequence is in
[the arm README's OpenShift Local section](../safe_agents/arms/openshift/README.md#openshift-local-a-laptop).
