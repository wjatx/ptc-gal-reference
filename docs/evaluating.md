# Evaluating the reference implementation

> For anyone who has followed the setup in the root `README.md` and wants to know what to look
> at next. It picks up where the README stops: which deployment path fits what you want to
> check, a laptop tour in order, and the honest state of the AWS and OpenShift paths.

What you can check depends on where the broker runs. The strongest claim this implementation
makes, that the enforcement point cannot grant itself authority, is a property of a platform
boundary, and a single machine has no such boundary to show. `docs/posture-ladder.md` names the
three postures; the table below maps them to the three places you can run this.

## Choose a path

| Path | What you can check | What you cannot | Effort |
|---|---|---|---|
| **Laptop** (posture 1) | The test suite, the generated conformance statement, the broker deciding real MCP tool calls, the taint hold, the audit tape, the broker embedded as a library | Any claim that rests on a boundary between the broker and the agent: grant writes denied by the platform, credentials held across a boundary, the agent's own built-in tools being confined | About ten minutes. No account |
| **AWS** (posture 3) | The broker under its own cloud identity, with an out-of-scope action refused by IAM rather than by broker code, and maker≠checker enforced by comparing credential ARNs | An end-to-end tool call decided on AWS by following a runbook: no guided walkthrough exists yet (see [AWS](#aws)) | Hours, an AWS account you can create IAM roles in, and a small daily cost |
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

## AWS

`infra/` is AWS CDK (TypeScript) for posture 3. It is not pinned to any account and resolves the
target from `CDK_DEFAULT_ACCOUNT`. A guided walkthrough from an empty account to a tool call
decided on AWS is being written. Until it lands, this is the state of the path:

- **Synth works offline.** From `infra/`, after `npm ci`, `npx cdk synth -c environment=development`
  needs no other context. CI runs the same synth plus the conformance assertions.
- **Read `docs/cdk-context-contract.md` before the first deploy.** The stacks take twenty-five
  context values, and thirteen of them degrade silently when omitted rather than failing.
- **Stay on `development`.** `staging` and `production` retain resources on teardown and put a
  seven-year GOVERNANCE-mode Object Lock on the audit bucket, which is not something to create
  while evaluating.
- **Cost.** Estimated from the synthesized resources rather than from a bill: roughly $0.50 a day
  on `development` with the network-security layer off (the default), and roughly $6.50 a day with
  it on. The difference is the interface endpoints and the NAT gateway; the cost profile in
  `docs/network-security-layer.md` breaks it down.
- **Known gaps on the way to a decided call.** `docs/broker-service-bringup.md` ends with the
  broker service running. The broker's security group admits only the agent's security group, so
  there is no documented way to send it a call from outside. The Fargate agent arm is driven by a
  Python function rather than a command. The Identity stack imports a GitHub Actions OIDC provider
  unconditionally (`infra/lib/identity-stack.ts`), which may fail on an account that has none; this
  is unverified.

The runbooks that exist: `docs/broker-service-bringup.md` for the broker service,
`docs/operator-identities.md` for the ceremony roles (read it before any Identity redeploy),
`docs/environments.md` for what each environment is for, and the two airlock runbooks listed in
`docs/README.md`.

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
