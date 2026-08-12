# Consuming safe-agents as a dependency

This is the **install-and-use** guide for an external agent repo (a live trading agent was the first) that
depends on the safe-agents platform as a package instead of living inside this monorepo. It is the
concrete counterpart to `docs/adopting-safe-agents.md` (which is the *conceptual* refactor — hold no
creds, route through the broker, declare an envelope). Read that for the *why*; read this for the
*how do I install and invoke it*.

The SDK is packaged (sa#106) as a single distribution named **`safe-agents`**, importable under the
**`safe_agents.*`** namespace. Distribution is **private and git-installable** — no public PyPI yet
(a private index is a later, separate call).

---

## 1. Install

Pin by tag or commit SHA — never an unpinned branch (the risk envelope must be reproducible):

```bash
# SSH (normal case — your repo/CI has read access to controlled-agents/safe-agents):
pip install "safe-agents @ git+ssh://git@github.com/controlled-agents/safe-agents.git@v0.63.0"

# HTTPS with a token, e.g. in CI:
pip install "safe-agents @ git+https://${GH_TOKEN}@github.com/controlled-agents/safe-agents.git@v0.63.0"
```

To actually reach AWS (provision/deploy, DynamoDB/S3 stores, live broker), install the **`aws`**
extra — it adds `boto3`. The base install deliberately omits `boto3` so the SDK stays importable and
unit-testable with no cloud SDK or credentials present; every AWS call site imports `boto3` lazily:

```bash
pip install "safe-agents[aws] @ git+ssh://git@github.com/controlled-agents/safe-agents.git@v0.63.0"
```

In a `pyproject.toml` / `requirements.txt`, pin the same way:

```toml
# pyproject.toml
dependencies = [
  "safe-agents[aws] @ git+ssh://git@github.com/controlled-agents/safe-agents.git@v0.63.0",
]
```

```
# requirements.txt
safe-agents[aws] @ git+ssh://git@github.com/controlled-agents/safe-agents.git@v0.63.0
```

Bump the pin (`@v0.2.1` → a newer tag) deliberately when you want a platform upgrade — that pin
*is* the version of the trusted floor your agent stands on.

## 2. What the install exposes

| Import | What it is |
|---|---|
| `safe_agents.pipeline` | the `provision → deploy → smoke` pipeline + its CLI (`safe_agents.pipeline.cli`) |
| `safe_agents.broker.schemas` | what a consumer **fills**: the seven schemas, `AgentManifest`, `Envelope`, `ToolOp` |
| `safe_agents.broker.api` | what a consumer **runs**: `build_runtime(manifest)`, `load_agent_manifest`, and the `BrokerRuntime` / `AgentRequest` / `BrokerResponse` call surface |
| `safe_agents.connectors` | the shared connectors (github; telegram) + the `Connector` protocol re-export — see `safe_agents/connectors/README.md` for the shared-vs-agent-owned split |
| `safe_agents.arms` | the four substrate arms (`ec2`, `ec2_woken`, `fargate`, `rhel_openshell`, `local`) behind one runner contract |
| `safe_agents.contract` | the runner-contract conformance harness |

**The broker's surface is exactly those two rows** [ruling: maintainer, 2026-07-26, #266]: *a consumer may
import what it fills and what it runs, never what decides.* Everything else under
`safe_agents.broker` is internal — including `broker.runtime` (which re-exports the `Doer`,
`SecretsProvider` and the credential strategies) and the PDP. A consumer able to import the
decision engine can route around the decision it is meant to be subject to, so you get the
runtime, never the runtime's parts. `safe_agents/broker/tests/test_consumer_boundary.py` enforces this, and an
earlier version of this table wrongly listed PDP/PEP/Doer/SecretsProvider as exposed.

Note what an import does *not* buy: `build_runtime` composes whatever backends the environment
selects, in-memory ones included. Identity separation, IAM confinement and the tamper-evident audit
chain are properties of a **deployment**, not of an import.

`examples/embedded_agent/` is the runnable worked example of exactly this surface — a plain Python
agent that composes a runtime, gets one call allowed and one refused, and states its rung honestly.
`python -m examples.embedded_agent.agent`, no account and no credentials.

Plus a console entrypoint, installed on your `PATH`:

```bash
safe-agents --help                       # == python -m safe_agents.pipeline.cli --help
```

Quick smoke that the install is healthy, from anywhere (no need to be in a checkout):

```bash
python -c "import safe_agents.pipeline, safe_agents.broker.schemas, safe_agents.connectors; print('ok')"
```

## 3. Your repo owns its manifest, policy, and agent-specific connectors

The extraction broke the old monorepo-sibling assumption: the pipeline no longer jumps to
`<repo>/agents/<name>` relative to itself. **Your agent package resolves beside its manifest** — the
pipeline's default is `<manifest's own directory>/<agent_package>`, no CLI flag needed. So an
external repo lays out its own agent exactly as this monorepo lays out its smoke fixtures — the
package sits *next to* the manifest, both under `agents/`:

```
example-agent/                      # your repo
├── pyproject.toml                  # depends on safe-agents[aws] @ <tag>
├── policies/
│   └── example-agent.yaml          # the network-egress confinement policy
└── agents/
    ├── example-agent.yaml          # the manifest (your risk envelope)
    └── example_agent/              # your agent package (agent_package: example_agent),
        └── connectors/             #   resolved beside the manifest by default — no --agent-root
            └── alpaca_connector.py # agent-owned connector (single-agent → lives with the agent)
```

(If you'd rather keep the package at your repo root — a normal top-level importable module — pass
`--agent-root .`; see §4. The layout above is the zero-flag default and needs no such flag.)

- **The manifest** (`agents/<name>.yaml`) is the risk envelope — subject to maker-checker promotion
  review. Put your branch protection / CODEOWNERS on it in *your* repo.
- **The policy** (`policies/<name>.yaml`) is the egress confinement. `agent_egress` lists only
  domain hosts reached *through the broker proxy* (e.g. `api.anthropic.com`); it must contain no raw
  connector IPs — connector traffic never leaves the agent directly. See this repo's
  `policies/smoke-*.yaml` for the canonical shape.
- **Agent-specific connectors** (Alpaca for a trading agent) are agent-owned and live in your repo;
  genuinely shared connectors (github) ship in the SDK. The `Connector` protocol comes from the SDK
  either way.

## 4. Invoke the pipeline against your own agent

The console entrypoint (or `python -m safe_agents.pipeline.cli`) drives the three phases. Point it at
your manifest; the agent package resolves from the manifest's own directory by default — no monorepo
assumption, no `PYTHONPATH` hack:

```bash
# dry-run first (validates the manifest + prints the plan; no AWS calls):
safe-agents agents/example-agent.yaml --env development --dry-run

# live:
safe-agents agents/example-agent.yaml --env development

# teardown (tagged, zero-orphan):
safe-agents agents/example-agent.yaml --env development --phase teardown
```

Agent-package resolution precedence (highest first):

1. `--agent-dir DIR` — an explicit package directory.
2. `--agent-root DIR` — resolves `<DIR>/<manifest.agent_package or name>`; use when your package tree
   is separate from where your manifests live.
3. **default** — `<manifest's own directory>/<agent_package>`, i.e. the package sits beside its
   manifest (exactly the in-tree layout above). This is the common case and needs no flag.

`--env` is `development | staging | production` (spelled out — never `dev`/`prod`).

## 5. Programmatic use

If you drive the pipeline from your own code rather than the CLI:

```python
from pathlib import Path
from safe_agents.pipeline import run_pipeline   # see safe_agents/pipeline/__init__.py for the surface

result = run_pipeline(
    Path("agents/example-agent.yaml"),
    dry_run=False,
    environment="development",
    # agent_root=Path("packages"),   # only if your package tree lives elsewhere
)
assert result.success, result.aborted_at
```

## 6. Verifying the whole thing (Phase 5 definition of done)

The extraction is "proven" for your repo when, from a clean checkout of *your* repo with only
`pip install` (no path hacks):

- the pin resolves and installs (`pip install "safe-agents[aws] @ git+ssh://…@v0.2.1"`);
- `python -c "import safe_agents.pipeline"` works;
- `safe-agents agents/<name>.yaml --env development --dry-run` validates your manifest; and
- the confined brokered smoke runs end-to-end (agent → broker → run record → audit) — the
  nine-gate acceptance bar the substrate arms already cleared live, now inherited as a dependency.

## 7. Where to read next

- `docs/adopting-safe-agents.md` — the conceptual refactor (route through the broker, declare an
  envelope, pick an arm). The Fargate + conversational patterns for the example agent are there.
- `broker/SCHEMAS.md` — the seven schemas that are the broker's contract.
- `core/RUNNER-CONTRACT.md` — the runner contract every agent run satisfies.
- `safe_agents/connectors/README.md` — the shared-vs-agent-owned connector split.
