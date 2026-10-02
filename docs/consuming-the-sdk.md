# Consuming safe-agents as a dependency

This is the **install-and-use** guide for an agent repository that depends on this platform as a
package rather than vendoring it. It is the concrete counterpart to
`docs/adopting-safe-agents.md`, which is the conceptual refactor: hold no credentials, route
through the broker, declare an envelope. Read that one for the *why*, and this one for *how do I
install and invoke it*.

The platform is packaged as a single distribution named **`safe-agents`**, importable under the
**`safe_agents.*`** namespace, and published to [PyPI](https://pypi.org/project/safe-agents/).

---

## 1. Install

The distribution's own metadata states version ranges for its dependencies, as a library should:
a range lets your resolver fit `safe-agents` beside everything else you depend on. A range cannot
carry a hash, though, so the guarantee that you get exactly the files that were tested comes from
a lock file installed with `--require-hashes`. There are two ways to have one.

### Installing `safe-agents` by itself

Each release publishes a requirements file that pins `safe-agents` and every package its `aws`
and `mcp` extras depend on, each at an exact version and the sha256 of its published files:

```bash
curl -fsSLO https://github.com/wjatx/ptc-gal-reference/releases/download/v0.73.0/safe-agents-0.73.0-requirements.txt
python -m pip install --require-hashes -r safe-agents-0.73.0-requirements.txt
```

With `--require-hashes`, pip refuses any file whose hash is not in the list and any requirement
that has no hash at all, so nothing arrives that the file does not name. The release workflow
installs from this same file, with `--require-hashes`, before it publishes anything
(`.github/workflows/release.yml`). `SHA256SUMS` on the release page lists the sha256 of the wheel,
the sdist and the requirements file.

### Depending on `safe-agents` from your own project

Pin an exact version in your own metadata, never a range (the risk envelope must be
reproducible), and name the extras you use:

```toml
# pyproject.toml
dependencies = [
  "safe-agents[mcp]==0.73.0",
]
```

Then compile a lock for your whole project with hashes, and install from it:

```bash
uv pip compile pyproject.toml --generate-hashes -o requirements.txt
python -m pip install --require-hashes -r requirements.txt
```

`pip-compile --generate-hashes` from pip-tools produces the same kind of file. Your lock takes
the `safe-agents` wheel's hash from PyPI; compare it with the one in the release's `SHA256SUMS`
if you want a second source for it.

The extras:

- **`aws`** adds `boto3`, needed to reach AWS (provision and deploy, the DynamoDB and S3 stores,
  a live broker). The base install omits it so the SDK stays importable and unit-testable with no
  cloud SDK or credentials present; every AWS call site imports `boto3` lazily.
- **`mcp`** adds the MCP SDK, which the stdio gateway and the reference MCP host client need and
  nothing else does.

### Without a lock

```bash
pip install "safe-agents==0.73.0"
```

This works, and it pins `safe-agents` alone. Its dependencies resolve to whatever is newest
within the stated ranges on the day you run it, with no hash checked. That is acceptable for a
first look and is not how to install a trusted floor.

### What else you can check

The files are uploaded to PyPI by trusted publishing from this repository's `release.yml`, with
no stored API token. The upload step is configured to record a provenance attestation for each
file (PEP 740), which names this repository and that workflow; PyPI shows it on the file's page.

Bump the pin to a newer version deliberately, when you want a platform upgrade. That pin *is* the
version of the trusted floor your agent stands on.

To stand on a commit that has not been released, pin the commit SHA by git URL instead:
`safe-agents @ git+https://github.com/wjatx/ptc-gal-reference.git@<40-hex SHA>`. A package with a
dependency of that form cannot itself be published to PyPI, which refuses direct-URL dependencies.
From a clone, `CONTRIBUTING.md` gives the hash-locked development install.

## 2. What the install exposes

| Import | What it is |
|---|---|
| `safe_agents.pipeline` | the `provision → deploy → smoke` pipeline + its CLI (`safe_agents.pipeline.cli`) |
| `safe_agents.broker.schemas` | what a consumer **fills**: the seven schemas, `AgentManifest`, `Envelope`, `ToolOp` |
| `safe_agents.broker.api` | what a consumer **runs**: `build_runtime(manifest)`, `load_agent_manifest`, and the `BrokerRuntime` / `AgentRequest` / `BrokerResponse` call surface, plus `GatewayClient` / `GatewayClientError` / `result_text` for running the stdio MCP gateway as a child process and asking it |
| `safe_agents.connectors` | the shared connectors (github; telegram) + the `Connector` protocol re-export — see `safe_agents/connectors/README.md` for the shared-vs-agent-owned split |
| `safe_agents.arms` | the substrate arms behind one runner contract (`ec2`, `ec2_woken`, `fargate`, `local`, `openshift`, `rhel_openshell`) |
| `safe_agents.contract` | the runner-contract conformance harness |

**The broker's surface is exactly those two rows** [ruling: maintainer, 2026-07-26]: *a consumer may
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
agent that composes a runtime, gets one call allowed and one refused, and states its posture honestly.
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

The pipeline makes no assumption about sitting in the same tree as your agent. **Your agent
package resolves beside its manifest**: the default is `<manifest's own directory>/<agent_package>`,
with no CLI flag needed. So your repository lays out its agent exactly as this one lays out its
smoke fixtures, the package sitting next to the manifest, both under `agents/`:

```
example-agent/                      # your repo
├── pyproject.toml                  # depends on safe-agents[aws]==<version>
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
  connector IPs, since connector traffic never leaves the agent directly. See this repository's
  `policies/smoke-*.yaml` for the canonical shape.
- **Agent-specific connectors** (a brokerage connector for a trading agent, say) are agent-owned
  and live in your repo;
  genuinely shared connectors (github) ship in the SDK. The `Connector` protocol comes from the SDK
  either way.

## 4. Invoke the pipeline against your own agent

The console entrypoint (or `python -m safe_agents.pipeline.cli`) drives the three phases. Point it at
your manifest; the agent package resolves from the manifest's own directory by default — no monorepo
assumption, no `PYTHONPATH` hack:

```bash
# dry-run first (validates the manifest + prints the plan; no AWS calls):
safe-agents agents/example-agent.yaml --env development --dry-run --ami-id "$AMI_ID"

# live:
safe-agents agents/example-agent.yaml --env development --ami-id "$AMI_ID"

# teardown (tagged, zero-orphan):
safe-agents agents/example-agent.yaml --env development --phase teardown
```

**The provision phase launches what you name, and has no default.** Pass the flag that matches
your manifest's arm:

| Arm | Flag | Value |
|---|---|---|
| `ec2`, `rhel-openshell` | `--ami-id` | The AMI id your bake produced: `ami-` plus 8 or 17 lowercase hex characters. `safe_agents/arms/ec2/ami/README.md` and `safe_agents/arms/rhel_openshell/ami/README.md` show how to read it. |
| `fargate` | `--image-uri` | Your image by digest: `<ecr-agent-repo-uri>@sha256:<64 lowercase hex characters>`. `docs/consumer-image-contract.md` shows how to read the digest back after the push. |
| `ec2-woken` | none | The phase deploys the airlock and launches nothing. The box is launched by `ec2_woken_box_provision(image_id=...)`. |

With no flag the provision phase fails before any AWS call, in a dry run as well as a real one, and
the message says how to get the value. A flag that does not apply to the arm is an error, and so is
either flag on a run that leaves out the provision phase. A dry run checks the form of the value
and makes no AWS call, so it does not confirm that the AMI or the image exists.

Two overrides exist for the case where you cannot name the exact thing:

- `--allow-newest-ami` resolves the newest AMI by the arm's tag rule. On `rhel-openshell`, when no
  baked AMI exists, it falls back to the Red Hat marketplace AMI with the highest release.
- `--allow-mutable-image-tag` lets `--image-uri` name a tag instead of a digest. `--image-uri` is
  still required. No flag brings back an implicit `latest`.

Each override prints a line in the plan that starts `OVERRIDE` and logs the same line at WARNING.
The line names what was chosen and the rule that chose it. Both are flags of the command only:
nothing reads them, or the AMI id or image URI, from the manifest or the environment.

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
    ami_id="ami-0123456789abcdef0",   # ec2 / rhel-openshell: the AMI your bake produced
    # image_uri="<ecr-agent-repo-uri>@sha256:<digest>",   # fargate: your image, by digest
    # agent_root=Path("packages"),   # only if your package tree lives elsewhere
)
assert result.success, result.aborted_at
```

`ami_id` and `image_uri` are the CLI's `--ami-id` and `--image-uri`, and the overrides are
`allow_newest_ami=True` and `allow_mutable_image_tag=True`. They must be real booleans passed by
your code: a string is refused, so a value lifted from a config file cannot switch one on. The
provisioners take the same arguments when called directly (`ec2_provision(image_id=...)`,
`rhel_openshell_provision(image_id=...)`, `ec2_woken_box_provision(image_id=...)`,
`fargate_provision(image_uri=...)`), and each refuses with `ImagePinError` when nothing is named.
An override used through `run_pipeline` is recorded as a step of the provision `PhaseResult`.

## 6. Verifying the install

The dependency is proven for your repo when, from a clean checkout of *your* repo with only
`pip install` and no path hacks:

- the pin resolves and installs;
- `python -c "import safe_agents.pipeline"` works;
- `safe-agents agents/<name>.yaml --env development --dry-run` with your arm's `--ami-id` or
  `--image-uri` validates your manifest; and
- the confined brokered smoke runs end to end (agent, broker, run record, audit), which is the
  acceptance bar the substrate arms clear, now inherited as a dependency.

## 7. Where to read next

- `docs/adopting-safe-agents.md` — the conceptual refactor (route through the broker, declare an
  envelope, pick an arm). The Fargate + conversational patterns for the example agent are there.
- `broker/SCHEMAS.md` — the seven schemas that are the broker's contract.
- `core/RUNNER-CONTRACT.md` — the runner contract every agent run satisfies.
- `safe_agents/connectors/README.md` — the shared-vs-agent-owned connector split.
