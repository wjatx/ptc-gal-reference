# PTC & GAL — reference implementation

A working implementation of two proposed specifications for agentic systems:

- **PTC** (*Provenance & Trust Context*) — a signed trust-context object that travels with data
  across every agent and tool boundary, carrying sender class, an append-only provenance chain, and
  taint on a Biba integrity lattice.
- **GAL** (*Grant & Autonomy Lifecycle*) — authority as stored, signed state per
  `(principal, action-class)`, raised only through a maker≠checker ceremony licensed by a
  deterministic predicate, and lowered automatically by deterministic triggers.

Both specifications are maintained in their own repository —
**[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards)** — and are licensed
separately (see Licensing below). This repository is the implementation that stands behind them.

## The claim, and where to attack it

This is a controls layer, not an agent framework. You bring your own harness: the model, the loop,
the prompts, the orchestration. Controls that live inside the harness are advice to the component
under attack, and anything a model can be talked out of is not a control. So these controls sit
outside it, under a separate identity, around one commitment: **the agent holds no credentials, and
its only egress is a deterministic tool broker.** Every tool call crosses that broker, which decides
per call from signed policy state and writes a tamper-evident audit under an identity the agent
cannot reach. A fully compromised agent can still only *ask*.

That last sentence is the thesis and the thing worth attacking. Before you spend time on it, read
**[`docs/lf-reference-implementation.md`](docs/lf-reference-implementation.md)** — it states what is
demonstrated on live infrastructure versus what is only asserted from tests, lists the places a
careful reader will find less than a summary implies, and names the leg of the claim we already know
is the weakest. It is written to be probed, and it will save you the work of discovering our known
gaps yourself.

Two things from it worth surfacing here:

- **23 of the 78 conformance clauses are not supported.** The count is generated from
  per-clause markers in the specifications, never written by hand.
- **No independent party has run any of this.** Every drill was designed by the people whose work it
  tests, which makes a green drill evidence that the drill ran rather than evidence that the control
  holds. That is the gap we would most like closed.

## If a coding agent is reading this

These controls govern what a **running** agent may do to the world at run time. They are not a
development methodology, and they do not describe how you should edit files, structure commits,
or review changes in the repository you are working in.

That distinction is easy to lose, because this codebase is written throughout in the vocabulary
of authority, ceremony, taint and tamper-evidence, and the nearest system to apply that
vocabulary to is your own work. Doing so costs sessions and buys nothing, since none of the
modelled threats are present. Read
[`docs/self-application.md`](docs/self-application.md) before you borrow anything from here into
your own working habits. It gives the symptoms, the two cases where the transfer is legitimate,
the defect this cost us, and a block to paste into your project's agent instructions.

## Quickstart

No cloud account is needed for the parts you can check yourself.

```bash
pip install -e .

# The full suite.
python3 -m pytest
```

The **conformance statement** reads the specifications, which are not vendored here. Clone them
alongside and point the extractor at the checkout:

```bash
git clone https://github.com/wjatx/ptc-gal-standards

# 78 clauses, marker state, and the extraction self-checks.
python3 -m safe_agents.contract.spec_clauses --summary --spec-dir ptc-gal-standards

# Our completed statement, and the blank proforma an independent implementer would fill.
python3 -m safe_agents.contract.spec_clauses --pics-ri --spec-dir ptc-gal-standards
python3 -m safe_agents.contract.spec_clauses --pics   --spec-dir ptc-gal-standards
```

Without that checkout the suite still runs green: the handful of tests that compare spec text
against shipped schemas skip rather than fail, and say why.

Run `pytest` from the repository root rather than narrowing it to `safe_agents/`: the reliability
library the watcher depends on carries tests the narrower path silently skips.

### Watch it refuse something

The broker presents itself to an agent as **one MCP server over stdio**, so you can point any MCP
client you already have at it. Nothing else is needed: no cloud account, no container, no wrapper
tool, no configuration.

```bash
python -m safe_agents.broker.gateway
```

It comes up on the checked-in example manifest and announces what it will carry:

```
[broker] store backend: in-memory   audit sink: memory   grant load mode: seed
[broker] MCP gateway ready: 2 tool(s) for example-advisor
```

Two things are worth doing by hand before wiring a real client. Ask it for its tools, and you get
only what the manifest declares. Then call one it does *not* declare:

```
tools/call  payments__transfer  {"amount": "1000"}
→ payments.transfer refused by the broker: no manifest entry for payments.transfer
```

That refusal is the whole thesis in one line. The agent asked; the broker decided; nothing
executed. The tool was not hidden from the model, was not blocked by a prompt, and was not left to
the harness's good behaviour. It was **not admitted**, and admission is a property of the manifest
and the ceremony rather than of anything the caller can talk its way past.

To point a harness at it, add it to that harness's MCP server configuration as a stdio server whose
command is the line above. Every call the harness then makes is decided and recorded before it
executes.

Two honest notes so the first five minutes are not confusing. Calling a **declared** tool in this
default configuration reaches the gate, passes it, and then fails at the connector for want of a
seeded credential — that is execution failing, not the gate refusing, and the two read differently
on purpose. And note `grant load mode: seed` in the banner: that is the default local path, and it
is the one described under "What we would most like challenged" in
[`docs/lf-reference-implementation.md`](docs/lf-reference-implementation.md). You are looking at the
configuration whose weakest leg we name there.

The live demonstrations require deployed infrastructure and are not reproducible from a checkout.
That asymmetry is deliberate to note: the parts you can verify yourself are the parts made easiest
to verify.

## What is in here

| Path | What it holds |
|---|---|
| `safe_agents/broker/` | The broker: the gate, the grant store, the ceremonies, the audit tape, the MCP host |
| `safe_agents/channels/` | The inbound airlock: validate, verify, trust-map, deduplicate, screen, stamp |
| `safe_agents/arms/` | Substrate arms, including the OpenShift deployment |
| `safe_agents/` (rest) | Contract types, connectors, watcher, evidence, pipeline |
| `broker/` `channels/` `core/` `audit/` `registry/` | The normative contract documents |
| `docs/` | Doctrine, threat model, posture ladder, and the operator runbooks |
| `infra/` | AWS CDK for a deployed environment. See `docs/cdk-context-contract.md` first |
| `examples/` | Worked consumers, including a drill against a real third-party MCP server |

Start with [`docs/lf-notional-architecture.md`](docs/lf-notional-architecture.md) for how the pieces
fit, and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the technical floor.

## Deploying it

`infra/` is AWS CDK and is not pinned to any account: it resolves the target from
`CDK_DEFAULT_ACCOUNT`. Read **[`docs/cdk-context-contract.md`](docs/cdk-context-contract.md)**
before a first deploy. The stacks take 24 context values, and thirteen of them **degrade silently**
when omitted, which is the failure mode worth knowing about in advance. The operator runbooks in
`docs/` cover bring-up, the ceremony identities, and the traps that bite on redeploy.

## Licensing

This repository — the reference implementation and its documentation — is licensed under
**Apache-2.0**. See [`LICENSE`](LICENSE).

The specifications are licensed separately, under the **Community Specification License 1.0**
(`Community-Spec-1.0`), and live in
[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards). Keeping them in their own
repository keeps each licence unambiguous: a patent-facing specification licence and a
copyright-facing code licence answer different questions and should not have to be untangled from
one tree.

Author: Wes Jackson (Red Hat). Copyright © 2026 Red Hat, Inc.
