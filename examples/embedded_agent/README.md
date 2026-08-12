# embedded_agent — the broker as a library

**Proof obligation:** the broker is embeddable in a plain Python program through the public
`safe_agents.broker.api` surface. Every other example here configures the broker *as a service* —
a manifest plus a consumer image. This one imports it.

```bash
python -m examples.embedded_agent.agent
```

No AWS account, no credentials, no container, no running service. Observed output:

```
[broker] envelope load mode: manifest
[broker] store backend: in-memory
[broker] audit sink: memory; secrets: fake
[broker] grant load mode: seed
search.query  -> allow
                 broker: The agent holds no connector credentials. Its only egress is the broker.
notify.send   -> deny: tool not granted to this principal

audit tape:
  seq=0  decision=allow  outcome=executed
  seq=1  decision=deny  outcome=denied
```

## Why this example exists

The framing line is a standing ruling [maintainer, 2026-07-24]: *"The product wrapper wraps agents you don't control;
agents you build can use the broker directly."* The second half was undemonstrable as a library —
the imports it needs were forbidden by the consumer-boundary guard and the constructor lived in a
directory named `prototype/`. #266 ruled the surface; this example is what turns that ruling from
an assertion into something you can run.

The gate that had been blocking it was **"no consumer needs it yet"** — self-sealing reasoning for
a capability whose consumers are the entire point [maintainer, 2026-07-25].

## The whole consumer surface

Four names, one import line:

```python
from safe_agents.broker.api import AgentRequest, build_runtime, load_agent_manifest
```

That is the contract [ruling: maintainer, 2026-07-26]: **a consumer may import what it FILLS
(`broker.schemas`) and what it RUNS (`broker.api`), never what DECIDES.** There is no import in
this directory that reaches the PDP, the Doer, or the `SecretsProvider`, and
`broker/tests/test_consumer_boundary.py` fails the build if one appears. A consumer that could
import the decision engine could route around the decision it is meant to be subject to.

## What the two calls show

`search.query` is granted, so the broker decides *allow* and the Doer executes the connector under
a credential this agent never sees. `notify.send` is **classified** in the manifest's `tool_ops`
but **not granted** in `grant_classes` — so the agent is free to ask, and the broker refuses with
`tool not granted to this principal`. No connector is called on that path, and the refusal is on
the tape.

That gap between *classified* and *granted* is deliberate. It is what makes the refusal a **policy
decision** rather than a missing entry: had `notify.send` simply been absent from `tool_ops`, the
runtime would have returned `no manifest entry for notify.send` before the PDP ever ran, and the
example would have demonstrated a typo instead of a control. (The complementary move — putting the
hazardous op structurally out of reach — is [`missileer/`](../missileer/), and it is the stronger
one when you can afford it.)

## What this does NOT buy you

This is the part the [posture ladder](../../docs/posture-ladder.md) exists to make you say out loud.

**An import is not a deployment.** `build_runtime` composes whatever backends the environment
selects. With no `BROKER_*` variables set — as above — the stores are in-memory, the audit sink is
in-memory, and the credentials are *fake*. The identity separation, the IAM confinement and the
tamper-evident audit chain are properties of a deployment, not of an import.

**Embedding is same-process, so several controls are conventions here rather than boundaries.**
The agent, the broker, the Doer and the audit sink are all objects in one Python process under one
OS user. `build_runtime` hands the sink straight back to the caller — the agent cannot reach the
writer *through the `BrokerResponse`*, which is a real and test-asserted property
(`runtime/pep.py:176-180`), but nothing stops a same-process caller that goes looking for it. This
configuration sits at **posture 1 or below**. What would move it up is not another rule; it is a
boundary — the broker in its own process or its own identity, which is postures 2 and 3.

**The credential story is real but narrow.** The agent never receives a credential, because the
Doer fetches it inside `execute()` and the response type has no field to carry one. That holds
here. What does not hold is anything about *confining* the agent: on a laptop, an embedded agent
that wanted a credential could read the same environment the broker reads.

## Relationships

- `docs/consuming-the-sdk.md` §2 — the two-tier import surface this example is written against.
- `docs/canonical-consumer.md` §3 — the five-seam consumer anatomy; `build_runtime(manifest)` is
  its centerpiece.
- `docs/posture-ladder.md` — the posture vocabulary the limits above are stated in.
- [`missileer/`](../missileer/) — the same `connector_providers` seam, used to prove the opposite
  move: absence rather than refusal.
- #266 (this example), #106 (the installable-SDK thread it advances).
