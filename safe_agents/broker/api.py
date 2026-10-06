"""broker.api — what a consumer RUNS, as a list you can read, and the one place
the three public tiers of the broker are stated.

This module exists because the repo contradicted itself. `docs/consuming-the-sdk.md`
§2 published `safe_agents.broker` as an exposed import, `docs/canonical-consumer.md`
§3 named `build_runtime(manifest)` the consumer pattern's centerpiece, and the
consumer-boundary guard permitted `broker.schemas` alone — while `build_runtime`
sat in a directory named `prototype/`. The published contract and the enforced
guard disagreed.

## The ruling [maintainer, 2026-07-26; amended 2026-10-06]

**A consumer may import what it FILLS, what it RUNS and what it ASKS WITH, never
what DECIDES.**

Three tiers, and nothing else:

===============================  ==================================================
Tier                             Surface
===============================  ==================================================
what a consumer FILLS            ``safe_agents.broker.schemas`` — the seven schemas,
                                 ``AgentManifest``, ``Envelope``, ``ToolOp``
what a consumer RUNS             this module — ``build_runtime`` and the runtime
                                 objects it hands back
what a consumer ASKS WITH        ``safe_agents.broker.client`` — ``GatewayClient``
                                 (the MCP gateway as a child process, over stdio),
                                 ``NetworkGatewayClient`` (the network MCP mouth,
                                 over streamable HTTP), ``GatewayClientError`` and
                                 ``result_text``
===============================  ==================================================

The 2026-07-26 ruling named two tiers and put the stdio ``GatewayClient`` in this
module, as a second way to run the broker. The 2026-10-06 ruling, made when the
gateway gained a network mouth and a second client, moved the clients to a tier
of their own. A client runs nothing. It carries frames to a gateway and reports
what came back, which is the position a wrapped agent is in: whoever holds one
can ask and can do nothing else. It decides nothing, so publishing it gives a
consumer no way around a decision.

The tiers are separate imports because they cost different things. Importing this
module loads the runtime: the decision path, the stores, the connectors. A process
that only asks, such as an agent inside a sandbox with the gateway outside it,
should not load any of that, and importing ``safe_agents.broker.client`` does not.

**The three client names are still importable from here.** ``GatewayClient``,
``GatewayClientError`` and ``result_text`` shipped in this module's ``__all__`` in
a published release, so they stay as re-exports of the same objects and existing
imports keep working. They are kept for compatibility only: importing them from
here still loads the runtime, exactly as it did before, and
``NetworkGatewayClient`` is deliberately not added here. New code imports all of
them from ``safe_agents.broker.client``.

Everything else in the broker is internal, and the interesting half of that is
what the previous doc text got wrong in the *other* direction: §2 listed
"PDP/PEP, Doer, SecretsProvider" as exposed imports. Those are what DECIDES and
what EXECUTES. A consumer importing the PDP can reimplement or route around the
decision it is supposed to be subject to, which is the one thing the broker
exists to prevent — "the broker is the one deliberately non-swappable
implementation" (`docs/contract-vs-reference.md`). So a consumer gets the
runtime, never the runtime's parts. Note `safe_agents.broker.runtime` is NOT a
public package for exactly this reason: it re-exports `Doer`, `SecretsProvider`
and the credential strategies.

## Why a curated façade rather than a moved module

`build_runtime` is the broker service's composition root: it resolves the store
arm, the audit sink, the secrets backend, the in-force envelope and the ToolOp
table, and it is coupled to a dozen sibling helpers by design. Relocating the
body would drag most of its package with it — including the modules whose
``python -m`` invocations are documented steps in both floors' bringup runbooks.
Re-exporting is not a veneer over a wart here: it makes the public surface an
explicit, greppable list instead of a package whose contents drift, which is the
property the boundary guard needs in order to mean anything.

## What this surface promises

Import stability. These names, with these shapes, are what a consumer builds
against; internal reorganization behind them is not a breaking change, and
`broker/tests/test_consumer_boundary.py` enforces that nothing outside the three
tiers is reachable from a consumer.

It does NOT promise that embedding the broker gets you the cloud floor's
guarantees. `build_runtime` composes whatever backends the environment selects,
including in-memory ones; the identity separation, the IAM confinement and the
tamper-evident audit chain are properties of a deployment, not of an import. The
posture ladder is where that distinction is stated honestly.
"""

from __future__ import annotations

from safe_agents.broker.client import GatewayClient, GatewayClientError, result_text
from safe_agents.broker.prototype.boot_config import load_agent_manifest
from safe_agents.broker.prototype.broker_server import build_runtime
from safe_agents.broker.runtime.pep import AgentRequest, BrokerResponse, BrokerRuntime

__all__ = [
    # What a consumer RUNS: construct the runtime from a manifest it filled.
    "build_runtime",
    "load_agent_manifest",
    # The runtime and its call surface. `handle_request` is the agent's ONLY
    # egress; the Doer and the SecretsProvider stay inside and are deliberately
    # absent from this list.
    "BrokerRuntime",
    "AgentRequest",
    "BrokerResponse",
    # Compatibility re-exports. These belong to the third tier, what a consumer
    # ASKS WITH (`safe_agents.broker.client`), and are the same objects. They stay
    # here because a published release exported them from this module.
    "GatewayClient",
    "GatewayClientError",
    "result_text",
]
