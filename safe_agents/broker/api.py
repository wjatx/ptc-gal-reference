"""broker.api — the base's public embedding surface, as a list you can read.

This module exists because the repo contradicted itself. `docs/consuming-the-sdk.md`
§2 published `safe_agents.broker` as an exposed import, `docs/canonical-consumer.md`
§3 named `build_runtime(manifest)` the consumer pattern's centerpiece, and the
consumer-boundary guard permitted `broker.schemas` alone — while `build_runtime`
sat in a directory named `prototype/`. The published contract and the enforced
guard disagreed (#266).

## The ruling [maintainer, 2026-07-26]

**A consumer may import what it FILLS and what it RUNS, never what DECIDES.**

Two tiers, and nothing else:

===============================  ==================================================
Tier                             Surface
===============================  ==================================================
what a consumer FILLS            ``safe_agents.broker.schemas`` — the seven schemas,
                                 ``AgentManifest``, ``Envelope``, ``ToolOp``
what a consumer RUNS             this module — ``build_runtime`` and the runtime
                                 objects it hands back
===============================  ==================================================

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
`broker/tests/test_consumer_boundary.py` enforces that nothing outside these two
tiers is reachable from a consumer.

It does NOT promise that embedding the broker gets you the cloud floor's
guarantees. `build_runtime` composes whatever backends the environment selects,
including in-memory ones; the identity separation, the IAM confinement and the
tamper-evident audit chain are properties of a deployment, not of an import. The
rung ladder is where that distinction is stated honestly.
"""

from __future__ import annotations

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
]
