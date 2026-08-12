"""agent.py — a plain Python agent that EMBEDS the broker (#266).

Run it:

    python -m examples.embedded_agent.agent

No AWS account, no credentials, no container, no service. The whole consumer
surface is the four imports below, and they are the entire public contract
[ruling: maintainer, 2026-07-26]: **a consumer may import what it FILLS
(`broker.schemas`) and what it RUNS (`broker.api`), never what DECIDES.**

What this file is demonstrating is not the search — it is the *shape*. An agent
that embeds the broker still cannot reach a connector, cannot reach a credential,
and cannot reach the audit tape's writer. It calls `handle_request` and receives a
`BrokerResponse`, which by construction carries no credential and exposes no path
to the Doer. A fully compromised version of this file can still only ask.

Read README.md beside this file for what that does and does NOT buy you. The
short version: this is an import, not a deployment, and it sits at posture 1 or
below (`docs/posture-ladder.md`).
"""

from __future__ import annotations

from pathlib import Path

from safe_agents.broker.api import AgentRequest, build_runtime, load_agent_manifest

_MANIFEST = Path(__file__).resolve().parent / "manifest.yaml"


def run() -> list[tuple[str, str, str | None]]:
    """Drive one granted call and one ungranted call; return what the broker decided.

    Returns a ``(coordinate, decision_kind, reason)`` triple per call so a test can
    assert on the decisions rather than on printed text.
    """
    # 1. Fill the contract: a manifest this consumer owns.
    manifest = load_agent_manifest(_MANIFEST)

    # 2. Run it: one call composes the whole runtime — stores, audit sink, secrets,
    #    the in-force envelope, the ToolOp table, the connectors. Which BACKENDS it
    #    composes is an environment question, not an import question; with no
    #    BROKER_* variables set this is the fully in-memory arm.
    runtime, sink = build_runtime(manifest)

    outcomes: list[tuple[str, str, str | None]] = []
    try:
        # 3. Ask for something granted. The broker decides, then the Doer executes
        #    under a credential this file never sees.
        granted = runtime.handle_request(
            AgentRequest(tool="search", op="query", args={"query": "broker"})
        )
        outcomes.append(("search.query", granted.decision_kind, granted.reason))
        print(f"search.query  -> {granted.decision_kind}")
        if granted.result is not None:
            for hit in granted.result.get("hits", []):
                print(f"                 {hit['topic']}: {hit['text']}")

        # 4. Ask for something the manifest CLASSIFIES but does not GRANT. This is
        #    the demonstration: the agent is free to ask and the broker refuses.
        #    No connector is called, and the refusal is written to the tape.
        ungranted = runtime.handle_request(
            AgentRequest(tool="notify", op="send", args={"text": "shipping it"})
        )
        outcomes.append(("notify.send", ungranted.decision_kind, ungranted.reason))
        print(f"notify.send   -> {ungranted.decision_kind}: {ungranted.reason}")

        # 5. The tape. The broker wrote this, not the agent — `build_runtime` hands
        #    the sink back to whoever composed the runtime, which in an embedded
        #    deployment is this same process. That co-location is exactly the
        #    property the posture ladder makes you say out loud; see README.md.
        print("\naudit tape:")
        for record in sink.records():
            print(f"  seq={record.seq}  decision={record.decision}  outcome={record.outcome}")
    finally:
        # 6. Release connector-held OS resources (MCP-HOST.md M20). Idempotent.
        runtime.close()

    return outcomes


if __name__ == "__main__":
    run()
