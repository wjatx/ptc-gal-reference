"""fake_agent.py — exercises the broker tool-call round-trip locally (sa#98 prototype).

Run the server first:   python3 -m safe_agents.broker.prototype.broker_server
Then:                   python3 -m safe_agents.broker.prototype.fake_agent

Stands in for the confined agent: it can ONLY send tool/op/args to the broker and read
back a decision + result. It never sees a credential, a connector, or the audit tape —
that confinement is the whole point. This script walks the round-trip so you can feel the
protocol and marshaling and see what falls out.
"""
from __future__ import annotations

import json
import os
import urllib.request

_BASE = os.environ.get("BROKER_URL", "http://127.0.0.1:8080")


def _get(path: str):
    with urllib.request.urlopen(f"{_BASE}{path}", timeout=10) as r:
        return json.load(r)


def _call(tool: str, op: str, args: dict, idempotency_key: str | None = None):
    body = json.dumps(
        {"tool": tool, "op": op, "args": args, "idempotency_key": idempotency_key}
    ).encode()
    req = urllib.request.Request(
        f"{_BASE}/call", data=body, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def _show(label: str, resp: dict) -> None:
    print(f"\n>>> {label}")
    print(f"    decision={resp.get('decision_kind')!r}  result={resp.get('result')!r}  "
          f"idempotent={resp.get('idempotent')}  intent_id={resp.get('intent_id')!r}  "
          f"reason={resp.get('reason')!r}")


def main() -> None:
    print(f"[agent] broker at {_BASE}")
    registry = _get("/registry")
    print(f"[agent] registry (what I'm allowed to even SEE): "
          f"{[f'{r['tool']}.{r['op']}' for r in registry]}")

    # 1. Allowed, low-risk op -> executes, result returned.
    _show("calendar.create_event (granted, low-risk) -> expect allow + result",
          _call("calendar", "create_event",
                {"title": "Standup", "start": "2026-07-01T09:00:00Z"},
                idempotency_key="turn-1:standup"))

    # 2. Same call, same idempotency key -> replayed, connector NOT re-run.
    _show("calendar.create_event REPLAY (same idempotency_key) -> expect idempotent=True",
          _call("calendar", "create_event",
                {"title": "Standup", "start": "2026-07-01T09:00:00Z"},
                idempotency_key="turn-1:standup"))

    # 3. External + irreversible -> require_approval: Intent frozen, NO execution.
    _show("payments.transfer (external, irreversible) -> expect require_approval + intent_id",
          _call("payments", "transfer", {"to": "acct-9", "amount": 500},
                idempotency_key="turn-2:pay"))

    # 4. An op the agent was NOT granted -> not in the registry; broker refuses.
    _show("crm.delete (NOT granted) -> expect deny/abstain (op removed from registry)",
          _call("crm", "delete", {"id": "lead-1"}, idempotency_key="turn-3:del"))

    # The audit tape the broker wrote (prototype-only debug view; the real agent never sees this).
    audit = _get("/audit")
    print("\n[agent] (debug) broker audit tape — what the broker recorded:")
    for r in audit:
        print(f"    seq={r['seq']}  decision={r['decision']:<16}  outcome={r['outcome']}")
    print("\n[agent] note: every response above carried a decision + result but NEVER a "
          "credential — that is the confinement we are proving.")


if __name__ == "__main__":
    main()
