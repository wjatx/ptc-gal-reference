"""broker.manifest — the ToolOp table primitive + a copyable catalog of generic ops.

A ToolOp classifies each tool operation once, as code/manifest-resident fact, never
from model input: the model cannot assert its 'send' is really a 'draft'. Since #171
the classifications themselves are CONSUMER-OWNED — they travel in the agent's
``AgentManifest.tool_ops`` and ``build_runtime`` compiles them into a per-runtime
``ToolOpTable`` the broker resolves every call against. The base owns the ToolOp
*schema* (broker/schemas) + the PDP rules that key on it, never the op *names*: a
consumer-defined op gates identically to any other op with the same classification,
regardless of what it is called.

``ToolOpTable`` is the primitive:
  - ``entry(tool, op)`` — the classification for (tool, op), or None. The PEP rejects
    any call for which this returns None (no entry ⇒ no connectable op).
  - ``served(principal, grants)`` — the capability-scoped view: ONLY the ops a
    principal may see given their active grants. An ungranted op is ABSENT (removal,
    not refusal) — no see-but-can't-use surface.

``CATALOG`` is an OPTIONAL, copy-only reference table of domain-neutral ops a manifest
author may copy into ``tool_ops``. It is deliberately NOT consulted at request time —
the runtime resolves only against the manifest-built table (the debaking invariant:
the base composition path names no op). It holds no domain-specific op; a trading
``alpaca.read`` or an ``email.send`` lives in the consumer's own manifest.

See broker/README.md §"Capability-scoped registry — removal over request" and
broker/SCHEMAS.md §2 (BrokeredCall / ToolOp).
"""

from __future__ import annotations

from safe_agents.broker.schemas import Grant, Principal, ToolOp


class ToolOpTable:
    """A per-agent tool-operation table: (tool, op) → ToolOp classification.

    Built from an ``AgentManifest.tool_ops`` list (``from_manifest``) or any explicit
    ``list[ToolOp]``. Insertion order is preserved for a deterministic served view.
    Duplicate (tool, op) keys are rejected at construction — one op, one verdict.
    """

    def __init__(self, entries: list[ToolOp]) -> None:
        index: dict[str, ToolOp] = {}
        for entry in entries:
            key = f"{entry.tool}.{entry.op}"
            if key in index:
                raise ValueError(
                    f"ToolOpTable declares {key!r} more than once; each (tool, op) must "
                    "have exactly one classification"
                )
            index[key] = entry
        self._entries = list(entries)
        self._index = index

    @classmethod
    def from_manifest(cls, manifest: "AgentManifest") -> "ToolOpTable":  # noqa: F821
        """Build the runtime table from a consumer manifest's ``tool_ops`` (#171)."""
        return cls(list(manifest.tool_ops))

    def entry(self, tool: str, op: str) -> ToolOp | None:
        """Return the classification for (tool, op), or None if absent.

        The PEP must reject any call for which this returns None — no table entry
        means no connectable op, regardless of what grants exist.
        """
        return self._index.get(f"{tool}.{op}")

    def served(self, principal: Principal, grants: list[Grant]) -> list[ToolOp]:
        """Return the ops this principal may SEE, scoped to active grants.

        An op not covered by any grant in *grants* is absent from the result —
        removal, not refusal. There is no see-but-can't-use surface. Order follows
        table insertion order within the granted set (deterministic).

        The principal argument is accepted for symmetry with the PEP call site and
        future tier-/skill-based scoping; filtering is currently keyed on
        Grant.actionClass alone. Grants naming an op absent from the table contribute
        nothing (no entry = no op), which is correct.
        """
        granted_classes = {g.actionClass for g in grants}
        return [
            entry
            for entry in self._entries
            if f"{entry.tool}.{entry.op}" in granted_classes
        ]

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# CATALOG — an OPTIONAL, copy-only reference of domain-neutral ops. NOT consulted
# at request time (the runtime resolves only against the manifest-built table). A
# manifest author may copy any of these into ``tool_ops``; the base holds no
# domain-specific op (email/calendar/crm/payments/alpaca live in consumer manifests).
#
# Field semantics (full contract on ToolOp in broker/schemas/brokered_call.py):
#   effect:     "read"  — allow-by-scope; "write" — default-deny
#   external:   True if the op crosses a trust boundary to an external party
#   reversible: shorthand for RECOVERABLE. True if a wrong execution is undoable OR
#               structurally bounded-blast (a fixed, broker-held destination the model
#               can't widen). False ONLY when a mistake is both irreversible AND
#               unbounded — rule 8 then requires approval every call. Omit for reads.
#   egress_arg: name of the arg whose value egresses to the provider (sa#137).
# ---------------------------------------------------------------------------

CATALOG: list[ToolOp] = [
    # --- GitHub ---
    # whoami: read (GET /user), crosses a trust boundary to GitHub. reversible unset —
    # not applicable to reads.
    ToolOp(tool="github", op="whoami", effect="read", external=True),

    # --- Search (sa#133) ---
    # query: read, crosses a trust boundary to the search provider. The RESPONSE is
    # untrusted free-text web content; the broker self-ingests every successful external
    # read into the TurnContext (sa#134), so the turn is tainted and a subsequent
    # external write escalates to require_approval. egress_arg="query" (sa#137): the
    # agent-composed query string egresses, so the broker bounds its size and meters
    # cumulative egress bytes — closing the query-as-exfil-channel gap.
    ToolOp(tool="search", op="query", effect="read", external=True, egress_arg="query"),

    # --- Ledger (sa#131) ---
    # append: write to the platform's OWN durable brief/ledger sink — no trust boundary
    # is crossed (external=False), and the sink is append-only so a wrong append is
    # recoverable (reversible=True). The destination bucket/prefix are broker-held
    # credential facts the model can never supply.
    ToolOp(tool="ledger", op="append", effect="write", external=False, reversible=True),

    # --- Notify ---
    # send: write, crosses a trust boundary. reversible=True reflects blast radius, not
    # undoability: the destination is a fixed, broker-held owner chat id (never a
    # model-suppliable arg), so an untainted send is low-blast and safe to allow
    # autonomously (rule 10); a tainted turn still hits rule 7 and requires approval.
    ToolOp(tool="notify", op="send", effect="write", external=True, reversible=True),

    # --- Peer / A2A publish (sa#156) ---
    # publish: emit an EventTrigger to a PEER agent's airlock. external=True,
    # effect="write" is the ENTIRE taint trigger — a tainted turn's publish hits the
    # standing tainted_external_write cut (rule 9), no publish-specific rule.
    # reversible=True (same shape as notify.send): the receiver re-gates everything it
    # carries at its own airlock, so a single publish cannot itself effect an
    # irreversible action; an UNTAINTED publish is allowed autonomously. The peer
    # endpoint/secret are broker-held connector facts the model cannot supply.
    ToolOp(tool="peer", op="publish", effect="write", external=True, reversible=True),
]

# A ToolOpTable over the CATALOG — a convenience for base tests/reference that want a
# known generic op WITHOUT authoring a manifest. NOT the runtime table (build_runtime
# builds that from the consumer manifest).
CATALOG_TABLE = ToolOpTable(CATALOG)


__all__ = [
    "ToolOpTable",
    "CATALOG",
    "CATALOG_TABLE",
]
