"""broker.taint.context — TurnContext: the per-turn taint accumulator.

A TurnContext is created by the PEP at the start of each turn. As the turn
ingests content from external sources, the context marks itself tainted when
any source fails the injected InputTrustMap check. The taint flag is
non-strippable: once set within a turn it cannot be cleared by the agent or
harness. The PEP materializes a Taint schema object from the context before
constructing each BrokeredCall — the model never supplies taint directly.

See broker/SCHEMAS.md §2 (BrokeredCall) and ARCHITECTURE.md §"Taint tracking".
"""

from __future__ import annotations

from safe_agents.broker.schemas import Taint

from .propagation import InputTrustMap


class TurnContext:
    """Accumulates source-based taint for one agent turn.

    The PEP creates one TurnContext per turn, passes it through all ingestion
    steps, then calls to_taint() when materializing each BrokeredCall. The
    context is the authoritative taint source; the model is never consulted.

    Non-strippable invariant: once _tainted is True it cannot become False
    within the same TurnContext instance. Agents or harnesses that construct
    a BrokeredCall with tainted=False while the context is tainted are ignored
    — the PEP always derives taint from context.to_taint(), not from the model.
    """

    def __init__(self, turn_id: str) -> None:
        self._turn_id = turn_id
        self._tainted = False
        self._sources: list[str] = []

    # ------------------------------------------------------------------
    # Ingestion hooks (called by the PEP / harness, never by the model)
    # ------------------------------------------------------------------

    def ingest_source(self, source: str, trust_map: InputTrustMap) -> None:
        """Ingest content from a source and taint the turn if untrusted.

        trust_map(source) is a deterministic config lookup — never an LLM call.
        If the source is untrusted, the turn is permanently marked tainted for
        this instance.
        """
        if not trust_map(source):
            self._mark_tainted(source)

    def ingest_memory_taint(self, taint_flag: bool, source: str) -> None:
        """Propagate a taint flag surfaced by the memory layer.

        When the memory/ layer recalls an entry that was originally tainted, it
        surfaces a boolean flag. This hook propagates that flag into the current
        turn without implementing the memory taint store — that belongs in
        memory/. Taint is not strippable by passing through memory: if the
        recalled entry was tainted, the calling turn is tainted.
        """
        if taint_flag:
            self._mark_tainted(source)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def to_taint(self) -> Taint:
        """Materialize the Taint schema object for embedding in a BrokeredCall.

        The PEP calls this when constructing each BrokeredCall. The returned
        object reflects the authoritative state of this context — not any value
        the model may have supplied.
        """
        return Taint(tainted=self._tainted, sources=list(self._sources))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _mark_tainted(self, source: str) -> None:
        """Set the non-strippable taint flag and record the source."""
        self._tainted = True
        if source not in self._sources:
            self._sources.append(source)

    # ------------------------------------------------------------------
    # Read-only properties (informational; do not expose a setter)
    # ------------------------------------------------------------------

    @property
    def tainted(self) -> bool:
        return self._tainted

    @property
    def turn_id(self) -> str:
        return self._turn_id
