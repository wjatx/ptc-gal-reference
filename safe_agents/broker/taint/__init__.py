"""broker.taint — source-based taint propagation for the PEP.

The module provides:
  - TurnContext: the per-turn taint accumulator (created by the PEP).
  - InputTrustMap: the type for per-agent injected source-trust config.
  - build_trust_map: convenience factory for tests and minimal examples.

Taint is deterministic and source-based: the model never judges trust.
The per-agent InputTrustMap is injected, never baked into the base.

Typical PEP usage:

    trust_map = build_trust_map(trusted_prefixes=["internal:", "db:"])
    ctx = TurnContext(turn_id=session.turnId)

    # At each ingestion point:
    ctx.ingest_source("email:inbox/42", trust_map)

    # When a memory recall surfaces taint:
    ctx.ingest_memory_taint(taint_flag=recalled_entry.tainted, source="memory:e7f")

    # When constructing a BrokeredCall:
    call = BrokeredCall(
        ...
        taint=ctx.to_taint(),
        ...
    )
"""

from .context import TurnContext
from .propagation import InputTrustMap, build_trust_map

__all__ = ["TurnContext", "InputTrustMap", "build_trust_map"]
