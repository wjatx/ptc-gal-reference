"""broker.pdp — the pure, deterministic Policy Decision Point.

Exports:
    decide  — the single entry point: decide(call, facts) -> Decision
    Facts   — the PIP-supplied pre-fetched facts type (PDP input; not a canonical schema)
    RULES   — the declared, executable rule table (useful for introspection and testing)
"""

from .engine import RULES, decide
from .facts import Facts

__all__ = ["decide", "Facts", "RULES"]
