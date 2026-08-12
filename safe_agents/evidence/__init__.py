"""safe_agents.evidence — reference-tier confidence constructors (#184).

Honest reference implementations behind the closed `ConfidenceMethod` catalog
(`broker/EVIDENCE.md`): one construction each for self-consistency, ensemble, and
conformal. Adoptable as-is, swappable by construction — a third-party constructor
that produces a `ConfidenceArtifact` passing the same E1/E2 conformance validation
is equally valid. This package imports ONLY the contract surface
(`safe_agents.broker.schemas`), so it is split-ready per
`docs/contract-vs-reference.md` §"Interim discipline".
"""
from __future__ import annotations

from .methods import (
    construct_conformal,
    construct_ensemble,
    construct_self_consistency,
)

__all__ = [
    "construct_self_consistency",
    "construct_ensemble",
    "construct_conformal",
]
