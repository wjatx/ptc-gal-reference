"""Tests for the reference-tier confidence constructors (#184).

Two things are proven here:

1. **The reference passes the contract.** Each constructor's `ConfidenceArtifact`
   round-trips through `model_validate(model_dump())` (the E1 clause a third-party
   constructor must also pass), its confidence/error math is exact, and its input
   validation is loud (a `ValueError`, never a clamp).
2. **The reference is split-ready.** An AST import guard (mirroring the
   consumer-boundary guard in `broker/tests/test_consumer_boundary.py`) asserts
   `methods.py`'s module-level imports resolve ONLY within
   `safe_agents.broker.schemas` and the stdlib — no reach into broker
   runtime/pdp/enforcement — so the package can be lifted into a separate reference
   distribution (`docs/contract-vs-reference.md` §"Interim discipline").
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from safe_agents.broker.schemas.evidence import ConfidenceArtifact
from safe_agents.evidence import (
    construct_conformal,
    construct_ensemble,
    construct_self_consistency,
)
from safe_agents.evidence import methods as methods_module

_AT = "2026-07-12T00:00:00Z"


# ---------------------------------------------------------------------------
# 1. E1 round-trip — the reference passes the same contract validation a
#    third-party constructor would (reference must clear the contract).
# ---------------------------------------------------------------------------


class TestArtifactsPassContractValidation:
    @pytest.mark.parametrize(
        "artifact",
        [
            construct_self_consistency(agreeing=9, total=10, computed_at=_AT),
            construct_ensemble(votes_for=4, members=5, computed_at=_AT),
            construct_conformal(
                nonconformity=0.2, threshold=0.5, coverage=0.9,
                calibration_size=500, computed_at=_AT,
            ),
        ],
    )
    def test_round_trips_through_model_validate(self, artifact: ConfidenceArtifact) -> None:
        reloaded = ConfidenceArtifact.model_validate(artifact.model_dump())
        assert reloaded == artifact
        # Never stale, no annotations — the constructor claims no drift knowledge.
        assert reloaded.stale is False
        assert reloaded.annotations == []


# ---------------------------------------------------------------------------
# 2. Value math — the constructed numbers are exact.
# ---------------------------------------------------------------------------


class TestValueMath:
    def test_self_consistency_fraction(self) -> None:
        art = construct_self_consistency(agreeing=9, total=10, computed_at=_AT)
        assert art.confidence == pytest.approx(0.9)
        assert art.error_prob == pytest.approx(0.1)
        assert art.evidence.method == "self-consistency"
        assert art.evidence.samples == 10
        assert art.evidence.agreement == pytest.approx(0.9)

    def test_ensemble_fraction(self) -> None:
        art = construct_ensemble(votes_for=3, members=4, computed_at=_AT)
        assert art.confidence == pytest.approx(0.75)
        assert art.error_prob == pytest.approx(0.25)
        assert art.evidence.method == "ensemble"
        assert art.evidence.members == 4

    def test_conformal_inside_the_set(self) -> None:
        # nonconformity <= threshold → inside the calibrated set → (coverage, 1-coverage)
        art = construct_conformal(
            nonconformity=0.2, threshold=0.5, coverage=0.9,
            calibration_size=500, computed_at=_AT,
        )
        assert art.confidence == pytest.approx(0.9)
        assert art.error_prob == pytest.approx(0.1)
        assert art.evidence.method == "conformal"
        assert art.evidence.coverage == pytest.approx(0.9)

    def test_conformal_outside_the_set_is_maximally_pessimistic(self) -> None:
        # nonconformity > threshold → outside the set → the guarantee says nothing → (0, 1)
        art = construct_conformal(
            nonconformity=0.8, threshold=0.5, coverage=0.9,
            calibration_size=500, computed_at=_AT,
        )
        assert art.confidence == 0.0
        assert art.error_prob == 1.0
        # Even outside the set the evidence still records the calibrated threshold.
        assert art.evidence.coverage == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# 3. Loud input validation — a bad observation is a ValueError, never a clamp.
# ---------------------------------------------------------------------------


class TestLoudValidation:
    def test_self_consistency_agreeing_over_total_raises(self) -> None:
        with pytest.raises(ValueError, match="agreeing must be in"):
            construct_self_consistency(agreeing=11, total=10, computed_at=_AT)

    def test_self_consistency_total_one_raises(self) -> None:
        with pytest.raises(ValueError, match="total must be > 1"):
            construct_self_consistency(agreeing=1, total=1, computed_at=_AT)

    def test_ensemble_members_one_raises(self) -> None:
        with pytest.raises(ValueError, match="members must be > 1"):
            construct_ensemble(votes_for=1, members=1, computed_at=_AT)

    def test_ensemble_votes_over_members_raises(self) -> None:
        with pytest.raises(ValueError, match="votes_for must be in"):
            construct_ensemble(votes_for=6, members=5, computed_at=_AT)

    def test_conformal_coverage_one_raises(self) -> None:
        with pytest.raises(ValueError, match="coverage must be strictly inside"):
            construct_conformal(
                nonconformity=0.2, threshold=0.5, coverage=1.0,
                calibration_size=500, computed_at=_AT,
            )

    def test_conformal_zero_calibration_raises(self) -> None:
        with pytest.raises(ValueError, match="calibration_size must be > 0"):
            construct_conformal(
                nonconformity=0.2, threshold=0.5, coverage=0.9,
                calibration_size=0, computed_at=_AT,
            )


# ---------------------------------------------------------------------------
# 4. Split-ready import guard — module-level imports resolve ONLY within
#    safe_agents.broker.schemas and the stdlib (mirrors the AST-walk technique of
#    broker/tests/test_consumer_boundary.py's consumer-boundary guard).
# ---------------------------------------------------------------------------

_ALLOWED_SAFE_AGENTS_PREFIX = "safe_agents.broker.schemas"
_STDLIB = set(sys.stdlib_module_names)


def _offending_imports(source: str) -> list[str]:
    """Return module-level imports that escape (schemas + stdlib) — empty == clean.

    A `safe_agents.*` import is clean iff it is under `safe_agents.broker.schemas`
    (the contract surface); any other module must be stdlib. Comments/prose naming a
    module never parse as an import node, so they cannot trip the guard.
    """
    offenders: list[str] = []

    def _check(module: str, lineno: int) -> None:
        top = module.split(".", 1)[0]
        if top == "safe_agents":
            if not module.startswith(_ALLOWED_SAFE_AGENTS_PREFIX):
                offenders.append(f"  line {lineno}: {module!r} escapes {_ALLOWED_SAFE_AGENTS_PREFIX!r}")
        elif top not in _STDLIB:
            offenders.append(f"  line {lineno}: {module!r} is neither stdlib nor the contract surface")

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check(alias.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            # Absolute imports only — a relative import (node.level > 0) has no
            # module prefix and stays inside this package, which is fine.
            if node.level == 0 and node.module:
                _check(node.module, node.lineno)
    return offenders


class TestSplitReadyImports:
    def test_methods_imports_only_schemas_and_stdlib(self) -> None:
        src = Path(methods_module.__file__).read_text()
        offenders = _offending_imports(src)
        assert not offenders, (
            "methods.py reached beyond the contract surface — a reference constructor "
            "may import only safe_agents.broker.schemas and the stdlib "
            "(docs/contract-vs-reference.md §Interim discipline):\n" + "\n".join(offenders)
        )

    def test_guard_has_teeth(self) -> None:
        # Prove green ≠ empty: a runtime reach and a third-party import are both flagged.
        assert _offending_imports("from safe_agents.broker.runtime.pep import PEP\n")
        assert _offending_imports("import requests\n")
        # The contract surface and stdlib are NOT flagged.
        assert _offending_imports("from safe_agents.broker.schemas.evidence import X\n") == []
        assert _offending_imports("import math\nfrom __future__ import annotations\n") == []
