"""Reference-tier confidence constructors behind the closed catalog (#184).

One honest instantiation each of the three `ConfidenceMethod` values
(`broker/EVIDENCE.md`): self-consistency, ensemble, conformal. Each is adoptable
as-is and swappable by construction — a third-party constructor is equally valid so
long as its `ConfidenceArtifact` passes the SAME E1/E2 conformance validation these
do (round-trips, discriminates by method, stays in range). Nothing here is
privileged; the catalog is a `Literal`, and a method is *selected*, never *injected*.

These are pure functions that turn ALREADY-OBTAINED raw observations — a sample
agreement count, a vote tally, a nonconformity score against a calibrated threshold —
into the typed artifact the deterministic gate keys on. There is no model call and no
I/O: HOW a consumer samples its model, runs its ensemble, or calibrates its conformal
predictor is the consumer's own business and stays outside the base (the same
discipline as `Liveness.overdue`, sa#160 — observe the fact, never manufacture it).

Split-ready (`docs/contract-vs-reference.md` §"Interim discipline"): the module-level
imports resolve only within `safe_agents.broker.schemas` and the stdlib — no reach
into broker runtime / pdp / enforcement — so this package can be lifted into a
separate reference distribution without dragging the broker with it.
"""
from __future__ import annotations

from safe_agents.broker.schemas.evidence import (
    ConfidenceArtifact,
    ConformalEvidence,
    EnsembleEvidence,
    SelfConsistencyEvidence,
)


def construct_self_consistency(
    *, agreeing: int, total: int, computed_at: str
) -> ConfidenceArtifact:
    """Confidence from agreement across independent samples of one prompt.

    `agreeing` of `total` independent samples reached the proposed action. Requires
    `total > 1` (a single sample cannot agree with itself) and `0 <= agreeing <=
    total` — anything else is a loud `ValueError`, not a clamped guess. Confidence is
    the agreement fraction; `error_prob` is the disagreement rate `1 - confidence`.
    """
    if total <= 1:
        raise ValueError(f"total must be > 1 (one sample cannot agree with itself); got {total}")
    if not 0 <= agreeing <= total:
        raise ValueError(f"agreeing must be in [0, {total}]; got {agreeing}")
    confidence = agreeing / total
    return ConfidenceArtifact(
        confidence=confidence,
        error_prob=1 - confidence,
        evidence=SelfConsistencyEvidence(samples=total, agreement=confidence),
        stale=False,
        computed_at=computed_at,
        annotations=[],
    )


def construct_ensemble(
    *, votes_for: int, members: int, computed_at: str
) -> ConfidenceArtifact:
    """Confidence from agreement across distinct ensemble members.

    `votes_for` of `members` distinct members (different models/prompts) voted for
    the proposed action. Requires `members > 1` and `0 <= votes_for <= members`
    (loud `ValueError` otherwise). Confidence is the vote fraction; `error_prob` is
    `1 - confidence`.
    """
    if members <= 1:
        raise ValueError(f"members must be > 1 (an ensemble of one is not an ensemble); got {members}")
    if not 0 <= votes_for <= members:
        raise ValueError(f"votes_for must be in [0, {members}]; got {votes_for}")
    confidence = votes_for / members
    return ConfidenceArtifact(
        confidence=confidence,
        error_prob=1 - confidence,
        evidence=EnsembleEvidence(members=members, agreement=confidence),
        stale=False,
        computed_at=computed_at,
        annotations=[],
    )


def construct_conformal(
    *,
    nonconformity: float,
    threshold: float,
    coverage: float,
    calibration_size: int,
    computed_at: str,
) -> ConfidenceArtifact:
    """Confidence from a calibrated conformal threshold (reference semantics).

    A conformal predictor calibrated to `coverage` (= 1 - alpha) admits the proposed
    action into its prediction set iff its `nonconformity` score does not exceed the
    calibrated `threshold`. This is ONE sound reading of a conformal score, documented
    as the reference CHOICE, not the only defensible one:

    - **inside the set** (`nonconformity <= threshold`) — the calibrated guarantee
      applies, so confidence is the calibrated `coverage` and `error_prob` is the
      complementary miscoverage `1 - coverage`.
    - **outside the set** (`nonconformity > threshold`) — the calibrated guarantee
      says NOTHING about this action, so the constructor is maximally pessimistic:
      `confidence = 0.0`, `error_prob = 1.0`. It does not extrapolate a guarantee the
      calibration never made.

    Requires `0 < coverage < 1` and `calibration_size > 0` (loud `ValueError`
    otherwise). The `evidence` records the calibrated threshold in force at
    construction; a later drift detector (#65, reference-tier, deferred) is what would
    set `stale` to void it — the constructor never claims staleness knowledge.
    """
    if not 0 < coverage < 1:
        raise ValueError(f"coverage must be strictly inside (0, 1); got {coverage}")
    if calibration_size <= 0:
        raise ValueError(f"calibration_size must be > 0; got {calibration_size}")
    if nonconformity <= threshold:
        confidence, error_prob = coverage, 1 - coverage
    else:
        confidence, error_prob = 0.0, 1.0
    return ConfidenceArtifact(
        confidence=confidence,
        error_prob=error_prob,
        evidence=ConformalEvidence(
            coverage=coverage, threshold=threshold, calibration_size=calibration_size
        ),
        stale=False,
        computed_at=computed_at,
        annotations=[],
    )
