"""Consumer-side confidence-attachment policy for the `confidence-reporter` (#184).

**This is NOT base code.** It lives under `examples/` on purpose. The base ships the
confidence MECHANISM — the `ConfidenceArtifact` contract, the deterministic
`meets_bar` predicate, and the `error_prob × blast_radius` budget draw — plus the
reference constructors under `safe_agents.evidence`. What the base does NOT ship, and
what this module supplies, is the two per-consumer judgements:

  * **HOW this agent obtains its raw observations** — how many independent samples it
    drew and how many agreed. HOW a consumer samples its model is its own business and
    stays outside the base (`safe_agents.evidence` turns already-obtained counts into
    the typed artifact; it never runs the model).
  * **WHAT a below-bar write means here** — under this reporter's abstain-is-safe
    polarity, a write that falls below the bar becomes the broker's `abstain` +
    escalation, and that IS the safe outcome. An act-safe consumer would re-derive its
    own below-bar response instead (silence would be its harm). Baking that polarity
    into the base is the latent safety bug the friction doctrine forbids
    (`docs/friction-doctrine.md` §"the below-bar polarity stays consumer-side"), so it
    is re-derived here, per agent — the same shape as `examples/liveness_policy.py`.
"""
from __future__ import annotations

from typing import Any

from safe_agents.evidence import construct_self_consistency


def confidence_payload(*, agreeing: int, total: int, computed_at: str) -> dict[str, Any]:
    """Build the `"confidence"` key an agent attaches to its `/call` body.

    Takes this agent's raw self-consistency observation (`agreeing` of `total`
    independent samples reached the proposed action) and returns the JSON-ready dict
    the broker validates back into a `ConfidenceArtifact` and gates on. The agent
    attaches this alongside its BrokeredCall; it never computes a bar or a verdict —
    the deterministic gate does, from the manifest's own `confidence` knob.
    """
    artifact = construct_self_consistency(
        agreeing=agreeing, total=total, computed_at=computed_at
    )
    return artifact.model_dump(mode="json")


# The consumer's below-bar response, made explicit (abstain-is-safe polarity).
#
# When `confidence_payload` yields an artifact below this manifest's `min_confidence`
# (0.85), the broker's `meets_bar` returns False and — through the existing polarity
# seam — routes the write to the `abstain` verb plus the approval queue. For THIS
# reporter that is exactly right: not publishing is always safe, so an under-confident
# report simply does not go out and a human is asked. There is deliberately no code
# here that "handles" the below-bar case: the safe outcome is the broker's default
# abstain, and the consumer's only job is to have declared `polarity: abstain`.
#
# An ACT-safe consumer (one whose harm is silence — a monitor that must alert) could
# NOT reuse this. It would re-derive its own below-bar response, because for it an
# abstain is the DoS, not the safe outcome. The base ships neither response; it ships
# the wiring and leaves the polarity to the manifest (`docs/friction-doctrine.md`).
