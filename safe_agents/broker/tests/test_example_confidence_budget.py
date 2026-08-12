"""Tests for the confidence_budget worked example (#184).

The confidence sibling of `test_iam_scoping.py`'s `TestScopedS3ExampleManifest`:
proves the `examples/confidence_budget/` consumer parses into an `AgentManifest`, its
`Envelope.confidence` knob round-trips, and its consumer-side `reporter_policy`
produces a payload that validates as a `ConfidenceArtifact` AND clears the manifest's
own bar for a 9/10 agreement (via the base `meets_bar` predicate — the same gate the
PDP wiring calls).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from safe_agents.broker.schemas import AgentManifest, ConfidenceArtifact
from safe_agents.broker.schemas.evidence import meets_bar

_EXAMPLES_ROOT = Path(__file__).resolve().parents[3] / "examples"
_MANIFEST_PATH = _EXAMPLES_ROOT / "confidence_budget" / "manifest.yaml"


class TestConfidenceBudgetExampleManifest:
    def test_manifest_parses_and_knob_round_trips(self) -> None:
        data = yaml.safe_load(_MANIFEST_PATH.read_text())
        manifest = AgentManifest.model_validate(data)

        knob = manifest.envelope.confidence
        assert knob is not None
        assert knob.min_confidence == 0.85
        assert knob.methods == ["self-consistency", "conformal"]
        assert knob.error_budget_tolerance == 0.5
        assert knob.blast_weights == {"low": 0.0001, "medium": 0.01, "high": 1.0}
        assert knob.high_blast == ["draft.save"]

        # The whole knob survives a validate(dump()) round-trip unchanged (E1-style).
        reloaded = AgentManifest.model_validate(manifest.model_dump())
        assert reloaded.envelope.confidence == knob

    def test_report_publish_is_high_blast_irreversible(self) -> None:
        # The high-blast weight (1.0) only bites because report.publish is classified
        # external + irreversible — the fact the README's worked draws depend on.
        data = yaml.safe_load(_MANIFEST_PATH.read_text())
        manifest = AgentManifest.model_validate(data)
        op = {f"{o.tool}.{o.op}": o for o in manifest.tool_ops}["report.publish"]
        assert op.external is True
        assert op.reversible is False


class TestReporterPolicyPayload:
    def test_payload_validates_and_meets_the_bar(self) -> None:
        from examples.confidence_budget.reporter_policy import confidence_payload

        data = yaml.safe_load(_MANIFEST_PATH.read_text())
        knob = AgentManifest.model_validate(data).envelope.confidence

        payload = confidence_payload(agreeing=9, total=10, computed_at="2026-07-12T00:00:00Z")

        # The agent-attached payload validates as the contract type the broker gates on.
        artifact = ConfidenceArtifact.model_validate(payload)
        assert artifact.confidence == 0.9

        # 9/10 = 0.9 clears the manifest's own 0.85 bar through the base predicate — the
        # above-bar publish of the README's worked call 1.
        assert meets_bar(artifact, knob) is True

    def test_below_bar_agreement_fails_the_same_bar(self) -> None:
        from examples.confidence_budget.reporter_policy import confidence_payload

        data = yaml.safe_load(_MANIFEST_PATH.read_text())
        knob = AgentManifest.model_validate(data).envelope.confidence

        # 8/10 = 0.8 < 0.85 → below-bar (README worked call 2, the abstain path).
        payload = confidence_payload(agreeing=8, total=10, computed_at="2026-07-12T00:00:00Z")
        assert meets_bar(ConfidenceArtifact.model_validate(payload), knob) is False
