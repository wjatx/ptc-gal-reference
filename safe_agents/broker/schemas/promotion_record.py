"""PromotionRecord schema — the append-only ceremony-ledger record for grant level changes.

Four record types share one ledger (see SCHEMAS.md §7):

- ``promotion``  — the maker-checker ceremony that raises a Grant's level.
- ``demotion``   — automatic deterministic demotion, ratified by the system
                   demotion evaluator (no human, no model). Supersedes the old
                   "demotion needs no record" exemption (broker/grant-lifecycle.md).
- ``bootstrap``  — the sanctioned seed record: first creation of a grant outside
                   the ceremony (seed_grants retires to bootstrap-only).
- ``tightening`` — voluntary any-level → in-loop move; always permitted, no
                   ceremony, no trigger.

This schema enforces field-SHAPE rules per record type only. Transition
validity (one-rung-up, level ordering) is the state machine's job
(broker/grant-lifecycle.md), never duplicated here.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import AutonomyLevel, Principal

# System identity that ratifies all automatic demotions (no human, no model).
DEMOTION_RATIFIER = "system:demotion-evaluator"


class PromotionRecord(BaseModel):
    """One append-only ledger record of a grant level change.

    Invariants enforced here (field shape only, per recordType):
    - promotion:  proposedBy must differ from ratifiedBy (maker ≠ checker);
                  predicate required non-empty; no demotion fields;
                  fromLevel=None only with toLevel=in-loop (the grant-creating
                  first promotion from the Recommend rung).
    - demotion:   ratifiedBy is the system demotion evaluator; triggeredBy
                  non-empty; demotionReason set; predicate absent; fromLevel
                  non-None (no grant exists at Recommend to demote).
    - bootstrap:  fromLevel is None (the Recommend rung — the seed creates the
                  grant); maker ≠ checker NOT enforced (single-operator seed is
                  sanctioned); predicate absent; no demotion fields.
    - tightening: toLevel is in-loop (tightening is by definition → in-loop);
                  fromLevel non-None (no grant exists at Recommend to tighten);
                  maker ≠ checker NOT enforced; predicate absent; no demotion
                  fields.
    """

    model_config = ConfigDict(extra="forbid")

    # which lifecycle act this record captures
    recordType: Literal["promotion", "demotion", "bootstrap", "tightening"] = "promotion"
    # the action class whose level changed
    actionClass: str
    # for whom
    principal: Principal
    # None = the Recommend rung (no-grant baseline; the record creates the grant).
    # Recommend is a rung but NOT a level — it can never be an enum value.
    fromLevel: AutonomyLevel | None
    toLevel: AutonomyLevel
    # ref to covered-distribution evidence (delayed-label recalibration result)
    evidence: str
    # signed promotion predicate authored in advance; stringency scales to blast
    # radius. Required non-empty for promotion; must be absent for other types.
    predicate: str | None = None
    # maker
    proposedBy: str
    # checker — must differ from maker on the promotion path
    ratifiedBy: str
    # How the two ceremony identities were established (#226). None — the
    # field's absence from every record written before #226, and its shape on
    # the cloud floor — means two IAM-backed STS credential ARNs: the maker's
    # credentials cannot mint the checker's. "solo-local" means ONE operator
    # held both, as two local roles with no IAM between them. The record must
    # never imply a review that did not happen (GAL §8), so the weaker
    # guarantee is stated rather than left to be assumed. DERIVED from the
    # identity strings by ceremony_identity.attestation_for — never asserted
    # independently, so marker and identity cannot disagree.
    attestation: Literal["solo-local"] | None = None
    # the envelope hash in force when the record was written
    envelopeHash: str
    # demotion-typed only: the DemotionTrigger values that fired
    triggeredBy: list[str] = Field(default_factory=list)
    # demotion-typed only
    demotionReason: Literal["failing", "pending-evidence"] | None = None
    ts: str

    @model_validator(mode="after")
    def shape_rules_per_record_type(self) -> "PromotionRecord":
        """Enforce the per-recordType field-shape rules (see class docstring)."""
        if self.recordType == "promotion":
            if self.proposedBy == self.ratifiedBy:
                raise ValueError(
                    f"proposedBy and ratifiedBy must differ: got '{self.proposedBy}' for both. "
                    "Widening autonomy requires maker ≠ checker."
                )
            if not self.predicate:
                raise ValueError(
                    "predicate is required (non-empty) for a promotion record: "
                    "the ceremony is licensed by a signed predicate authored in advance."
                )
            if self.fromLevel is None and self.toLevel is not AutonomyLevel.in_loop:
                raise ValueError(
                    f"a promotion record with fromLevel=None must have toLevel='in-loop': "
                    f"the only Recommend-origin transition is the grant-creating first "
                    f"promotion (Recommend → in-loop, broker/grant-lifecycle.md), got "
                    f"toLevel='{self.toLevel.value}'."
                )
            self._forbid_demotion_fields()

        elif self.recordType == "demotion":
            if self.ratifiedBy != DEMOTION_RATIFIER:
                raise ValueError(
                    f"a demotion record must be ratified by '{DEMOTION_RATIFIER}': "
                    f"got '{self.ratifiedBy}'. Demotion is automatic — no human, no model."
                )
            if not self.triggeredBy:
                raise ValueError(
                    "triggeredBy must be non-empty for a demotion record: "
                    "a demotion is always tripped by at least one deterministic trigger."
                )
            if self.demotionReason is None:
                raise ValueError(
                    "demotionReason is required for a demotion record "
                    "('failing' or 'pending-evidence' — never collapse the two)."
                )
            if self.fromLevel is None:
                raise ValueError(
                    "fromLevel is required (non-None) for a demotion record: a demotion "
                    "cannot originate from the Recommend rung — no grant exists there."
                )
            self._forbid_predicate()

        elif self.recordType == "bootstrap":
            if self.fromLevel is not None:
                raise ValueError(
                    f"fromLevel must be None for a bootstrap record: the seed creates the "
                    f"grant from the Recommend rung (no-grant baseline), got "
                    f"'{self.fromLevel.value}'."
                )
            self._forbid_predicate()
            self._forbid_demotion_fields()

        else:  # tightening
            if self.toLevel is not AutonomyLevel.in_loop:
                raise ValueError(
                    f"toLevel must be 'in-loop' for a tightening record — tightening is by "
                    f"definition a voluntary move to in-loop, got '{self.toLevel.value}'."
                )
            if self.fromLevel is None:
                raise ValueError(
                    "fromLevel is required (non-None) for a tightening record: a tightening "
                    "cannot originate from the Recommend rung — no grant exists there."
                )
            self._forbid_predicate()
            self._forbid_demotion_fields()

        return self

    def _forbid_predicate(self) -> None:
        if self.predicate is not None:
            raise ValueError(
                f"predicate must be absent for a {self.recordType!r} record: "
                "only the promotion ceremony is predicate-licensed."
            )

    def _forbid_demotion_fields(self) -> None:
        if self.triggeredBy:
            raise ValueError(
                f"triggeredBy must be empty for a {self.recordType!r} record: "
                "triggers belong to demotion records only."
            )
        if self.demotionReason is not None:
            raise ValueError(
                f"demotionReason must be None for a {self.recordType!r} record: "
                "it belongs to demotion records only."
            )
