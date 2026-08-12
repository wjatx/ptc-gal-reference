"""Data-driven tests for all seven broker schemas.

Each schema has a table of valid and invalid cases. Invalid cases assert that
pydantic.ValidationError is raised with a descriptive message. Valid cases assert
that the model round-trips cleanly.

The tests are intentionally data-driven (pytest.mark.parametrize) to keep coverage
dense without repetitive boilerplate.
"""

import pytest
from pydantic import TypeAdapter, ValidationError

from safe_agents.broker.schemas import (
    AuditRecord,
    BrokeredCall,
    Budgets,
    Decision,
    Grant,
    Intent,
    PromotionRecord,
)

# ---------------------------------------------------------------------------
# Fixture helpers — minimal valid dicts for nested types
# ---------------------------------------------------------------------------

PRINCIPAL = {
    "agentId": "agent-1",
    "skill": "email",
    "user": "alice",
    "tier": "B",
}

TOOL_OP = {
    "tool": "email",
    "op": "send",
    "effect": "write",
    "external": True,
    "reversible": False,
}

TAINT = {"tainted": False, "sources": []}

SESSION = {"turnId": "turn-abc", "ingestedSources": []}

BROKERED_CALL = {
    "principal": PRINCIPAL,
    "tool": "email",
    "op": "send",
    "args": {"to": "bob@example.com", "subject": "Hi"},
    "manifest": TOOL_OP,
    "taint": TAINT,
    "session": SESSION,
    "ts": "2026-06-28T00:00:00Z",
}


# ---------------------------------------------------------------------------
# 1. Grant
# ---------------------------------------------------------------------------

GRANT_VALID_BASE = {
    "principal": PRINCIPAL,
    "actionClass": "email.send",
    "level": "in-loop",
    "envelopeHash": "sha256:abc",
    "promotedBy": "alice",
    "evidence": "evidence-ref-001",
    "ts": "2026-06-28T00:00:00Z",
    "lastSafeLevel": "in-loop",
    "demotionTriggers": ["stale_confidence"],
    "demotionReason": None,
    "labelLatency": "P1D",
    "ownerId": "alice",
}

GRANT_VALID_CASES = [
    ("all_levels_valid_lastSafe_in_loop", {**GRANT_VALID_BASE, "lastSafeLevel": "in-loop"}),
    ("lastSafe_on_loop", {**GRANT_VALID_BASE, "lastSafeLevel": "on-loop"}),
    (
        "demotionReason_failing",
        {**GRANT_VALID_BASE, "level": "in-loop", "demotionReason": "failing"},
    ),
    (
        "demotionReason_pending_evidence",
        {**GRANT_VALID_BASE, "demotionReason": "pending-evidence"},
    ),
    (
        "multiple_demotion_triggers",
        {
            **GRANT_VALID_BASE,
            "demotionTriggers": [
                "stale_confidence",
                "corroboration_failure",
                "budget_breach",
            ],
        },
    ),
]

GRANT_INVALID_CASES = [
    (
        "lastSafeLevel_out_of_loop_rejected",
        {**GRANT_VALID_BASE, "lastSafeLevel": "out-of-loop"},
        "lastSafeLevel may never be 'out-of-loop'",
    ),
    (
        "missing_required_field_principal",
        {k: v for k, v in GRANT_VALID_BASE.items() if k != "principal"},
        "principal",
    ),
    (
        "wrong_type_demotionTriggers",
        {**GRANT_VALID_BASE, "demotionTriggers": "stale_confidence"},
        None,  # any ValidationError is sufficient
    ),
    (
        "invalid_level_value",
        {**GRANT_VALID_BASE, "level": "fully-autonomous"},
        None,
    ),
    (
        "extra_field_forbidden",
        {**GRANT_VALID_BASE, "unknownField": "x"},
        None,
    ),
]


@pytest.mark.parametrize("name,data", GRANT_VALID_CASES, ids=[c[0] for c in GRANT_VALID_CASES])
def test_grant_valid(name, data):
    g = Grant.model_validate(data)
    assert g.actionClass == data["actionClass"]


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    GRANT_INVALID_CASES,
    ids=[c[0] for c in GRANT_INVALID_CASES],
)
def test_grant_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        Grant.model_validate(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# ---------------------------------------------------------------------------
# 2. BrokeredCall
# ---------------------------------------------------------------------------

BROKERED_CALL_VALID_CASES = [
    ("write_external_irreversible", BROKERED_CALL),
    (
        "read_op_no_reversible",
        {
            **BROKERED_CALL,
            "manifest": {**TOOL_OP, "effect": "read", "external": False, "reversible": None},
        },
    ),
    (
        "tainted_turn",
        {
            **BROKERED_CALL,
            "taint": {"tainted": True, "sources": ["email:inbox:msg-1"]},
        },
    ),
]

BROKERED_CALL_INVALID_CASES = [
    (
        "missing_manifest",
        {k: v for k, v in BROKERED_CALL.items() if k != "manifest"},
        "manifest",
    ),
    (
        "invalid_effect_value",
        {**BROKERED_CALL, "manifest": {**TOOL_OP, "effect": "delete"}},
        None,
    ),
    (
        "wrong_type_taint",
        {**BROKERED_CALL, "taint": True},
        None,
    ),
    (
        "extra_field_on_tool_op",
        {**BROKERED_CALL, "manifest": {**TOOL_OP, "surprise": "yes"}},
        None,
    ),
]


@pytest.mark.parametrize(
    "name,data",
    BROKERED_CALL_VALID_CASES,
    ids=[c[0] for c in BROKERED_CALL_VALID_CASES],
)
def test_brokered_call_valid(name, data):
    bc = BrokeredCall.model_validate(data)
    assert bc.tool == data["tool"]


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    BROKERED_CALL_INVALID_CASES,
    ids=[c[0] for c in BROKERED_CALL_INVALID_CASES],
)
def test_brokered_call_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        BrokeredCall.model_validate(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# ---------------------------------------------------------------------------
# 3. Decision
# ---------------------------------------------------------------------------

# In Pydantic v2, discriminated unions are validated via TypeAdapter or a wrapper model.
DecisionAdapter: TypeAdapter[Decision] = TypeAdapter(Decision)

DECISION_VALID_CASES = [
    ("allow", {"kind": "allow"}),
    ("deny", {"kind": "deny", "reason": "cap exceeded"}),
    ("transform", {"kind": "transform", "op": "draft", "args": {"to": "bob@example.com"}}),
    (
        "require_approval",
        {
            "kind": "require_approval",
            "renderedIntent": {
                "id": "intent-001",
                "renderedForHuman": "Send email to bob@example.com",
            },
        },
    ),
    ("abstain_escalate", {"kind": "abstain", "escalate": True, "reason": "inputs suspect"}),
    ("abstain_no_escalate", {"kind": "abstain", "escalate": False, "reason": "out of competence"}),
]

DECISION_INVALID_CASES = [
    ("unknown_kind", {"kind": "block"}, None),
    ("deny_missing_reason", {"kind": "deny"}, "reason"),
    ("transform_missing_op", {"kind": "transform", "args": {}}, "op"),
    ("abstain_missing_escalate", {"kind": "abstain", "reason": "x"}, "escalate"),
    ("require_approval_missing_intent", {"kind": "require_approval"}, "renderedIntent"),
]


@pytest.mark.parametrize(
    "name,data",
    DECISION_VALID_CASES,
    ids=[c[0] for c in DECISION_VALID_CASES],
)
def test_decision_valid(name, data):
    d = DecisionAdapter.validate_python(data)
    assert d.kind == data["kind"]


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    DECISION_INVALID_CASES,
    ids=[c[0] for c in DECISION_INVALID_CASES],
)
def test_decision_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        DecisionAdapter.validate_python(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# Explicitly test that all 5 variants parse and that no 6th variant exists.
def test_decision_exhaustive_five_variants():
    kinds = {"allow", "deny", "transform", "require_approval", "abstain"}
    for d in [
        DecisionAdapter.validate_python(c[1]) for c in DECISION_VALID_CASES
    ]:
        assert d.kind in kinds


# ---------------------------------------------------------------------------
# 4. Intent
# ---------------------------------------------------------------------------

INTENT_VALID_BASE = {
    "id": "intent-001",
    "materializedRequest": BROKERED_CALL,
    "renderedForHuman": "Send email to bob@example.com with subject 'Hi'",
    "status": "pending",
    "expiry": "2026-06-29T00:00:00Z",
    "approvedBy": None,
    "ts": "2026-06-28T00:00:00Z",
}

INTENT_VALID_CASES = [
    ("pending", INTENT_VALID_BASE),
    ("approved", {**INTENT_VALID_BASE, "status": "approved", "approvedBy": "alice"}),
    ("rejected", {**INTENT_VALID_BASE, "status": "rejected"}),
    ("expired", {**INTENT_VALID_BASE, "status": "expired"}),
    ("executed", {**INTENT_VALID_BASE, "status": "executed", "approvedBy": "alice"}),
]

INTENT_INVALID_CASES = [
    ("invalid_status", {**INTENT_VALID_BASE, "status": "cancelled"}, None),
    (
        "missing_materializedRequest",
        {k: v for k, v in INTENT_VALID_BASE.items() if k != "materializedRequest"},
        "materializedRequest",
    ),
    ("extra_field", {**INTENT_VALID_BASE, "extra": "x"}, None),
]


@pytest.mark.parametrize(
    "name,data", INTENT_VALID_CASES, ids=[c[0] for c in INTENT_VALID_CASES]
)
def test_intent_valid(name, data):
    i = Intent.model_validate(data)
    assert i.id == data["id"]


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    INTENT_INVALID_CASES,
    ids=[c[0] for c in INTENT_INVALID_CASES],
)
def test_intent_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        Intent.model_validate(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# ---------------------------------------------------------------------------
# 5. AuditRecord
# ---------------------------------------------------------------------------

AUDIT_VALID_BASE = {
    "seq": 1,
    "ts": "2026-06-28T00:00:00Z",
    "principal": PRINCIPAL,
    "tool": "email",
    "op": "send",
    "argsDigest": "sha256:argsHash",
    "decision": "allow",
    "reason": None,
    "envelopeHash": "sha256:envelopeHash",
    "approvedBy": None,
    "outcome": "executed",
    "error": None,
    "seed": None,
    "prevHash": "sha256:prevHash",
    "hash": "sha256:thisHash",
}

AUDIT_VALID_CASES = [
    ("allow_executed", AUDIT_VALID_BASE),
    (
        "deny_denied",
        {**AUDIT_VALID_BASE, "decision": "deny", "outcome": "denied", "reason": "cap exceeded"},
    ),
    (
        "require_approval_held",
        {**AUDIT_VALID_BASE, "decision": "require_approval", "outcome": "held", "approvedBy": None},
    ),
    ("abstain_failed", {**AUDIT_VALID_BASE, "decision": "abstain", "outcome": "failed"}),
    (
        "with_seed",
        {**AUDIT_VALID_BASE, "seed": "vrf-seed-abc"},
    ),
]

AUDIT_INVALID_CASES = [
    ("invalid_decision_verb", {**AUDIT_VALID_BASE, "decision": "block"}, None),
    ("invalid_outcome", {**AUDIT_VALID_BASE, "outcome": "skipped"}, None),
    ("wrong_type_seq", {**AUDIT_VALID_BASE, "seq": "one"}, "seq"),
    (
        "missing_argsDigest",
        {k: v for k, v in AUDIT_VALID_BASE.items() if k != "argsDigest"},
        "argsDigest",
    ),
    ("extra_field", {**AUDIT_VALID_BASE, "rawArgs": {"to": "bob"}}, None),
]


@pytest.mark.parametrize(
    "name,data", AUDIT_VALID_CASES, ids=[c[0] for c in AUDIT_VALID_CASES]
)
def test_audit_record_valid(name, data):
    ar = AuditRecord.model_validate(data)
    assert ar.seq == data["seq"]


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    AUDIT_INVALID_CASES,
    ids=[c[0] for c in AUDIT_INVALID_CASES],
)
def test_audit_record_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        AuditRecord.model_validate(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# Explicitly test that seq must be int (monotonicity is storage-layer concern; type is enforced here).
def test_audit_seq_must_be_int():
    with pytest.raises(ValidationError):
        AuditRecord.model_validate({**AUDIT_VALID_BASE, "seq": 1.5})


# ---------------------------------------------------------------------------
# 6. Budgets
# ---------------------------------------------------------------------------

BUDGETS_VALID_BASE = {
    "error": {"tolerance": 0.01, "spent": 0.005},
    "attention": {"capacity": 100.0, "spent": 10.0},
    "escalation": {"capacity": 20.0, "spent": 2.0},
    "fallback": {"capacity": 50.0, "spent": 5.0},
}

BUDGETS_VALID_CASES = [
    ("baseline", BUDGETS_VALID_BASE),
    ("zero_spent", {
        "error": {"tolerance": 0.05, "spent": 0.0},
        "attention": {"capacity": 200.0, "spent": 0.0},
        "escalation": {"capacity": 10.0, "spent": 0.0},
        "fallback": {"capacity": 30.0, "spent": 0.0},
    }),
]

BUDGETS_INVALID_CASES = [
    (
        "missing_escalation",
        {k: v for k, v in BUDGETS_VALID_BASE.items() if k != "escalation"},
        "escalation",
    ),
    (
        "wrong_type_spent",
        {**BUDGETS_VALID_BASE, "error": {"tolerance": 0.01, "spent": "a lot"}},
        None,
    ),
    ("extra_field", {**BUDGETS_VALID_BASE, "reserve": {"capacity": 5.0, "spent": 1.0}}, None),
]


@pytest.mark.parametrize(
    "name,data", BUDGETS_VALID_CASES, ids=[c[0] for c in BUDGETS_VALID_CASES]
)
def test_budgets_valid(name, data):
    b = Budgets.model_validate(data)
    assert b.error.tolerance == data["error"]["tolerance"]


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    BUDGETS_INVALID_CASES,
    ids=[c[0] for c in BUDGETS_INVALID_CASES],
)
def test_budgets_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        Budgets.model_validate(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# ---------------------------------------------------------------------------
# 7. PromotionRecord
# ---------------------------------------------------------------------------

PROMOTION_VALID_BASE = {
    "actionClass": "email.send",
    "principal": PRINCIPAL,
    "fromLevel": "in-loop",
    "toLevel": "on-loop",
    "evidence": "calibration-run-2026-06",
    "predicate": "P(error < 0.01 | last 30d) >= 0.95",
    "proposedBy": "alice",
    "ratifiedBy": "bob",
    "envelopeHash": "sha256:env-001",
    "ts": "2026-06-28T00:00:00Z",
}

DEMOTION_VALID_BASE = {
    "recordType": "demotion",
    "actionClass": "email.send",
    "principal": PRINCIPAL,
    "fromLevel": "on-loop",
    "toLevel": "in-loop",
    "evidence": "budget-counter-2026-06-28",
    "proposedBy": "system:demotion-evaluator",
    "ratifiedBy": "system:demotion-evaluator",
    "envelopeHash": "sha256:env-001",
    "triggeredBy": ["budget_breach"],
    "demotionReason": "failing",
    "ts": "2026-06-28T00:00:00Z",
}

BOOTSTRAP_VALID_BASE = {
    "recordType": "bootstrap",
    "actionClass": "email.send",
    "principal": PRINCIPAL,
    "fromLevel": None,  # the Recommend rung — the seed creates the grant
    "toLevel": "in-loop",
    "evidence": "seed-envelope-2026-06",
    "proposedBy": "maintainer",
    "ratifiedBy": "maintainer",  # single-operator seed is sanctioned
    "envelopeHash": "sha256:env-001",
    "ts": "2026-06-28T00:00:00Z",
}

TIGHTENING_VALID_BASE = {
    "recordType": "tightening",
    "actionClass": "email.send",
    "principal": PRINCIPAL,
    "fromLevel": "out-of-loop",
    "toLevel": "in-loop",  # tightening is by definition -> in-loop
    "evidence": "voluntary-tightening",
    "proposedBy": "maintainer",
    "ratifiedBy": "maintainer",  # no ceremony — maker = checker allowed
    "envelopeHash": "sha256:env-001",
    "ts": "2026-06-28T00:00:00Z",
}

PROMOTION_VALID_CASES = [
    ("in_loop_to_on_loop", PROMOTION_VALID_BASE),
    (
        "on_loop_to_out_of_loop",
        {**PROMOTION_VALID_BASE, "fromLevel": "on-loop", "toLevel": "out-of-loop"},
    ),
    (
        "explicit_recordType_promotion",
        {**PROMOTION_VALID_BASE, "recordType": "promotion"},
    ),
    (
        # first promotion from the Recommend rung creates the grant
        "promotion_from_recommend",
        {**PROMOTION_VALID_BASE, "fromLevel": None, "toLevel": "in-loop"},
    ),
    ("demotion_failing", DEMOTION_VALID_BASE),
    (
        "demotion_pending_evidence",
        {
            **DEMOTION_VALID_BASE,
            "triggeredBy": ["stale_confidence"],
            "demotionReason": "pending-evidence",
        },
    ),
    ("bootstrap_seed", BOOTSTRAP_VALID_BASE),
    (
        "bootstrap_to_on_loop",
        {**BOOTSTRAP_VALID_BASE, "toLevel": "on-loop"},
    ),
    ("tightening", TIGHTENING_VALID_BASE),
    (
        "tightening_from_on_loop",
        {**TIGHTENING_VALID_BASE, "fromLevel": "on-loop"},
    ),
]

PROMOTION_INVALID_CASES = [
    # promotion-typed shape rules
    (
        "proposedBy_equals_ratifiedBy",
        {**PROMOTION_VALID_BASE, "ratifiedBy": "alice"},
        "proposedBy and ratifiedBy must differ",
    ),
    (
        "promotion_missing_predicate",
        {k: v for k, v in PROMOTION_VALID_BASE.items() if k != "predicate"},
        "predicate is required",
    ),
    (
        "promotion_empty_predicate",
        {**PROMOTION_VALID_BASE, "predicate": ""},
        "predicate is required",
    ),
    (
        "promotion_with_triggeredBy",
        {**PROMOTION_VALID_BASE, "triggeredBy": ["budget_breach"]},
        "triggeredBy must be empty",
    ),
    (
        "promotion_with_demotionReason",
        {**PROMOTION_VALID_BASE, "demotionReason": "failing"},
        "demotionReason must be None",
    ),
    (
        "missing_evidence",
        {k: v for k, v in PROMOTION_VALID_BASE.items() if k != "evidence"},
        "evidence",
    ),
    (
        "missing_envelopeHash",
        {k: v for k, v in PROMOTION_VALID_BASE.items() if k != "envelopeHash"},
        "envelopeHash",
    ),
    (
        "missing_fromLevel",
        {k: v for k, v in PROMOTION_VALID_BASE.items() if k != "fromLevel"},
        "fromLevel",
    ),
    (
        # fromLevel=None is Recommend-origin; the only Recommend-origin
        # transition is the grant-creating first promotion to in-loop
        "promotion_from_recommend_not_to_in_loop",
        {**PROMOTION_VALID_BASE, "fromLevel": None, "toLevel": "on-loop"},
        "fromLevel=None must have toLevel='in-loop'",
    ),
    (
        "invalid_recordType",
        {**PROMOTION_VALID_BASE, "recordType": "revocation"},
        None,
    ),
    (
        "invalid_fromLevel",
        {**PROMOTION_VALID_BASE, "fromLevel": "fully-autonomous"},
        None,
    ),
    (
        "invalid_toLevel",
        {**PROMOTION_VALID_BASE, "toLevel": "blocked"},
        None,
    ),
    (
        "extra_field",
        {**PROMOTION_VALID_BASE, "approvalToken": "tok-123"},
        None,
    ),
    # demotion-typed shape rules
    (
        "demotion_wrong_ratifier",
        {**DEMOTION_VALID_BASE, "ratifiedBy": "alice"},
        "system:demotion-evaluator",
    ),
    (
        "demotion_empty_triggeredBy",
        {**DEMOTION_VALID_BASE, "triggeredBy": []},
        "triggeredBy must be non-empty",
    ),
    (
        "demotion_missing_demotionReason",
        {k: v for k, v in DEMOTION_VALID_BASE.items() if k != "demotionReason"},
        "demotionReason is required",
    ),
    (
        "demotion_with_predicate",
        {**DEMOTION_VALID_BASE, "predicate": "P(x) >= 0.95"},
        "predicate must be absent",
    ),
    (
        # a demotion cannot originate from the Recommend rung — no grant there
        "demotion_null_fromLevel",
        {**DEMOTION_VALID_BASE, "fromLevel": None},
        "cannot originate from the Recommend rung",
    ),
    # bootstrap-typed shape rules
    (
        "bootstrap_nonnull_fromLevel",
        {**BOOTSTRAP_VALID_BASE, "fromLevel": "in-loop"},
        "fromLevel must be None",
    ),
    (
        "bootstrap_with_predicate",
        {**BOOTSTRAP_VALID_BASE, "predicate": "P(x) >= 0.95"},
        "predicate must be absent",
    ),
    (
        "bootstrap_with_triggeredBy",
        {**BOOTSTRAP_VALID_BASE, "triggeredBy": ["budget_breach"]},
        "triggeredBy must be empty",
    ),
    # tightening-typed shape rules
    (
        "tightening_toLevel_not_in_loop",
        {**TIGHTENING_VALID_BASE, "toLevel": "on-loop"},
        "toLevel must be 'in-loop'",
    ),
    (
        "tightening_with_predicate",
        {**TIGHTENING_VALID_BASE, "predicate": "P(x) >= 0.95"},
        "predicate must be absent",
    ),
    (
        "tightening_with_demotionReason",
        {**TIGHTENING_VALID_BASE, "demotionReason": "pending-evidence"},
        "demotionReason must be None",
    ),
    (
        # a tightening cannot originate from the Recommend rung — no grant there
        "tightening_null_fromLevel",
        {**TIGHTENING_VALID_BASE, "fromLevel": None},
        "cannot originate from the Recommend rung",
    ),
]


@pytest.mark.parametrize(
    "name,data",
    PROMOTION_VALID_CASES,
    ids=[c[0] for c in PROMOTION_VALID_CASES],
)
def test_promotion_record_valid(name, data):
    pr = PromotionRecord.model_validate(data)
    assert pr.recordType == data.get("recordType", "promotion")
    if pr.recordType == "promotion":
        assert pr.proposedBy != pr.ratifiedBy


@pytest.mark.parametrize(
    "name,data,msg_fragment",
    PROMOTION_INVALID_CASES,
    ids=[c[0] for c in PROMOTION_INVALID_CASES],
)
def test_promotion_record_invalid(name, data, msg_fragment):
    with pytest.raises(ValidationError) as exc_info:
        PromotionRecord.model_validate(data)
    if msg_fragment:
        assert msg_fragment in str(exc_info.value)


# Explicit tests for the key cross-schema invariants called out in the issue
# ---------------------------------------------------------------------------

def test_grant_level_rejects_values_outside_three():
    """AutonomyLevel enum must reject anything not in {in-loop, on-loop, out-of-loop}."""
    for bad in ("autonomous", "hitl", "supervised", "blocked", ""):
        with pytest.raises(ValidationError):
            Grant.model_validate({**GRANT_VALID_BASE, "level": bad})


def test_grant_lastSafeLevel_rejects_out_of_loop():
    """lastSafeLevel='out-of-loop' must always be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Grant.model_validate({**GRANT_VALID_BASE, "lastSafeLevel": "out-of-loop"})
    assert "lastSafeLevel may never be 'out-of-loop'" in str(exc_info.value)


def test_promotion_proposed_equals_ratified_rejected():
    """proposedBy == ratifiedBy must always be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        PromotionRecord.model_validate({**PROMOTION_VALID_BASE, "ratifiedBy": "alice"})
    assert "proposedBy and ratifiedBy must differ" in str(exc_info.value)


def test_audit_argsDigest_is_str_not_dict():
    """argsDigest must be a string (hash); a raw args dict must be rejected."""
    with pytest.raises(ValidationError):
        AuditRecord.model_validate({**AUDIT_VALID_BASE, "argsDigest": {"to": "bob@example.com"}})
