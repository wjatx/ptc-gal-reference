"""LAPSE_TERM_RATIFIED over what the stores really hold (#183; GAL §6.11, GAL-44).

A4 over the real writers on every store backend, read back through that
backend's own loader: seed, a promotion with a term, its lapse, a second
promotion with a new term and its lapse leave no finding. A1 and A6 over the
attack the rule exists for: a lapse record naming a later term, signed under
the evaluator's key (or, on a ledger that has not adopted signing, unsigned),
appended through the record store alone beside a grant still at the original
term. The audit reports it naming the coordinate and both terms, the record's
own signature verifies so no other rule speaks for the term, and the real
`acknowledge` ceremony refuses to waive it. It is still reported once honest
lapses and a renewal have been written after it.

The clause table is in test_grants_lapse_term_audit_rule.py.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_NOT_WAIVABLE,
    GRANT_TERM_RATIFIED,
    LAPSE_TERM_RATIFIED,
    RECORD_SIGNATURE_VERIFIES,
)
from safe_agents.broker.grants.lapse import run_lapse
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.broker.tests import reattestation_scaffold as reattestation
from safe_agents.broker.tests.grant_ts_scaffold import (
    AFTER_FAR_TERM,
    COORDINATE,
    FAR_TERM,
    acknowledge,
    audit,
    ledger,
    load,
    promote,
    stored_grant,
)
from safe_agents.broker.tests.reattestation_scaffold import IN, ON, _seed
from safe_agents.broker.tests.test_grant_store_differential import ACTION_CLASS, PRINCIPAL

# The three-backend harness and the two-key fixture, re-bound so pytest
# resolves each by name here.
backend = reattestation.backend
roles = reattestation.roles

RENEWED_TERM = "2100-01-01T00:00:00+00:00"
AFTER_RENEWED_TERM = datetime.datetime(2100, 1, 2, tzinfo=datetime.UTC)
# The planted record: a term five months past the ratified one, stamped after
# it, so the record does not also name a term later than its own ts.
PLANTED_TERM = "2099-06-01T00:00:00+00:00"
PLANTED_AT = "2099-06-02T00:00:00+00:00"


def _term_findings(report):
    return [v for v in report.violations if v.rule == LAPSE_TERM_RATIFIED]


def _lapse(backend, now):
    outcome = run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=backend.grants, record_store=backend.records, now=now
    )
    assert outcome.status == "lapsed", outcome.reason


def test_every_sanctioned_writer_leaves_lapse_records_the_rule_passes(backend, monkeypatch):
    """A4 on what the stores hold: two terms, two lapses, each lapse record held
    to the promotion before it and not to the one after."""
    steps = [
        ("seed", lambda: _seed(backend, monkeypatch, level=IN)),
        ("promote with a term", lambda: promote(backend, ON, certified_until=FAR_TERM)),
        ("lapse", lambda: _lapse(backend, AFTER_FAR_TERM)),
        ("re-promote with a new term", lambda: promote(backend, ON, certified_until=RENEWED_TERM)),
        ("lapse again", lambda: _lapse(backend, AFTER_RENEWED_TERM)),
    ]
    for name, step in steps:
        step()
        assert _term_findings(audit(backend)) == [], (
            f"A4 AN HONEST LEDGER PASSES: after {name} on {backend.name} the "
            f"ceremony's own ledger reported {LAPSE_TERM_RATIFIED}"
        )
    lapse_terms = [r.certifiedUntil for r in ledger(backend) if r.recordType == "lapse"]
    assert lapse_terms == [FAR_TERM, RENEWED_TERM], (
        "premise: each lapse record must carry the term that expired, or the rule "
        f"had nothing to judge (got {lapse_terms})"
    )


def _plant(backend, monkeypatch, signer):
    """Seed, promote with FAR_TERM, then append a lapse record naming
    PLANTED_TERM through the record store alone. The grant is left as the
    promotion wrote it, at the original term."""
    _seed(backend, monkeypatch, level=IN)
    promote(backend, ON, certified_until=FAR_TERM)
    grant = stored_grant(backend)
    planted = PromotionRecord(
        recordType="lapse",
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=ON,
        toLevel=IN,
        evidence=f"certification term expired: certifiedUntil={PLANTED_TERM}",
        proposedBy=DEMOTION_RATIFIER,
        ratifiedBy=DEMOTION_RATIFIER,
        envelopeHash=grant.envelopeHash,
        demotionReason="pending-evidence",
        ts=PLANTED_AT,
        certifiedUntil=PLANTED_TERM,
    )
    signature = signer.sign_record(planted) if signer is not None else None
    backend.records.put_record(planted, None, signature=signature)
    assert stored_grant(backend).certifiedUntil == FAR_TERM, "premise: the grant was not written"


@pytest.mark.parametrize("signed", [True, False], ids=["evaluator-signed", "unsigned-ledger"])
def test_a_planted_lapse_record_naming_a_later_term_is_reported(
    backend, monkeypatch, roles, signed
):
    _, evaluator_signer, resolvers = roles
    _plant(backend, monkeypatch, evaluator_signer if signed else None)

    report = audit(backend, record_key_resolver=resolvers if signed else None)

    (finding,) = _term_findings(report) or [None]
    assert finding is not None, (
        f"A1: on {backend.name} a lapse record naming {PLANTED_TERM!r}, appended "
        f"beside a grant at the ratified {FAR_TERM!r}, was not reported: {report.violations}"
    )
    assert finding.coordinate == COORDINATE, f"A1: wrong coordinate {finding.coordinate!r}"
    assert repr(PLANTED_TERM) in finding.detail and repr(FAR_TERM) in finding.detail, (
        f"A1: the finding must name both terms: {finding.detail}"
    )
    # The grant is at the ratified term, so the grant's term rule rightly has
    # nothing to say: before this rule, nothing spoke for the record's term.
    assert GRANT_TERM_RATIFIED not in {v.rule for v in report.violations}
    if signed:
        lapse_signature_findings = [
            v
            for v in report.violations
            if v.rule == RECORD_SIGNATURE_VERIFIES and v.detail.startswith("lapse record")
        ]
        assert lapse_signature_findings == [], (
            "premise: the planted record is evaluator-signed and must verify, so the "
            f"signature rule cannot be what reports it: {lapse_signature_findings}"
        )


def test_the_acknowledge_ceremony_refuses_to_waive_it(backend, monkeypatch, roles, capsys):
    issuer_signer, evaluator_signer, resolvers = roles
    _plant(backend, monkeypatch, evaluator_signer)
    (finding,) = _term_findings(audit(backend, record_key_resolver=resolvers))
    capsys.readouterr()

    assert acknowledge(backend, monkeypatch, finding, issuer_signer) != 0, (
        f"A6 UN-WAIVABLE: on {backend.name} the acknowledge ceremony accepted "
        f"{LAPSE_TERM_RATIFIED}"
    )
    said = capsys.readouterr().out
    assert "is not waivable" in said, (
        f"A6: the ceremony must refuse because the rule is not waivable, said: {said}"
    )
    report = audit(backend, record_key_resolver=resolvers)
    assert finding in report.violations and not report.acknowledged, (
        "A6 UN-WAIVABLE: after a refused acknowledgment the finding must stand: "
        f"{report.violations} / {report.acknowledged}"
    )
    assert ACKNOWLEDGMENT_NOT_WAIVABLE not in {v.rule for v in report.violations}, (
        "premise: the ceremony refused, so it stored nothing for the audit to police"
    )
    assert load(backend).acknowledgments == (), (
        f"A6: on {backend.name} the refused ceremony stored an acknowledgment"
    )


def test_a_planted_lapse_record_stays_reported_after_honest_lapses_follow(
    backend, monkeypatch, roles
):
    """A1: every lapse record is judged, not only the coordinate's latest. The
    real writers lapse the grant, renew it and lapse it again after the plant,
    so the planted record is no longer the last lapse at its coordinate."""
    _, evaluator_signer, resolvers = roles
    _plant(backend, monkeypatch, evaluator_signer)
    _lapse(backend, AFTER_FAR_TERM)
    promote(backend, ON, certified_until=RENEWED_TERM)
    _lapse(backend, AFTER_RENEWED_TERM)
    lapse_terms = [r.certifiedUntil for r in ledger(backend) if r.recordType == "lapse"]
    assert lapse_terms[-1] == RENEWED_TERM and PLANTED_TERM in lapse_terms[:-1], (
        f"premise: the planted lapse record must precede an honest one, got {lapse_terms}"
    )

    findings = _term_findings(audit(backend, record_key_resolver=resolvers))

    assert [repr(PLANTED_TERM) in f.detail for f in findings] == [True], (
        f"A1: on {backend.name} the planted lapse record naming {PLANTED_TERM!r} must be "
        f"the one finding once honest lapses follow it, got {[f.detail for f in findings]}"
    )
