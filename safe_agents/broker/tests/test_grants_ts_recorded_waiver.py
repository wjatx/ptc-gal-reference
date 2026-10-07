"""A GRANT_TS_RECORDED finding is excused by a signed acknowledgment and by
nothing else (#166; GAL §6.11, GAL-32).

T4 (waivable, and only by acknowledgment), T5 (the acknowledgment binds the
grant's stored bytes) and T6 (reported as green with an annotation; an
acknowledgment that does not verify is not applied). The ledger under test is
the one the rule was made waivable for: a grant re-attested before
re-attestation appended a record, on every store backend, dispositioned by the
real `acknowledge` ceremony.

The clause table and the shared harness are in grant_ts_scaffold.py.
"""

from __future__ import annotations

import datetime

import pytest

from safe_agents.broker.grants.acknowledgments import WAIVABLE_RULES
from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    ANNOTATION_SIGNING_EPOCH_UNSET,
    GRANT_TS_RECORDED,
    RECORD_SIGNATURE_VERIFIES,
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    run_audit,
)
from safe_agents.broker.grants.audit_command import AuditTarget, render_text, report_to_dict
from safe_agents.broker.tests import reattestation_scaffold as reattestation
from safe_agents.broker.tests import test_record_signing_roles as signing_roles
from safe_agents.broker.tests.grant_ts_scaffold import (
    CHECKER,
    acknowledge,
    audit,
    dataset,
    ledger,
    load,
    rewrite_grant,
    stored_grant,
    tighten,
    ts_findings,
)
from safe_agents.broker.tests.reattestation_scaffold import (
    IN,
    NEW_HASH,
    ON,
    OPERATOR,
    _bootstrap,
    _demotion,
    _planted,
    _seed,
)
from safe_agents.broker.tests.test_grant_store_differential import make_grant
from safe_agents.broker.tests.test_record_signing_roles import _acknowledgment, _keypair

# The three-backend harness and the two-key fixture, re-bound so pytest
# resolves each by name here.
backend = reattestation.backend
roles = signing_roles.roles


EPOCH = "2026-01-01T00:00:00+00:00"
NOW = datetime.datetime(2026, 9, 1, tzinfo=datetime.UTC)


def _later(ts: str, days: int = 1) -> str:
    return (datetime.datetime.fromisoformat(ts) + datetime.timedelta(days=days)).isoformat()


def _reattested_before_the_record_existed(backend, monkeypatch, **seeded):
    """A seeded grant, then the write `re-seed` used to make: envelopeHash,
    promotedBy and ts rewritten, HMAC-clean, with nothing appended. Returns
    the one finding a keyed audit makes of it."""
    _seed(backend, monkeypatch, level=ON, **seeded)
    rewrite_grant(
        backend,
        envelopeHash=NEW_HASH,
        promotedBy=OPERATOR,
        ts=_later(ledger(backend)[-1].ts),
    )
    (finding,) = ts_findings(audit(backend))
    return finding


# ---------------------------------------------------------------------------
# T4: waivable, and only by a signed acknowledgment
# ---------------------------------------------------------------------------


def test_the_rule_is_in_the_closed_waivable_set():
    assert GRANT_TS_RECORDED in WAIVABLE_RULES, (
        f"T4: {GRANT_TS_RECORDED} must be acknowledgeable, or a ledger "
        "re-attested before re-attestation wrote a record can never be brought "
        "into line"
    )
    # The whole set, so that adding to it is a change this suite sees.
    assert WAIVABLE_RULES == frozenset(
        {
            "LEDGER_COUNTERPART",
            "RECORD_SIGNATURE_VERIFIES",
            "GRANT_ENVELOPE_IN_FORCE",
            "LEVEL_DROP_RECORDED",
            GRANT_TS_RECORDED,
        }
    )


def test_an_old_reattestation_is_brought_into_line_by_one_acknowledgment(
    backend, monkeypatch, roles
):
    """T4 and T6 end to end: the finding, the ceremony, and a report that is
    green and says why."""
    issuer_signer, _evaluator, resolvers = roles
    finding = _reattested_before_the_record_existed(backend, monkeypatch)

    assert acknowledge(backend, monkeypatch, finding, issuer_signer) == 0, (
        f"T4: the acknowledge ceremony refused a {GRANT_TS_RECORDED} finding"
    )

    report = audit(backend, record_key_resolver=resolvers)
    assert report.violations == (), (
        f"T4: on {backend.name} a verified acknowledgment of the exact finding "
        f"must disposition it: {report.violations}"
    )
    assert [a.violation for a in report.acknowledged] == [finding], (
        "T6: an acknowledged finding is reported under `acknowledged`, never "
        f"dropped: {report.acknowledged}"
    )
    (annotated,) = report.acknowledged
    assert CHECKER in annotated.waiver_ref, "T6: the annotation names who acknowledged it"

    payload = report_to_dict(report, AuditTarget("sqlite", "unused"))
    assert payload["clean"] and [a["rule"] for a in payload["acknowledged"]] == [
        GRANT_TS_RECORDED
    ], f"T6: the machine-readable report must carry the acknowledged finding: {payload}"
    assert f"acknowledged [{GRANT_TS_RECORDED}]" in render_text(payload), (
        "T6: the operator rendering must print the acknowledged finding"
    )


@pytest.mark.parametrize(
    "epoch",
    [None, "2020-01-01T00:00:00+00:00", "2026-08-15T00:00:00+00:00"],
    ids=["no-epoch", "epoch-before-the-grant", "epoch-after-the-grant"],
)
def test_no_date_or_epoch_takes_a_grant_out_of_scope(backend, monkeypatch, roles, epoch):
    _issuer, _evaluator, resolvers = roles
    finding = _reattested_before_the_record_existed(backend, monkeypatch)

    report = audit(
        backend,
        record_key_resolver=resolvers,
        signing_epoch=epoch,
        now=NOW if epoch else None,
    )

    assert ts_findings(report) == [finding], (
        f"T4: with the record-signing epoch at {epoch} the finding must stand "
        "unchanged; this rule has no adoption date"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"evidence": "re-attested-before-the-record-existed"},
        {"promotedBy": "arn:aws:sts::111111111111:assumed-role/PromotionRole/legacy"},
        {"demotionReason": "pending-evidence"},
        {"certifiedUntil": "2020-01-01T00:00:00+00:00"},
        {"ownerId": "exempt"},
    ],
    ids=lambda changes: next(iter(changes)),
)
def test_no_field_the_grant_carries_excuses_it(changes):
    """T4: whatever else the unexplained write put on the grant, a ts that is
    not the ledger's is reported."""
    grant = make_grant(ts="2026-07-09T00:00:00+00:00", **changes)
    assert ts_findings(run_audit(dataset(grant, [_bootstrap()]))), (
        f"T4: a grant carrying {changes} was passed with a ts no record carries"
    )


PLANTS = [
    # A reattestation must be signed with or without an epoch.
    pytest.param(lambda ts: _planted(ts, ON), None, id="reattestation-no-epoch"),
    # A demotion that fired on a grant at its floor moves no level, so no
    # level rule sees it. Unsigned, it is in scope once an epoch is declared.
    pytest.param(lambda ts: _demotion(ts, ON, ON), EPOCH, id="floor-demotion-epoch-set"),
]


@pytest.mark.parametrize(("plant", "epoch"), PLANTS)
def test_a_planted_record_at_the_grant_s_ts_does_not_make_it_green(
    backend, monkeypatch, roles, plant, epoch
):
    """The one thing besides an acknowledgment that silences the finding is a
    record at the grant's ts, and that is what a sanctioned write leaves. A
    writer with no signing key can plant one. The finding then moves to the
    signature rule, and the report stays red."""
    _issuer, _evaluator, resolvers = roles
    _reattested_before_the_record_existed(backend, monkeypatch, lastSafeLevel=ON)
    planted = plant(stored_grant(backend).ts)
    backend.records.put_record(planted, None)

    report = audit(
        backend, record_key_resolver=resolvers, signing_epoch=epoch, now=NOW if epoch else None
    )

    assert ts_findings(report) == []
    # The plant's own finding, not the unsigned bootstrap's beside it.
    assert any(
        v.rule == RECORD_SIGNATURE_VERIFIES
        and f"{planted.recordType} record ts={planted.ts}" in v.detail
        for v in report.violations
    ), (
        "T4: an unsigned record planted at the grant's ts must leave the audit "
        f"red under {RECORD_SIGNATURE_VERIFIES}: {report.violations}"
    )


def test_with_no_epoch_a_planted_unsigned_record_is_annotated_not_caught(
    backend, monkeypatch, roles
):
    """The limit, stated. With RECORD_SIGNING_EPOCH unset the signature rule
    asks nothing of an unsigned demotion, so one planted at the grant's ts
    silences this rule and no other rule reports it. The report is not
    silently green: it carries the annotation that says the all-types signing
    requirement was not enforced."""
    _issuer, _evaluator, resolvers = roles
    _reattested_before_the_record_existed(backend, monkeypatch, lastSafeLevel=ON)
    backend.records.put_record(_demotion(stored_grant(backend).ts, ON, ON), None)

    report = audit(backend, record_key_resolver=resolvers)

    assert ts_findings(report) == []
    assert any(a.startswith(ANNOTATION_SIGNING_EPOCH_UNSET) for a in report.annotations), (
        "T6: a report that could not vouch for the planted record's writer "
        f"must say the signing requirement was narrowed: {report.annotations}"
    )


# ---------------------------------------------------------------------------
# T5: the acknowledgment binds the grant's stored bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rewrite",
    [
        pytest.param(lambda g: {"ts": _later(g.ts)}, id="ts-moved-again"),
        # The same ts on other bytes: a detail naming only the two timestamps
        # would read the same, and the old acknowledgment would cover it.
        pytest.param(lambda g: {"evidence": "rewritten-after-acknowledgment"}, id="same-ts"),
        pytest.param(lambda g: {"lastSafeLevel": ON}, id="same-ts-other-floor"),
    ],
)
def test_a_grant_rewritten_after_it_was_acknowledged_is_a_new_finding(
    backend, monkeypatch, roles, rewrite
):
    issuer_signer, _evaluator, resolvers = roles
    acknowledged = _reattested_before_the_record_existed(backend, monkeypatch)
    assert acknowledge(backend, monkeypatch, acknowledged, issuer_signer) == 0
    assert audit(backend, record_key_resolver=resolvers).violations == ()

    rewrite_grant(backend, **rewrite(stored_grant(backend)))

    report = audit(backend, record_key_resolver=resolvers)
    (finding,) = ts_findings(report) or [None]
    assert finding is not None, (
        f"T5: on {backend.name} the grant was rewritten after its finding was "
        "acknowledged and the audit reported nothing. The acknowledgment "
        f"covered bytes it was not signed over: {report.acknowledged}"
    )
    assert finding.detail != acknowledged.detail
    assert report.acknowledged == (), (
        "T5: the old acknowledgment must cover nothing once the grant's stored "
        f"bytes have changed: {report.acknowledged}"
    )


def test_a_sanctioned_write_after_the_acknowledgment_clears_the_finding(
    backend, monkeypatch, roles
):
    """The acknowledgment defers the remediation, and the next ceremony write
    is the remediation: grant and record carry one ts again."""
    issuer_signer, _evaluator, resolvers = roles
    finding = _reattested_before_the_record_existed(backend, monkeypatch)
    assert acknowledge(backend, monkeypatch, finding, issuer_signer) == 0

    tighten(backend)

    report = audit(backend, record_key_resolver=resolvers)
    assert ts_findings(report) == [] and report.acknowledged == (), (
        f"T2/T5: after a sanctioned write on {backend.name} there is no finding "
        f"left to report or to annotate: {report.violations} {report.acknowledged}"
    )


def test_a_finding_with_no_stored_bytes_to_bind_is_never_waived(roles):
    """GAL-32: a finding that cannot be bound to stored bytes is un-waivable.
    An acknowledgment over its exact detail, correctly signed, applies to
    nothing."""
    issuer_signer, _evaluator, resolvers = roles
    unbound = AuditDataset(
        grants=(AuditedGrant(grant=make_grant(level=IN, ts="2026-07-09T00:00:00+00:00")),),
        records=(AuditedRecord(record=_bootstrap()),),
    )
    (finding,) = ts_findings(run_audit(unbound))

    report = run_audit(
        AuditDataset(
            grants=unbound.grants,
            records=unbound.records,
            acknowledgments=(_acknowledgment(finding, issuer_signer),),
        ),
        record_key_resolver=resolvers,
    )

    assert ts_findings(report) == [finding] and report.acknowledged == (), (
        "T5: a finding over a grant entry with no stored bytes was waived; "
        "there was nothing for the acknowledgment to bind"
    )


# ---------------------------------------------------------------------------
# T6: an acknowledgment that does not verify is not applied
# ---------------------------------------------------------------------------


def test_an_acknowledgment_signed_by_an_unknown_key_is_not_applied(
    backend, monkeypatch, roles
):
    _issuer, _evaluator, resolvers = roles
    stranger, _pem = _keypair("issuer:not-in-the-verify-map")
    finding = _reattested_before_the_record_existed(backend, monkeypatch)
    assert acknowledge(backend, monkeypatch, finding, stranger) == 0

    report = audit(backend, record_key_resolver=resolvers)

    assert ts_findings(report) == [finding] and report.acknowledged == (), (
        "T6: an acknowledgment whose signature does not verify must leave the "
        f"finding standing: {report.acknowledged}"
    )
    assert ACKNOWLEDGMENT_SIGNATURE_VERIFIES in {v.rule for v in report.violations}


def test_an_acknowledgment_signed_by_the_evaluator_is_not_applied(
    backend, monkeypatch, roles
):
    """A waiver mints green, so it is the issuer's to sign. The evaluator's
    key is a known key and still the wrong one."""
    _issuer, evaluator_signer, resolvers = roles
    finding = _reattested_before_the_record_existed(backend, monkeypatch)
    assert acknowledge(backend, monkeypatch, finding, evaluator_signer) == 0

    report = audit(backend, record_key_resolver=resolvers)

    assert ts_findings(report) == [finding] and report.acknowledged == (), (
        f"T6: an evaluator-signed acknowledgment was applied: {report.acknowledged}"
    )


def test_with_no_verify_keys_no_acknowledgment_is_applied(backend, monkeypatch, roles):
    issuer_signer, _evaluator, _resolvers = roles
    finding = _reattested_before_the_record_existed(backend, monkeypatch)
    assert acknowledge(backend, monkeypatch, finding, issuer_signer) == 0

    report = audit(backend)

    assert ts_findings(report) == [finding] and report.acknowledged == (), (
        "T6: with no verify keys an acknowledgment cannot be checked and must "
        "not be applied"
    )
    assert ACKNOWLEDGMENT_SIGNATURE_VERIFIES in report.skipped_rules, (
        "T6: skipping acknowledgment verification must be reported, not silent"
    )


def test_the_ceremony_refuses_to_acknowledge_unsigned(backend, monkeypatch):
    finding = _reattested_before_the_record_existed(backend, monkeypatch)

    try:
        status = acknowledge(backend, monkeypatch, finding, None)
    except Exception as exc:  # any exception is the defect under test
        pytest.fail(
            "T4: with no signer the acknowledge ceremony must refuse before it "
            f"builds anything; it went on and raised {exc!r}"
        )
    assert status == 1, (
        "T4: the only thing that excuses a finding is a SIGNED acknowledgment"
    )
    assert load(backend).acknowledgments == (), "a refused ceremony writes nothing"
