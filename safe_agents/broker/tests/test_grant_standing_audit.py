"""The audit's half of signing-key standing (GAL §6.10, GAL-41, #179).

Each rule is pinned with one ledger that breaks it and one that does not, and
each is pinned un-waivable: an acknowledgment that verifies does not move it.
"""

from __future__ import annotations

import datetime
import json

import pytest

from safe_agents.broker.grants.acknowledgments import (
    WAIVABLE_RULES,
    AcknowledgmentRecord,
    canonical_ack_payload,
    sign_acknowledgment,
    violation_detail_digest,
)
from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    RECORD_SIGNATURE_VERIFIES,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.grants.audit_key_standing import (
    ANNOTATION_ISSUER_STANDING_UNCONFIGURED,
    GRANT_STANDING_WITHDRAWN,
    KEY_SIGNED_AFTER_RETIREMENT,
    KEY_STANDING_RULES,
    RECORD_SIGNER_IN_STANDING,
    WITHDRAWAL_RECORD_MATCHES_LEDGER,
)
from safe_agents.broker.grants.record_signing import RoleKeyResolvers
from safe_agents.broker.grants.withdrawal import run_withdrawal
from safe_agents.broker.schemas.clock_skew import skew_bound
from safe_agents.broker.tests.grant_standing_scaffold import (
    BOOTSTRAP_TS,
    IN,
    ON,
    World,
    grant,
    record,
)
from safe_agents.broker.tests.test_grant_term_lapse import ACTION_CLASS, PRINCIPAL
from safe_agents.channels.keys import key_resolver_from_map

MINUTE = datetime.timedelta(minutes=1)


@pytest.fixture
def world():
    return World()


def _audit(world, *, extra=(), evaluator_withdrawn=None, skew=None):
    kwargs = {"clock_skew": skew} if skew is not None else {}
    return run_audit(
        dataset_from_items(world.items() + list(extra)),
        record_key_resolver=world.resolvers(evaluator_withdrawn=evaluator_withdrawn),
        **kwargs,
    )


def _rules(report):
    return sorted(v.rule for v in report.violations)


def _ack_item(world, violation, *, signer="issuer-b"):
    ack = AcknowledgmentRecord(
        rule=violation.rule,
        coordinate=violation.coordinate,
        detailDigest=violation_detail_digest(violation.detail),
        rationale="honest history",
        acknowledgedBy="arn:aws:sts::123:assumed-role/PromotionRole/maintainer",
        ts="2026-10-02T00:00:00+00:00",
    )
    envelope = sign_acknowledgment(ack, world.keys[signer][0])
    return {
        "pk": f"ACK#{ack.coordinate}",
        "sk": f"{ack.ts}#{ack.rule}",
        "data": canonical_ack_payload(ack),
        "signature": json.dumps(envelope, sort_keys=True),
    }


def test_the_standing_rules_are_never_waivable():
    assert not set(KEY_STANDING_RULES) & WAIVABLE_RULES


def test_a_clean_ledger_with_standing_configured_is_clean(world):
    world.promoted()
    report = _audit(world, evaluator_withdrawn=False)
    assert report.violations == ()
    assert not any(a.startswith(ANNOTATION_ISSUER_STANDING_UNCONFIGURED) for a in report.annotations)


def test_a_withdrawn_signer_and_the_grant_resting_on_it_are_reported(world):
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw()
    report = _audit(world)
    assert _rules(report) == [
        GRANT_STANDING_WITHDRAWN, RECORD_SIGNER_IN_STANDING, RECORD_SIGNER_IN_STANDING,
    ], "the bootstrap and the promotion it signed, and the grant still above lastSafeLevel"
    assert RECORD_SIGNATURE_VERIFIES not in _rules(report)


def test_an_acknowledgment_waives_no_standing_finding(world):
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw()
    first = _audit(world)
    acks = [_ack_item(world, v) for v in first.violations]
    # Filed under the waivable signature rule instead, it matches nothing either.
    acks += [
        _ack_item(world, type(v)(RECORD_SIGNATURE_VERIFIES, v.coordinate, v.detail))
        for v in first.violations
    ]
    report = _audit(world, extra=acks)
    assert sorted(v.rule for v in report.violations if v.rule in KEY_STANDING_RULES) == _rules(first)
    assert report.acknowledged == ()


def test_once_the_runner_lowers_the_grant_only_the_record_findings_remain(world):
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw()
    world.source.refresh()
    outcome = run_withdrawal(
        PRINCIPAL, ACTION_CLASS, grant_store=world.grants, record_store=world.records,
        standing=world.source, now=world.clock.now, record_signer=world.evaluator,
    )
    assert outcome.status == "lowered"
    report = _audit(world, evaluator_withdrawn=False)
    assert _rules(report) == [RECORD_SIGNER_IN_STANDING, RECORD_SIGNER_IN_STANDING]


def test_an_evaluator_withdrawal_is_a_finding_on_its_records(world):
    world.promoted()
    world.write(record("demotion", "2026-09-03T00:00:00+00:00", fromLevel=ON, toLevel=ON),
                grant(ts="2026-09-03T00:00:00+00:00"), signer="evaluator")
    report = _audit(world, evaluator_withdrawn=True)
    assert _rules(report) == [RECORD_SIGNER_IN_STANDING]
    assert "evaluator key 'evaluator-e'" in report.violations[0].detail


@pytest.mark.parametrize(
    ("retired_at", "skew", "reported"),
    [
        ("2026-09-01T12:00:00+00:00", None, True),   # after the bootstrap, before the promotion
        ("2026-09-03T00:00:00+00:00", None, False),  # after both
        ("2026-09-02T00:01:00+00:00", 120, True),    # within the skew bound of the promotion
        ("2026-09-02T00:01:00+00:00", None, False),
    ],
)
def test_a_record_signed_after_its_keys_retirement_is_reported(world, retired_at, skew, reported):
    world.promoted()
    world.clock.now += MINUTE
    world.retire(at=datetime.datetime.fromisoformat(retired_at))
    report = _audit(world, skew=skew_bound(skew) if skew else None)
    rules = _rules(report)
    assert (KEY_SIGNED_AFTER_RETIREMENT in rules) is reported
    assert GRANT_STANDING_WITHDRAWN not in rules and RECORD_SIGNER_IN_STANDING not in rules


def test_a_withdrawal_record_the_ledger_supports_is_clean(world):
    world.promoted()
    world.clock.now += MINUTE
    world.withdraw()
    world.source.refresh()
    run_withdrawal(PRINCIPAL, ACTION_CLASS, grant_store=world.grants, record_store=world.records,
                   standing=world.source, now=world.clock.now, record_signer=world.evaluator)
    assert WITHDRAWAL_RECORD_MATCHES_LEDGER not in _rules(_audit(world))


@pytest.mark.parametrize("ledger", ["key-in-standing", "no-licensing-record", "unsigned-licensing"])
def test_a_withdrawal_record_the_ledger_does_not_support_is_reported(world, ledger):
    if ledger == "no-licensing-record":
        world.write(record("demotion", BOOTSTRAP_TS, fromLevel=ON, toLevel=ON),
                    grant(ts=BOOTSTRAP_TS), signer="evaluator")
    else:
        world.promoted(signer=None if ledger == "unsigned-licensing" else "issuer-a")
    planted = record("withdrawal", "2026-09-05T00:00:00+00:00")
    world.write(planted, grant(level=IN, ts="2026-09-05T00:00:00+00:00",
                               demotionReason="pending-evidence"), signer="evaluator")
    report = _audit(world)
    assert WITHDRAWAL_RECORD_MATCHES_LEDGER in _rules(report)


def test_no_issuer_standing_document_is_annotated_as_not_conforming(world):
    world.promoted()
    resolvers = RoleKeyResolvers(
        issuer=key_resolver_from_map({"issuer-a": world.keys["issuer-a"][1]}),
        evaluator=key_resolver_from_map({"evaluator-e": world.evaluator_pem}),
    )
    report = run_audit(dataset_from_items(world.items()), record_key_resolver=resolvers)
    notes = [a for a in report.annotations if a.startswith(ANNOTATION_ISSUER_STANDING_UNCONFIGURED)]
    assert len(notes) == 1 and "does not conform to GAL-41" in notes[0]
    assert report.violations == ()


def test_unsigned_history_is_not_a_standing_finding(world):
    world.promoted(signer=None, bootstrap_signer=None)
    world.clock.now += MINUTE
    world.withdraw()
    rules = _rules(_audit(world))
    assert GRANT_STANDING_WITHDRAWN not in rules and RECORD_SIGNER_IN_STANDING not in rules


def test_an_acknowledgment_signed_by_a_withdrawn_key_waives_nothing(world):
    world.promoted()
    # A waivable finding to acknowledge: the grant's ts is later than its ledger's.
    world.grants._store.clear()
    world.grants.put_grant(grant(ts="2026-09-09T00:00:00+00:00"))
    first = _audit(world)
    (finding,) = [v for v in first.violations if v.rule in WAIVABLE_RULES]
    ack = _ack_item(world, finding, signer="issuer-b")
    assert _audit(world, extra=[ack]).acknowledged != ()
    world.clock.now += MINUTE
    world.withdraw("issuer-b")
    report = _audit(world, extra=[ack])
    assert report.acknowledged == ()
    assert ACKNOWLEDGMENT_SIGNATURE_VERIFIES in _rules(report)
