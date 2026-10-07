"""A ledger written by the ceremony carries no GRANT_TS_RECORDED finding (#166).

T2, over the real writers on every store backend, read back through that
backend's own loader. Also the two bypass writes of T1 made through the real
stores, so the rule is seen to fire through each loader and not only over a
hand-built dataset.

The clause table and the shared harness are in grant_ts_scaffold.py.
"""

from __future__ import annotations

import datetime

from safe_agents.broker.grants.audit import GRANT_TAMPER, GRANT_TS_RECORDED
from safe_agents.broker.schemas.common import DemotionTrigger
from safe_agents.broker.tests import reattestation_scaffold as reattestation
from safe_agents.broker.tests.grant_ts_scaffold import (
    COORDINATE,
    FAR_TERM,
    audit,
    demote,
    lapse,
    ledger,
    load,
    promote,
    rewrite_grant,
    stored_digest,
    stored_grant,
    tighten,
    ts_findings,
)
from safe_agents.broker.tests.reattestation_scaffold import (
    IN,
    NEW_HASH,
    ON,
    OUT,
    _reattest,
    _seed,
)
from safe_agents.broker.tests.test_grant_store_differential import make_record

# The three-backend harness, re-bound so pytest resolves it by name here.
backend = reattestation.backend

TRIGGERS = [DemotionTrigger.budget_breach]


def _assert_clean(backend, after: str) -> None:
    report = audit(backend)
    assert stored_grant(backend).ts == ledger(backend)[-1].ts, (
        f"T2 premise: after {after} on {backend.name} the grant and the record "
        "beside it must carry one ts, or the writer is at fault and not the rule"
    )
    assert ts_findings(report) == [], (
        f"T2: after {after} on {backend.name} a ledger written only by the "
        f"ceremony reported {GRANT_TS_RECORDED}: {ts_findings(report)}"
    )
    # Keyed and with no envelope rows, nothing else has cause to fire either.
    assert report.violations == (), f"after {after} on {backend.name}: {report.violations}"


def test_every_sanctioned_writer_leaves_a_ledger_the_rule_passes(backend, monkeypatch):
    """seed, promote, lapse, promote, promote, demote, tighten, re-seed: after
    each one, the audit of what is stored holds no finding."""
    steps = [
        ("seed", lambda: _seed(backend, monkeypatch, level=IN, demotionTriggers=TRIGGERS)),
        ("promote with a term", lambda: promote(backend, ON, certified_until=FAR_TERM)),
        # Stamped at the evaluation instant, decades ahead of the wall clock.
        # Every later write is stamped after it, so the rest of the walk also
        # covers a ledger whose ts runs ahead of wall time.
        ("lapse", lambda: lapse(backend)),
        ("re-promote", lambda: promote(backend, ON)),
        ("promote again", lambda: promote(backend, OUT)),
        ("demote", lambda: demote(backend)),
        ("re-promote after a demotion", lambda: promote(backend, ON)),
        ("tighten", lambda: tighten(backend)),
        ("re-seed", lambda: _reattest(backend, monkeypatch)),
    ]
    written = []
    for name, step in steps:
        step()
        written.append(name)
        _assert_clean(backend, name)

    assert [r.recordType for r in ledger(backend)] == [
        "bootstrap",
        "promotion",
        "lapse",
        "promotion",
        "promotion",
        "demotion",
        "promotion",
        "tightening",
        "reattestation",
    ], f"the walk did not write what it claims to have covered: {written}"


def test_a_coordinate_whose_latest_record_is_a_reattestation_passes(backend, monkeypatch):
    """The level-deriving rules read the ledger as it stood before a
    reattestation. This rule reads a timestamp, and the grant's is the
    reattestation's own, so passing over the type would report every
    re-attested grant."""
    _seed(backend, monkeypatch, level=ON)
    _reattest(backend, monkeypatch)

    records = ledger(backend)
    grant = stored_grant(backend)
    assert records[-1].recordType == "reattestation" and grant.envelopeHash == NEW_HASH
    assert grant.ts == records[-1].ts != records[0].ts, (
        "T2 premise: re-seed stamps the grant with its reattestation record's "
        "ts, which is later than the bootstrap's"
    )
    assert ts_findings(audit(backend)) == [], (
        "T2: a grant whose latest record is a reattestation carries that "
        f"record's ts and must pass {GRANT_TS_RECORDED}. A finding here means "
        "the rule passed over the reattestation type, as the level rules do"
    )


def test_a_grant_rewritten_with_no_record_is_reported_through_every_loader(
    backend, monkeypatch
):
    """T1, later direction, on what the stores really hold: the grant is
    written again and nothing is appended."""
    _seed(backend, monkeypatch, level=IN)
    recorded = ledger(backend)[-1].ts
    later = (datetime.datetime.fromisoformat(recorded) + datetime.timedelta(days=1)).isoformat()

    rewrite_grant(backend, ts=later, envelopeHash=NEW_HASH)

    report = audit(backend)
    (finding,) = ts_findings(report) or [None]
    assert finding is not None, (
        f"T1: on {backend.name} a grant rewritten with no record beside it "
        f"(ts {later}, latest record {recorded}) was not reported"
    )
    assert finding.coordinate == COORDINATE
    assert "is later than" in finding.detail, f"T1 direction: {finding.detail}"
    assert repr(later) in finding.detail and repr(recorded) in finding.detail, (
        f"T5: the detail must name both timestamps: {finding.detail}"
    )
    (entry,) = load(backend).grants
    assert stored_digest(entry.raw_data) in finding.detail, (
        f"T5: on {backend.name} the detail must name the sha256 of the grant's "
        f"stored bytes as the loader read them: {finding.detail}"
    )
    # The rewrite was HMAC-clean, so the keyed tamper rule has nothing to say:
    # this is the write no other rule sees.
    assert GRANT_TAMPER not in {v.rule for v in report.violations}


def test_a_record_whose_grant_write_did_not_land_is_reported_through_every_loader(
    backend, monkeypatch
):
    """T1, earlier direction: a record is appended and the grant stays as it
    was."""
    _seed(backend, monkeypatch, level=IN)
    grant_ts = stored_grant(backend).ts
    later = (datetime.datetime.fromisoformat(grant_ts) + datetime.timedelta(days=1)).isoformat()

    backend.records.put_record(
        make_record(recordType="tightening", fromLevel=IN, toLevel=IN, ts=later), None
    )

    (finding,) = ts_findings(audit(backend)) or [None]
    assert finding is not None, (
        f"T1: on {backend.name} a record at {later} with the grant still at "
        f"{grant_ts} was not reported"
    )
    assert "is earlier than" in finding.detail, f"T1 direction: {finding.detail}"
    assert repr(grant_ts) in finding.detail and repr(later) in finding.detail, (
        f"T5: the detail must name both timestamps: {finding.detail}"
    )
