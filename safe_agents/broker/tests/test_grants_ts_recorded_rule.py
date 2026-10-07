"""GRANT_TS_RECORDED over hand-built datasets: the rule on its own (#166).

T1 (the rule, both directions), T3 (latest means the maximum instant) and T7
(no crash, and no finding where another rule already owns the fact).

The clause table and the shared harness are in grant_ts_scaffold.py.
"""

from __future__ import annotations

import pytest

from safe_agents.broker import grants as grants_package
from safe_agents.broker.grants.audit import (
    GRANT_TAMPER,
    GRANT_TS_RECORDED,
    LEDGER_COUNTERPART,
    UNPARSEABLE_ITEM,
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    _grant_ts_mismatch,
    _ts_instant,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.store import _hmac_payload, canonical_grant_payload
from safe_agents.broker.tests.grant_ts_scaffold import (
    COORDINATE,
    dataset,
    stored_digest,
    ts_findings,
)
from safe_agents.broker.tests.reattestation_scaffold import (
    IN,
    ON,
    _bootstrap,
    _demotion,
    _planted,
    _promotion,
    _record,
)
from safe_agents.broker.tests.test_grant_store_differential import (
    GRANT_PK,
    GRANT_SK,
    HMAC_KEY,
    RECORD_PK,
    make_grant,
)

BOOTSTRAP_TS = "2026-07-01T00:00:00+00:00"
PROMOTION_TS = "2026-07-02T00:00:00+00:00"
LATER = "2026-07-09T00:00:00+00:00"
LEDGER = [_bootstrap(BOOTSTRAP_TS), _promotion(PROMOTION_TS)]


def _findings(grant, records, **kwargs):
    return ts_findings(run_audit(dataset(grant, records), **kwargs))


def test_the_rule_name_is_on_the_package_surface():
    """A caller that filters a report by rule imports the name from the
    package, as it does every other rule's."""
    assert "GRANT_TS_RECORDED" in grants_package.__all__, (
        f"T1: {GRANT_TS_RECORDED} is a named rule and must be exported from "
        "safe_agents.broker.grants beside the others"
    )
    assert grants_package.GRANT_TS_RECORDED == GRANT_TS_RECORDED


# ---------------------------------------------------------------------------
# T1: the rule, in both directions
# ---------------------------------------------------------------------------


def test_a_grant_carrying_its_latest_record_s_ts_is_clean():
    assert _findings(make_grant(level=ON, ts=PROMOTION_TS), LEDGER) == [], (
        f"T1: a grant whose ts is its latest record's must not report {GRANT_TS_RECORDED}"
    )


@pytest.mark.parametrize(
    ("grant_ts", "direction", "meaning"),
    [
        pytest.param(LATER, "is later than", "the ledger does not explain", id="later"),
        pytest.param(
            BOOTSTRAP_TS, "is earlier than", "grant write did not land", id="earlier"
        ),
    ],
)
def test_a_grant_ts_that_is_not_the_latest_record_s_is_one_named_finding(
    grant_ts, direction, meaning
):
    grant = make_grant(level=ON, ts=grant_ts)

    findings = _findings(grant, LEDGER)

    assert len(findings) == 1, (
        f"T1: a grant ts {grant_ts} against a latest record at {PROMOTION_TS} "
        f"must be exactly one {GRANT_TS_RECORDED} finding, got {findings}"
    )
    (finding,) = findings
    assert finding.coordinate == COORDINATE
    assert direction in finding.detail and meaning in finding.detail, (
        f"T1: the finding must say which direction the mismatch runs: {finding.detail}"
    )
    assert repr(grant_ts) in finding.detail and repr(PROMOTION_TS) in finding.detail, (
        f"T5: the detail must name both timestamps: {finding.detail}"
    )
    assert stored_digest(canonical_grant_payload(grant)) in finding.detail, (
        f"T5: the detail must name the sha256 of the grant's stored bytes: {finding.detail}"
    )


def test_the_same_instant_in_another_form_is_not_the_value_a_writer_stamped():
    """A sanctioned write puts ONE value on the record and on the grant. A
    grant ts that names the same instant with a different spelling was not
    written by that write."""
    (finding,) = _findings(make_grant(level=ON, ts="2026-07-02T00:00:00Z"), LEDGER) or [None]
    assert finding is not None, (
        "T1: a grant ts that only names the latest record's instant, in a "
        "different form, differs from that record's ts and must be reported"
    )
    assert "in a different form" in finding.detail, (
        "T1: a grant ts naming the latest record's instant in another spelling "
        "is neither later nor earlier than it, and the finding must say so: "
        f"{finding.detail}"
    )


def test_either_spelling_of_a_shared_latest_instant_is_a_latest_record_s_ts():
    """Two records at one instant, spelled two ways, are both latest. Equality
    is on the stored string of a latest record, so a grant carrying either
    string carries a latest record's ts. No ceremony writes the second
    spelling; the rule must still not pick one of the two by sort order."""
    same_instant = "2026-07-01T19:00:00-05:00"
    assert _ts_instant(same_instant) == _ts_instant(PROMOTION_TS), "premise: one instant"
    records = [*LEDGER, _record("tightening", same_instant, fromLevel=ON, toLevel=IN)]
    for spelling in (PROMOTION_TS, same_instant):
        assert _findings(make_grant(level=IN, ts=spelling), records) == [], (
            f"T1: {spelling!r} is the stored ts of a record at the latest instant; "
            "a finding here means only one spelling of that instant was accepted"
        )


def test_every_record_type_can_be_the_latest_one():
    """T1/T2: the rule reads a timestamp, so no type is passed over. A
    reattestation and a demotion each move the latest ts like any record."""
    reattested = [*LEDGER, _planted(LATER, ON)]
    assert _findings(make_grant(level=ON, ts=LATER), reattested) == [], (
        "T2: a grant carrying its reattestation record's ts is clean; a "
        "finding here means the rule passed over the type"
    )
    assert _findings(make_grant(level=ON, ts=PROMOTION_TS), reattested), (
        "T1: a reattestation record with the grant still at the ts before it "
        "is a record whose grant write did not land"
    )
    demoted = [*LEDGER, _demotion(LATER, ON, IN)]
    assert _findings(make_grant(level=IN, ts=LATER), demoted) == []
    assert _findings(make_grant(level=IN, ts=PROMOTION_TS), demoted)


# ---------------------------------------------------------------------------
# T3: latest is the maximum instant
# ---------------------------------------------------------------------------

# 04:00 UTC on the 2nd, written with an offset: a later instant than
# PROMOTION_TS and an earlier string. The stores refuse to append it
# (validate_record_ts), so it stands for a row no ceremony wrote, which is
# exactly the row whose ts the audit must not read by its spelling.
OFFSET_LATEST = "2026-07-01T23:00:00-05:00"


@pytest.mark.parametrize("order", ["as-written", "reversed"])
def test_latest_is_found_by_instant_not_by_string_or_list_order(order):
    records = [*LEDGER, _record("tightening", OFFSET_LATEST, fromLevel=ON, toLevel=IN)]
    if order == "reversed":
        records.reverse()
    assert sorted(r.ts for r in records)[-1] == PROMOTION_TS, "premise: string order disagrees"

    assert _findings(make_grant(level=IN, ts=OFFSET_LATEST), records) == [], (
        f"T3: the latest record is the one at {OFFSET_LATEST} (04:00 UTC on the "
        "2nd). A finding here means latest was taken by string or list order"
    )
    (finding,) = _findings(make_grant(level=IN, ts=PROMOTION_TS), records) or [None]
    assert finding is not None and "is earlier than" in finding.detail, (
        f"T3: a grant at {PROMOTION_TS} is EARLIER than the latest record's "
        f"instant, whatever the strings sort as: {finding}"
    )
    assert repr(OFFSET_LATEST) in finding.detail


def test_records_listed_out_of_order_do_not_move_the_latest():
    records = [_promotion(PROMOTION_TS), _bootstrap(BOOTSTRAP_TS)]
    assert _findings(make_grant(level=ON, ts=PROMOTION_TS), records) == [], (
        "T3: the dataset listed the bootstrap last; the latest record is still "
        "the promotion"
    )


@pytest.mark.parametrize("latest_at", [0, 1, 2])
def test_the_rule_itself_does_not_read_the_latest_from_list_order(latest_at):
    """run_audit sorts a coordinate's records by sort key before any rule sees
    them, so through it a rule that took the last element would pass the test
    above. This one hands the rule its list directly, with the latest record
    at each position in turn."""
    entries = [
        AuditedRecord(record=r, raw_data=canonical_record_payload(r))
        for r in (_bootstrap(BOOTSTRAP_TS), _bootstrap("2026-06-01T00:00:00+00:00"))
    ]
    promotion = _promotion(PROMOTION_TS)
    entries.insert(
        latest_at, AuditedRecord(record=promotion, raw_data=canonical_record_payload(promotion))
    )

    assert _grant_ts_mismatch(PROMOTION_TS, entries) is None, (
        f"T3: with the latest record at position {latest_at} of the list, a "
        "grant carrying its ts was reported. Latest was read from list order"
    )
    mismatch = _grant_ts_mismatch(BOOTSTRAP_TS, entries)
    assert mismatch is not None and "is earlier than" in mismatch[0], (
        f"T3: with the latest record at position {latest_at}, a grant at the "
        f"bootstrap's ts is earlier than the latest record: {mismatch}"
    )


def test_a_naive_ts_is_read_as_utc_the_way_the_ledger_clock_reads_it():
    """The ledger clock reads a naive ts as UTC, for history from before the
    stores refused one, and stamps the next record after it. The audit must
    agree with the writer on which record is latest, so it reads it the same
    way: a naive ts is an instant, and a grant carrying it is clean."""
    naive = "2026-07-03T00:00:00"
    records = [*LEDGER, _record("tightening", naive, fromLevel=ON, toLevel=IN)]

    assert _findings(make_grant(level=IN, ts=naive), records) == [], (
        f"T3: a naive record ts {naive!r} is read as UTC, as the ledger clock "
        "reads it, and is the latest record here. A finding means the audit "
        "and the writer disagree on which record is latest"
    )
    (finding,) = _findings(make_grant(level=IN, ts=PROMOTION_TS), records) or [None]
    assert finding is not None and "is earlier than" in finding.detail, (
        f"T3: a grant at {PROMOTION_TS} is earlier than the naive record read "
        f"as UTC: {finding}"
    )


# ---------------------------------------------------------------------------
# T7: no crash, no double blame
# ---------------------------------------------------------------------------


def _item(grant, *, grant_hash=None) -> dict:
    payload = canonical_grant_payload(grant)
    return {
        "pk": GRANT_PK,
        "sk": GRANT_SK,
        "data": payload,
        "grantHash": grant_hash if grant_hash is not None else _hmac_payload(payload, HMAC_KEY),
    }


def _record_items(records) -> list[dict]:
    return [
        {"pk": RECORD_PK, "sk": f"{r.ts}#{r.recordType}", "data": canonical_record_payload(r)}
        for r in records
    ]


def test_a_quarantined_grant_is_reported_for_its_ts_only_when_its_ts_is_wrong():
    """A grant that fails its HMAC is GRANT_TAMPER's. This rule reads the ts
    of the bytes as stored and adds a finding only when that ts is not the
    ledger's: the two findings are two facts, and on a keyless run, where
    GRANT_TAMPER cannot run, this one is all that is left to see the rewrite."""
    clean_ts = make_grant(level=ON, ts=PROMOTION_TS)
    moved_ts = make_grant(level=ON, ts=LATER)

    def rules(grant, **kwargs):
        items = [_item(grant, grant_hash="0" * 64), *_record_items(LEDGER)]
        return {v.rule for v in run_audit(dataset_from_items(items), **kwargs).violations}

    assert rules(clean_ts, hmac_key=HMAC_KEY) == {GRANT_TAMPER}, (
        "T7: a quarantined grant whose ts is still its latest record's is "
        f"GRANT_TAMPER's alone; {GRANT_TS_RECORDED} must not also fire"
    )
    assert rules(moved_ts, hmac_key=HMAC_KEY) == {GRANT_TAMPER, GRANT_TS_RECORDED}, (
        "T7: a quarantined grant whose ts was also moved is both findings"
    )
    assert rules(moved_ts) == {GRANT_TS_RECORDED}, (
        "T7: keyless, the HMAC rule is skipped and the ts finding still stands"
    )


def test_an_unparseable_grant_is_unparseable_item_s_and_nothing_crashes():
    items = [{"pk": GRANT_PK, "sk": GRANT_SK, "data": "{not json"}, *_record_items(LEDGER)]

    report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY)

    assert {v.rule for v in report.violations} == {UNPARSEABLE_ITEM}, (
        "T7: a grant that cannot be parsed has no ts to read; it is "
        f"UNPARSEABLE_ITEM's and {GRANT_TS_RECORDED} does not fire"
    )


def test_a_grant_with_no_record_at_all_is_ledger_counterpart_s():
    report = run_audit(dataset(make_grant(ts=LATER), []))

    assert {v.rule for v in report.violations} == {LEDGER_COUNTERPART}, (
        "T7: with no record at the coordinate there is no latest record to "
        f"hold the grant to; the orphan is LEDGER_COUNTERPART's, and {GRANT_TS_RECORDED} "
        "firing too would ask for two acknowledgments of one fact"
    )


@pytest.mark.parametrize(
    "lone",
    [
        pytest.param(_demotion(PROMOTION_TS, ON, IN), id="lone-demotion"),
        pytest.param(_planted(PROMOTION_TS, IN), id="lone-reattestation"),
    ],
)
def test_a_grant_with_only_records_that_earn_nothing_is_both_rules_(lone):
    """The boundary with LEDGER_COUNTERPART is "no record at all", which is
    narrower than that rule's own condition (no bootstrap or promotion). A
    lone demotion or reattestation is still a latest record. A grant whose ts
    is not that record's is two facts, a grant nothing earned and a grant
    write nothing recorded, and both rules report. A grant that does carry
    the record's ts is the first fact only."""

    def rules(grant_ts):
        report = run_audit(dataset(make_grant(level=IN, ts=grant_ts), [lone]))
        return {v.rule for v in report.violations}

    assert LEDGER_COUNTERPART in rules(LATER), "premise: nothing earned this grant"
    assert GRANT_TS_RECORDED in rules(LATER), (
        f"T7: a coordinate holding only a {lone.recordType} record has a latest "
        f"record, and a grant ts that is not that record's is {GRANT_TS_RECORDED}'s "
        f"as well as {LEDGER_COUNTERPART}'s. Skipping the rule here would pass a "
        "grant write that no record explains"
    )
    assert GRANT_TS_RECORDED not in rules(PROMOTION_TS), (
        f"T7: a grant carrying its lone {lone.recordType} record's ts is "
        f"{LEDGER_COUNTERPART}'s alone"
    )


def test_records_with_no_grant_are_not_this_rule_s():
    report = run_audit(dataset(None, LEDGER))

    assert ts_findings(report) == [], (
        f"T7: {GRANT_TS_RECORDED} reports a GRANT, and here there is none to report"
    )


OUT_OF_RANGE = "0001-01-01T00:00:00+23:59"  # parses, and has no UTC form
NOT_INSTANTS = ["not-a-timestamp", "", OUT_OF_RANGE]


def _findings_or_fail(grant, records, what: str):
    """The findings, with a crash turned into the failure it is."""
    try:
        return _findings(grant, records)
    except Exception as exc:  # any exception is the defect under test
        pytest.fail(
            f"T7: {what} is not an instant and must be a finding; the audit "
            f"raised {exc!r} instead of reporting it"
        )


def test_a_value_that_is_not_a_string_is_not_an_instant():
    """Grant.ts and a record's ts are held to str at parse, so no loader hands
    the rule anything else. A dataset entry built in memory without validation
    can, and it reads as not an instant like any other bad value."""
    for value in (None, 20260702, b"2026-07-02T00:00:00+00:00"):
        try:
            instant = _ts_instant(value)
        except Exception as exc:  # any exception is the defect under test
            pytest.fail(
                f"T7: a ts of {value!r} is not an instant and must read as "
                f"None; reading it raised {exc!r}"
            )
        assert instant is None, f"T7: a ts of {value!r} was read as the instant {instant}"


@pytest.mark.parametrize("bad_ts", NOT_INSTANTS)
def test_a_grant_ts_that_is_not_an_instant_is_a_finding_and_never_a_crash(bad_ts):
    (finding,) = _findings_or_fail(
        make_grant(level=ON, ts=bad_ts), LEDGER, f"a grant ts {bad_ts!r}"
    ) or [None]
    assert finding is not None, (
        f"T7: a grant ts {bad_ts!r} is not the ts of any record and must be reported"
    )
    assert repr(bad_ts) in finding.detail and "is not an instant" in finding.detail


@pytest.mark.parametrize("bad_ts", NOT_INSTANTS)
def test_a_record_ts_that_is_not_an_instant_is_a_finding_and_never_a_crash(bad_ts):
    """No ceremony appends such a record. It is not skipped: a row that
    decided for itself whether it counted toward "latest" could be planted to
    do exactly that. The grant at its coordinate is reported until the row is
    dealt with, even when the grant's own ts is that same string."""
    records = [*LEDGER, _record("tightening", bad_ts, fromLevel=ON, toLevel=IN)]
    for grant_ts in (PROMOTION_TS, bad_ts):
        (finding,) = _findings_or_fail(
            make_grant(level=IN, ts=grant_ts), records, f"a record ts {bad_ts!r}"
        ) or [None]
        assert finding is not None, (
            f"T7: a record ts {bad_ts!r} leaves the latest record unestablished; "
            f"the grant (ts {grant_ts!r}) must be reported, not passed"
        )
        assert repr(bad_ts) in finding.detail and "not established" in finding.detail


def test_a_grant_entry_with_no_stored_bytes_is_still_reported():
    """The in-memory dataset shape allows an entry without its stored bytes.
    The finding is made all the same; that it can never be waived is pinned in
    test_grants_ts_recorded_waiver.py."""
    report = run_audit(
        AuditDataset(
            grants=(AuditedGrant(grant=make_grant(level=ON, ts=LATER)),),
            records=tuple(AuditedRecord(record=r) for r in LEDGER),
        )
    )
    (finding,) = ts_findings(report) or [None]
    assert finding is not None and "no stored bytes" in finding.detail, (
        f"T7: a grant entry without stored bytes must still be reported: {finding}"
    )
