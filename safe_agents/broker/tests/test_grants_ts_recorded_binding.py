"""What a GRANT_TS_RECORDED finding is bound to, and what cannot unbind it
(#166; GAL §6.11, GAL-32).

T4 (no date and no field, on the grant or on a record, takes a grant out of
scope) and T5 (an acknowledgment covers the stored bytes it was signed over,
verbatim, and the ledger state the finding was judged against). These run
over hand-built items so that a row can hold what no ceremony writes: a ts
from any year, a grant whose stored bytes are not canonical, a record whose ts
is not an instant. The same clauses over the real stores and the real
acknowledgment ceremony are in test_grants_ts_recorded_waiver.py.

The clause table and the shared harness are in grant_ts_scaffold.py.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from safe_agents.broker.grants.audit import (
    GRANT_ENVELOPE_IN_FORCE,
    GRANT_TS_RECORDED,
    AuditDataset,
    AuditedRecord,
    _coordinate_ledger_digest,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.grants.record_signing import canonical_record_payload
from safe_agents.broker.grants.store import _hmac_payload, canonical_grant_payload
from safe_agents.broker.schemas import Envelope
from safe_agents.broker.schemas.envelope import compute_envelope_hash
from safe_agents.broker.tests import test_record_signing_roles as signing_roles
from safe_agents.broker.tests.grant_ts_scaffold import dataset, stored_digest, ts_findings
from safe_agents.broker.tests.reattestation_scaffold import (
    IN,
    NEW_HASH,
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
from safe_agents.broker.tests.test_record_signing_roles import _acknowledgment

# The two-key fixture, re-bound so pytest resolves it by name here.
roles = signing_roles.roles

BOOTSTRAP_TS = "2026-07-01T00:00:00+00:00"
PROMOTION_TS = "2026-07-02T00:00:00+00:00"
LATER = "2026-07-09T00:00:00+00:00"


def _grant_item(data: str, *, grant_hash: str | None = None) -> dict:
    return {
        "pk": GRANT_PK,
        "sk": GRANT_SK,
        "data": data,
        "grantHash": grant_hash if grant_hash is not None else _hmac_payload(data, HMAC_KEY),
    }


def _record_items(records) -> list[dict]:
    return [
        {"pk": RECORD_PK, "sk": f"{r.ts}#{r.recordType}", "data": canonical_record_payload(r)}
        for r in records
    ]


def _acknowledged(data: AuditDataset, finding, signer) -> AuditDataset:
    """``data`` with a correctly signed acknowledgment of ``finding`` in it."""
    return dataclasses.replace(data, acknowledgments=(_acknowledgment(finding, signer),))


def _with_grant_and_ledger(acknowledged: AuditDataset, current: AuditDataset) -> AuditDataset:
    """The acknowledgments already stored, beside the grant and ledger as they
    now stand."""
    return dataclasses.replace(current, acknowledgments=acknowledged.acknowledgments)


# ---------------------------------------------------------------------------
# T4: no date, and no field on the grant or on a record
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record_ts", "grant_ts"),
    [
        pytest.param("1999-12-31T00:00:00+00:00", "2000-01-01T00:00:00+00:00", id="1999-later"),
        pytest.param("2000-01-01T00:00:00+00:00", "1999-12-31T00:00:00+00:00", id="1999-earlier"),
        pytest.param("2026-10-05T00:00:00+00:00", "2026-10-06T00:00:00+00:00", id="2026-later"),
        pytest.param("2026-10-06T00:00:00+00:00", "2026-10-05T00:00:00+00:00", id="2026-earlier"),
        pytest.param("2098-12-31T00:00:00+00:00", "2099-01-01T00:00:00+00:00", id="2099-later"),
        pytest.param("2099-01-01T00:00:00+00:00", "2098-12-31T00:00:00+00:00", id="2099-earlier"),
    ],
)
def test_no_date_on_the_grant_or_the_record_takes_it_out_of_scope(record_ts, grant_ts):
    """The rule has no adoption date. A grant from before the rule existed is
    held to its ledger exactly as one written tomorrow is, and old history is
    excused one grant at a time by acknowledgment, never by when it was
    written."""
    findings = ts_findings(
        run_audit(dataset(make_grant(ts=grant_ts), [_bootstrap(record_ts)]))
    )
    assert len(findings) == 1, (
        f"T4: a grant ts {grant_ts} against a latest record at {record_ts} was "
        f"not reported. {GRANT_TS_RECORDED} has no adoption date: no ts, on the "
        "grant or on a record, puts a coordinate before or after the rule"
    )


@pytest.mark.parametrize(
    "records",
    [
        pytest.param([_record("bootstrap", BOOTSTRAP_TS, fromLevel=None, toLevel=IN,
                              attestation="solo-local")], id="attestation"),
        pytest.param([_record("bootstrap", BOOTSTRAP_TS, fromLevel=None, toLevel=IN,
                              evidence="re-attested-before-the-record-existed")], id="evidence"),
        pytest.param([_record("bootstrap", BOOTSTRAP_TS, fromLevel=None, toLevel=IN,
                              envelopeHash=NEW_HASH)], id="envelopeHash"),
        pytest.param([_bootstrap(BOOTSTRAP_TS),
                      _promotion(PROMOTION_TS, certifiedUntil="2020-01-01T00:00:00+00:00")],
                     id="certifiedUntil"),
        pytest.param([_bootstrap(BOOTSTRAP_TS, to_level=ON), _demotion(PROMOTION_TS, ON, IN)],
                     id="demotionReason"),
        pytest.param([_bootstrap(BOOTSTRAP_TS), _planted(PROMOTION_TS, IN)],
                     id="an-earlier-reattestation"),
    ],
)
def test_no_field_a_record_carries_excuses_the_grant(records):
    """Whoever wrote a row wrote its fields too, so nothing a record says
    about itself or its coordinate takes the grant beside it out of scope."""
    assert ts_findings(run_audit(dataset(make_grant(ts=LATER, envelopeHash=NEW_HASH), records))), (
        f"T4: a grant with a ts no record carries was passed because of what "
        f"a record at its coordinate carries: {[r.model_dump(exclude_none=True) for r in records]}"
    )


def test_carrying_the_in_force_envelope_hash_excuses_nothing():
    """The grant the waiver exists for is one re-attested before re-attestation
    appended a record: it carries the envelope hash in force and a ts no
    record carries. That is also what any other unrecorded write to a healthy
    grant looks like, so being in force is no exemption. Each such grant is
    acknowledged, one at a time."""
    envelope = Envelope(polarity="abstain")
    in_force = compute_envelope_hash(envelope)
    grant = make_grant(ts=LATER, envelopeHash=in_force)
    items = [
        _grant_item(canonical_grant_payload(grant)),
        *_record_items([_bootstrap(BOOTSTRAP_TS)]),
        {
            "pk": f"ENVELOPE#{GRANT_PK.removeprefix('GRANT#')}",
            "sk": "V0",
            "data": envelope.model_dump_json(),
        },
    ]
    loaded = dataset_from_items(items)
    assert [e.envelope_hash for e in loaded.envelopes] == [in_force], "premise: one envelope row"

    report = run_audit(loaded, hmac_key=HMAC_KEY)

    assert GRANT_ENVELOPE_IN_FORCE not in {v.rule for v in report.violations}, (
        "premise: the grant carries the hash in force for its principal"
    )
    assert ts_findings(report), (
        "T4: a grant carrying the in-force envelope hash was passed with a ts "
        "no record carries. Matching the envelope row is not an exemption: an "
        "old re-attestation and any other unrecorded write both look like this"
    )


# ---------------------------------------------------------------------------
# T5: the stored bytes, verbatim
# ---------------------------------------------------------------------------


def _respelled(payload: str, indent: int) -> str:
    """The same JSON value in other bytes."""
    return json.dumps(json.loads(payload), indent=indent)


def test_the_digest_is_of_the_stored_bytes_and_not_of_what_they_parse_to(roles):
    """Integrity binds stored bytes. Two spellings of one JSON value are two
    stored strings, and an acknowledgment signed over one says nothing about
    the other: a digest over a re-serialization would read them as the same
    grant and carry the acknowledgment across a rewrite."""
    issuer_signer, _evaluator, resolvers = roles
    canonical = canonical_grant_payload(make_grant(ts=LATER))
    as_stored, rewritten = _respelled(canonical, 2), _respelled(canonical, 4)
    ledger = _record_items([_bootstrap(BOOTSTRAP_TS)])

    before = dataset_from_items([_grant_item(as_stored), *ledger])
    (finding,) = ts_findings(run_audit(before))
    assert stored_digest(as_stored) in finding.detail, (
        f"T5: the detail must name the sha256 of the bytes as stored: {finding.detail}"
    )
    assert stored_digest(canonical) not in finding.detail, (
        "T5: the detail names the digest of a canonical re-serialization of the "
        "grant, not of the bytes that are stored"
    )

    acknowledged = _acknowledged(before, finding, issuer_signer)
    assert run_audit(acknowledged, record_key_resolver=resolvers).acknowledged, (
        "premise: the acknowledgment applies to the bytes it was signed over"
    )
    after = _with_grant_and_ledger(
        acknowledged, dataset_from_items([_grant_item(rewritten), *ledger])
    )
    report = run_audit(after, record_key_resolver=resolvers)
    assert ts_findings(report) and report.acknowledged == (), (
        "T5: the grant's stored bytes were rewritten (the same JSON value, "
        "spelled differently) and the old acknowledgment still covered them. "
        f"It binds a re-serialization, not the stored bytes: {report.acknowledged}"
    )


def test_a_rewrite_that_leaves_the_stored_hash_attribute_in_place_is_a_new_finding(roles):
    """The item's grantHash is an attribute beside the data. A writer without
    the HMAC key changes the data and leaves it, and an audit run without the
    key cannot tell. The finding binds the data itself, so the acknowledgment
    does not follow the attribute onto other bytes."""
    issuer_signer, _evaluator, resolvers = roles
    original = canonical_grant_payload(make_grant(ts=LATER))
    rewritten = canonical_grant_payload(make_grant(ts=LATER, level=ON))
    kept_hash = _hmac_payload(original, HMAC_KEY)
    ledger = _record_items([_bootstrap(BOOTSTRAP_TS)])

    before = dataset_from_items([_grant_item(original), *ledger])
    (finding,) = ts_findings(run_audit(before))
    acknowledged = _acknowledged(before, finding, issuer_signer)
    after = _with_grant_and_ledger(
        acknowledged,
        dataset_from_items([_grant_item(rewritten, grant_hash=kept_hash), *ledger]),
    )

    # Keyless for the grant HMAC, keyed for signatures: the run in which
    # nothing but this binding sees the rewrite.
    report = run_audit(after, record_key_resolver=resolvers)
    assert ts_findings(report) and report.acknowledged == (), (
        "T5: the grant's data was rewritten with its grantHash attribute left "
        "in place and the old acknowledgment still covered it. The detail "
        f"binds the attribute, not the stored bytes: {report.acknowledged}"
    )


# ---------------------------------------------------------------------------
# T5: the finding with no latest ts to name binds the whole coordinate ledger
# ---------------------------------------------------------------------------

UNREADABLE = "not-a-timestamp"


def _unestablished(*extra) -> list:
    return [
        _bootstrap(BOOTSTRAP_TS),
        _promotion(PROMOTION_TS),
        _record("tightening", UNREADABLE, fromLevel=ON, toLevel=IN),
        *extra,
    ]


def _acknowledged_unestablished(roles):
    issuer_signer, _evaluator, resolvers = roles
    grant = make_grant(level=IN, ts=PROMOTION_TS)
    before = dataset(grant, _unestablished())
    (finding,) = ts_findings(run_audit(before))
    assert "not established" in finding.detail and "the 3 records there" in finding.detail, (
        "T5: with a record ts that is not an instant there is no latest ts to "
        "name, and the detail must bind the ledger it was judged against "
        f"in its place: {finding.detail}"
    )
    acknowledged = _acknowledged(before, finding, issuer_signer)
    report = run_audit(acknowledged, record_key_resolver=resolvers)
    assert [a.violation for a in report.acknowledged] == [finding], (
        "premise: this finding is waivable, by an acknowledgment of its exact detail"
    )
    return grant, acknowledged, resolvers


LEDGER_CHANGES = [
    # The "earlier" direction of T1: a record whose grant write did not land.
    pytest.param(
        lambda: _unestablished(_demotion(LATER, IN, IN)), id="a-later-record-appended"
    ),
    pytest.param(lambda: [r for r in _unestablished() if r.ts != PROMOTION_TS],
                 id="the-promotion-record-removed"),
    pytest.param(
        lambda: [
            _bootstrap(BOOTSTRAP_TS),
            _promotion(PROMOTION_TS, evidence="replaced-after-acknowledgment"),
            _record("tightening", UNREADABLE, fromLevel=ON, toLevel=IN),
        ],
        id="a-record-replaced-at-its-ts",
    ),
]


@pytest.mark.parametrize("changed_ledger", LEDGER_CHANGES)
def test_an_acknowledged_unestablished_latest_does_not_exempt_the_coordinate(
    roles, changed_ledger
):
    """Nothing but an acknowledgment excuses a finding, and an acknowledgment
    excuses what it was signed over. If this variant's detail named only the
    grant and the unreadable ts, one acknowledgment would cover the coordinate
    for as long as that record stayed, whatever was appended or removed beside
    it: a standing exemption from the rule."""
    grant, acknowledged, resolvers = _acknowledged_unestablished(roles)

    after = _with_grant_and_ledger(acknowledged, dataset(grant, changed_ledger()))
    report = run_audit(after, record_key_resolver=resolvers)

    assert ts_findings(report) and report.acknowledged == (), (
        "T4/T5: the ledger at the coordinate changed after the finding was "
        "acknowledged, with the grant's bytes and the unreadable record left "
        "as they were, and the old acknowledgment still covered it: "
        f"{report.acknowledged}"
    )


def test_the_ledger_binding_does_not_depend_on_the_order_records_are_listed_in():
    """run_audit sorts a coordinate's records before any rule reads them, and
    two rows can still share a sort key, so the digest is taken over the
    records as a set. The helper is handed its list directly here."""
    entries = list(dataset(None, _unestablished()).records)

    assert _coordinate_ledger_digest(entries) == _coordinate_ledger_digest(entries[::-1]), (
        "T5: the same records listed in another order are the ledger the "
        "acknowledgment was signed over; the digest binding them must not move"
    )
    assert _coordinate_ledger_digest(entries) != _coordinate_ledger_digest(entries[:-1]), (
        "T5: a ledger with a record removed is a different ledger"
    )


def test_an_unestablished_latest_with_a_record_that_has_no_stored_bytes_is_never_waived(roles):
    """GAL-32: a finding that cannot be bound is un-waivable. Here the grant's
    bytes are present and one record's are not, so the ledger half of the
    binding is missing."""
    issuer_signer, _evaluator, resolvers = roles
    bound = dataset(make_grant(level=IN, ts=PROMOTION_TS), _unestablished())
    unbound = dataclasses.replace(
        bound,
        records=(AuditedRecord(record=bound.records[0].record), *bound.records[1:]),
    )
    (finding,) = ts_findings(run_audit(unbound))
    assert "no stored bytes" in finding.detail, finding.detail

    report = run_audit(
        _acknowledged(unbound, finding, issuer_signer), record_key_resolver=resolvers
    )

    assert ts_findings(report) == [finding] and report.acknowledged == (), (
        "T5: a finding whose ledger state could not be bound (a record entry "
        f"with no stored bytes) was waived: {report.acknowledged}"
    )
