"""Certification term and lapse (#255; GAL §6.7.6, GAL-34, §4.3 lapse row, §5.1).

What this file pins, in order:

- READ side: a grant whose term has passed is enforced at lastSafeLevel at an
  explicit instant, with nothing written — including the quiet-log case where
  NO record follows the promotion. The verdict moves with ``now`` alone: the
  grant's ``ts`` and the ledger's timestamps, far past or far future, never
  move it. The boundary ``now == certifiedUntil`` is lapsed.
- WRITE side: the lapse writer appends exactly one lapse-typed record
  (triggeredBy empty, reason pending-evidence, ratified by the system
  evaluator), lands on lastSafeLevel, never revokes, and is idempotent.
- No-term grants never lapse.
- Terms are ceremony-only: every non-promotion write that would lengthen or
  drop a term is refused before anything is written, on all three backends.
- Integrity: a grant serialized by the pre-#255 code (a pinned literal)
  verifies and re-serializes byte-identically; a term at rest is HMAC-bound.
- Audit: lapse records are legitimate transitions, a signed one verifies, a
  malformed one (triggeredBy set) is a finding, and an unrecorded drop is a
  finding.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.grants.audit import (
    LEVEL_DROP_RECORDED,
    LEVEL_LEDGER_CONSISTENT,
    RECORD_SIGNATURE_VERIFIES,
    UNPARSEABLE_ITEM,
    AuditDataset,
    AuditedGrant,
    AuditedRecord,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.grants.ceremony import InMemoryPromotionRecordStore, PromotionCeremony
from safe_agents.broker.grants.lapse import LapseNotDueError, apply_lapse, build_lapse, run_lapse
from safe_agents.broker.grants.predicate import ActionClassMetrics
from safe_agents.broker.grants.record_signing import (
    RoleKeyResolvers,
    canonical_record_payload,
    signer_from_pem,
)
from safe_agents.broker.grants.rung import RungStateMachine
from safe_agents.broker.grants.sqlite_store import SqliteGrantStore, SqlitePromotionRecordStore
from safe_agents.broker.grants.store import (
    InMemoryGrantStore,
    TermExtensionRefusedError,
    _hmac_payload,
    canonical_grant_payload,
    compute_grant_hash,
)
from safe_agents.broker.grants.term import effective_level, extends_term, term_passed
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.prototype.broker_server import _make_pip
from safe_agents.broker.schemas import BrokeredCall, Envelope, Grant, PromotionRecord
from safe_agents.broker.schemas import Session, Taint, compute_envelope_hash
from safe_agents.broker.schemas.common import AutonomyLevel, Principal
from safe_agents.broker.schemas.evidence import ConfidenceArtifact, SelfConsistencyEvidence
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.channels.keys import key_resolver_from_map

UTC = datetime.UTC
IN, ON, OUT = AutonomyLevel.in_loop, AutonomyLevel.on_loop, AutonomyLevel.out_of_loop

PRINCIPAL = Principal(agentId="lapse-agent", skill="advisor", user="ops", tier="B")
ACTION_CLASS = "notify.send"  # in CATALOG_TABLE, so the real PIP can be driven
ENV_HASH = compute_envelope_hash(Envelope(polarity="abstain"))
HMAC_KEY = b"lapse-test-hmac-key"
COUNTER_CAP = 100.0

TERM = "2026-08-01T01:00:00+00:00"
TERM_DT = datetime.datetime(2026, 8, 1, 1, 0, tzinfo=UTC)
BEFORE = TERM_DT - datetime.timedelta(seconds=1)
AFTER = TERM_DT + datetime.timedelta(days=30)


def _grant(**overrides) -> Grant:
    base = dict(
        principal=PRINCIPAL,
        actionClass=ACTION_CLASS,
        level=ON,
        envelopeHash=ENV_HASH,
        promotedBy="checker-bob",
        evidence="evidence-ref",
        ts="2026-07-15T00:00:00+00:00",
        lastSafeLevel=IN,
        demotionTriggers=[],
        demotionReason=None,
        labelLatency="PT1H",
        ownerId="owner:ops",
        certifiedUntil=TERM,
    )
    base.update(overrides)
    return Grant(**base)


def _bootstrap_record(grant: Grant, ts: str = "2026-07-01T00:00:00+00:00") -> PromotionRecord:
    return PromotionRecord(
        recordType="bootstrap",
        actionClass=grant.actionClass,
        principal=grant.principal,
        fromLevel=None,
        toLevel=IN,
        evidence="seed",
        proposedBy="operator",
        ratifiedBy="operator",
        envelopeHash=grant.envelopeHash,
        ts=ts,
    )


def _promotion_record(
    ts: str, to_level: AutonomyLevel = ON, certified_until: str | None = TERM
) -> PromotionRecord:
    return PromotionRecord(
        recordType="promotion",
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=IN if to_level is ON else ON,
        toLevel=to_level,
        evidence="evidence-ref",
        predicate="predicate passed",
        proposedBy="maker-alice",
        ratifiedBy="checker-bob",
        envelopeHash=ENV_HASH,
        ts=ts,
        certifiedUntil=certified_until,
    )


def _call() -> BrokeredCall:
    tool, op = ACTION_CLASS.split(".")
    return BrokeredCall(
        principal=PRINCIPAL,
        tool=tool,
        op=op,
        args={"message": "hi"},
        manifest=CATALOG_TABLE.entry(tool, op),
        taint=Taint(tainted=False, sources=[]),
        session=Session(turnId="test-lapse", ingestedSources=[]),
        ts="2026-07-06T00:00:00Z",
    )


def _enforced_level(store, now: datetime.datetime) -> AutonomyLevel:
    """The level the REAL per-call PIP hands the PDP, at an injected instant."""
    pip = _make_pip(store, InMemoryStore(), COUNTER_CAP, ENV_HASH, clock=lambda: now)
    facts = pip(_call())
    assert facts.grant_present and not facts.quarantined
    return facts.grant_level


def _promote_with_term(term: str | None, *, ratify_at: datetime.datetime):
    """Bootstrap at in-loop, then run the REAL ceremony in-loop -> on-loop
    carrying ``term``. Returns (grant_store, record_store). Nothing is written
    after the promotion."""
    grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    record_store = InMemoryPromotionRecordStore()
    seed = _grant(level=IN, certifiedUntil=None)
    grant_store.write_record_and_grant(_bootstrap_record(seed), seed, record_store)

    proposal = PromotionCeremony.propose_promotion(
        PRINCIPAL,
        ACTION_CLASS,
        ON,
        "evidence-ref",
        "maker-alice",
        proposal_id="prop-lapse",
        expires_at="2099-01-01T00:00:00+00:00",
        owner_id="owner:ops",
        from_level=IN,
        envelope_hash=ENV_HASH,
        label_latency="PT1H",
        demotion_triggers=[],
        last_safe_level=IN,
        metrics=ActionClassMetrics(
            false_action_count=0, human_override_count=0, observation_count=100
        ),
        window_n=100,
        min_observations=10,
        threshold=0.05,
        artifact=ConfidenceArtifact(
            confidence=0.9,
            error_prob=0.1,
            evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
            computed_at="2026-07-12T00:00:00+00:00",
        ),
        covered=True,
        provenance_maturity="signed-lineage",
        blast_class="low",
        error_budget=None,
        certified_until=term,
    )
    result = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    ).execute(proposal, "checker-bob", now=ratify_at)
    assert result.status == "ratified", result.reason
    return grant_store, record_store


# ---------------------------------------------------------------------------
# READ side — explicit instant, no writer, quiet log
# ---------------------------------------------------------------------------


def test_quiet_log_grant_is_enforced_at_last_safe_level_past_its_term():
    """The case the arc exists for: promoted with a short term, then NOTHING —
    no record, no sweep. Past the term the PIP already enforces lastSafeLevel;
    before it, the full level. Same store, only the instant differs."""
    ratified_at = TERM_DT - datetime.timedelta(hours=1)
    grant_store, record_store = _promote_with_term(TERM, ratify_at=ratified_at)
    records_after_promotion = len(record_store.records)

    assert _enforced_level(grant_store, BEFORE) is ON
    assert _enforced_level(grant_store, AFTER) is IN

    # Pure read: the evaluation wrote nothing, and the stored grant is untouched.
    assert len(record_store.records) == records_after_promotion
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is ON


def test_boundary_instant_is_lapsed():
    """now == certifiedUntil is lapsed (the proposal_expired comparison, >=)."""
    grant_store, _ = _promote_with_term(TERM, ratify_at=BEFORE)
    assert _enforced_level(grant_store, TERM_DT - datetime.timedelta(microseconds=1)) is ON
    assert _enforced_level(grant_store, TERM_DT) is IN


_FAR_PAST = "2001-01-01T00:00:00+00:00"
_FAR_FUTURE = "2099-01-01T00:00:00+00:00"


@pytest.mark.parametrize("grant_ts", [_FAR_PAST, TERM, _FAR_FUTURE])
@pytest.mark.parametrize("latest_record_ts", [_FAR_PAST, _FAR_FUTURE])
def test_record_timestamps_never_move_the_verdict(grant_ts, latest_record_ts):
    """Only ``now`` decides. The grant's ts and the latest ledger record's ts
    — far past or far future — leave the enforced level exactly where the
    instant puts it."""
    grant = _grant(ts=grant_ts)
    grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    record_store = InMemoryPromotionRecordStore()
    record_store.put_record(_bootstrap_record(grant, ts="2000-06-01T00:00:00+00:00"))
    grant_store.write_record_and_grant(
        _promotion_record(latest_record_ts), grant, record_store
    )

    assert _enforced_level(grant_store, BEFORE) is ON
    assert _enforced_level(grant_store, AFTER) is IN


@pytest.mark.parametrize(
    ("level", "last_safe", "now", "expected"),
    [
        (ON, IN, BEFORE, ON),
        (ON, IN, TERM_DT, IN),
        (OUT, ON, AFTER, ON),
        (OUT, IN, AFTER, IN),
        (IN, IN, AFTER, IN),
        # demotion can leave lastSafeLevel ABOVE the level (the re-promotion
        # reference): a lapse must never raise it
        (IN, ON, AFTER, IN),
    ],
)
def test_effective_level_table(level, last_safe, now, expected):
    grant = _grant(level=level, lastSafeLevel=last_safe)
    assert effective_level(grant, now) is expected


@pytest.mark.parametrize("now", [BEFORE, TERM_DT, AFTER, datetime.datetime.max.replace(tzinfo=UTC)])
def test_no_term_grant_never_lapses(now):
    grant = _grant(certifiedUntil=None)
    assert term_passed(grant, now) is False
    assert effective_level(grant, now) is ON
    grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    grant_store.put_grant(grant)
    assert _enforced_level(grant_store, now) is ON
    outcome = run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=grant_store,
        record_store=InMemoryPromotionRecordStore(), now=now,
    )
    assert outcome.status == "no-term"


def test_naive_instant_is_refused():
    with pytest.raises(ValueError, match="timezone-aware"):
        term_passed(_grant(), datetime.datetime(2026, 8, 1))


@pytest.mark.parametrize(
    "bad",
    ["2026-08-01T01:00:00", "2026-08-01T01:00:00+02:00", "not-a-date", ""],
)
def test_certified_until_must_be_an_explicit_utc_instant(bad):
    with pytest.raises(ValidationError, match="certifiedUntil"):
        _grant(certifiedUntil=bad)


# ---------------------------------------------------------------------------
# WRITE side — one lapse record, idempotent, never a demotion, never a revoke
# ---------------------------------------------------------------------------


def _stores_with(grant: Grant, signer=None):
    grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    record_store = InMemoryPromotionRecordStore()
    record_store.put_record(_bootstrap_record(grant))
    # the promotion that raised the grant ratified the grant's own term
    promotion = _promotion_record("2026-07-02T00:00:00+00:00", certified_until=grant.certifiedUntil)
    grant_store.write_record_and_grant(
        promotion,
        grant,
        record_store,
        signature=signer.sign_record(promotion) if signer is not None else None,
    )
    return grant_store, record_store


def test_writer_appends_exactly_one_well_shaped_lapse_record():
    grant_store, record_store = _stores_with(_grant())
    before = len(record_store.records)

    outcome = run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER
    )

    assert outcome.status == "lapsed"
    new = record_store.records[before:]
    assert len(new) == 1
    record = new[0]
    assert record.recordType == "lapse"
    assert record.triggeredBy == []
    assert record.demotionReason == "pending-evidence"
    assert record.predicate is None
    assert record.ratifiedBy == DEMOTION_RATIFIER
    assert (record.fromLevel, record.toLevel) == (ON, IN)
    assert TERM in record.evidence
    assert record.ts == AFTER.isoformat()

    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert not stored.quarantined
    assert stored.grant.level is IN  # lastSafeLevel, not revoked
    assert stored.grant.demotionReason == "pending-evidence"
    assert stored.grant.certifiedUntil == TERM  # carried forward, never extended
    assert stored.grant.lastSafeLevel is IN


def test_writer_is_idempotent():
    grant_store, record_store = _stores_with(_grant())
    first = run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER
    )
    count = len(record_store.records)
    stored_bytes = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).raw_data

    later = AFTER + datetime.timedelta(days=365)
    second = run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=later
    )

    assert (first.status, second.status) == ("lapsed", "nothing-to-lapse")
    assert len(record_store.records) == count
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).raw_data == stored_bytes


@pytest.mark.parametrize(
    ("grant", "now", "status"),
    [
        (_grant(), BEFORE, "not-due"),
        (_grant(level=IN), AFTER, "nothing-to-lapse"),
        (_grant(level=IN, lastSafeLevel=ON), AFTER, "nothing-to-lapse"),
        (_grant(certifiedUntil=None), AFTER, "no-term"),
    ],
    ids=["term-ahead", "already-at-floor", "below-last-safe", "no-term"],
)
def test_writer_writes_nothing_when_no_lapse_is_owed(grant, now, status):
    grant_store, record_store = _stores_with(grant)
    count = len(record_store.records)
    outcome = run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=now
    )
    assert outcome.status == status
    assert len(record_store.records) == count


def test_build_lapse_refuses_when_nothing_is_owed():
    with pytest.raises(LapseNotDueError):
        build_lapse(_grant(), BEFORE)


def test_lapse_lands_on_last_safe_on_loop_from_out_of_loop():
    grant = _grant(level=OUT, lastSafeLevel=ON)
    updated, record = build_lapse(grant, AFTER)
    assert (updated.level, record.fromLevel, record.toLevel) == (ON, OUT, ON)


def test_writer_signs_the_record_when_given_a_signer():
    issuer_signer, evaluator_signer, resolvers = _role_signers()
    grant_store, record_store = _stores_with(_grant(), issuer_signer)
    updated, record = apply_lapse(
        _grant(),
        store=grant_store,
        record_store=record_store,
        now=AFTER,
        record_signer=evaluator_signer,
    )
    signature = record_store.signature_for(record)
    assert signature is not None
    dataset = _dataset_from_stores(grant_store, record_store)
    report = run_audit(dataset, hmac_key=HMAC_KEY, record_key_resolver=resolvers)
    assert report.violations == ()


@pytest.mark.parametrize(
    "overrides",
    [
        {"triggeredBy": ["stale_confidence"]},
        {"demotionReason": "failing"},
        {"demotionReason": None},
        {"ratifiedBy": "checker-bob"},
        {"predicate": "predicate passed"},
        {"fromLevel": None},
        {"toLevel": OUT},
    ],
    ids=["trigger-named", "failing", "no-reason", "human-ratifier", "predicate", "recommend", "ool"],
)
def test_lapse_record_shape_is_enforced(overrides):
    fields = dict(
        recordType="lapse",
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=ON,
        toLevel=IN,
        evidence=f"certification term expired: certifiedUntil={TERM}",
        proposedBy=DEMOTION_RATIFIER,
        ratifiedBy=DEMOTION_RATIFIER,
        envelopeHash=ENV_HASH,
        demotionReason="pending-evidence",
        ts=AFTER.isoformat(),
    )
    PromotionRecord(**fields)  # the well-shaped baseline validates
    fields.update(overrides)
    with pytest.raises(ValidationError):
        PromotionRecord(**fields)


# ---------------------------------------------------------------------------
# Ceremony-only terms — extension in place refused on every backend
# ---------------------------------------------------------------------------


def _sqlite_stores(tmp_path):
    db = tmp_path / "grants.db"
    return SqliteGrantStore(HMAC_KEY, db), SqlitePromotionRecordStore(db)


@pytest.fixture(params=["memory", "sqlite", "dynamodb"])
def stores(request, tmp_path, monkeypatch):
    if request.param == "memory":
        yield InMemoryGrantStore(hmac_key=HMAC_KEY), InMemoryPromotionRecordStore()
        return
    if request.param == "sqlite":
        yield _sqlite_stores(tmp_path)
        return
    pytest.importorskip("moto", reason="moto is required for the DynamoDB backend")
    import boto3
    from moto import mock_aws

    from safe_agents.broker.grants.store import DynamoDBGrantStore, DynamoDBPromotionRecordStore

    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    table = "grants-lapse-test"
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName=table,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.Table(table).wait_until_exists()
        yield (
            DynamoDBGrantStore(hmac_key=HMAC_KEY, table_name=table),
            DynamoDBPromotionRecordStore(table_name=table),
        )


_LATER_TERM = "2026-09-01T00:00:00+00:00"
_EARLIER_TERM = "2026-07-20T00:00:00+00:00"


@pytest.mark.parametrize(
    ("new_term", "refused"),
    [(_LATER_TERM, True), (None, True), (TERM, False), (_EARLIER_TERM, False)],
    ids=["lengthen", "drop", "unchanged", "shorten"],
)
def test_update_grant_refuses_term_extension(stores, new_term, refused):
    """update_grant is every no-record path (re-seed, re-ratify): it may keep
    or shorten a term, never lengthen or drop one."""
    grant_store, record_store = stores
    grant = _grant()
    grant_store.write_record_and_grant(_bootstrap_record(grant), grant, record_store)
    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    updated = grant.model_copy(update={"certifiedUntil": new_term, "evidence": "refreshed"})

    if refused:
        with pytest.raises(TermExtensionRefusedError, match="promotion ceremony"):
            grant_store.update_grant(updated, read.stored_hash, None, prev_raw_data=read.raw_data)
        assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).raw_data == read.raw_data
    else:
        grant_store.update_grant(updated, read.stored_hash, None, prev_raw_data=read.raw_data)
        assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.certifiedUntil == new_term


@pytest.mark.parametrize("record_type", ["tightening", "lapse", "demotion"])
def test_record_paired_writes_refuse_term_extension(stores, record_type):
    """The atomic record+grant path refuses a lengthened term for every record
    type but promotion; nothing is written on either leg."""
    grant_store, record_store = stores
    grant = _grant()
    grant_store.write_record_and_grant(_bootstrap_record(grant), grant, record_store)
    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    shapes = {
        "tightening": dict(toLevel=IN),
        "lapse": dict(toLevel=IN, demotionReason="pending-evidence"),
        "demotion": dict(
            toLevel=IN, demotionReason="failing", triggeredBy=["budget_breach"]
        ),
    }
    record = PromotionRecord(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        fromLevel=ON,
        evidence="x",
        proposedBy=DEMOTION_RATIFIER,
        ratifiedBy=DEMOTION_RATIFIER,
        envelopeHash=ENV_HASH,
        ts="2026-07-03T00:00:00+00:00",
        **shapes[record_type],
    )
    extended = grant.model_copy(update={"level": IN, "certifiedUntil": _LATER_TERM})

    with pytest.raises(TermExtensionRefusedError):
        grant_store.write_record_and_grant(record, extended, record_store, expected=read)
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).raw_data == read.raw_data
    assert record_type not in {r.recordType for r in record_store.list_records(PRINCIPAL, ACTION_CLASS)}


def test_re_ratify_cannot_extend_a_term():
    """The lateral evidence-refresh path carries the term forward; a caller
    that tries to smuggle a longer one through it is refused by the store."""
    grant_store, record_store = _stores_with(_grant())
    machine = RungStateMachine(
        ceremony=PromotionCeremony(grant_store=grant_store, promotion_record_store=record_store),
        grant_store=grant_store,
        record_store=record_store,
    )
    refreshed = machine.re_ratify(_grant(), "fresh-evidence", "checker-bob")
    assert refreshed.certifiedUntil == TERM


def test_re_promotion_sets_a_new_term_and_clears_the_lapse():
    """Recovery is the ordinary upward path: after a lapse, a ratified
    promotion with fresh evidence carries a NEW term (the only way one is set)."""
    grant_store, record_store = _promote_with_term(TERM, ratify_at=BEFORE)
    assert run_lapse(
        PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER
    ).status == "lapsed"

    new_term = (AFTER + datetime.timedelta(days=90)).isoformat()
    proposal = _reproposal(certified_until=new_term)
    result = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    ).execute(proposal, "checker-bob", now=AFTER)

    assert result.status == "ratified", result.reason
    assert result.promotion_record.certifiedUntil == new_term
    assert "certifiedUntil" not in result.promotion_record.predicate
    stored = grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant
    assert (stored.level, stored.certifiedUntil, stored.demotionReason) == (ON, new_term, None)


def test_ceremony_refuses_a_term_not_after_ratification():
    grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    record_store = InMemoryPromotionRecordStore()
    seed = _grant(level=IN, certifiedUntil=None)
    grant_store.write_record_and_grant(_bootstrap_record(seed), seed, record_store)
    result = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    ).execute(_reproposal(certified_until=TERM), "checker-bob", now=TERM_DT)
    assert result.status == "rejected"
    assert "lapsed on arrival" in result.reason


def test_ceremony_refuses_to_promote_over_an_unrecorded_lapse():
    """Stored on-loop but its term has passed: promoting from the stored level
    would raise past a lapsed certification. The lapse is recorded first."""
    grant_store, record_store = _promote_with_term(TERM, ratify_at=BEFORE)
    proposal = _reproposal(from_level=ON, target_level=OUT, last_safe_level=ON)
    result = PromotionCeremony(
        grant_store=grant_store, promotion_record_store=record_store
    ).execute(proposal, "checker-bob", now=AFTER)
    assert result.status == "rejected"
    assert "lapse is not yet recorded" in result.reason
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is ON


def _reproposal(**overrides):
    base = dict(
        proposal_id="prop-re",
        expires_at="2099-01-01T00:00:00+00:00",
        owner_id="owner:ops",
        from_level=IN,
        envelope_hash=ENV_HASH,
        label_latency="PT1H",
        demotion_triggers=[],
        last_safe_level=IN,
        metrics=ActionClassMetrics(
            false_action_count=0, human_override_count=0, observation_count=100
        ),
        window_n=100,
        min_observations=10,
        threshold=0.05,
        artifact=ConfidenceArtifact(
            confidence=0.9,
            error_prob=0.1,
            evidence=SelfConsistencyEvidence(samples=5, agreement=0.9),
            computed_at="2026-07-12T00:00:00+00:00",
        ),
        covered=True,
        provenance_maturity="signed-lineage",
        blast_class="low",
        error_budget=None,
    )
    target = overrides.pop("target_level", ON)
    base.update(overrides)
    return PromotionCeremony.propose_promotion(
        PRINCIPAL, ACTION_CLASS, target, "fresh-evidence", "maker-alice", **base
    )


# ---------------------------------------------------------------------------
# Integrity — evolution never indicts, tampering always does
# ---------------------------------------------------------------------------

# Produced by the PRE-#255 code (main @ 94f88c0: canonical_grant_payload and
# _hmac_payload, key b"legacy-fixture-key"). Pinned as literals so this test
# fails if the current code ever stops reproducing or verifying those bytes.
_LEGACY_PAYLOAD = (
    '{"actionClass":"email.send","demotionReason":null,"demotionTriggers":'
    '["budget_breach","false_action"],"envelopeHash":"sha256:env-legacy","evidence":'
    '"evidence/legacy/2026-07-01..2026-07-14","labelLatency":"P3D","lastSafeLevel":'
    '"in-loop","level":"on-loop","ownerId":"owner:operations","principal":{"agentId":'
    '"legacy-agent","skill":"mail","tier":"B","user":"ops"},"promotedBy":'
    '"identity:checker-7","ts":"2026-07-15T14:02:11+00:00"}'
)
_LEGACY_HASH = "b61fd8c46167f440b72808c7b15de2c0e92d922442fa9c23706af1c1b766935d"
_LEGACY_KEY = b"legacy-fixture-key"


def _legacy_store(tmp_path, backend: str):
    principal = Principal(agentId="legacy-agent", skill="mail", user="ops", tier="B")
    if backend == "memory":
        store = InMemoryGrantStore(hmac_key=_LEGACY_KEY)
        store._store[("legacy-agent#mail#ops#B", "email.send")] = {
            "data": _LEGACY_PAYLOAD,
            "grantHash": _LEGACY_HASH,
        }
    else:
        from safe_agents.broker import sqlite_substrate as substrate

        db = tmp_path / "legacy.db"
        store = SqliteGrantStore(_LEGACY_KEY, db)
        conn = store._connection()
        with substrate.transaction(conn):
            substrate.put_new_item(
                conn,
                "GRANT#legacy-agent#mail#ops#B",
                "CLASS#email.send",
                {"data": _LEGACY_PAYLOAD, "grantHash": _LEGACY_HASH},
            )
    return store, principal


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_legacy_grant_still_verifies_and_reserializes_byte_identically(tmp_path, backend):
    store, principal = _legacy_store(tmp_path, backend)
    read = store.get_grant(principal, "email.send")

    assert not read.quarantined, read.quarantine_reason
    assert read.grant.certifiedUntil is None
    assert canonical_grant_payload(read.grant) == _LEGACY_PAYLOAD
    assert compute_grant_hash(read.grant, _LEGACY_KEY) == _LEGACY_HASH
    # and a legacy grant carries no term, so it never lapses
    assert effective_level(read.grant, AFTER) is ON


def test_a_set_term_is_inside_the_integrity_basis():
    payload = canonical_grant_payload(_grant())
    assert f'"certifiedUntil":"{TERM}"' in payload


@pytest.mark.parametrize(
    "tampered_term",
    ['"certifiedUntil":"2099-01-01T00:00:00+00:00"', None],
    ids=["term-extended-at-rest", "term-deleted-at-rest"],
)
def test_tampered_term_at_rest_is_quarantined(tampered_term):
    grant_store = InMemoryGrantStore(hmac_key=HMAC_KEY)
    grant_store.put_grant(_grant())
    item = grant_store._store[("lapse-agent#advisor#ops#B", ACTION_CLASS)]
    original = f'"certifiedUntil":"{TERM}"'
    if tampered_term is None:
        item["data"] = item["data"].replace(original + ",", "")
    else:
        item["data"] = item["data"].replace(original, tampered_term)
    assert item["data"] != canonical_grant_payload(_grant())

    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    assert read.quarantined and read.grant is None
    assert "hash mismatch" in read.quarantine_reason


def test_extends_term_table():
    assert extends_term(None, None) is False
    assert extends_term(None, TERM) is False
    assert extends_term(TERM, TERM) is False
    assert extends_term(TERM, _EARLIER_TERM) is False
    assert extends_term(TERM, _LATER_TERM) is True
    assert extends_term(TERM, None) is True
    # 'Z' and '+00:00' spell the same instant: not an extension
    assert extends_term(TERM, "2026-08-01T01:00:00Z") is False


# ---------------------------------------------------------------------------
# Audit — lapse records are legitimate; malformed ones and silent drops are not
# ---------------------------------------------------------------------------


def _signer_and_resolver(key_id: str = "issuer:lapse-test"):
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return (
        signer_from_pem(key_id, "zone-test", private_pem),
        key_resolver_from_map({key_id: public_pem}),
    )


def _role_signers():
    """An ISSUER key and a separate EVALUATOR key, as a real floor provisions them.

    A lapse record is signed by the demotion evaluator (GAL §6.7.2), not by the
    issuer, so a fixture that signed both with one key would verify only
    because the auditor had stopped checking which identity signed what. These
    two tests carry BOTH a promotion and a lapse, so they exercise both roles
    in one dataset.
    """
    issuer_signer, issuer_resolver = _signer_and_resolver("issuer:lapse-test")
    evaluator_signer, evaluator_resolver = _signer_and_resolver("evaluator:lapse-test")
    resolvers = RoleKeyResolvers(issuer=issuer_resolver, evaluator=evaluator_resolver)
    return issuer_signer, evaluator_signer, resolvers


def _dataset_from_stores(grant_store, record_store) -> AuditDataset:
    read = grant_store.get_grant(PRINCIPAL, ACTION_CLASS)
    records = []
    for record in record_store.list_records(PRINCIPAL, ACTION_CLASS):
        records.append(
            AuditedRecord(
                record=record,
                signature=record_store.signature_for(record),
                raw_data=record_store.stored_data_for(record),
            )
        )
    return AuditDataset(
        grants=(AuditedGrant(grant=read.grant, raw_data=read.raw_data, stored_hash=read.stored_hash),),
        records=tuple(records),
        proposals=(),
        envelopes=(),
        acknowledgments=(),
        parse_violations=(),
    )


def test_a_lapsed_grant_audits_clean():
    grant_store, record_store = _stores_with(_grant())
    run_lapse(PRINCIPAL, ACTION_CLASS, grant_store=grant_store, record_store=record_store, now=AFTER)
    report = run_audit(_dataset_from_stores(grant_store, record_store), hmac_key=HMAC_KEY)
    assert report.violations == ()


def test_a_tampered_signed_lapse_record_fails_verification():
    issuer_signer, evaluator_signer, resolvers = _role_signers()
    grant_store, record_store = _stores_with(_grant(), issuer_signer)
    _, record = apply_lapse(
        _grant(),
        store=grant_store,
        record_store=record_store,
        now=AFTER,
        record_signer=evaluator_signer,
    )
    dataset = _dataset_from_stores(grant_store, record_store)
    tampered = tuple(
        AuditedRecord(
            record=e.record,
            signature=e.signature,
            raw_data=e.raw_data.replace(TERM, "2099-01-01T00:00:00+00:00")
            if e.record.recordType == "lapse"
            else e.raw_data,
        )
        for e in dataset.records
    )
    report = run_audit(
        AuditDataset(
            grants=dataset.grants, records=tampered, proposals=(), envelopes=(),
            acknowledgments=(), parse_violations=(),
        ),
        hmac_key=HMAC_KEY,
        record_key_resolver=resolvers,
    )
    flagged = [v for v in report.violations if v.rule == RECORD_SIGNATURE_VERIFIES]
    assert len(flagged) == 1 and flagged[0].detail.startswith("lapse record")


def test_a_lapse_record_naming_a_trigger_is_a_finding():
    """A lapse record with triggeredBy set cannot parse, so it surfaces as a
    finding — never as a legitimate transition."""
    grant = _grant()
    _, record = build_lapse(grant, AFTER)
    bad_bytes = canonical_record_payload(record).replace(
        '"triggeredBy":[]', '"triggeredBy":["stale_confidence"]'
    )
    items = [
        {
            "pk": "GRANT#lapse-agent#advisor#ops#B",
            "sk": f"CLASS#{ACTION_CLASS}",
            "data": canonical_grant_payload(grant),
            "grantHash": _hmac_payload(canonical_grant_payload(grant), HMAC_KEY),
        },
        {
            "pk": f"RECORD#lapse-agent#advisor#ops#B#{ACTION_CLASS}",
            "sk": f"{record.ts}#lapse",
            "data": bad_bytes,
        },
    ]
    report = run_audit(dataset_from_items(items), hmac_key=HMAC_KEY)
    rules = {v.rule for v in report.violations}
    assert UNPARSEABLE_ITEM in rules


def test_a_level_drop_with_no_record_is_a_finding():
    """The grant fell to lastSafeLevel but no lapse (or any) record explains it."""
    grant_store, record_store = _stores_with(_grant())
    dropped = _grant(level=IN, demotionReason="pending-evidence")
    dataset = _dataset_from_stores(grant_store, record_store)
    dataset = AuditDataset(
        grants=(
            AuditedGrant(
                grant=dropped,
                raw_data=canonical_grant_payload(dropped),
                stored_hash=compute_grant_hash(dropped, HMAC_KEY),
            ),
        ),
        records=dataset.records,
        proposals=(), envelopes=(), acknowledgments=(), parse_violations=(),
    )
    rules = {v.rule for v in run_audit(dataset, hmac_key=HMAC_KEY).violations}
    assert LEVEL_DROP_RECORDED in rules
    assert LEVEL_LEDGER_CONSISTENT not in rules


# ---------------------------------------------------------------------------
# The deployable entrypoint — the lapse pass runs in the demotion runner
# ---------------------------------------------------------------------------


def test_runner_main_runs_the_lapse_pass_before_demotion(monkeypatch, capsys):
    """The one-shot runner (the system evaluator identity) lapses an expired
    term at the wall clock — the outermost caller — and reports it on its own
    JSON line. TERM is in the past of any clock this suite runs under."""
    import json

    from safe_agents.broker.grants import runner

    grant_store, record_store = _stores_with(_grant())
    monkeypatch.setattr(runner, "_build_stores", lambda _table: (grant_store, record_store))
    for env in (
        "ISSUER_SIGNING_KEY_SECRET_ARN",
        "ISSUER_SIGNING_KEY_FILE",
        "ISSUER_SIGNING_KEY_ID",
        "EVALUATOR_SIGNING_KEY_SECRET_ARN",
        "EVALUATOR_SIGNING_KEY_FILE",
        "EVALUATOR_SIGNING_KEY_ID",
    ):
        monkeypatch.delenv(env, raising=False)

    rc = runner.main(
        [
            "--principal-agent-id", PRINCIPAL.agentId,
            "--skill", PRINCIPAL.skill,
            "--user", PRINCIPAL.user,
            "--tier", PRINCIPAL.tier,
            "--action-class", ACTION_CLASS,
        ]
    )

    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert rc == 0
    assert [line["event"] for line in lines] == ["lapse_runner", "demotion_runner"]
    assert lines[0]["status"] == "lapsed"
    assert grant_store.get_grant(PRINCIPAL, ACTION_CLASS).grant.level is IN
    assert [r.recordType for r in record_store.records][-1] == "lapse"


def test_proposal_codec_carries_the_term_and_leaves_no_term_bytes_unchanged():
    """The term is proposal CONTENT (inside the proposal HMAC) when set, and
    absent from the bytes when not, so every pre-#255 proposal still loads."""
    from safe_agents.broker.grants.proposals import proposal_from_json, proposal_to_json

    no_term = _reproposal()
    assert "certified_until" not in proposal_to_json(no_term)
    assert proposal_from_json(proposal_to_json(no_term)).certified_until is None

    termed = _reproposal(certified_until=TERM)
    assert f'"certified_until":"{TERM}"' in proposal_to_json(termed)
    assert proposal_from_json(proposal_to_json(termed)) == termed


# ---------------------------------------------------------------------------
# PromotionRecord.certifiedUntil — the ratified term on the signed record
# ---------------------------------------------------------------------------

# Produced by the PRE-#255 code (main @ 94f88c0): canonical_record_payload and
# RecordSigner.sign_record, with the deterministic Ed25519 test key derived from
# bytes(range(32)) below. Ed25519 signing is deterministic, so the current code
# must reproduce these exact bytes AND this exact signature.
_LEGACY_RECORD_PAYLOAD = (
    '{"actionClass":"email.send","attestation":null,"demotionReason":null,'
    '"envelopeHash":"sha256:env-legacy","evidence":"evidence/legacy/2026-07-01..2026-07-14",'
    '"fromLevel":"in-loop","predicate":"predicate passed","principal":{"agentId":'
    '"legacy-agent","skill":"mail","tier":"B","user":"ops"},"proposedBy":"maker-alice",'
    '"ratifiedBy":"checker-bob","recordType":"promotion","toLevel":"on-loop",'
    '"triggeredBy":[],"ts":"2026-07-15T14:02:11+00:00"}'
)
_LEGACY_RECORD_ENVELOPE = {
    "payloadType": "application/vnd.in-toto+json",
    "payload": (
        "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJwcmVkaWNhdGUiOnsicmVjb3JkIjp7"
        "ImFjdGlvbkNsYXNzIjoiZW1haWwuc2VuZCIsImVudmVsb3BlSGFzaCI6InNoYTI1NjplbnYtbGVnYWN5IiwicHJv"
        "cG9zZWRCeSI6Im1ha2VyLWFsaWNlIiwicmF0aWZpZWRCeSI6ImNoZWNrZXItYm9iIiwicmVjb3JkVHlwZSI6InBy"
        "b21vdGlvbiIsInRzIjoiMjAyNi0wNy0xNVQxNDowMjoxMSswMDowMCJ9LCJzaWduZXIiOnsia2V5X2lkIjoiaXNz"
        "dWVyOmxlZ2FjeSIsInpvbmUiOiJ6b25lLWxlZ2FjeSJ9fSwicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2FmZS1h"
        "Z2VudHMuZGV2L3Byb21vdGlvbi1yZWNvcmQvdjEiLCJzdWJqZWN0IjpbeyJkaWdlc3QiOnsic2hhMjU2IjoiM2Y5"
        "OGViOTFmMDljZTM5ZmMyMTBlOWZjNTlhNDU2NDFjOTJjZjZiNzFiZWViNDY0ZmQwNGFmMWY0NTQ0NDI2ZSJ9LCJu"
        "YW1lIjoicHJvbW90aW9uLXJlY29yZCJ9XX0="
    ),
    "signatures": [
        {
            "keyid": "issuer:legacy",
            "sig": "oMPXmiRNxqVSghHNCMu0vogIwdqzDgoeIC6/U+bMNTm/9qqTiUvw8OV9EY5x+x3r3Ga8ojs0hRfh1H5HcgkKBQ==",
        }
    ],
}


def _legacy_record_signer_and_resolver():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return (
        signer_from_pem("issuer:legacy", "zone-legacy", private_pem),
        key_resolver_from_map({"issuer:legacy": public_pem}),
    )


def test_legacy_record_bytes_and_signature_are_unchanged():
    from safe_agents.broker.grants.record_signing import verify_record

    signer, resolver = _legacy_record_signer_and_resolver()
    record = PromotionRecord.model_validate_json(_LEGACY_RECORD_PAYLOAD)

    assert record.certifiedUntil is None
    assert canonical_record_payload(record) == _LEGACY_RECORD_PAYLOAD
    assert verify_record(_LEGACY_RECORD_PAYLOAD, _LEGACY_RECORD_ENVELOPE, resolver).ok
    assert signer.sign_record(record) == _LEGACY_RECORD_ENVELOPE


def test_a_ratified_term_is_inside_the_signed_record_bytes():
    from safe_agents.broker.grants.record_signing import verify_record

    signer, resolver = _signer_and_resolver()
    record = _promotion_record("2026-07-02T00:00:00+00:00")
    stored = canonical_record_payload(record)
    assert f'"certifiedUntil":"{TERM}"' in stored
    envelope = signer.sign_record(record)
    assert verify_record(stored, envelope, resolver).ok
    tampered = stored.replace(TERM, "2099-01-01T00:00:00+00:00")
    assert not verify_record(tampered, envelope, resolver).ok


@pytest.mark.parametrize("record_type", ["bootstrap", "demotion", "tightening", "lapse"])
def test_only_a_promotion_record_may_carry_a_term(record_type):
    shapes = {
        "bootstrap": dict(fromLevel=None, toLevel=IN, ratifiedBy="operator"),
        "demotion": dict(
            fromLevel=ON, toLevel=IN, ratifiedBy=DEMOTION_RATIFIER,
            triggeredBy=["budget_breach"], demotionReason="failing",
        ),
        "tightening": dict(fromLevel=ON, toLevel=IN, ratifiedBy="operator"),
        "lapse": dict(
            fromLevel=ON, toLevel=IN, ratifiedBy=DEMOTION_RATIFIER,
            demotionReason="pending-evidence",
        ),
    }
    fields = dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        evidence="x",
        proposedBy="operator",
        envelopeHash=ENV_HASH,
        ts="2026-07-03T00:00:00+00:00",
        **shapes[record_type],
    )
    PromotionRecord(**fields)  # the baseline without a term validates
    with pytest.raises(ValidationError, match="set only by a ratified promotion"):
        PromotionRecord(**fields, certifiedUntil=TERM)


@pytest.mark.parametrize("bad", ["2026-08-01T01:00:00", "2026-08-01T01:00:00+02:00", "soon"])
def test_record_term_must_be_an_explicit_utc_instant(bad):
    with pytest.raises(ValidationError, match="certifiedUntil"):
        _promotion_record("2026-07-02T00:00:00+00:00", certified_until=bad)


def _term_audit(grant: Grant, records: list[PromotionRecord]) -> set[str]:
    dataset = AuditDataset(
        grants=(
            AuditedGrant(
                grant=grant,
                raw_data=canonical_grant_payload(grant),
                stored_hash=compute_grant_hash(grant, HMAC_KEY),
            ),
        ),
        records=tuple(
            AuditedRecord(record=r, signature=None, raw_data=canonical_record_payload(r))
            for r in records
        ),
        proposals=(), envelopes=(), acknowledgments=(), parse_violations=(),
    )
    return {v.rule for v in run_audit(dataset, hmac_key=HMAC_KEY).violations}


_BOOT = _bootstrap_record(_grant())
_PROMO = _promotion_record("2026-07-02T00:00:00+00:00")
_LAPSE_REC = build_lapse(_grant(), AFTER)[1]


@pytest.mark.parametrize(
    ("grant", "records", "fires"),
    [
        (_grant(), [_BOOT, _PROMO], False),
        (_grant(certifiedUntil=None), [_BOOT, _promotion_record(
            "2026-07-02T00:00:00+00:00", certified_until=None)], False),
        # a later lapse explains the LEVEL; the term stays the ratified one
        (_grant(level=IN, demotionReason="pending-evidence"), [_BOOT, _PROMO, _LAPSE_REC], False),
        (_grant(certifiedUntil=_LATER_TERM), [_BOOT, _PROMO], True),
        (_grant(certifiedUntil=None), [_BOOT, _PROMO], True),
        (_grant(), [_BOOT, _promotion_record(
            "2026-07-02T00:00:00+00:00", certified_until=None)], True),
        # bootstrap-only: nothing was ratified, so the grant may carry no term
        (_grant(level=IN), [_BOOT], True),
        (_grant(level=IN, certifiedUntil=None), [_BOOT], False),
    ],
    ids=[
        "match", "both-none", "lapsed-match", "grant-longer", "grant-dropped",
        "grant-term-never-ratified", "bootstrap-with-term", "bootstrap-no-term",
    ],
)
def test_grant_term_must_equal_the_ratified_term(grant, records, fires):
    from safe_agents.broker.grants.audit import GRANT_TERM_RATIFIED

    assert (GRANT_TERM_RATIFIED in _term_audit(grant, records)) is fires


def test_ceremony_output_audits_clean_on_the_term_rule():
    """End to end: the grant and signed record the REAL ceremony writes agree."""
    from safe_agents.broker.grants.audit import GRANT_TERM_RATIFIED

    grant_store, record_store = _promote_with_term(TERM, ratify_at=BEFORE)
    report = run_audit(_dataset_from_stores(grant_store, record_store), hmac_key=HMAC_KEY)
    assert GRANT_TERM_RATIFIED not in {v.rule for v in report.violations}
    assert report.violations == ()
