"""Re-attestation appends a record: what it may change on the grant.

#164; GAL §6.6, GAL-15.

R5: only `envelopeHash`, `promotedBy` and `ts` change, and the stores refuse a
`reattestation` write that moves anything else, that creates a grant, or whose
record does not describe the grant beside it.

The clause table and the shared harness are in reattestation_scaffold.py.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.grants.store import (
    REATTESTATION_GRANT_FIELDS,
    ReattestationRefusedError,
    canonical_grant_payload,
    refuse_reattestation_drift,
)
from safe_agents.broker.tests import reattestation_scaffold as harness
from safe_agents.broker.tests.reattestation_scaffold import (
    ACTION_CLASS,
    IN,
    NEW_HASH,
    OLD_HASH,
    ON,
    OPERATOR,
    OUT,
    PRINCIPAL,
    RESEEDED_AT,
    TERM,
    _bootstrap,
    _planted,
    _promotion,
    _reattest,
    _reattestation,
    _seed,
    _writer_pair,
    make_grant,
)

#: The three-backend fixture, re-bound so pytest resolves it by name here too.
backend = harness.backend


# ===========================================================================
# R5 — the grant delta
# ===========================================================================


class TestR5GrantDelta:
    def test_reseed_changes_three_fields_and_nothing_else(self, backend, monkeypatch):
        before = _seed(
            backend,
            monkeypatch,
            level=ON,
            lastSafeLevel=IN,
            demotionReason="pending-evidence",
            certifiedUntil=TERM,
            demotionTriggers=["budget_breach"],
        ).grant

        _reattest(backend, monkeypatch)

        after = backend.grants.get_grant(PRINCIPAL, ACTION_CLASS).grant
        changed = {
            name for name in type(after).model_fields if getattr(before, name) != getattr(after, name)
        }
        assert changed == REATTESTATION_GRANT_FIELDS
        assert (after.envelopeHash, after.promotedBy) == (NEW_HASH, OPERATOR)
        assert (after.level, after.lastSafeLevel) == (ON, IN)
        assert after.demotionReason == "pending-evidence"
        assert after.certifiedUntil == TERM

    def test_the_writer_changes_three_fields_and_nothing_else(self):
        before, after, _record = _writer_pair()
        changed = {
            name for name in type(after).model_fields if getattr(before, name) != getattr(after, name)
        }
        assert changed == REATTESTATION_GRANT_FIELDS, (
            "I5 GRANT DELTA: a re-attestation changes envelopeHash, promotedBy and ts "
            f"and nothing else; the writer changed {sorted(changed)}"
        )
        assert (after.envelopeHash, after.promotedBy) == (NEW_HASH, OPERATOR), (
            "I5 GRANT DELTA: the grant takes the NEW hash and the re-attesting identity"
        )

    def test_the_guard_judges_reattestation_writes_and_only_those(self):
        """The store guard is keyed on the record type. Any other type is not
        its business, whatever the grant beside it does; a reattestation is
        judged whatever else is true."""
        current = make_grant(level=ON, envelopeHash=OLD_HASH)
        stored = canonical_grant_payload(current)
        raised = current.model_copy(update={"level": OUT, "evidence": "fresh"})
        try:
            refuse_reattestation_drift(stored, _promotion(fromLevel=ON, toLevel=OUT), raised)
            refuse_reattestation_drift(None, _bootstrap(), current)
        except ReattestationRefusedError as exc:
            pytest.fail(
                "I5 GRANT DELTA: the re-attestation guard judged a write that is not a "
                f"reattestation: {exc}"
            )
        try:
            refuse_reattestation_drift(stored, _planted(RESEEDED_AT.isoformat(), OUT), raised)
        except ReattestationRefusedError:
            pass
        else:
            pytest.fail(
                "I5 GRANT DELTA: the re-attestation guard let a reattestation-typed write "
                "change the grant's level and evidence"
            )

    @pytest.mark.parametrize(
        "drift",
        [
            dict(level=IN),
            dict(lastSafeLevel=ON),
            dict(demotionReason="failing"),
            dict(certifiedUntil="2026-08-01T00:00:00+00:00"),  # shortened: no term rule objects
            dict(certifiedUntil=None),
            dict(evidence="fresh-evidence-ref"),
            dict(ownerId="mallory"),
            dict(demotionTriggers=["budget_breach"]),
        ],
        ids=["level", "lastSafeLevel", "reason", "term-shorter", "term-dropped", "evidence",
             "owner", "triggers"],
    )
    def test_the_store_refuses_a_reattestation_that_moves_anything_else(
        self, backend, monkeypatch, drift
    ):
        current = _seed(backend, monkeypatch, level=ON, lastSafeLevel=IN, certifiedUntil=TERM)
        ts = RESEEDED_AT.isoformat()
        honest = current.grant.model_copy(
            update={"envelopeHash": NEW_HASH, "promotedBy": OPERATOR, "ts": ts}
        )
        drifted = honest.model_copy(update=drift)
        # The record describes the drifted grant, so only the delta rule can object.
        record = _reattestation(fromLevel=drifted.level, toLevel=drifted.level)

        with pytest.raises(ReattestationRefusedError, match="may change only"):
            backend.grants.write_record_and_grant(
                record, drifted, backend.records, None, expected=current
            )

        assert backend.raw_grant_data() == current.raw_data
        assert not backend.raw_record_exists(record)

    @pytest.mark.parametrize(
        "mismatch",
        [
            dict(fromLevel=IN, toLevel=IN),
            dict(envelopeHash=OLD_HASH),
            dict(ratifiedBy="someone-else"),
            dict(ts="2026-07-26T09:00:00.000001+00:00"),
        ],
        ids=["level", "envelopeHash", "ratifiedBy", "ts"],
    )
    def test_the_store_refuses_a_record_that_does_not_describe_the_grant(
        self, backend, monkeypatch, mismatch
    ):
        current = _seed(backend, monkeypatch, level=ON)
        updated = current.grant.model_copy(
            update={"envelopeHash": NEW_HASH, "promotedBy": OPERATOR, "ts": RESEEDED_AT.isoformat()}
        )
        record = _reattestation(**mismatch)

        with pytest.raises(ReattestationRefusedError, match="does not describe"):
            backend.grants.write_record_and_grant(
                record, updated, backend.records, None, expected=current
            )

        assert backend.raw_grant_data() == current.raw_data
        assert not backend.raw_record_exists(record)

    def test_a_reattestation_cannot_create_a_grant(self, backend):
        grant = make_grant(
            level=ON, envelopeHash=NEW_HASH, promotedBy=OPERATOR, ts=RESEEDED_AT.isoformat()
        )
        record = _reattestation()

        with pytest.raises(ReattestationRefusedError, match="cannot create"):
            backend.grants.write_record_and_grant(record, grant, backend.records, None)

        assert backend.raw_grant_data() is None
        assert not backend.raw_record_exists(record)

    def test_an_honest_reattestation_passes_the_store_guard(self, backend, monkeypatch):
        current = _seed(backend, monkeypatch, level=ON)
        updated = current.grant.model_copy(
            update={"envelopeHash": NEW_HASH, "promotedBy": OPERATOR, "ts": RESEEDED_AT.isoformat()}
        )
        backend.grants.write_record_and_grant(
            _reattestation(), updated, backend.records, None, expected=current
        )
        assert backend.raw_grant_data() == canonical_grant_payload(updated)
