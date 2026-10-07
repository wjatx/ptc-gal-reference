"""A lapse record carries the term that expired, as a field (#165).

GAL §5.2, §6.7.6. A lapse record's `ts` is the instant the evaluator wrote it.
The instant enforcement fell is the grant's `certifiedUntil`, and until #165
the record named it only inside `evidence`, which is opaque to every reader.
The record now carries it as `certifiedUntil`. Each clause below is one
property of that field, and each assertion names its clause when it fails.

| Clause | Guarantee |
|---|---|
| **L1** | CARRIED: a lapse record the evaluator writes carries `certifiedUntil` equal, as the exact stored string, to the term on the grant that lapsed, on all three store backends. |
| **L2** | WHERE ALLOWED: the field is accepted on a `promotion` and a `lapse` record and refused on every other type, at construction, which is also where every reader parses one. |
| **L3** | ABSENCE ACCEPTED: a lapse record with no `certifiedUntil` parses, verifies, passes the store's guard and is not an audit finding. |
| **L4** | NO STORED BYTES CHANGE: a lapse record written and signed before the field was allowed (a pinned literal) re-serializes to the same bytes and verifies under the same signature. |
| **L5** | TS IS NOT THE TERM: the record's `ts` is the ledger clock's write instant, equal to the grant's, and is never the term. |
| **L6** | BOUND BY THE SIGNATURE: changing or removing `certifiedUntil` on a stored signed lapse record fails verification. |
| **L7** | A LAPSE STILL CANNOT MOVE THE TERM: the writer leaves the grant's `certifiedUntil` and `lastSafeLevel` alone, a lapse record carrying a longer term buys no extension, and the stores refuse a lapse write whose record misstates the term or whose grant moves either field. |
| **L8** | NOBODY MISREADS IT: the audit's ratified-term rule reads promotion records only, and no reader depends on the `evidence` string. |

The guard in L7 (`store.refuse_lapse_drift`) would refuse a wrong record from
the writer, and a refusal says nothing about what the writer built. So L1, L5
and L7 each test `build_lapse` directly as well as through a store.

The clauses are pinned in three modules, split so a failure is easy to isolate:
L1, L2 and L5 in test_grants_lapse_term_field.py, L3, L4 and L6 in
test_grants_lapse_term_bytes.py, L7 and L8 in test_grants_lapse_term_guard.py.
This module holds what they share: the three-backend fixture, the constants and
the record builders. It is not collected itself.
"""

from __future__ import annotations

import pytest

from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.promotion_record import DEMOTION_RATIFIER
from safe_agents.broker.tests import test_grant_term_lapse as base
from safe_agents.broker.tests.test_grant_term_lapse import (
    ACTION_CLASS,
    AFTER,
    ENV_HASH,
    IN,
    ON,
    PRINCIPAL,
    TERM,
    _bootstrap_record,
    _promotion_record,
)

#: The three-backend fixture, reused as it stands. A test module re-binds it by
#: name so pytest resolves it there too.
stores = base.stores

# A valid term in a spelling no serializer here would produce: 'Z', and
# fractional seconds that are all zero. A writer that parsed the term and wrote
# it back would emit TERM's spelling and fail L1.
ODD_TERM = "2026-08-01T01:00:00.000000Z"
LATER_TERM = "2026-09-01T00:00:00+00:00"
EARLIER_TERM = "2026-07-20T00:00:00+00:00"
PROMOTED_AT = "2026-07-02T00:00:00+00:00"


def _seeded(stores, grant, *, promoted_at: str = PROMOTED_AT, signer=None):
    """A grant on the backend with the bootstrap and promotion that explain it."""
    grant_store, record_store = stores
    record_store.put_record(_bootstrap_record(grant))
    promotion = _promotion_record(promoted_at, certified_until=grant.certifiedUntil)
    grant_store.write_record_and_grant(
        promotion,
        grant,
        record_store,
        signature=signer.sign_record(promotion) if signer is not None else None,
    )
    return grant_store, record_store


def _lapse_record(**overrides) -> PromotionRecord:
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
    fields.update(overrides)
    return PromotionRecord(**fields)


def _lapses(record_store) -> list[PromotionRecord]:
    return [r for r in record_store.list_records(PRINCIPAL, ACTION_CLASS) if r.recordType == "lapse"]


def _must_refuse(invariant: str, errors, write) -> None:
    """``write`` must raise one of ``errors``; anything else fails naming the clause."""
    try:
        write()
    except errors:
        return
    except Exception as exc:  # the wrong refusal is still the wrong behaviour
        pytest.fail(f"{invariant}: refused, but with {type(exc).__name__}: {exc}")
    pytest.fail(f"{invariant}: the write or construction was accepted")


_SHAPES = {
    "promotion": dict(fromLevel=IN, toLevel=ON, predicate="predicate passed",
                      proposedBy="maker-alice", ratifiedBy="checker-bob"),
    "lapse": dict(fromLevel=ON, toLevel=IN, proposedBy=DEMOTION_RATIFIER,
                  ratifiedBy=DEMOTION_RATIFIER, demotionReason="pending-evidence"),
    "bootstrap": dict(fromLevel=None, toLevel=IN, proposedBy="operator", ratifiedBy="operator"),
    "tightening": dict(fromLevel=ON, toLevel=IN, proposedBy="operator", ratifiedBy="operator"),
    "demotion": dict(fromLevel=ON, toLevel=IN, proposedBy=DEMOTION_RATIFIER,
                     ratifiedBy=DEMOTION_RATIFIER, triggeredBy=["budget_breach"],
                     demotionReason="failing"),
    "reattestation": dict(fromLevel=ON, toLevel=ON, proposedBy="operator", ratifiedBy="operator"),
}


def _typed(record_type: str, **overrides) -> dict:
    return dict(
        recordType=record_type,
        actionClass=ACTION_CLASS,
        principal=PRINCIPAL,
        evidence="x",
        envelopeHash=ENV_HASH,
        ts="2026-07-03T00:00:00+00:00",
        **_SHAPES[record_type],
        **overrides,
    )
