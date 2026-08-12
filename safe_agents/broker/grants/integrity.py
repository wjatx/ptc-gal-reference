"""Grant integrity helpers — orphan detection and dead-grant reporting.

Read-only audit tools: compose the existing lifecycle modules and surface
violations; never auto-correct or write to any store.

Public API
----------
OrphanedGrant
    A grant with no matching PromotionRecord in the record store.
DeadGrantEntry
    A grant with no counter activity within the reporting window.
detect_orphaned_grants(grants, records) -> list[OrphanedGrant]
    Return grants that have no PromotionRecord counterpart.
report_dead_grants(grant_activity, *, window_days, as_of) -> list[DeadGrantEntry]
    Surface grants inactive for more than window_days (human review only; no auto-prune).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from safe_agents.broker.schemas import Grant, PromotionRecord
from safe_agents.broker.schemas.common import Principal


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrphanedGrant:
    """A grant found in the store without a matching PromotionRecord.

    A grant without a PromotionRecord counterpart was written outside the
    maker-checker ceremony path — an integrity violation. Callers should
    surface this for human review, not silently discard it.
    """

    grant: Grant


@dataclass(frozen=True)
class DeadGrantEntry:
    """A grant with no counter activity within the reporting window.

    Dead grants are surfaced for human review only; they are never auto-pruned.
    Deletion requires a human-initiated ceremony.
    """

    grant: Grant
    last_activity: datetime.datetime
    days_stale: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _principal_key(principal: Principal) -> str:
    return f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"


# ---------------------------------------------------------------------------
# Orphan detection
# ---------------------------------------------------------------------------


def detect_orphaned_grants(
    grants: list[Grant],
    records: list[PromotionRecord],
) -> list[OrphanedGrant]:
    """Return grants that have no matching PromotionRecord.

    A grant without a PromotionRecord counterpart was written outside the
    maker-checker ceremony — an integrity violation. The matching key is
    (principal, actionClass): a grant is covered if at least one record
    shares its principal and actionClass.

    Note: demotions append a demotion-typed record on the same ledger (Phase 3,
    docs/GAL.md §3 — superseding the old no-record exemption), so a demoted
    grant is covered both by the record that last raised its level and by its
    demotion record. The matching key is unchanged; ledger-level checks (e.g.
    every demotion has a record) are Phase 5 work (#62), not done here.

    Args:
        grants: the grants to audit.
        records: all known PromotionRecords (e.g. from InMemoryPromotionRecordStore.records).

    Returns:
        List of OrphanedGrant for each grant with no matching record.
    """
    covered: set[tuple[str, str]] = {
        (_principal_key(r.principal), r.actionClass) for r in records
    }
    return [
        OrphanedGrant(grant=g)
        for g in grants
        if (_principal_key(g.principal), g.actionClass) not in covered
    ]


# ---------------------------------------------------------------------------
# Dead-grant report
# ---------------------------------------------------------------------------


def report_dead_grants(
    grant_activity: list[tuple[Grant, datetime.datetime]],
    *,
    window_days: int = 30,
    as_of: datetime.datetime | None = None,
) -> list[DeadGrantEntry]:
    """Surface grants with no counter activity within the reporting window.

    Callers supply (grant, last_activity_ts) pairs; this function returns
    those where last_activity_ts is older than window_days before as_of.
    Dead grants are NOT auto-pruned — surfaced for human decision only.

    Args:
        grant_activity: list of (grant, last_activity_datetime) tuples.
            last_activity_datetime should be timezone-aware (UTC recommended).
        window_days: inactivity threshold in days (default 30).
        as_of: reference datetime for the staleness comparison. Defaults
            to datetime.datetime.now(datetime.timezone.utc).

    Returns:
        List of DeadGrantEntry for grants inactive beyond window_days.
    """
    reference = as_of or datetime.datetime.now(datetime.timezone.utc)
    cutoff = reference - datetime.timedelta(days=window_days)

    result: list[DeadGrantEntry] = []
    for grant, last_activity in grant_activity:
        if last_activity < cutoff:
            delta = reference - last_activity
            result.append(DeadGrantEntry(
                grant=grant,
                last_activity=last_activity,
                days_stale=delta.days,
            ))
    return result
