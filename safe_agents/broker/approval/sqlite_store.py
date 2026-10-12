"""SQLite implementation of the IntentStore Protocol (product-wrapper Phase 1, grants-sqlite slice).

The local durable backend for the approval layer's intent items, built on
``sqlite_substrate`` (one db file, WAL, item-shaped rows keyed exactly like the
DynamoDB single-table items). Fills ``IntentStore`` exactly as
``InMemoryIntentStore`` and ``DynamoIntentStore`` do — same item attributes
(materializedRequest as a JSON string, approvedBy/executedAt only when
present), same atomic compare-and-set transition semantics via the substrate's
``BEGIN IMMEDIATE`` transaction.

One deliberate layout difference from Dynamo: expiry rides the substrate's
indexed ``expires_at`` COLUMN as ISO-8601, not an epoch ``ttl`` attribute in
the item. Dynamo's epoch attr exists only to feed the DDB TTL daemon; sqlite
has no daemon, so the item JSON carries no ttl and the column serves the boot
sweep instead. Expiry is a PREDICATE AT USE (deletion timing is never
correctness: ``approve()`` checks the intent's ``expiry`` field at use
regardless of whether the row still exists). :meth:`SqliteIntentStore.sweep_expired`
is a BOUNDED-LAG privacy property, not an enforcement mechanism — an expired
intent's payload should not linger forever — scoped strictly to RESOLVED
INTENT# rows and run by the broker (wired by boot code, never this module).

It does not delete a PENDING row until a grace period past its expiry (#163),
the same grace a pending row's DynamoDB time-to-live carries. An undecided hold
whose expiry passed is first expired by the runtime's expiry sweep, which writes
its audit record; only then is the row resolved and eligible at its expiry.
Deleting it first would leave the tape showing a hold followed by nothing. The
grace bounds retention for a pending row no sweep will ever resolve: a hold
written before the pending index existed, or one whose principal never runs a
broker again. Such a row is deleted unrecorded once the grace has passed.

The executed-transition retention semantics match Dynamo (trigger-range pin): the
retention window derives from ``executed_at`` ITSELF, not the store's clock,
so expires_at == executedAt + EXECUTED_INTENT_RETENTION_DAYS holds
structurally. A tz-naive executed_at is UTC, never broker-local (evidence-labeling
finding).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from pathlib import Path

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.approval.store import (
    EXECUTED_INTENT_RETENTION_DAYS,
    PENDING_EXPIRY_ATTR,
    PENDING_TTL_GRACE_DAYS,
    PENDING_PRINCIPAL_ATTR,
    PENDING_STATUS,
    IntentAlreadyPendingError,
    _is_expiry_candidate,
    _now_epoch,
    intent_from_item,
    intent_item_attrs,
)
from safe_agents.broker.schemas import Intent


def _parse_utc(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp to an aware UTC datetime.

    Accepts the 'Z' suffix (Dynamo's put path does the same ``.replace``) and
    treats a tz-naive timestamp as UTC (an evidence-labeling finding). All expiry
    comparisons go through here — datetime comparison, never string
    comparison, so 'Z' and '+00:00' spellings of one instant compare equal.
    """
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _status_of(item: str) -> str | None:
    """The status attribute of a stored item, or None when it cannot be read.

    An unreadable item is treated as not pending and so stays eligible for the
    privacy delete exactly as before.
    """
    try:
        attrs = json.loads(item)
    except (TypeError, ValueError):
        return None
    return attrs.get("status") if isinstance(attrs, dict) else None


class SqliteIntentStore(substrate.SqliteStoreBase):
    """SQLite-backed ``IntentStore``.

    Item layout mirrors ``DynamoIntentStore`` (minus the ttl attr — see the
    module docstring):
        pk = "INTENT#<intent_id>"  sk = "v0"
        attrs {"data": <canonical frozen-half payload — the intent HMAC basis>,
               "intentHash": <hmac over those exact bytes>,
               "status"[, "approvedBy"][, "executedAt"]}
    The substrate ``expires_at`` column carries the intent's expiry (or, once
    executed, executedAt + the retention window) as normalized ISO-8601.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        hmac_key: bytes,
        journal_mode: str = substrate.JOURNAL_WAL,
        read_only: bool = False,
    ) -> None:
        super().__init__(db_path, journal_mode=journal_mode, read_only=read_only)
        self._hmac_key = hmac_key

    @staticmethod
    def _item_key(intent_id: str) -> tuple[str, str]:
        return f"INTENT#{intent_id}", "v0"

    def put_intent(self, intent: Intent) -> None:
        # Conditional put matching DynamoIntentStore's (#39): refuse to
        # replace a pending intent, write over an absent or resolved one.
        # Spelled as read-check then insert-or-update inside BEGIN IMMEDIATE,
        # never REPLACE, so the check and the write see one state. The
        # expires_at column carries the expiry normalized through datetime
        # parsing so a 'Z'-suffixed expiry lands in '+00:00' form.
        pk, sk = self._item_key(intent.id)
        expires_at = _parse_utc(intent.expiry).isoformat()
        conn = self._connection()
        with substrate.transaction(conn):
            attrs = intent_item_attrs(intent, self._hmac_key)
            existing = substrate.get_item(conn, pk, sk)
            if existing is not None and existing.get("status") == PENDING_STATUS:
                raise IntentAlreadyPendingError(intent.id)
            if existing is None:
                substrate.put_new_item(conn, pk, sk, attrs, expires_at=expires_at)
            else:
                substrate.update_existing_item(conn, pk, sk, attrs, expires_at=expires_at)

    def get_intent(self, intent_id: str) -> Intent | None:
        attrs = substrate.get_item(self._connection(), *self._item_key(intent_id))
        if attrs is None:
            return None
        # Verify-then-parse over the STORED bytes — the shared helper,
        # so all three backends quarantine identically.
        return intent_from_item(intent_id, attrs, self._hmac_key)

    def transition_status(
        self,
        intent_id: str,
        expected_status: str,
        new_status: str,
        approved_by: str | None = None,
        executed_at: str | None = None,
    ) -> bool:
        pk, sk = self._item_key(intent_id)
        conn = self._connection()
        with substrate.transaction(conn):
            # Read item AND its expires_at column inside BEGIN IMMEDIATE — the
            # read is the ConditionExpression (serialized against every other
            # writer, so two concurrent same-expected transitions produce
            # exactly one True), and the column must be read so a non-executed
            # transition carries it forward unchanged.
            row = conn.execute(
                "SELECT item, expires_at FROM items WHERE pk = ? AND sk = ?", (pk, sk)
            ).fetchone()
            if row is None:
                return False
            attrs = json.loads(row[0])
            expires_at: str | None = row[1]
            if attrs["status"] != expected_status:
                return False
            attrs["status"] = new_status
            if new_status != PENDING_STATUS:
                # Leaving pending ends expiry candidacy (#163).
                attrs.pop(PENDING_PRINCIPAL_ATTR, None)
                attrs.pop(PENDING_EXPIRY_ATTR, None)
            if approved_by is not None:
                attrs["approvedBy"] = approved_by
            if executed_at is not None:
                # Stamp executedAt AND extend the expires_at column so the
                # executed intent survives its short approval window for the
                # after-the-fact /flag review (evidence labeling). The retention
                # anchors on executed_at itself, never the store's clock
                # (trigger-range pin) — same derivation as DynamoIntentStore's ttl.
                executed_dt = _parse_utc(executed_at)
                attrs["executedAt"] = executed_at
                expires_at = (
                    executed_dt + timedelta(days=EXECUTED_INTENT_RETENTION_DAYS)
                ).isoformat()
            substrate.update_existing_item(conn, pk, sk, attrs, expires_at=expires_at)
            return True

    def expired_pending_candidates(self, principal_key: str, now: datetime) -> list[str]:
        """Pending intents of ``principal_key`` whose expiry is at or before ``now``.

        Reads the item attributes' pending index (the item column's JSON, never
        the HMAC'd ``data`` payload), the sqlite spelling of DynamoDB's sparse
        index Query. Candidates only: the runtime verify-then-parses each.
        """
        now_epoch = _now_epoch(now)
        rows = self._connection().execute(
            "SELECT pk, item FROM items WHERE pk LIKE 'INTENT#%'"
        ).fetchall()
        ids: list[str] = []
        for pk, item in rows:
            try:
                attrs = json.loads(item)
            except (TypeError, ValueError):
                continue
            if isinstance(attrs, dict) and _is_expiry_candidate(attrs, principal_key, now_epoch):
                ids.append(pk[len("INTENT#"):])
        return ids

    def sweep_expired(self, now: datetime | None = None) -> int:
        """Delete INTENT# rows whose retention has passed; return the count.

        This is the sqlite stand-in for the DynamoDB TTL daemon, run at boot by
        the broker (boot wiring calls it — this module never does). It is a
        BOUNDED-LAG PRIVACY property, never correctness: expiry is a PREDICATE
        AT USE (``approve()`` checks the intent's ``expiry`` field
        whether or not the row was swept; deletion timing is never
        load-bearing), the sweep only bounds how long an expired intent's
        payload can linger at rest.

        Scoped strictly to INTENT# rows — other item families using the
        expires_at column (e.g. proposal items) own their own lifecycles — and
        a PENDING one only once ``PENDING_TTL_GRACE_DAYS`` past its expiry
        (#163): an undecided hold is expired, with its audit record, by the
        runtime's expiry sweep first, and the grace only bounds how long a hold
        no sweep resolves can linger.
        Comparison is by parsed datetime, never string order, so 'Z' and
        '+00:00' spellings of one instant compare correctly; ``now=None``
        means ``datetime.now(UTC)``, and a tz-naive ``now`` is treated as UTC.
        """
        moment = datetime.now(UTC) if now is None else now
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        conn = self._connection()
        deleted = 0
        with substrate.transaction(conn):
            rows = conn.execute(
                "SELECT pk, sk, item, expires_at FROM items "
                "WHERE pk LIKE 'INTENT#%' AND expires_at IS NOT NULL"
            ).fetchall()
            pending_grace = timedelta(days=PENDING_TTL_GRACE_DAYS)
            for pk, sk, item, expires_at in rows:
                deadline = _parse_utc(expires_at)
                if _status_of(item) == PENDING_STATUS:
                    deadline += pending_grace
                if deadline < moment:
                    conn.execute(
                        "DELETE FROM items WHERE pk = ? AND sk = ?", (pk, sk)
                    )
                    deleted += 1
        return deleted
