"""SQLite implementation of the EnforcementStore Protocol (product-wrapper Phase 1, grants-sqlite slice).

The local durable backend behind the enforcement layer's three item families —
budget counters, idempotency records, and the write-ahead ledger — built on
``sqlite_substrate`` (one db file, WAL, item-shaped rows keyed exactly like the
DynamoDB single-table items so ``example-wrapper migrate`` stays a row pump). One
contract, three backends: this class fills ``EnforcementStore`` exactly as
``InMemoryStore`` and ``DynamoStore`` do — same key layout (COUNTER#/IDEM#/
LEDGER# prefixes, sk "v0"), same omit-when-None attribute discipline, same
compare-and-set semantics.

Atomicity has no ConditionExpression here: every mutating operation runs
inside ``BEGIN IMMEDIATE`` (the substrate's ``transaction``), which holds the
single writer lock from BEGIN — a read-check-write inside the transaction is
serialized against every other writer, so the in-transaction check IS the
condition, evaluated atomically against current state. Two concurrent
``try_increment_counter`` calls cannot both pass a cap with less than 2×delta
of headroom, and two ``put_idempotency_if_absent`` calls with one key produce
exactly one True.

Missing-ledger-entry semantics deliberately match ``InMemoryStore`` (KeyError),
not ``DynamoStore`` (whose update_item on an absent key silently upserts a
partial item — an accident of UpdateItem, not a contract): a status transition
on a ledger entry that was never written is a caller bug and must be loud.
"""

from __future__ import annotations

import json

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.enforcement.types import (
    DEFAULT_IDEMPOTENCY_STATUS,
    IdempotencyRecord,
    LedgerEntry,
)


class SqliteEnforcementStore(substrate.SqliteStoreBase):
    """SQLite-backed ``EnforcementStore``.

    Item layout mirrors ``DynamoStore`` key-for-key:
        counter  pk="COUNTER#<counter_key>"  sk="v0"
                 attrs {"spent": <number>}
        idem     pk="IDEM#<key>"             sk="v0"
                 attrs {"decision_json", "ts", "status"[, "result_json"][, "error"]}
        ledger   pk="LEDGER#<entry_id>"      sk="v0"
                 attrs {"call_json", "decision_kind", "status", "ts_created"
                        [, "idempotency_key"][, "ts_committed"][, "error"]}

    Optional attributes are OMITTED when None, matching the Dynamo items, so a
    row pumped between backends is attribute-for-attribute identical. One
    lazily-opened connection per store instance, on the db path the caller
    resolved (boot wiring owns the env-var seam — never this module).
    """

    # -- idempotency ----------------------------------------------------------

    @staticmethod
    def _idem_key(key: str) -> tuple[str, str]:
        return f"IDEM#{key}", "v0"

    def get_idempotency(self, key: str) -> IdempotencyRecord | None:
        attrs = substrate.get_item(self._connection(), *self._idem_key(key))
        if attrs is None:
            return None
        return IdempotencyRecord(
            key=key,
            decision_json=attrs["decision_json"],
            ts=attrs["ts"],
            # Tolerate absence, matching DynamoStore: records for
            # deny/abstain/require_approval outcomes carry no result_json.
            result_json=attrs.get("result_json"),
            # Tolerate absence, matching DynamoStore: a row written before the
            # claim lifecycle is a completed outcome by construction.
            status=attrs.get("status", DEFAULT_IDEMPOTENCY_STATUS),
            error=attrs.get("error"),
        )

    def put_idempotency_if_absent(self, record: IdempotencyRecord) -> bool:
        attrs: dict = {
            "decision_json": record.decision_json,
            "ts": record.ts,
            "status": record.status,
        }
        # Only persist result_json when a result was actually produced, so
        # non-executing decisions don't write an empty attribute (same as Dynamo).
        if record.result_json is not None:
            attrs["result_json"] = record.result_json
        if record.error is not None:
            attrs["error"] = record.error
        pk, sk = self._idem_key(record.key)
        conn = self._connection()
        with substrate.transaction(conn):
            # The read-inside-BEGIN-IMMEDIATE is the attribute_not_exists
            # condition: serialized against every other writer, so exactly one
            # of two concurrent callers sees absence and wins.
            if substrate.get_item(conn, pk, sk) is not None:
                return False
            substrate.put_new_item(conn, pk, sk, attrs)
            return True

    def _transition_idempotency(self, key: str, mutate) -> bool:
        """Compare-and-set a claim inside one BEGIN IMMEDIATE transaction.

        The status check happens under the writer lock, which is the sqlite
        spelling of Dynamo's ConditionExpression on ``#status = :in_flight``: an
        absent row, or one another writer already settled, reports False rather
        than overwriting a settled outcome. ``mutate`` edits the attribute map in
        place and is only ever called once the condition has held.
        """
        pk, sk = self._idem_key(key)
        conn = self._connection()
        with substrate.transaction(conn):
            attrs = substrate.get_item(conn, pk, sk)
            if attrs is None or attrs.get("status") != "in_flight":
                return False
            mutate(attrs)
            substrate.update_existing_item(conn, pk, sk, attrs)
            return True

    def complete_idempotency(
        self, key: str, *, decision_json: str, result_json: str | None
    ) -> bool:
        def _mutate(attrs: dict) -> None:
            attrs["decision_json"] = decision_json
            attrs["status"] = "executed"
            # Omit-when-None, matching the put path and Dynamo's REMOVE, so a
            # completed row is attribute-for-attribute what a direct put wrote.
            if result_json is None:
                attrs.pop("result_json", None)
            else:
                attrs["result_json"] = result_json

        return self._transition_idempotency(key, _mutate)

    def fail_idempotency(self, key: str, *, error: str) -> bool:
        def _mutate(attrs: dict) -> None:
            attrs["status"] = "failed"
            attrs["error"] = error

        return self._transition_idempotency(key, _mutate)

    def delete_idempotency(self, key: str) -> None:
        # The substrate deliberately ships no delete helper (the MCP stores
        # never delete), but the EnforcementStore Protocol REQUIRES eviction:
        # enforce() deletes stale non-executed outcomes (#148) so the key
        # becomes recordable again once a retry actually executes. A direct
        # DELETE here is idempotent like DynamoDB DeleteItem — deleting an
        # absent key succeeds silently.
        pk, sk = self._idem_key(key)
        conn = self._connection()
        with substrate.transaction(conn):
            conn.execute("DELETE FROM items WHERE pk = ? AND sk = ?", (pk, sk))

    # -- counters -------------------------------------------------------------

    @staticmethod
    def _counter_item_key(counter_key: str) -> tuple[str, str]:
        return f"COUNTER#{counter_key}", "v0"

    def try_increment_counter(self, counter_key: str, delta: float, cap: float) -> bool:
        if cap - delta < 0:
            return False  # a single action larger than the whole cap can never fit
        pk, sk = self._counter_item_key(counter_key)
        conn = self._connection()
        with substrate.transaction(conn):
            # Read-check-write under the writer lock: the sqlite spelling of
            # Dynamo's conditional UpdateItem — two concurrent callers cannot
            # both pass the cap when less than 2×delta of headroom remains.
            attrs = substrate.get_item(conn, pk, sk)
            current = 0.0 if attrs is None else float(attrs["spent"])
            if current + delta > cap:
                return False
            new_attrs = {"spent": current + delta}
            if attrs is None:
                substrate.put_new_item(conn, pk, sk, new_attrs)
            else:
                substrate.update_existing_item(conn, pk, sk, new_attrs)
            return True

    def read_counter(self, counter_key: str) -> float:
        attrs = substrate.get_item(self._connection(), *self._counter_item_key(counter_key))
        if attrs is None or "spent" not in attrs:
            return 0.0
        return float(attrs["spent"])

    # -- ledger ---------------------------------------------------------------

    @staticmethod
    def _ledger_item_key(entry_id: str) -> tuple[str, str]:
        return f"LEDGER#{entry_id}", "v0"

    @staticmethod
    def _ledger_attrs(entry: LedgerEntry) -> dict:
        attrs: dict = {
            "call_json": entry.call_json,
            "decision_kind": entry.decision_kind,
            "status": entry.status,
            "ts_created": entry.ts_created,
        }
        if entry.idempotency_key is not None:
            attrs["idempotency_key"] = entry.idempotency_key
        if entry.ts_committed is not None:
            attrs["ts_committed"] = entry.ts_committed
        if entry.error is not None:
            attrs["error"] = entry.error
        return attrs

    def write_ledger(self, entry: LedgerEntry) -> None:
        # A blind put matching DynamoStore's put_item (overwrite allowed) —
        # spelled as read-check then insert-or-update, never REPLACE, so the
        # substrate's no-blind-REPLACE discipline holds.
        pk, sk = self._ledger_item_key(entry.entry_id)
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is None:
                substrate.put_new_item(conn, pk, sk, self._ledger_attrs(entry))
            else:
                substrate.update_existing_item(conn, pk, sk, self._ledger_attrs(entry))

    def _transition_ledger(self, entry_id: str, updates: dict) -> None:
        """Read-modify-write a ledger entry's status fields in one transaction.

        A missing entry raises KeyError, matching InMemoryStore's dict access —
        a transition on an entry that was never written is a caller bug, not a
        silent upsert (the DynamoStore divergence noted in the module docstring).
        """
        pk, sk = self._ledger_item_key(entry_id)
        conn = self._connection()
        with substrate.transaction(conn):
            attrs = substrate.get_item(conn, pk, sk)
            if attrs is None:
                raise KeyError(entry_id)
            attrs.update(updates)
            substrate.update_existing_item(conn, pk, sk, attrs)

    def commit_ledger(self, entry_id: str, ts_committed: str) -> None:
        self._transition_ledger(
            entry_id, {"status": "committed", "ts_committed": ts_committed}
        )

    def compensate_ledger(self, entry_id: str, error: str) -> None:
        self._transition_ledger(entry_id, {"status": "compensated", "error": error})

    def escalate_ledger(self, entry_id: str, error: str) -> None:
        self._transition_ledger(entry_id, {"status": "escalated", "error": error})

    def get_uncommitted_entries(self) -> list[LedgerEntry]:
        """All uncommitted entries — WAL replay on restart.

        A direct SELECT over the LEDGER# prefix with the status filter in
        Python after json.loads (json_extract would work but plain filtering
        reads clearer at this scale, and the ledger is small).
        """
        rows = self._connection().execute(
            "SELECT pk, item FROM items WHERE pk LIKE 'LEDGER#%'"
        ).fetchall()
        entries: list[LedgerEntry] = []
        for pk, item in rows:
            attrs = json.loads(item)
            if attrs["status"] != "uncommitted":
                continue
            entries.append(
                LedgerEntry(
                    entry_id=pk.removeprefix("LEDGER#"),
                    idempotency_key=attrs.get("idempotency_key"),
                    call_json=attrs["call_json"],
                    decision_kind=attrs["decision_kind"],
                    status=attrs["status"],
                    ts_created=attrs["ts_created"],
                    ts_committed=attrs.get("ts_committed"),
                    error=attrs.get("error"),
                )
            )
        return entries
