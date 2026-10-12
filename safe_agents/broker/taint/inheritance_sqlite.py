"""SQLite implementation of ``InheritanceStore`` (PTC-51, #177).

Rows live in the broker-writable database, the file ``BROKER_SQLITE_PATH``
names, beside counters and intents. They never live in the grant space's own
file (``BROKER_SQLITE_GRANTS_PATH``): on a cluster that file is mounted
read-only into the broker so the kernel refuses the broker a grant write, and
an inheritance record is something the broker must be able to write. The
DynamoDB store keeps the rows in the grants table under ``INHERIT#``, confined
by IAM; here the mount topology does the confining, and the record's key space
does not need the read-only file.

Keyed exactly like the DynamoDB rows (``inheritance.py``), so a row pump moves
them verbatim. The substrate's ``expires_at`` column carries ``notAfter`` for a
later sweep to find; nothing here deletes, and expiry is a predicate at use.
"""

from __future__ import annotations

import json
from datetime import datetime

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.schemas import InheritanceRecord
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.schemas.inheritance import parse_aware_instant

from .inheritance import (
    InheritanceRecordExistsError,
    instant_key,
    record_pk,
    record_sk,
)


class SqliteInheritanceStore(substrate.SqliteStoreBase):
    """SQLite-backed ``InheritanceStore``: ``pk``/``sk`` as on DynamoDB, ``{"data": json}``."""

    def put_record(self, record: InheritanceRecord) -> None:
        pk, sk = record_pk(record.target), record_sk(record)
        conn = self._connection()
        with substrate.transaction(conn):
            if substrate.get_item(conn, pk, sk) is not None:
                raise InheritanceRecordExistsError(record.id)
            substrate.put_new_item(
                conn,
                pk,
                sk,
                {"data": record.model_dump_json()},
                expires_at=parse_aware_instant(record.notAfter).isoformat(),
            )

    def live_records(self, target: Principal, now: datetime) -> list[InheritanceRecord]:
        rows = self._connection().execute(
            "SELECT item FROM items WHERE pk = ? AND sk > ? ORDER BY sk ASC",
            (record_pk(target), instant_key(now)),
        ).fetchall()
        records = [
            InheritanceRecord.model_validate_json(json.loads(item)["data"])
            for (item,) in rows
        ]
        return [r for r in records if r.live_at(now)]
