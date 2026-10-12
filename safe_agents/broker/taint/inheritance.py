"""broker.taint.inheritance -- the taint inheritance ledger's store (PTC-51, #177).

An op whose image-baked ``ToolOp`` declares ``causes_context`` creates a context
that acts later: a deferred run of the same principal, or a child principal.
Before such an op runs, the causing broker writes an ``InheritanceRecord`` keyed
by the target principal. Every runtime reads the unexpired records for its own
principal when it mints a turn and ingests their sources, so the context starts
no cleaner than the turn that caused it (``broker/TAINT.md``).

This module holds the store contract, two of its three implementations, and the
two pure helpers a writer needs:

  InheritanceStore            the protocol: ``put_record`` and ``live_records``
  InMemoryInheritanceStore    one process; for tests and an injected store
  DynamoInheritanceStore      rows in the grants table under ``INHERIT#``
  SqliteInheritanceStore      in ``inheritance_sqlite.py``; rows in broker.db
  inheritance_target          who a declaration's record is keyed by
  resolve_not_after           when a record stops tainting

Key layout, identical on DynamoDB and sqlite so a row pump moves rows verbatim:

    pk = "INHERIT#<agentId>#<skill>#<user>#<tier>"   (the target principal)
    sk = "<notAfter as UTC, fixed width>#<record id>"
    data = the record as JSON

The sort key leads with ``notAfter`` so a read asks for one partition from the
current instant onward: a Query by partition key with a key condition, never a
Scan. Expiry stays a predicate at use: every implementation re-checks
``record.live_at(now)`` after the read, so a key boundary is never the only
thing deciding whether a record still taints.

Failure directions. A write that fails raises, and the caller does not run the
cause op. A read that fails raises, and the caller mints the turn tainted.
Neither is caught here.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from safe_agents.broker.delegation.keys import principal_key
from safe_agents.broker.schemas import SELF_TARGET, CausesContext, InheritanceRecord
from safe_agents.broker.schemas.common import Principal
from safe_agents.broker.schemas.inheritance import parse_aware_instant

if TYPE_CHECKING:
    from safe_agents.broker.delegation.types import SubGrant

# The key space the records live in. On DynamoDB the broker's write is confined
# to it by a dynamodb:LeadingKeys condition (infra/lib/identity-stack.ts).
INHERIT_PREFIX = "INHERIT#"


class InheritanceRecordExistsError(Exception):
    """A row is already stored at this record's key (its target, notAfter and id).

    Writes are create-only. A second write of one key is a caller bug, never an
    update, so it refuses rather than replacing what is there.
    """


class InheritanceStoreRequiredError(ValueError):
    """A runtime whose ToolOp table declares a cause op was given no inheritance store.

    The floor (PTC-51): a declaration is the consumer's only switch, and a cause
    op with nowhere to write its record would hand its context a clean turn. So
    the runtime refuses to exist rather than run the op without the record.
    """


def require_inheritance_store(
    cause_entries: list, store: "InheritanceStore | None"
) -> None:
    """Refuse when ``cause_entries`` is non-empty and ``store`` is None.

    ``cause_entries`` is ``ToolOpTable.cause_entries()``. The message names
    every declaring entry, so the operator sees which ops forced the store.
    """
    if cause_entries and store is None:
        names = ", ".join(f"{e.tool}.{e.op}" for e in cause_entries)
        raise InheritanceStoreRequiredError(
            f"tool_ops declares causes_context on {names}, but no inheritance store is "
            "configured. A cause op writes an inheritance record before it runs, and "
            "without a store its context would start clean. Run on a durable store "
            "(BROKER_STORE=sqlite or dynamo, where build_runtime builds one) or pass "
            "inheritance_store=."
        )


def record_pk(target: Principal) -> str:
    """The partition key every record for ``target`` lives under.

    The principal segment is ``delegation.keys.principal_key``, the rendering the
    grant, envelope and counter keys share.
    """
    return f"{INHERIT_PREFIX}{principal_key(target)}"


def instant_key(instant: datetime) -> str:
    """An aware instant as a fixed-width UTC string that sorts chronologically."""
    if instant.tzinfo is None:
        raise ValueError(f"{instant!r} states no UTC offset")
    return instant.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def record_sk(record: InheritanceRecord) -> str:
    """The sort key: notAfter first, so a read can start at the current instant."""
    return f"{instant_key(parse_aware_instant(record.notAfter))}#{record.id}"


def inheritance_target(decl: CausesContext, causing: Principal) -> Principal:
    """The principal a declaration's record is keyed by.

    ``"self"`` is the causing principal, a deferred run of itself. Anything else
    is the declared child. The target comes only from the image-baked
    declaration, never from a call's arguments.
    """
    if decl.target == SELF_TARGET:
        return causing
    assert isinstance(decl.target, Principal)  # the schema admits nothing else
    return decl.target


def resolve_not_after(
    decl: CausesContext,
    *,
    issued_at: datetime,
    sub_grant: "SubGrant | None" = None,
) -> datetime:
    """When a record written at ``issued_at`` stops tainting its target.

    ``issued_at`` plus the declaration's ``horizon_seconds``, the consumer's
    stated exposure window. For a child target whose sub-grant the broker's
    store holds, the LATER of that and the sub-grant's expiry: a child that also
    holds grants of its own keeps acting past its sub-grant's expiry, so the
    horizon still bounds it, and a sub-grant that outlives the horizon extends
    the record to its expiry. Taking the later value never shortens a record's
    life. For a ``"self"`` target the horizon alone.

    ``sub_grant`` is the target's sub-grant as the broker's store holds it, or
    None. It is ignored for a ``"self"`` target, and refused if it names a
    principal other than the child, since its expiry would bound the wrong
    context.

    Fixed at write time. Nothing extends a record once it is written.
    """
    if issued_at.tzinfo is None:
        raise ValueError(f"issued_at {issued_at!r} states no UTC offset")
    horizon_end = issued_at + timedelta(seconds=decl.horizon_seconds)
    if sub_grant is not None and isinstance(decl.target, Principal):
        if sub_grant.principal != decl.target:
            raise ValueError(
                f"sub-grant {sub_grant.id!r} is held by "
                f"{principal_key(sub_grant.principal)}, not the declared target "
                f"{principal_key(decl.target)}; its expiry would bound the wrong context"
            )
        return max(horizon_end, parse_aware_instant(sub_grant.expiry))
    return horizon_end


@runtime_checkable
class InheritanceStore(Protocol):
    """Where inheritance records live. Written and read by the broker only.

    The agent never holds a reference to this store or a credential for it.
    """

    def put_record(self, record: InheritanceRecord) -> None:
        """Persist one record, create-only, durably, before returning.

        Raises ``InheritanceRecordExistsError`` when a row already holds the
        record's key, and lets every other failure propagate. The caller
        runs the cause op only after this returns.
        """
        ...

    def live_records(self, target: Principal, now: datetime) -> list[InheritanceRecord]:
        """Every record for ``target`` whose ``notAfter`` is after ``now``.

        Ordered by ``notAfter`` ascending. A read failure, or a stored row that
        does not parse, propagates; the caller mints the turn tainted.
        """
        ...


class InMemoryInheritanceStore:
    """Thread-safe, one process. Two runtimes share it only by sharing the object.

    Nothing survives the process, so ``build_runtime`` never chooses this for
    a deployment: it is a store a caller injects, for tests and for runtimes
    that live in one process.
    """

    def __init__(self) -> None:
        self._rows: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def put_record(self, record: InheritanceRecord) -> None:
        pk = record_pk(record.target)
        with self._lock:
            partition = self._rows.setdefault(pk, {})
            sk = record_sk(record)
            if sk in partition:
                raise InheritanceRecordExistsError(record.id)
            partition[sk] = record.model_dump_json()

    def live_records(self, target: Principal, now: datetime) -> list[InheritanceRecord]:
        floor = instant_key(now)
        with self._lock:
            rows = sorted(self._rows.get(record_pk(target), {}).items())
        records = [InheritanceRecord.model_validate_json(data) for sk, data in rows if sk > floor]
        return [r for r in records if r.live_at(now)]


class DynamoInheritanceStore:
    """Records in the grants table, under their own ``INHERIT#`` key space.

    The grants table because a child zone's runtime already reads it with the
    same identity that reads its grants, so a deployment gains no new table and
    no new read permission. The broker's one write there is an ``UpdateItem``
    confined by ``dynamodb:LeadingKeys`` to ``INHERIT#*``: it is the broker's
    first write into another principal's partition, and the only thing it can
    write is taint.

    The write is a conditional create (``attribute_not_exists(pk)``) through
    ``update_item``, the idiom the proposal stores use, so no ``PutItem`` is
    needed. The read is a strongly consistent Query on the target's partition
    from the current instant onward. The grants table carries no time-to-live,
    so an expired row stays stored until something removes it; the key
    condition and the predicate at use keep it from tainting anything.

    boto3 is imported lazily, so importing this module needs no AWS dependency.
    """

    def __init__(self, table_name: str) -> None:
        self._table_name = table_name
        self.__table = None

    @property
    def _table(self):
        if self.__table is None:
            import boto3  # noqa: PLC0415 -- lazy: no credentials needed at import

            self.__table = boto3.resource("dynamodb").Table(self._table_name)
        return self.__table

    def put_record(self, record: InheritanceRecord) -> None:
        from botocore.exceptions import ClientError  # noqa: PLC0415

        try:
            self._table.update_item(
                Key={"pk": record_pk(record.target), "sk": record_sk(record)},
                UpdateExpression="SET #data = :data",
                ConditionExpression="attribute_not_exists(pk)",
                ExpressionAttributeNames={"#data": "data"},
                ExpressionAttributeValues={":data": record.model_dump_json()},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise InheritanceRecordExistsError(record.id) from exc
            raise

    def live_records(self, target: Principal, now: datetime) -> list[InheritanceRecord]:
        from boto3.dynamodb.conditions import Key  # noqa: PLC0415

        kwargs: dict = {
            "KeyConditionExpression": Key("pk").eq(record_pk(target))
            & Key("sk").gt(instant_key(now)),
            "ConsistentRead": True,
        }
        records: list[InheritanceRecord] = []
        while True:
            resp = self._table.query(**kwargs)
            for item in resp.get("Items", []):
                records.append(InheritanceRecord.model_validate_json(item["data"]))
            last = resp.get("LastEvaluatedKey")
            if not last:
                return [r for r in records if r.live_at(now)]
            kwargs["ExclusiveStartKey"] = last
