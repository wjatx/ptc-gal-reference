"""Fault-injecting fakes for the broker substrate.

Each fake implements the same Protocol as the real component but raises or
errors on command. Plug these into BrokerRuntime in place of the real
implementations to verify that injected faults produce loud failures — never
a silent success.

All fakes are AWS-free; none import boto3 or require credentials.

Exports:
    FaultEnforcementStore  — wraps InMemoryStore; raises on configured operations.
    FaultAuditSink         — raises on append(); last_hash / next_seq still work
                             so emit() can build the record before failing to write it.
    FaultSecretsProvider   — always raises on fetch_secret().
    FaultConnector         — always raises on execute() (simulates timeout / network error).
    StoreError             — raised by FaultEnforcementStore.
    AuditError             — raised by FaultAuditSink.
    SecretsError           — raised by FaultSecretsProvider.
    ConnectorError         — raised by FaultConnector.
"""

from __future__ import annotations

from typing import Any

from safe_agents.broker.audit._hash import GENESIS_PREV_HASH
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.enforcement.types import IdempotencyRecord, LedgerEntry
from safe_agents.broker.schemas import AuditRecord


# ---------------------------------------------------------------------------
# Domain errors — distinct types so tests can assert the specific fault origin.
# ---------------------------------------------------------------------------


class StoreError(RuntimeError):
    """Raised by FaultEnforcementStore to simulate a DynamoDB failure."""


class AuditError(RuntimeError):
    """Raised by FaultAuditSink to simulate an S3 PutObject failure."""


class SecretsError(RuntimeError):
    """Raised by FaultSecretsProvider to simulate a Secrets Manager failure."""


class ConnectorError(RuntimeError):
    """Raised by FaultConnector to simulate a connector timeout or network error."""


# ---------------------------------------------------------------------------
# FaultEnforcementStore
# ---------------------------------------------------------------------------


class FaultEnforcementStore:
    """EnforcementStore that injects failures on specified operations.

    All operations not listed in fail_on delegate transparently to an
    InMemoryStore. The methods listed in fail_on raise StoreError instead.

    Parameters
    ----------
    fail_on:
        Set of method names that should raise. Valid entries:
        "get_idempotency", "put_idempotency_if_absent", "complete_idempotency",
        "fail_idempotency", "delete_idempotency",
        "try_increment_counter", "read_counter", "write_ledger", "commit_ledger",
        "compensate_ledger", "escalate_ledger", "get_uncommitted_entries".
    inner:
        Optional InMemoryStore to delegate to. A fresh one is created when
        not supplied.
    """

    def __init__(
        self,
        *,
        fail_on: set[str] | None = None,
        inner: InMemoryStore | None = None,
    ) -> None:
        self._inner = inner or InMemoryStore()
        self._fail_on: set[str] = fail_on or set()

    def _check(self, method: str) -> None:
        if method in self._fail_on:
            raise StoreError(f"simulated DynamoDB failure in {method!r}")

    # -- idempotency -----------------------------------------------------------

    def get_idempotency(self, key: str) -> IdempotencyRecord | None:
        self._check("get_idempotency")
        return self._inner.get_idempotency(key)

    def put_idempotency_if_absent(self, record: IdempotencyRecord) -> bool:
        self._check("put_idempotency_if_absent")
        return self._inner.put_idempotency_if_absent(record)

    def complete_idempotency(
        self, key: str, *, decision_json: str, result_json: str | None
    ) -> bool:
        self._check("complete_idempotency")
        return self._inner.complete_idempotency(
            key, decision_json=decision_json, result_json=result_json
        )

    def fail_idempotency(self, key: str, *, error: str) -> bool:
        self._check("fail_idempotency")
        return self._inner.fail_idempotency(key, error=error)

    def delete_idempotency(self, key: str) -> None:
        self._check("delete_idempotency")
        self._inner.delete_idempotency(key)

    # -- counters --------------------------------------------------------------

    def try_increment_counter(
        self, counter_key: str, delta: float, cap: float
    ) -> bool:
        self._check("try_increment_counter")
        return self._inner.try_increment_counter(counter_key, delta, cap)

    def read_counter(self, counter_key: str) -> float:
        self._check("read_counter")
        return self._inner.read_counter(counter_key)

    # -- ledger ----------------------------------------------------------------

    def write_ledger(self, entry: LedgerEntry) -> None:
        self._check("write_ledger")
        self._inner.write_ledger(entry)

    def commit_ledger(self, entry_id: str, ts_committed: str) -> None:
        self._check("commit_ledger")
        self._inner.commit_ledger(entry_id, ts_committed)

    def compensate_ledger(self, entry_id: str, error: str) -> None:
        self._check("compensate_ledger")
        self._inner.compensate_ledger(entry_id, error)

    def escalate_ledger(self, entry_id: str, error: str) -> None:
        self._check("escalate_ledger")
        self._inner.escalate_ledger(entry_id, error)

    def get_uncommitted_entries(self) -> list[LedgerEntry]:
        self._check("get_uncommitted_entries")
        return self._inner.get_uncommitted_entries()


# ---------------------------------------------------------------------------
# FaultAuditSink
# ---------------------------------------------------------------------------


class FaultAuditSink:
    """AuditSink that raises AuditError on every append() call.

    last_hash and next_seq return the genesis/initial values so that emit()
    can build and hash the AuditRecord before the sink refuses to store it.
    This simulates an S3 PutObject failure after the record is fully formed
    but before it lands in the WORM store.
    """

    def append(self, record: AuditRecord) -> None:
        raise AuditError(
            f"simulated S3 PutObject failure at seq={record.seq}"
        )

    @property
    def last_hash(self) -> str:
        return GENESIS_PREV_HASH

    @property
    def next_seq(self) -> int:
        return 0


# ---------------------------------------------------------------------------
# FaultSecretsProvider
# ---------------------------------------------------------------------------


class FaultSecretsProvider:
    """SecretsProvider that always raises SecretsError on fetch_secret().

    Simulates AWS Secrets Manager being unavailable or the IAM role lacking
    permission. The Doer calls this inside execute(); a failure here means
    the connector never receives a credential and cannot be called.
    """

    def fetch_secret(self, secret_name: str) -> str:
        raise SecretsError(
            f"simulated Secrets Manager failure for {secret_name!r}"
        )


# ---------------------------------------------------------------------------
# FaultConnector
# ---------------------------------------------------------------------------


class FaultConnector:
    """Connector that always raises ConnectorError on execute().

    Simulates a downstream timeout, network partition, or transient error
    after the broker has decided to allow the call. The Doer will propagate
    this error back through the enforcement layer.

    Parameters
    ----------
    error:
        Optional custom exception to raise. Defaults to a ConnectorError.
    """

    def __init__(self, *, error: Exception | None = None) -> None:
        self._error = error or ConnectorError("simulated connector timeout")

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        raise self._error
