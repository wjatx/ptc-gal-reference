"""broker.enforcement — execution-integrity layer for the tool broker.

Exports:
    enforce           — the main entry point; wraps PDP decision with:
                          idempotency deduplication
                          premise revalidation (re-read facts, re-decide)
                          atomic budget counter decrement
                          write-ahead ledger (WAL)
                          HITL gate for require_approval decisions
    EnforcementStore  — the persistence Protocol (implement for a new backend)
    InMemoryStore     — thread-safe in-process fake for tests
    DynamoStore       — DynamoDB implementation with conditional writes (lazy boto3)
    EnforcementResult — the return type of enforce()
    LedgerEntry       — WAL record type
    IdempotencyRecord — stored outcome for idempotency deduplication

See engine.py for the full behavioral contract; SCHEMAS.md §6 for budget semantics.
"""

from .engine import enforce
from .store import (
    ACTION_CAP_SUFFIX,
    ERROR_BUDGET_SUFFIX,
    FALSE_ACTION_SUFFIX,
    HUMAN_OVERRIDE_SUFFIX,
    OBSERVATIONS_SUFFIX,
    QUERY_BYTES_SUFFIX,
    UNBOUNDED_COUNTER_CAP,
    DynamoStore,
    EnforcementStore,
    InMemoryStore,
    current_period_bucket,
    current_utc_day,
    period_step,
    read_counter_window,
    scoped_counter_key,
)
from .types import EnforcementResult, IdempotencyRecord, LedgerEntry

__all__ = [
    "enforce",
    "scoped_counter_key",
    "read_counter_window",
    "current_utc_day",
    "current_period_bucket",
    "period_step",
    "OBSERVATIONS_SUFFIX",
    "FALSE_ACTION_SUFFIX",
    "HUMAN_OVERRIDE_SUFFIX",
    "ERROR_BUDGET_SUFFIX",
    "QUERY_BYTES_SUFFIX",
    "ACTION_CAP_SUFFIX",
    "UNBOUNDED_COUNTER_CAP",
    "EnforcementStore",
    "InMemoryStore",
    "DynamoStore",
    "EnforcementResult",
    "IdempotencyRecord",
    "LedgerEntry",
]
