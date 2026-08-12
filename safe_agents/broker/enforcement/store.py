"""EnforcementStore — persistence interface for enforcement state.

Two implementations:
  InMemoryStore  — thread-safe in-process fake for tests; no AWS, no creds
  DynamoStore    — production DynamoDB with conditional writes; boto3 is imported
                   lazily (inside methods) so this module loads without credentials

The Protocol is the contract; callers depend only on it.
"""

from __future__ import annotations

import datetime
import threading
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .types import IdempotencyRecord, LedgerEntry

if TYPE_CHECKING:
    from safe_agents.broker.schemas.common import CounterPeriod, Principal


# ---------------------------------------------------------------------------
# Evidence-counter suffixes (#193) — the track-record labels the grant ceremony
# reads and the PEP writes, on the same scoped_counter_key coordinate as the
# budget meters so evidence and enforcement can never disagree. Defined HERE
# (not in grants/) because the PEP is the writer and must not import upward;
# grants/commands.py re-exports them for its readers.
# ---------------------------------------------------------------------------
OBSERVATIONS_SUFFIX = "observations"
FALSE_ACTION_SUFFIX = "false_action"
HUMAN_OVERRIDE_SUFFIX = "human_override"
ERROR_BUDGET_SUFFIX = "error_budget"
QUERY_BYTES_SUFFIX = "query_bytes"
ACTION_CAP_SUFFIX = "counter"

# Evidence counters are labels, not caps — they must never refuse an increment.
UNBOUNDED_COUNTER_CAP = 1e18

# ---------------------------------------------------------------------------
# Counter periods (#212) — the time-scale knob.
#
# The bucket segment of every counter key is a PERIOD bucket. "utc-day" is the
# default and its bucket format (YYYYMMDD) is byte-for-byte the pre-#212 key, so
# every existing row reads as a day-period row with no migration ("compat via
# period-in-key": an 8-digit bucket IS a day bucket; an hour bucket carries a
# 'T'). The period is manifest-named and image-baked — authority-shaping config
# is never store-mutable — and there is deliberately NO clock-injection seam:
# real time always elapses, only the bucket size changes.
# ---------------------------------------------------------------------------
_PERIOD_FORMAT: dict[str, str] = {"utc-day": "%Y%m%d", "utc-hour": "%Y%m%dT%H"}
_PERIOD_STEP: dict[str, datetime.timedelta] = {
    "utc-day": datetime.timedelta(days=1),
    "utc-hour": datetime.timedelta(hours=1),
}

# Bound on read_counter_window's bucket-key loop: wide enough for any plausible
# evidence window, small enough that a typo'd window can't turn one read into
# thousands of point reads. Per period — a year of days, a year of hours.
MAX_WINDOW_PERIODS: dict[str, int] = {"utc-day": 366, "utc-hour": 8784}

# Back-compat name (pre-#212): the day-period window bound.
MAX_WINDOW_DAYS = MAX_WINDOW_PERIODS["utc-day"]


def period_step(period: "CounterPeriod" = "utc-day") -> datetime.timedelta:
    """One period's wall-clock length — the multiplier consumers use to express
    lifecycle durations (dwell hysteresis, proposal TTLs) in periods."""
    _require_known_period(period)
    return _PERIOD_STEP[period]


def _require_known_period(period: str) -> None:
    if period not in _PERIOD_FORMAT:
        raise ValueError(
            f"unknown counter period {period!r}; expected one of {sorted(_PERIOD_FORMAT)}"
        )


def _validate_bucket(bucket: str, period: str) -> None:
    """Refuse a bucket that does not match the period's format — a malformed
    bucket keys the wrong coordinate silently, so it raises instead."""
    if period == "utc-day":
        if len(bucket) == 8 and bucket.isdigit():
            return
        raise ValueError(f"utc-day bucket must be a YYYYMMDD string, got {bucket!r}")
    # utc-hour: YYYYMMDDTHH
    if len(bucket) == 11 and bucket[8] == "T" and (bucket[:8] + bucket[9:]).isdigit():
        return
    raise ValueError(f"utc-hour bucket must be a YYYYMMDDTHH string, got {bucket!r}")


def period_bucket_of(
    moment: datetime.datetime, period: "CounterPeriod" = "utc-day"
) -> str:
    """Render an aware datetime as its UTC period-bucket key segment — the one
    derivation of the bucket format (writers, readers, and back-writers all
    key through here or its callers)."""
    _require_known_period(period)
    return moment.astimezone(datetime.UTC).strftime(_PERIOD_FORMAT[period])


def current_period_bucket(period: "CounterPeriod" = "utc-day") -> str:
    """The current UTC period bucket — the one derivation callers use to pin an
    anchor_bucket across several read_counter_window calls."""
    return period_bucket_of(datetime.datetime.now(datetime.UTC), period)


def current_utc_day() -> str:
    """Today's UTC day as the YYYYMMDD key segment — the day-period
    specialization of current_period_bucket, kept for its many callers."""
    return current_period_bucket("utc-day")


def scoped_counter_key(
    principal: "Principal",
    tool: str,
    op: str,
    suffix: str,
    *,
    period: "CounterPeriod" = "utc-day",
    bucket: str | None = None,
    day: str | None = None,
) -> str:
    """The ONE derivation of a budget-counter key — used by both the PEP (which
    increments) and the PIP (which reads facts); they MUST agree or the PDP's cap
    rule evaluates a different counter than enforce() draws.

    Scoped by PRINCIPAL and UTC PERIOD (day-scoping decided 2026-07-08, cutover
    smoke; generalized to periods in #212): the original bare
    ``{tool}.{op}:counter`` key was shared by every principal on the table and
    never reset, so ``caps.actions_per_utc_day`` compared against all-time
    GLOBAL spend — one principal could exhaust another's budget, and every
    principal eventually walked into its own cap on accumulated history.
    Principal-scoping isolates budgets; period-scoping makes each cap a per-op
    PER-PERIOD budget with no reset job (a new period is a new key; old keys age
    out). ``suffix`` is "counter" (action cap), "query_bytes" (sa#137 egress
    budget), or an evidence label (the ``*_SUFFIX`` constants above, #193).

    ``period`` is the manifest-named bucket size (default "utc-day", whose key
    is byte-for-byte the pre-#212 format). ``bucket`` addresses a specific
    period's key — used by read_counter_window to walk a multi-period evidence
    window. None means the current period, which every writer uses; only
    readers pass an explicit bucket. A malformed bucket raises rather than
    silently keying the wrong coordinate. ``day`` is the pre-#212 spelling of
    ``bucket`` and asserts day semantics (it refuses under any other period).
    """
    _require_known_period(period)
    if day is not None:
        if bucket is not None:
            raise ValueError("pass bucket= or day=, not both")
        if period != "utc-day":
            raise ValueError(
                f"day= asserts a utc-day bucket but period is {period!r}; pass bucket="
            )
        bucket = day
    principal_key = f"{principal.agentId}#{principal.skill}#{principal.user}#{principal.tier}"
    if bucket is None:
        bucket = current_period_bucket(period)
    else:
        _validate_bucket(bucket, period)
    return f"{principal_key}:{tool}.{op}:{bucket}:{suffix}"


def read_counter_window(
    store: "EnforcementStore",
    principal: "Principal",
    tool: str,
    op: str,
    suffix: str,
    window_periods: int,
    *,
    period: "CounterPeriod" = "utc-day",
    anchor_bucket: str | None = None,
) -> float:
    """Sum a scoped counter over the last ``window_periods`` periods (anchor
    inclusive).

    read_counter is a single-period point read, so before #193 a ceremony
    ``window_n`` silently meant "the current period only". This walks the
    bucket-keyed coordinates directly — a bounded loop of point reads, fine at
    this scale since the counters table has no TTL (bucket keys are retained
    forever). A rollup item would be a second write path for the same fact;
    rejected.

    ``anchor_bucket`` (in the period's bucket format, default the current
    period) pins the newest period of the window. A caller reading SEVERAL
    suffixes for one evaluation must derive the anchor once and pass it to
    every read — otherwise a period rollover between reads sums the metrics
    over different windows. A window at one period NEVER reads another
    period's rows (the bucket formats are disjoint), so a period mismatch
    between writer and reader yields zero evidence — failing toward less
    authority, never a wrong sum.
    """
    _require_known_period(period)
    max_window = MAX_WINDOW_PERIODS[period]
    if not 1 <= window_periods <= max_window:
        raise ValueError(
            f"window_periods must be between 1 and {max_window} for {period}, "
            f"got {window_periods}"
        )
    fmt = _PERIOD_FORMAT[period]
    if anchor_bucket is None:
        anchor = datetime.datetime.now(datetime.UTC)
    else:
        _validate_bucket(anchor_bucket, period)
        anchor = datetime.datetime.strptime(anchor_bucket, fmt)
    step = _PERIOD_STEP[period]
    total = 0.0
    for offset in range(window_periods):
        bucket = (anchor - offset * step).strftime(fmt)
        total += store.read_counter(
            scoped_counter_key(principal, tool, op, suffix, period=period, bucket=bucket)
        )
    return total


@runtime_checkable
class EnforcementStore(Protocol):
    """Persistence interface for the enforcement layer.

    All mutating operations that require atomicity (counter increments, idempotency
    insertion) are expressed as compare-and-set primitives returning a bool to
    indicate whether the caller won the race.
    """

    def get_idempotency(self, key: str) -> IdempotencyRecord | None:
        """Return the stored record for this key, or None if not seen before."""
        ...

    def put_idempotency_if_absent(self, record: IdempotencyRecord) -> bool:
        """Insert the record only if the key is not already present.

        Returns True on first insertion; False if the key already exists.
        Must be atomic: two concurrent calls with the same key produce exactly one True.
        """
        ...

    def delete_idempotency(self, key: str) -> None:
        """Remove the stored record for this key; a no-op if absent.

        Used by enforce() to evict stale non-executed outcomes (#148) so the
        key becomes recordable again once a retry actually executes.
        """
        ...

    def try_increment_counter(
        self, counter_key: str, delta: float, cap: float
    ) -> bool:
        """Atomically increment the named counter by delta if cap is not exceeded.

        Returns True when the counter is updated (current + delta <= cap).
        Returns False when the cap would be exceeded (current + delta > cap).

        Must be atomic: two concurrent calls cannot both succeed if the remaining
        headroom is less than 2 × delta.
        """
        ...

    def read_counter(self, counter_key: str) -> float:
        """Return the current accumulated counter value (0.0 if never incremented).

        A read-only point read — never mutates. Both real callers stay
        side-effect-free through it: the PIP derives its budget facts (the cap
        counter, the sa#137 query-egress counter) and the PEP detects an
        error-budget breach after metering (#184). The authoritative atomic bound
        stays try_increment_counter's compare-and-set; this read is advisory.
        """
        ...

    def write_ledger(self, entry: LedgerEntry) -> None:
        """Persist the ledger entry. Must be durable before the connector is called."""
        ...

    def commit_ledger(self, entry_id: str, ts_committed: str) -> None:
        """Mark a ledger entry as committed (side effect successfully executed)."""
        ...

    def compensate_ledger(self, entry_id: str, error: str) -> None:
        """Mark a ledger entry as compensated (undo attempted after failure)."""
        ...

    def escalate_ledger(self, entry_id: str, error: str) -> None:
        """Mark a ledger entry as escalated (human intervention required)."""
        ...

    def get_uncommitted_entries(self) -> list[LedgerEntry]:
        """Return all entries with status 'uncommitted' — WAL replay on restart."""
        ...


# ---------------------------------------------------------------------------
# InMemoryStore — thread-safe fake; atomicity via per-key Lock
# ---------------------------------------------------------------------------


class InMemoryStore:
    """Thread-safe in-memory implementation for tests and local development.

    Counter atomicity is enforced with a per-counter threading.Lock that wraps
    a check → mutate cycle. This exercises the same compare-and-set semantics as
    DynamoDB's ConditionExpression without requiring AWS credentials or network.
    """

    def __init__(self) -> None:
        self._idempotency: dict[str, IdempotencyRecord] = {}
        self._idempotency_lock = threading.Lock()

        # Counters are protected individually so unrelated counters do not contend.
        self._counters: dict[str, float] = {}
        self._counter_locks: dict[str, threading.Lock] = {}
        self._counter_registry_lock = threading.Lock()

        self._ledger: dict[str, LedgerEntry] = {}
        self._ledger_lock = threading.Lock()

    # -- idempotency ----------------------------------------------------------

    def get_idempotency(self, key: str) -> IdempotencyRecord | None:
        with self._idempotency_lock:
            return self._idempotency.get(key)

    def put_idempotency_if_absent(self, record: IdempotencyRecord) -> bool:
        with self._idempotency_lock:
            if record.key in self._idempotency:
                return False
            self._idempotency[record.key] = record
            return True

    def delete_idempotency(self, key: str) -> None:
        with self._idempotency_lock:
            self._idempotency.pop(key, None)

    # -- counters -------------------------------------------------------------

    def _get_counter_lock(self, key: str) -> threading.Lock:
        with self._counter_registry_lock:
            if key not in self._counter_locks:
                self._counter_locks[key] = threading.Lock()
            return self._counter_locks[key]

    def try_increment_counter(
        self, counter_key: str, delta: float, cap: float
    ) -> bool:
        lock = self._get_counter_lock(counter_key)
        with lock:
            current = self._counters.get(counter_key, 0.0)
            if current + delta > cap:
                return False
            self._counters[counter_key] = current + delta
            return True

    def read_counter(self, counter_key: str) -> float:
        """Read the current counter value without incrementing (EnforcementStore)."""
        lock = self._get_counter_lock(counter_key)
        with lock:
            return self._counters.get(counter_key, 0.0)

    # -- ledger ---------------------------------------------------------------

    def write_ledger(self, entry: LedgerEntry) -> None:
        with self._ledger_lock:
            self._ledger[entry.entry_id] = entry

    def commit_ledger(self, entry_id: str, ts_committed: str) -> None:
        with self._ledger_lock:
            e = self._ledger[entry_id]
            e.status = "committed"
            e.ts_committed = ts_committed

    def compensate_ledger(self, entry_id: str, error: str) -> None:
        with self._ledger_lock:
            e = self._ledger[entry_id]
            e.status = "compensated"
            e.error = error

    def escalate_ledger(self, entry_id: str, error: str) -> None:
        with self._ledger_lock:
            e = self._ledger[entry_id]
            e.status = "escalated"
            e.error = error

    def get_uncommitted_entries(self) -> list[LedgerEntry]:
        with self._ledger_lock:
            return [e for e in self._ledger.values() if e.status == "uncommitted"]

    def get_ledger_entry(self, entry_id: str) -> LedgerEntry | None:
        """Test helper — retrieve a ledger entry by ID."""
        with self._ledger_lock:
            return self._ledger.get(entry_id)


# ---------------------------------------------------------------------------
# DynamoStore — production implementation with conditional writes
# ---------------------------------------------------------------------------


class DynamoStore:
    """DynamoDB-backed store with conditional writes for atomic counter increments.

    boto3 is imported lazily (inside each method body) so importing this class does
    not require AWS credentials or the boto3 package to be importable. Unit tests
    use InMemoryStore and never instantiate DynamoStore.

    Table layout (single-table design; pk=partition key, sk=sort key):

      Counter items:
        pk = "COUNTER#{counter_key}"  sk = "v0"
        spent = Decimal              (accumulated; compared atomically)

      Idempotency items:
        pk = "IDEM#{key}"            sk = "v0"
        decision_json = str, ts = str, result_json? = str (absent for
        deny/abstain/require_approval and for records written before sa#108)

      Ledger items:
        pk = "LEDGER#{entry_id}"     sk = "v0"
        idempotency_key?, call_json, decision_kind, status, ts_created,
        ts_committed?, error?

    The table name is resolved at construction time from the CDK StateStack export;
    callers pass it as a string (e.g. os.environ["COUNTERS_TABLE"]).
    """

    def __init__(self, table_name: str) -> None:
        self._table_name = table_name
        self.__table = None  # resolved lazily on first access

    @property
    def _table(self):
        if self.__table is None:
            import boto3  # noqa: PLC0415 — lazy: no creds needed at import time

            dynamodb = boto3.resource("dynamodb")
            self.__table = dynamodb.Table(self._table_name)
        return self.__table

    # -- idempotency ----------------------------------------------------------

    def get_idempotency(self, key: str) -> IdempotencyRecord | None:
        resp = self._table.get_item(Key={"pk": f"IDEM#{key}", "sk": "v0"})
        item = resp.get("Item")
        if item is None:
            return None
        return IdempotencyRecord(
            key=key,
            decision_json=item["decision_json"],
            ts=item["ts"],
            # Tolerate absence: records written before sa#108 (and every
            # deny/abstain/require_approval record) carry no result_json → None.
            result_json=item.get("result_json"),
        )

    def put_idempotency_if_absent(self, record: IdempotencyRecord) -> bool:
        from botocore.exceptions import ClientError  # noqa: PLC0415

        item: dict = {
            "pk": f"IDEM#{record.key}",
            "sk": "v0",
            "decision_json": record.decision_json,
            "ts": record.ts,
        }
        # Only persist result_json when a result was actually produced, so
        # non-executing decisions don't write an empty attribute.
        if record.result_json is not None:
            item["result_json"] = record.result_json

        try:
            self._table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(pk)",
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def delete_idempotency(self, key: str) -> None:
        # DeleteItem is idempotent in DynamoDB — deleting an absent key succeeds.
        self._table.delete_item(Key={"pk": f"IDEM#{key}", "sk": "v0"})

    # -- counters -------------------------------------------------------------

    def try_increment_counter(
        self, counter_key: str, delta: float, cap: float
    ) -> bool:
        """Atomically add delta to the counter iff the result would not exceed cap.

        Uses DynamoDB conditional UpdateItem so two concurrent callers cannot both
        succeed when less than 2×delta of headroom remains.
        """
        from decimal import Decimal  # noqa: PLC0415

        from botocore.exceptions import ClientError  # noqa: PLC0415

        d_delta = Decimal(str(delta))
        # DynamoDB ConditionExpressions forbid BOTH arithmetic (`spent + delta`) AND functions like
        # if_not_exists — only attribute_(not_)exists + comparisons are allowed. So precompute
        # headroom = cap - delta and condition on the CURRENT value:
        #   attribute_not_exists(spent) OR spent <= headroom   ⟺   spent + delta <= cap
        # (arithmetic stays in the UpdateExpression, which does allow it). The conditional
        # UpdateItem is atomic, so two concurrent callers cannot both pass the cap.
        d_headroom = Decimal(str(cap)) - d_delta
        if d_headroom < 0:
            return False  # a single action larger than the whole cap can never fit

        try:
            self._table.update_item(
                Key={"pk": f"COUNTER#{counter_key}", "sk": "v0"},
                UpdateExpression=(
                    "SET spent = if_not_exists(spent, :zero) + :delta"
                ),
                ConditionExpression=(
                    "attribute_not_exists(spent) OR spent <= :headroom"
                ),
                ExpressionAttributeValues={
                    ":delta": d_delta,
                    ":headroom": d_headroom,
                    ":zero": Decimal("0"),
                },
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def read_counter(self, counter_key: str) -> float:
        """Read the current accumulated counter value (0.0 if never incremented).

        Non-atomic point read used by the PIP to derive the cap-budget fact; the
        authoritative atomic check is try_increment_counter()'s ConditionExpression.
        """
        resp = self._table.get_item(Key={"pk": f"COUNTER#{counter_key}", "sk": "v0"})
        item = resp.get("Item")
        if item is None or "spent" not in item:
            return 0.0
        return float(item["spent"])

    # -- ledger ---------------------------------------------------------------

    def write_ledger(self, entry: LedgerEntry) -> None:
        item: dict = {
            "pk": f"LEDGER#{entry.entry_id}",
            "sk": "v0",
            "call_json": entry.call_json,
            "decision_kind": entry.decision_kind,
            "status": entry.status,
            "ts_created": entry.ts_created,
        }
        if entry.idempotency_key is not None:
            item["idempotency_key"] = entry.idempotency_key
        if entry.ts_committed is not None:
            item["ts_committed"] = entry.ts_committed
        if entry.error is not None:
            item["error"] = entry.error
        self._table.put_item(Item=item)

    def commit_ledger(self, entry_id: str, ts_committed: str) -> None:
        self._table.update_item(
            Key={"pk": f"LEDGER#{entry_id}", "sk": "v0"},
            UpdateExpression="SET #status = :committed, ts_committed = :ts",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":committed": "committed",
                ":ts": ts_committed,
            },
        )

    def compensate_ledger(self, entry_id: str, error: str) -> None:
        self._table.update_item(
            Key={"pk": f"LEDGER#{entry_id}", "sk": "v0"},
            UpdateExpression="SET #status = :s, #error = :e",
            ExpressionAttributeNames={"#status": "status", "#error": "error"},
            ExpressionAttributeValues={":s": "compensated", ":e": error},
        )

    def escalate_ledger(self, entry_id: str, error: str) -> None:
        self._table.update_item(
            Key={"pk": f"LEDGER#{entry_id}", "sk": "v0"},
            UpdateExpression="SET #status = :s, #error = :e",
            ExpressionAttributeNames={"#status": "status", "#error": "error"},
            ExpressionAttributeValues={":s": "escalated", ":e": error},
        )

    def get_uncommitted_entries(self) -> list[LedgerEntry]:
        """Scan for uncommitted entries. In production, use a GSI for efficiency."""
        resp = self._table.scan(
            FilterExpression="#status = :uncommitted",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":uncommitted": "uncommitted"},
        )
        entries: list[LedgerEntry] = []
        for item in resp.get("Items", []):
            entry_id = item["pk"].removeprefix("LEDGER#")
            entries.append(
                LedgerEntry(
                    entry_id=entry_id,
                    idempotency_key=item.get("idempotency_key"),
                    call_json=item["call_json"],
                    decision_kind=item["decision_kind"],
                    status=item["status"],
                    ts_created=item["ts_created"],
                    ts_committed=item.get("ts_committed"),
                    error=item.get("error"),
                )
            )
        return entries
