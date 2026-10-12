"""broker.runtime.input_age — the age of every fetched input a decision depends on.

PTC §6.13 and GAL §6.15 (#176): for each input a decision depended on that was
fetched from a source, the decision point records the instant as of which it
established that input; no input is used past a maximum age the deployment
declares for it; and the decision records its horizon, the earliest instant at
which any input it depended on passes its maximum age. A call held on a decision
is evaluated again when it is released, and an input past its age at that instant
refuses the release.

What a recorded instant is
--------------------------
``InputAsOf`` carries the instant the broker fetched the input and, where the
source stated one, the time the source gave for its answer. The as-of instant is
the EARLIER of the two, computed and never stored, so nothing can hand the broker
an as-of later than its own fetch: a replayed old answer carries its old time and
ages out, and a source whose clock runs fast, or that lies, cannot make its
answer look fresher than the moment it was fetched. Every fetch instant here is
read from the clock BEFORE the read it stamps, which can only make an input look
older than it is.

No source on the broker's decision path states a time for its answer today: the
manifest is a file, and the envelope, grant, counter, delegation and intent rows
are store reads that answer as of the read. The stated time is honoured wherever
one is supplied, and ``InputAsOf`` is the one place an as-of is computed.

What a maximum age buys, and what it does not
---------------------------------------------
A decision that depends on an input past its declared age is refused, before any
counter is drawn or connector reached, with a reason naming the input. That is
the whole of it. Nothing here re-reads an input: the per-call inputs are read
fresh on every decision anyway, and the startup inputs (manifest, envelope,
hmac_key) are fetched again only when the process restarts. So a declared age on
a startup input is a deadline by which the deployment must restart the broker,
after which it refuses every call until it does. With no age declared, the
default, nothing is refused and the as-of instants are still recorded.

Recording never gates: the as-of instants and the horizon ride on the audit
record of each decision whatever the knob says. The age check itself fails
closed: an error while checking refuses the decision with a reason saying so,
and never treats the inputs as fresh.

Decision points the broker reaches during a decision
----------------------------------------------------
A connector can hold a decision point of its own that reads a fetched input, as
the MCP host does with its two-key admission snapshot. ``DecisionInputs.bound``
makes the decision in progress the current one for the duration of the
connector call, and ``establish_in_current_decision`` lets that decision point
add its input to it, so the input's as-of rides on the same record. Outside a
bound decision it records nothing.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Mapping

from safe_agents.broker.schemas.common import InputName
from safe_agents.broker.schemas.decision import Decision, Deny

Clock = Callable[[], datetime.datetime]

# The reason prefix on a decision refused because an input it depends on is past
# its declared maximum age. The input's name follows, so the tape says which.
INPUT_PAST_MAX_AGE_REASON = "input past maximum age"

# The reason prefix on a decision refused because the age check itself raised.
# Fails closed: an error while checking is never read as "every input is fresh".
INPUT_AGE_CHECK_FAILED_REASON = "input age check failed"

_LATEST_INSTANT = datetime.datetime.max.replace(tzinfo=datetime.UTC)


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


@dataclass(frozen=True)
class InputAsOf:
    """When the broker established one input: its fetch, and any time the source stated."""

    fetched_at: datetime.datetime
    stated_at: datetime.datetime | None = None

    @property
    def as_of(self) -> datetime.datetime:
        """The earlier of the fetch and the source's stated time; never later than the fetch."""
        if self.stated_at is None:
            return self.fetched_at
        return min(self.fetched_at, self.stated_at)


@dataclass(frozen=True)
class InputAgePolicy:
    """What a runtime knows about its inputs before any call: built once at startup.

    ``startup`` holds the as-of of every input read once at startup. ``max_age``
    is the deployment's declared maximum age per input; empty declares none.
    """

    startup: Mapping[InputName, InputAsOf] = field(default_factory=dict)
    max_age: Mapping[InputName, datetime.timedelta] = field(default_factory=dict)

    @classmethod
    def from_seconds(
        cls,
        startup: Mapping[InputName, InputAsOf],
        max_age_seconds: Mapping[InputName, int],
    ) -> "InputAgePolicy":
        return cls(
            startup=dict(startup),
            max_age={
                name: datetime.timedelta(seconds=seconds)
                for name, seconds in max_age_seconds.items()
            },
        )


def end_of(as_of: datetime.datetime, max_age: datetime.timedelta) -> datetime.datetime:
    """The instant an input established at ``as_of`` passes ``max_age``.

    Clamped to the last representable instant: an end past it is no bound at
    all, and must never raise inside a decision.
    """
    try:
        return as_of + max_age
    except OverflowError:
        return _LATEST_INSTANT


@dataclass(frozen=True)
class StaleInput:
    """One input past its maximum age at an evaluation instant."""

    name: str
    as_of: datetime.datetime
    max_age: datetime.timedelta

    def describe(self) -> str:
        return (
            f"{self.name} (as of {self.as_of.isoformat()}, maximum age "
            f"{int(self.max_age.total_seconds())}s)"
        )


class DecisionInputs:
    """The inputs ONE decision depended on, and when each was established.

    Built per decision, never shared between requests: a runtime serves
    concurrent calls, and one call's reads must not stamp another's record.
    Starts from the runtime's startup inputs; the per-call reads are added as the
    decision makes them.
    """

    def __init__(self, policy: InputAgePolicy, clock: Clock) -> None:
        self._max_age = policy.max_age
        self._clock = clock
        self._entries: dict[str, InputAsOf] = dict(policy.startup)

    def establish(
        self,
        name: InputName,
        fetched_at: datetime.datetime,
        stated_at: datetime.datetime | None = None,
    ) -> None:
        """Record that this decision read ``name`` at ``fetched_at``.

        A second read of the same input in one decision (the PIP runs for the
        initial decision and again for premise revalidation) keeps the EARLIER
        as-of: the decision depended on both reads, and the earlier one ages first.
        """
        entry = InputAsOf(fetched_at=fetched_at, stated_at=stated_at)
        held = self._entries.get(name)
        if held is None or entry.as_of < held.as_of:
            self._entries[name] = entry

    def timed(
        self, read: Callable[[Any], Any], names: Iterable[InputName]
    ) -> Callable[[Any], Any]:
        """Wrap a read so each call establishes ``names`` at the instant it began."""
        names = tuple(names)

        def _read(arg: Any) -> Any:
            fetched_at = self._clock()
            result = read(arg)
            for name in names:
                self.establish(name, fetched_at)
            return result

        return _read

    def horizon(self) -> datetime.datetime | None:
        """The earliest instant any input this decision depended on passes its age.

        None when no input it depended on has a declared maximum age: no bound.
        """
        ends = [
            end_of(entry.as_of, self._max_age[name])
            for name, entry in self._entries.items()
            if name in self._max_age
        ]
        return min(ends) if ends else None

    def stale(self, now: datetime.datetime) -> list[StaleInput]:
        """Every input past its maximum age at ``now``. At the horizon itself is past."""
        return [
            StaleInput(name=name, as_of=entry.as_of, max_age=self._max_age[name])
            for name, entry in sorted(self._entries.items())
            if name in self._max_age and now >= end_of(entry.as_of, self._max_age[name])
        ]

    def gate(self, decider: Callable[[Any, Any], Decision]) -> Callable[[Any, Any], Decision]:
        """Wrap a decider so an input past its age refuses, at the instant it decides.

        Runs for the initial decision and for enforce()'s premise revalidation
        alike, so the instant checked is the last one before any counter is drawn
        or connector reached. The wrapped decider is not consulted on a refusal.
        An error while checking refuses too, naming the error's type: the check
        fails closed and never lets the decision through unchecked.
        """

        def _gated(call: Any, facts: Any) -> Decision:
            try:
                stale = self.stale(self._clock())
            except Exception as exc:  # noqa: BLE001 - fail closed, recorded as the reason
                return Deny(
                    kind="deny",
                    reason=f"{INPUT_AGE_CHECK_FAILED_REASON}: {type(exc).__name__}",
                )
            if stale:
                return Deny(
                    kind="deny",
                    reason=(
                        f"{INPUT_PAST_MAX_AGE_REASON}: "
                        + "; ".join(item.describe() for item in stale)
                    ),
                )
            return decider(call, facts)

        return _gated

    @contextlib.contextmanager
    def bound(self) -> Iterator["DecisionInputs"]:
        """Make this the current decision while a connector call runs.

        A decision point inside the connector adds its own input through
        ``establish_in_current_decision``. The binding is a context variable, so
        it follows the call into work the connector schedules from this thread
        and never reaches a concurrent decision's.
        """
        token = _CURRENT_DECISION.set(self)
        try:
            yield self
        finally:
            _CURRENT_DECISION.reset(token)

    def audit_fields(self) -> dict[str, Any]:
        """The ``emit`` keyword arguments carrying this decision's instants and horizon."""
        horizon = self.horizon()
        return {
            "inputs_as_of": {
                name: entry.as_of.isoformat() for name, entry in sorted(self._entries.items())
            }
            or None,
            "horizon": horizon.isoformat() if horizon is not None else None,
        }


_CURRENT_DECISION: contextvars.ContextVar[DecisionInputs | None] = contextvars.ContextVar(
    "safe_agents_current_decision_inputs", default=None
)


def establish_in_current_decision(
    name: InputName,
    fetched_at: datetime.datetime,
    stated_at: datetime.datetime | None = None,
) -> None:
    """Add an input to the decision in progress, if one is bound; else nothing."""
    inputs = _CURRENT_DECISION.get()
    if inputs is not None:
        inputs.establish(name, fetched_at, stated_at)
