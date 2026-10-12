"""clock_skew — a declared skew bound, applied toward less authority.

PTC §6.13 (PTC-49) and GAL §6.7.6 (GAL-42): where the evaluation instant is
compared with a time asserted under another party's clock, a declared skew
bound is applied in the direction that confers LESS authority.

  * An END (an expiry, a certification term, an authority-lowering record) is
    treated as effective up to the bound EARLIER. The comparison is made at
    ``end_judged_at(now, bound) == now + bound``.
  * A START (an authority-raising record, a not-before time, the instant a
    dwell period is counted from) is treated as effective up to the bound
    LATER. The comparison is made at ``start_judged_at(now, bound) == now - bound``.

A bound of zero reproduces the unbounded comparison exactly, and zero is the
default everywhere (docs/friction-doctrine.md: the knob ships OFF).

What this buys, and no more: a party whose clock runs slow, or who holds a
message back, gets no extra window past an end it asserted. Applied one way,
the bound costs an honest party at most its own width. It does not detect a
lying clock, and it does not bound how far a clock may drift.

The bound is RECEIVER configuration: the image-baked ``AgentManifest`` (the
broker, the drain, the ceremony commands), the ``ChannelsManifest`` (the
airlock), or an operator-named CLI flag where a command reads no manifest. It
is never read from the envelope, the grant, the record or the request a
presenter sends. A negative bound is refused rather than accepted: it would
apply the skew toward MORE authority, which is the exact failure this exists
to prevent. A bound wider than ``MAX_CLOCK_SKEW_SECONDS`` (one day) is refused
at load too: no real clock disagreement is that wide, and an unchecked typo
would otherwise load and then fail every comparison with an overflow at
evaluation time instead of naming the field.
"""

from __future__ import annotations

import argparse
import datetime

ZERO_SKEW = datetime.timedelta(0)

# The widest bound any configuration may declare: one day. Far past any honest
# clock disagreement, and far short of where ``now + bound`` overflows.
MAX_CLOCK_SKEW_SECONDS = 86_400
MAX_SKEW = datetime.timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)

_TOO_WIDE = (
    f"a clock-skew bound must be at most {MAX_CLOCK_SKEW_SECONDS} seconds (one day); "
    "a wider bound is a typo, not a clock"
)

_NEGATIVE = (
    "a clock-skew bound must not be negative: a negative bound would apply the "
    "skew toward MORE authority (PTC §6.13, GAL §6.7.6)"
)


def skew_bound(seconds: int) -> datetime.timedelta:
    """The declared bound, in whole seconds, as a timedelta.

    Refuses a negative bound and one wider than ``MAX_CLOCK_SKEW_SECONDS``.

    ``bool`` is refused even though it is an ``int``: ``True`` is not a bound
    anyone meant to declare.
    """
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise TypeError(
            f"clock_skew_seconds must be an int, got {type(seconds).__name__}"
        )
    if seconds < 0:
        raise ValueError(f"{_NEGATIVE}; got clock_skew_seconds={seconds}")
    if seconds > MAX_CLOCK_SKEW_SECONDS:
        raise ValueError(f"{_TOO_WIDE}; got clock_skew_seconds={seconds}")
    return datetime.timedelta(seconds=seconds)


def skew_seconds_arg(text: str) -> int:
    """argparse ``type=`` for a ``--clock-skew-seconds`` flag: an int in [0, one day]."""
    try:
        seconds = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--clock-skew-seconds must be a whole number of seconds, got {text!r}"
        ) from exc
    if seconds < 0:
        raise argparse.ArgumentTypeError(f"{_NEGATIVE}; got {seconds}")
    if seconds > MAX_CLOCK_SKEW_SECONDS:
        raise argparse.ArgumentTypeError(f"{_TOO_WIDE}; got {seconds}")
    return seconds


def _require_bound(bound: datetime.timedelta) -> datetime.timedelta:
    if not isinstance(bound, datetime.timedelta):
        raise TypeError(f"a clock-skew bound must be a timedelta, got {type(bound).__name__}")
    if bound < ZERO_SKEW:
        raise ValueError(f"{_NEGATIVE}; got {bound}")
    if bound > MAX_SKEW:
        raise ValueError(f"{_TOO_WIDE}; got {bound}")
    return bound


def end_judged_at(now: datetime.datetime, bound: datetime.timedelta) -> datetime.datetime:
    """The instant an END asserted under another clock is compared against.

    ``now + bound``: the end takes effect up to the bound earlier than the
    asserted instant.
    """
    return now + _require_bound(bound)


def start_judged_at(now: datetime.datetime, bound: datetime.timedelta) -> datetime.datetime:
    """The instant a START asserted under another clock is compared against.

    ``now - bound``: the start takes effect up to the bound later than the
    asserted instant.
    """
    return now - _require_bound(bound)
