"""durations — the `whenever` seam for ISO-8601 durations (sa#214).

Library posture (sa#214, decided 2026-07-16): the stdlib stays for the
UTC-pure core (period buckets, absolute-timedelta window stepping, epoch
TTLs) — it is correct there and a migration is churn without a bug class.
`whenever` (Rust-backed) is adopted surgically at the risky edges as we touch
them. This module is the first edge: duration PARSING, which the stdlib
cannot do at all.

Validate, never normalize: stored grants carry an integrity hash over their
JSON bytes and proposals ride an HMAC — a validator that rewrote "P3W" to
"P21D" would break both. The wire format stays the exact string given; only
acceptance is decided here.
"""

from whenever import ItemizedDelta

# Calendar units are ambiguous as time spans (a month is 28–31 days, a year
# 365–366): a label latency carrying them has no deterministic length, so they
# are refused. Weeks and days are exact and stay allowed.
_CALENDAR_AMBIGUOUS_UNITS = ("years", "months")


def validate_label_latency(value: str) -> str:
    """Accept a labelLatency string or raise ValueError; never rewrite it.

    The accepted grammar: an ISO-8601 duration parseable by
    `ItemizedDelta.parse_iso`, nonnegative (a negative time-to-ground-truth is
    meaningless), with no year/month components (calendar-ambiguous as
    timedeltas). "PT0S" is allowed — immediate ground truth is coherent.
    """
    try:
        delta = ItemizedDelta.parse_iso(value)
    except ValueError as exc:
        raise ValueError(
            f"labelLatency must be an ISO-8601 duration (e.g. 'PT1H', 'P7D'); "
            f"got {value!r}: {exc}"
        ) from exc
    if delta.sign() < 0:
        raise ValueError(
            f"labelLatency must be nonnegative; got {value!r} — a negative "
            "time-to-ground-truth is meaningless."
        )
    ambiguous = [u for u in _CALENDAR_AMBIGUOUS_UNITS if u in set(delta.keys())]
    if ambiguous:
        raise ValueError(
            f"labelLatency must not carry calendar-ambiguous units "
            f"({', '.join(ambiguous)}); got {value!r} — a month/year has no "
            "deterministic length. Use weeks, days, or time units."
        )
    return value
