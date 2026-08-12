"""
loud_failure — core assert-the-artifact / loud-failure primitives.

Design rules (from sa#25):
  - Never raise Python exceptions for assertion failures; the caller is a
    shell pipeline. Write JSON to stderr and call sys.exit(1).
  - All failures include: invariant, observed, component, ts (UTC ISO-8601).
  - assert_artifact(True, ...) returns normally and emits nothing.
  - require_evidence(label) forces the caller to name what evidence they
    checked, preventing "I called the function" from counting as proof.
"""

import datetime
import functools
import json
import sys
from typing import Any, Callable, Union

_DEFAULT_COMPONENT = "reliability.loud_failure"


def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _emit_failure(invariant: str, observed: str, component: str) -> None:
    record = {
        "level": "ERROR",
        "invariant": invariant,
        "observed": observed,
        "component": component,
        "ts": _now_utc(),
    }
    print(json.dumps(record), file=sys.stderr)
    sys.exit(1)


def assert_artifact(
    predicate: Union[bool, Callable[[], bool]],
    label: str,
    *,
    component: str = _DEFAULT_COMPONENT,
    observed: str | None = None,
) -> None:
    """Assert that an artifact or side effect actually occurred.

    predicate — bool or zero-arg callable returning bool.
    label     — human-readable name of the invariant being checked.
    component — component raising the assertion (defaults to this module).
    observed  — what was actually observed (auto-derived when omitted).

    Pass: returns normally, emits nothing.
    Fail: writes a JSON record to stderr and calls sys.exit(1).

    Example:
        assert_artifact(file_exists("/audit/run.log"), "audit log written")
        assert_artifact(False, "audit bucket reachable")  # exits 1
    """
    if callable(predicate):
        result = predicate()
        if result:
            return
        _emit_failure(
            label,
            observed if observed is not None else "predicate returned False",
            component,
        )
    else:
        if predicate:
            return
        _emit_failure(
            label,
            observed if observed is not None else repr(predicate),
            component,
        )


def require_evidence(label: str, *, component: str | None = None) -> Callable:
    """Decorator — force a check function to return truthy evidence.

    Prevents "I called the function" from counting as proof. The decorated
    function must return a truthy value; falsy → assert_artifact fails loudly.

    component defaults to the decorated function's qualified name.

    Example:
        @require_evidence("S3 audit bucket contains objects")
        def check_bucket(bucket_name):
            return list_objects(bucket_name)  # truthy on non-empty

        check_bucket("my-audit-bucket")  # exits 1 if list is empty
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            comp = component or fn.__qualname__
            assert_artifact(
                bool(result),
                label,
                component=comp,
                observed=f"{fn.__qualname__!r} returned {result!r}",
            )
            return result
        return wrapper
    return decorator
