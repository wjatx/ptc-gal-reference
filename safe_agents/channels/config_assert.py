"""#205 — mechanical post-deploy assertion for the channels airlock/drain binding.

The retro finding this closes: deploy-time values (the airlock's CHANNELS_MANIFEST
path, the drain's manifest path + receiver) were improvised by sub-agents during
deploys because nothing mechanically compared the deployed function configuration
against what the operator *intended*. This module is the pure comparison/refusal
core; the opt-in live check in ``tests/test_airlock_config_live.py`` binds it to
``lambda:GetFunctionConfiguration`` + the CloudFormation exports.

Doctrine (matches the ceremony surface's fail-toward-nothing posture):

- The operator-declared expectations (``AIRLOCK_EXPECTED_MANIFEST``, and for the
  drain ``AIRLOCK_EXPECTED_DRAIN_MANIFEST`` / ``AIRLOCK_EXPECTED_DRAIN_RECEIVER``)
  have NO default. An unset expectation is a REFUSAL — a loud failure telling the
  operator to declare it — never a silent skip and never "accept whatever was
  deployed". Accepting the deployed value as its own expectation would make the
  check vacuously green, which is the exact blindness #205 exists to remove.
- A deliberately-manifestless deploy (the stack omits ``CHANNELS_MANIFEST``
  entirely — the legal empty-manifest drop-everything posture) is declared with
  the literal expectation value ``@absent`` (:data:`EXPECT_ABSENT`): the check
  then asserts the key is genuinely absent from the function config. Absence is
  always NAMED, never inferred from an unset expectation.
- The mechanical bindings (queue URL, dedupe table, webhook secret ARN) are
  cross-checked against the CloudFormation exports the stack itself publishes,
  so drift between the function env and the stack wiring is caught too.
- Every failure reports each key's actual-vs-expected, operator-debuggable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "ConfigAssertRefusal",
    "EXPECT_ABSENT",
    "Mismatch",
    "compare_env",
    "format_mismatches",
    "require_expectation",
]

#: Rendered for a key absent from the function environment (distinct from empty).
ABSENT = "<absent>"

#: Operator sentinel: the literal expectation value ``@absent`` declares "this
#: deploy carries NO such binding" (e.g. a deliberately-manifestless airlock,
#: where the stack omits CHANNELS_MANIFEST entirely — the legal drop-everything
#: posture). The check then asserts the key is genuinely absent from the
#: deployed environment; a present key is a mismatch. Absence must be NAMED via
#: this sentinel — an unset expectation still refuses, never infers absence.
EXPECT_ABSENT = "@absent"


class ConfigAssertRefusal(RuntimeError):
    """The operator did not declare an expectation the check needs.

    Raised (never a skip) when a required ``AIRLOCK_EXPECTED_*`` env var is unset
    or empty — the check refuses to run against an unnamed expectation.
    """


@dataclass(frozen=True)
class Mismatch:
    """One env key whose deployed value differs from the expectation."""

    key: str
    expected: str
    actual: str

    def render(self) -> str:
        return f"{self.key}: expected={self.expected!r} actual={self.actual!r}"


def require_expectation(name: str, *, environ: dict[str, str] | None = None) -> str:
    """Resolve an operator-declared expectation from ``name`` — refusing if unset.

    No default and no fallback to the deployed value: an unset/empty expectation
    raises :class:`ConfigAssertRefusal` with instructions, so the check can never
    silently bless whatever happens to be deployed.

    The returned value may be the :data:`EXPECT_ABSENT` sentinel (``@absent``) —
    an explicitly named "no such binding on this deploy", which is a declaration,
    not a default.
    """
    env = os.environ if environ is None else environ
    value = env.get(name, "").strip()
    if not value:
        raise ConfigAssertRefusal(
            f"expectation {name} is not declared — refusing to assert. "
            f"Export {name}=<the value you intended to deploy> and re-run; "
            "this check never accepts the deployed value as its own expectation."
        )
    return value


def compare_env(actual_env: dict[str, str], expected: dict[str, str]) -> list[Mismatch]:
    """Compare a function's environment against the expected key→value map.

    Returns one :class:`Mismatch` per expected key whose deployed value differs
    (a key missing from ``actual_env`` reports as ``<absent>``). Keys present in
    ``actual_env`` but not in ``expected`` are ignored — this asserts the named
    bindings, it is not an exhaustive env diff.

    An expected value of :data:`EXPECT_ABSENT` (``@absent``) inverts the check
    for that key: the operator declared the deploy carries no such binding, so
    the key must be genuinely missing from ``actual_env`` — a present key (even
    empty) is a mismatch.
    """
    mismatches: list[Mismatch] = []
    for key, want in sorted(expected.items()):
        if want == EXPECT_ABSENT:
            if key in actual_env:
                mismatches.append(
                    Mismatch(key=key, expected=EXPECT_ABSENT, actual=actual_env[key])
                )
        elif actual_env.get(key, ABSENT) != want:
            mismatches.append(
                Mismatch(key=key, expected=want, actual=actual_env.get(key, ABSENT))
            )
    return mismatches


def format_mismatches(function_name: str, mismatches: list[Mismatch]) -> str:
    """One operator-debuggable block: every failing key, actual vs expected."""
    lines = "\n".join(f"  {m.render()}" for m in mismatches)
    return f"deployed configuration of {function_name} does not match:\n{lines}"
