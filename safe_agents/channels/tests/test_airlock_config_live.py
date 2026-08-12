"""#205 — opt-in live post-deploy assertion of the airlock/drain deploy binding.

Sibling to ``test_airlock_live.py`` (same env-gated, exports-resolved idiom). Run
IMMEDIATELY after any channels deploy to prove the deployed function
configuration matches what the operator INTENDED — the mechanical fix for the
retro finding that deploy-time values (manifest path, drain receiver) were
improvised rather than asserted.

Opt-in: AIRLOCK_CONFIG_ASSERT=1 with AWS credentials for the target account.

Operator contract (no defaults — an unset expectation REFUSES, never skips):

- AIRLOCK_EXPECTED_MANIFEST          — the CHANNELS_MANIFEST path you deployed,
  or the literal sentinel ``@absent`` for a deliberately-manifestless deploy
  (no channelsManifestPath context — the stack omits CHANNELS_MANIFEST and the
  empty manifest drops everything); the check then asserts the env var is
  genuinely absent from the function config. Absence must be NAMED — an unset
  expectation still refuses.
- AIRLOCK_EXPECTED_DRAIN_MANIFEST    — required when the drain is deployed
  (``@absent`` carries the same semantics)
- AIRLOCK_EXPECTED_DRAIN_RECEIVER    — required when the drain is deployed
  (``@absent`` carries the same semantics)
- AIRLOCK_ENV                        — environment (default: development)

The mechanical bindings (accepted-queue URL, dedupe table, webhook secret ARN)
are cross-checked against the CloudFormation exports the stacks publish, so the
function env cannot silently drift from the stack wiring. Drain presence is
detected from the ``channels-drain-function-name`` export — absent means the
drain is not deployed (a legitimate skip, unlike an unnamed expectation).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from safe_agents.channels.config_assert import (
    compare_env,
    format_mismatches,
    require_expectation,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("AIRLOCK_CONFIG_ASSERT"),
    reason="AIRLOCK_CONFIG_ASSERT not set — opt-in post-deploy config assertion",
)

_ENV = os.environ.get("AIRLOCK_ENV", "development")

# infra/lib/naming.ts: resourceName(env, base) = f"safe-agents-{env}-{base}".
_AIRLOCK_FUNCTION = f"safe-agents-{_ENV}-airlock"

# CloudFormation export keys (infra/lib/naming.ts exportName = safe-agents-{env}-{key}).
_EXPORT_QUEUE = "channel-accepted-queue-url"
_EXPORT_DEDUPE = "channel-dedupe-table-name"
_EXPORT_SECRET = "channels-webhook-secret-arn"
_EXPORT_DRAIN_FN = "channels-drain-function-name"


def resolve_live() -> SimpleNamespace:
    """Resolve exports + a lambda client (the test_airlock_live.py idiom)."""
    import boto3

    cfn = boto3.client("cloudformation")
    exports: dict[str, str] = {}
    for page in cfn.get_paginator("list_exports").paginate():
        for exp in page["Exports"]:
            exports[exp["Name"]] = exp["Value"]

    def export(key: str) -> str:
        name = f"safe-agents-{_ENV}-{key}"
        assert name in exports, f"missing CloudFormation export {name} — is the stack deployed?"
        return exports[name]

    def export_or_none(key: str) -> str | None:
        return exports.get(f"safe-agents-{_ENV}-{key}")

    return SimpleNamespace(
        export=export,
        export_or_none=export_or_none,
        lam=boto3.client("lambda"),
    )


@pytest.fixture(scope="module")
def live():
    return resolve_live()


def _function_env(lam, function_name: str) -> dict[str, str]:
    conf = lam.get_function_configuration(FunctionName=function_name)
    return conf.get("Environment", {}).get("Variables", {})


def test_airlock_deploy_binding(live):
    """The airlock's manifest + mechanical bindings match intent and exports."""
    expected = {
        # Operator-declared intent — refuses loudly if not named (never defaults).
        "CHANNELS_MANIFEST": require_expectation("AIRLOCK_EXPECTED_MANIFEST"),
        # Mechanical bindings — must equal the stacks' own exports.
        "CHANNELS_ACCEPTED_QUEUE_URL": live.export(_EXPORT_QUEUE),
        "CHANNELS_DEDUPE_TABLE": live.export(_EXPORT_DEDUPE),
        "CHANNELS_WEBHOOK_SECRET_ARN": live.export(_EXPORT_SECRET),
    }
    actual = _function_env(live.lam, _AIRLOCK_FUNCTION)
    mismatches = compare_env(actual, expected)
    assert not mismatches, format_mismatches(_AIRLOCK_FUNCTION, mismatches)


def test_drain_deploy_binding(live):
    """When the drain is deployed, its manifest + receiver match intent."""
    drain_fn = live.export_or_none(_EXPORT_DRAIN_FN)
    if drain_fn is None:
        pytest.skip(
            f"export safe-agents-{_ENV}-{_EXPORT_DRAIN_FN} absent — drain not deployed"
        )
    expected = {
        "CHANNELS_DRAIN_MANIFEST": require_expectation("AIRLOCK_EXPECTED_DRAIN_MANIFEST"),
        "CHANNELS_DRAIN_RECEIVER": require_expectation("AIRLOCK_EXPECTED_DRAIN_RECEIVER"),
    }
    actual = _function_env(live.lam, drain_fn)
    mismatches = compare_env(actual, expected)
    assert not mismatches, format_mismatches(drain_fn, mismatches)
