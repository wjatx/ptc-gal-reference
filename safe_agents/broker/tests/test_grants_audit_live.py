"""#62 — opt-in read-only audit of the DEPLOYED grants table.

Opt-in: set GRANTS_AUDIT_LIVE=1 with AWS credentials for the target account
(the same env-gated idiom as test_airlock_live.py). The table name resolves
from the `safe-agents-<env>-grants-table-name` CloudFormation export the State
stack publishes, so the run needs no per-run wiring; GRANTS_AUDIT_ENV selects
the environment (default: development).

Two modes, decided by what the invoking identity holds:

  keyless — no BROKER_HMAC_KEY in env: the CI mode (the namespace-split
            doctrine keeps the grant HMAC key away from CI identities). The
            HMAC rules land in skipped_rules and the test asserts that set
            EXACTLY — a rule silently vanishing from skipped_rules is a
            failure, never a quieter pass.
  keyed   — BROKER_HMAC_KEY present (operator-fetched, consumed with the same
            .encode() the demotion runner uses): the tamper rules run too.

RECORD_SIGNATURE_VERIFIES runs when ISSUER_VERIFY_KEYS_PARAM names the SSM
parameter holding the issuer's PUBLIC keys ({key_id: public_key_pem} JSON —
issuer_keys.resolve_issuer_verify_keys, the #194 read-only seam; deliberately
Parameter Store, not Secrets Manager, so the watcher keeps reading no secrets
at all). Unset, the rule lands in skipped_rules and is asserted skipped —
same loud-and-exact discipline as the HMAC rules. A set-but-unresolvable
parameter fails the run closed, never a quieter pass.

The test performs NO writes: its only AWS calls are CloudFormation
list_exports and the auditor's paginated DynamoDB Scan.
"""

import os
from types import SimpleNamespace

import pytest

from safe_agents.broker.grants.audit import (
    ACKNOWLEDGMENT_SIGNATURE_VERIFIES,
    HMAC_RULES,
    RECORD_SIGNATURE_VERIFIES,
    load_dataset,
    run_audit,
)
from safe_agents.broker.grants.issuer_keys import resolve_issuer_verify_keys

pytestmark = pytest.mark.skipif(
    not os.environ.get("GRANTS_AUDIT_LIVE"),
    reason="GRANTS_AUDIT_LIVE not set — opt-in read-only audit of the deployed grants table",
)

_ENV = os.environ.get("GRANTS_AUDIT_ENV", "development")


def resolve_live() -> SimpleNamespace:
    """Resolve the deployed grants table.

    GRANTS_AUDIT_TABLE_NAME wins when set — the CI job passes the deterministic
    per-env name so the watcher role needs no cloudformation:ListExports; the
    CloudFormation-export path stays for operator runs.
    """
    import boto3

    override = os.environ.get("GRANTS_AUDIT_TABLE_NAME")
    if override:
        return SimpleNamespace(table=boto3.resource("dynamodb").Table(override))

    cfn = boto3.client("cloudformation")
    exports: dict[str, str] = {}
    for page in cfn.get_paginator("list_exports").paginate():
        for exp in page["Exports"]:
            exports[exp["Name"]] = exp["Value"]

    name = f"safe-agents-{_ENV}-grants-table-name"
    assert name in exports, (
        f"missing CloudFormation export {name} — is the State stack deployed?"
    )
    return SimpleNamespace(table=boto3.resource("dynamodb").Table(exports[name]))


@pytest.fixture(scope="module")
def live():
    return resolve_live()


def test_live_grants_table_audit_is_clean(live):
    # Same key sourcing + encoding as the demotion runner's _build_stores:
    # BROKER_HMAC_KEY env, utf-8 encoded; absent/empty = keyless mode.
    hmac_key = os.environ.get("BROKER_HMAC_KEY", "").encode() or None
    # Read-only issuer verify keys (#194): None when ISSUER_VERIFY_KEYS_PARAM
    # is unset; a set-but-unresolvable parameter raises and fails the run.
    record_key_resolver = resolve_issuer_verify_keys()

    report = run_audit(
        load_dataset(live.table),
        hmac_key=hmac_key,
        record_key_resolver=record_key_resolver,
    )

    mode = "keyed" if hmac_key else "keyless"
    sig_mode = "verify-keys" if record_key_resolver is not None else "no-verify-keys"
    print(
        f"grants audit ({_ENV}, {mode}, {sig_mode}): "
        f"{report.grants_examined} grants, {report.records_examined} records, "
        f"{report.proposals_examined} proposals examined; "
        f"{len(report.violations)} violations; "
        f"{len(report.acknowledged)} acknowledged; "
        f"skipped_rules={sorted(report.skipped_rules)}"
    )
    # Acknowledged findings (#196) are annotations, never silence: print each
    # so a green-with-annotations dispatch shows exactly what was waived.
    for entry in report.acknowledged:
        print(
            f"  acknowledged [{entry.violation.rule}] {entry.violation.coordinate}: "
            f"{entry.waiver_ref}"
        )

    # Skipping must be loud AND exact: a rule missing from skipped_rules in
    # keyless mode means it either ran without the key or silently vanished.
    expected_skipped = set()
    if record_key_resolver is None:
        expected_skipped.add(RECORD_SIGNATURE_VERIFIES)
        # No resolver ⇒ acknowledgments cannot be verified, so none apply
        # (fail toward RED) and the skip is loud.
        expected_skipped.add(ACKNOWLEDGMENT_SIGNATURE_VERIFIES)
    if hmac_key is None:
        expected_skipped |= set(HMAC_RULES)
    assert set(report.skipped_rules) == expected_skipped, (
        f"{mode} mode must skip exactly {sorted(expected_skipped)}, "
        f"got {sorted(report.skipped_rules)}"
    )

    rendered = "\n".join(
        f"  [{v.rule}] {v.coordinate}: {v.detail}" for v in report.violations
    )
    assert report.violations == (), (
        f"live grants-table audit ({_ENV}, {mode}) found "
        f"{len(report.violations)} violation(s):\n{rendered}"
    )
