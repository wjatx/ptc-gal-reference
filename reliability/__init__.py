"""
reliability — assert-the-artifact / loud-failure pattern library.

Base platform package for sa#6 (reliability & testing). Agent-agnostic.

Public API:
    assert_artifact(predicate, label, *, component, observed)
    require_evidence(label, *, component)

    emit_heartbeat(*, component, heartbeat_fn, extra)
    emit_meta_alarm(msg, *, component, extra)
    emit_content_alarm(msg, *, notify_fn, component, extra)

    SmokeHarness   — non-exiting check aggregator for alert-path smoke tests
    CheckResult    — result dataclass for a single smoke check

Predicate helpers (pass directly to assert_artifact or SmokeHarness.check):
    file_exists(path, *, min_bytes)
    s3_object_exists(bucket, key, *, client)
    dynamodb_item_exists(table_name, key, *, client)
    policy_matches(policy_doc, expected)
"""

from reliability.loud_failure import assert_artifact, require_evidence
from reliability.meta_alarm import emit_content_alarm, emit_heartbeat, emit_meta_alarm
from reliability.predicates import (
    dynamodb_item_exists,
    file_exists,
    policy_matches,
    s3_object_exists,
)
from reliability.smoke import CheckResult, SmokeHarness

__all__ = [
    "assert_artifact",
    "require_evidence",
    "emit_heartbeat",
    "emit_meta_alarm",
    "emit_content_alarm",
    "file_exists",
    "s3_object_exists",
    "dynamodb_item_exists",
    "policy_matches",
    "SmokeHarness",
    "CheckResult",
]
