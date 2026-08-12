"""broker.auditor — off-substrate audit-chain verifier + egress-drift watchdog.

Two independent checks; both return structured findings (never raise on detection):

    check_chain_integrity(reader)  — verify the audit tape has no gaps or mutations.
    check_egress_drift(source)     — detect drift between committed and live egress rules.

Both are WATCHDOGS: they detect and alarm; they never write, fix, or apply changes.
Remediation is always a human action.

Injected interfaces allow in-memory fakes for tests (no AWS required) and lazy-boto3
production implementations:

    AuditTapeReader         — protocol for reading the tape (injected into chain verifier).
    EgressPolicySource      — protocol for supplying committed + live rules (injected into watchdog).

    FileTapeReader          — the local floor's JSON-lines tape (#300).
    InMemoryTapeReader      — list-backed fake for tests.
    S3TapeReader            — lazy-boto3 S3 production reader.

    InMemoryEgressPolicySource      — list-backed fake for tests.
    FilePlusAWSEgressPolicySource   — file (committed) + EC2 DescribeSecurityGroupRules (live).

Findings:

    ChainIntegrityFinding  — intact: bool, error: str | None, broken_seq: int | None.
    EgressDriftFinding     — drifted: bool, severity: str, items, extra_live, extra_committed.
                             severity is per-category (ok|warning|critical, sa#52); the
                             watchdog covers both the SG layer and the netns/proxy layer.
"""

from ._chain_verifier import (
    AuditTapeReader,
    ChainIntegrityFinding,
    FileTapeReader,
    InMemoryTapeReader,
    S3TapeReader,
    check_chain_integrity,
)
from ._egress_watchdog import (
    LAYER_NETNS_PROXY,
    LAYER_SG,
    SEVERITY_CRITICAL,
    SEVERITY_OK,
    SEVERITY_WARNING,
    DriftItem,
    EgressDriftFinding,
    EgressPolicySource,
    FilePlusAWSEgressPolicySource,
    InMemoryEgressPolicySource,
    check_egress_drift,
    load_snapshot_rules,
)

__all__ = [
    # chain verifier
    "check_chain_integrity",
    "AuditTapeReader",
    "ChainIntegrityFinding",
    "FileTapeReader",
    "InMemoryTapeReader",
    "S3TapeReader",
    # egress watchdog
    "check_egress_drift",
    "EgressPolicySource",
    "EgressDriftFinding",
    "DriftItem",
    "InMemoryEgressPolicySource",
    "FilePlusAWSEgressPolicySource",
    "load_snapshot_rules",
    # egress severity + layer constants
    "SEVERITY_OK",
    "SEVERITY_WARNING",
    "SEVERITY_CRITICAL",
    "LAYER_SG",
    "LAYER_NETNS_PROXY",
]
