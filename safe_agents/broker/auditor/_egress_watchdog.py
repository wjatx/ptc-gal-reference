"""Egress-policy drift watchdog — compares committed rules to live rules.

This is a WATCHDOG: it detects and reports drift; it never writes, fixes, or applies
changes. All remediation is a human action.

The policy source is injected so callers can supply an in-memory fake for tests or
an AWS/on-box-backed source for production without touching this logic.

Two layers are covered (sa#52; reconciled with docs/model-egress.md):

  layer="sg"          — the box-level security-group egress/ingress rules (CDK synth is
                        the source of truth). Governs what the *box* may reach.
  layer="netns_proxy" — the per-agent confinement: the blackhole-default route in the
                        agent netns, the veth /30 topology, and the model-proxy hostname
                        allowlist (the agent-netns-setup.sh + model-proxy-stub.py scripts
                        are the source of truth). This is the layer that actually confines
                        an autonomous agent on a co-hosted box, where an SG cannot.

Each rule is a plain dict carrying a "layer" field (default "sg" when absent). Equality is
key-order-independent (canonical JSON comparison) so field reordering is not treated as
drift. Severity is assigned per drift item, not as one binary flag (sa#52):

  layer=sg, extra in live, direction=egress  → critical (potential egress bypass)
  layer=sg, extra in live, direction=ingress → warning  (inbound change, monitor only)
  layer=sg, present in git but missing live   → warning  (tighter than expected)
  layer=netns_proxy, proxy allowlist widened  → critical (extra reachable model host)
  layer=netns_proxy, blackhole/veth altered   → critical (confinement topology change)
  layer=netns_proxy, allowlisted host missing → warning  (model may be unreachable)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# Severities (ordered low → high for the finding-level rollup).
SEVERITY_OK = "ok"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
_SEVERITY_RANK = {SEVERITY_OK: 0, SEVERITY_WARNING: 1, SEVERITY_CRITICAL: 2}

# Layers a rule may belong to.
LAYER_SG = "sg"
LAYER_NETNS_PROXY = "netns_proxy"

# Which side of the diff a drift item sits on.
PRESENCE_EXTRA_LIVE = "extra_live"  # in live, absent from committed (shadow rule)
PRESENCE_EXTRA_COMMITTED = "extra_committed"  # committed, absent from live (missing rule)


def _canonical_key(rule: dict) -> str:
    """Deterministic serialisation of a rule dict for set-membership tests."""
    return json.dumps(rule, sort_keys=True, separators=(",", ":"), default=str)


def _classify(rule: dict, presence: str) -> tuple[str, str]:
    """Return (severity, reason) for a single drifted rule.

    Dispatches on the rule's layer; within the SG layer on direction, within the
    netns/proxy layer on kind. An unrecognised layer or kind defaults to critical:
    an unclassifiable difference in the confinement boundary is treated as the loud,
    safe outcome rather than silently downgraded.
    """
    layer = rule.get("layer", LAYER_SG)

    if layer == LAYER_NETNS_PROXY:
        kind = rule.get("kind")
        if kind == "proxy_allow":
            if presence == PRESENCE_EXTRA_LIVE:
                return SEVERITY_CRITICAL, "model-proxy allowlist widened beyond committed hosts"
            return SEVERITY_WARNING, "committed model host missing from live proxy allowlist"
        if kind == "default_route":
            # A missing committed blackhole, or a different live default route, both
            # mean the agent netns has a route it should not — confinement breach.
            return SEVERITY_CRITICAL, "agent-netns blackhole default route missing or altered"
        if kind == "veth":
            return SEVERITY_CRITICAL, "agent-netns veth topology altered (reachable peer changed)"
        return SEVERITY_CRITICAL, "unrecognised netns/proxy expectation drift"

    # layer == sg (the default).
    if presence == PRESENCE_EXTRA_LIVE:
        if rule.get("direction") == "ingress":
            return SEVERITY_WARNING, "extra inbound rule in live (monitor; not the confinement)"
        # egress or unknown direction → treat as a potential egress bypass.
        return SEVERITY_CRITICAL, "extra outbound rule in live (potential egress bypass)"
    return SEVERITY_WARNING, "committed rule missing in live (tighter than expected)"


@runtime_checkable
class EgressPolicySource(Protocol):
    """Provides committed and live egress rule snapshots for comparison.

    Rules from both layers may be mixed in either list; each carries its own "layer"
    field and check_egress_drift() classifies per-rule.
    """

    def committed(self) -> list[dict]:
        """Return the egress rules as checked in to git (the authoritative spec)."""
        ...

    def live(self) -> list[dict]:
        """Return the egress rules currently enforced in the live environment."""
        ...


@dataclass(frozen=True)
class DriftItem:
    """One drifted rule, with its layer-aware severity and a human-readable reason.

    rule     — the original rule dict (not the canonical key).
    presence — PRESENCE_EXTRA_LIVE | PRESENCE_EXTRA_COMMITTED.
    layer    — LAYER_SG | LAYER_NETNS_PROXY.
    severity — SEVERITY_CRITICAL | SEVERITY_WARNING.
    reason   — why this severity was assigned (for the structured alarm message).
    """

    rule: dict
    presence: str
    layer: str
    severity: str
    reason: str


@dataclass(frozen=True)
class EgressDriftFinding:
    """Structured result from check_egress_drift().

    drifted=False, severity="ok"      — live matches committed exactly.
    drifted=True                      — at least one rule differs; severity is the
                                        highest severity among the per-rule items
                                        ("critical" if any item is critical, else "warning").

    items          — per-rule DriftItem objects carrying per-category severity (sa#52).
    extra_live     — rule dicts present in live but absent from committed (shadow rules).
    extra_committed — rule dicts present in committed but absent from live (missing rules).

    extra_live / extra_committed are convenience views over `items`; they hold the
    original rule dicts, not the canonical keys.
    """

    drifted: bool
    severity: str  # "ok" | "warning" | "critical"
    items: list[DriftItem] = field(default_factory=list)
    extra_live: list[dict] = field(default_factory=list)
    extra_committed: list[dict] = field(default_factory=list)

    @property
    def critical_items(self) -> list[DriftItem]:
        """Drift items that must page (severity == critical)."""
        return [i for i in self.items if i.severity == SEVERITY_CRITICAL]

    @property
    def warning_items(self) -> list[DriftItem]:
        """Drift items that log but do not page (severity == warning)."""
        return [i for i in self.items if i.severity == SEVERITY_WARNING]


def check_egress_drift(source: EgressPolicySource) -> EgressDriftFinding:
    """Compare committed and live egress rules; return a structured drift finding.

    Comparison is symmetric: a rule missing from either side is drift. Order within
    each list does not matter and field reordering is not drift (canonical-key
    equality). Duplicate rules on the same side are deduplicated before comparison.
    Each drifted rule is classified per its layer/direction/kind (sa#52); the
    finding-level severity is the highest among the per-rule items.
    """
    committed = source.committed()
    live = source.live()

    committed_keys = {_canonical_key(r): r for r in committed}
    live_keys = {_canonical_key(r): r for r in live}

    items: list[DriftItem] = []
    extra_live: list[dict] = []
    extra_committed: list[dict] = []

    for key, rule in live_keys.items():
        if key not in committed_keys:
            extra_live.append(rule)
            severity, reason = _classify(rule, PRESENCE_EXTRA_LIVE)
            items.append(
                DriftItem(
                    rule=rule,
                    presence=PRESENCE_EXTRA_LIVE,
                    layer=rule.get("layer", LAYER_SG),
                    severity=severity,
                    reason=reason,
                )
            )

    for key, rule in committed_keys.items():
        if key not in live_keys:
            extra_committed.append(rule)
            severity, reason = _classify(rule, PRESENCE_EXTRA_COMMITTED)
            items.append(
                DriftItem(
                    rule=rule,
                    presence=PRESENCE_EXTRA_COMMITTED,
                    layer=rule.get("layer", LAYER_SG),
                    severity=severity,
                    reason=reason,
                )
            )

    if not items:
        return EgressDriftFinding(drifted=False, severity=SEVERITY_OK)

    severity = max((i.severity for i in items), key=lambda s: _SEVERITY_RANK[s])
    return EgressDriftFinding(
        drifted=True,
        severity=severity,
        items=items,
        extra_live=extra_live,
        extra_committed=extra_committed,
    )


def load_snapshot_rules(path: str) -> list[dict]:
    """Read a committed snapshot file and return its rule list.

    Accepts either a bare JSON list of rule dicts or the wrapped snapshot object
    (infra/snapshots/<arm>.json) of the form {"rules": [...], ...metadata}. The
    wrapped form is what gen-egress-snapshot.py produces.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return list(data.get("rules", []))
    return list(data)


# ---------------------------------------------------------------------------
# In-memory fake source — for tests and local development only
# ---------------------------------------------------------------------------

class InMemoryEgressPolicySource:
    """EgressPolicySource backed by plain lists. No AWS required."""

    def __init__(
        self,
        *,
        committed_rules: list[dict],
        live_rules: list[dict],
    ) -> None:
        self._committed = list(committed_rules)
        self._live = list(live_rules)

    def committed(self) -> list[dict]:
        return list(self._committed)

    def live(self) -> list[dict]:
        return list(self._live)


# ---------------------------------------------------------------------------
# AWS Security Group source — production, lazy boto3 import
# ---------------------------------------------------------------------------

class FilePlusAWSEgressPolicySource:
    """EgressPolicySource that reads committed rules from a snapshot file on disk
    and live SG rules from AWS EC2 DescribeSecurityGroupRules.

    committed_snapshot_path: path to infra/snapshots/<arm>.json (bare list or wrapped
        {"rules": [...]}); checked into git.
    security_group_id: the SG whose rules are the egress enforcement boundary.

    NOTE (scope): live() covers only the SG layer (layer="sg"). Live introspection of
    the netns/proxy layer (layer="netns_proxy") is the on-box smoke + the off-substrate
    auditor's job (sa#26) and is NOT implemented here. This class is a partial,
    SG-only live source; sa#26 owns the full live path (both layers).

    boto3 is imported lazily so callers that only use InMemoryEgressPolicySource
    (e.g. tests) do not pay the import cost.

    IAM note: requires only ec2:DescribeSecurityGroupRules on the target SG.
    No write permissions of any kind.
    """

    def __init__(
        self,
        committed_snapshot_path: str,
        security_group_id: str,
    ) -> None:
        self._snapshot_path = committed_snapshot_path
        self._sg_id = security_group_id
        self._client = None

    def _ec2(self):
        if self._client is None:
            import boto3  # noqa: PLC0415 — intentional lazy import
            self._client = boto3.client("ec2")
        return self._client

    def committed(self) -> list[dict]:
        return load_snapshot_rules(self._snapshot_path)

    def live(self) -> list[dict]:
        ec2 = self._ec2()
        response = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [self._sg_id]}]
        )
        return response.get("SecurityGroupRules", [])
