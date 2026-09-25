"""Tests for broker.auditor — chain verifier + egress-drift watchdog.

All tests run against in-memory fakes. No AWS credentials, no live S3, no boto3.

Acceptance criteria (from sa#26):
1. A valid tape passes chain integrity.
2. A gap (deleted record) is detected.
3. A mutation (tampered field) is detected.
4. Egress-policy drift (live != committed) is flagged.
5. No egress drift passes clean.
"""

import json
from pathlib import Path

import pytest

from safe_agents.broker.audit import InMemorySink, emit
from safe_agents.broker.auditor import (
    InMemoryEgressPolicySource,
    InMemoryTapeReader,
    check_chain_integrity,
    check_egress_drift,
    load_snapshot_rules,
)
from safe_agents.broker.schemas.common import Principal

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

PRINCIPAL = Principal(agentId="agent-audit", skill="watchdog", user="system", tier="A")

BASE_EMIT = dict(
    principal=PRINCIPAL,
    tool="s3",
    op="get_object",
    args={"bucket": "audit-bucket", "key": "test.json"},
    envelope_hash="sha256:envelope-test",
    decision="allow",
    outcome="executed",
)


def _build_tape(n: int) -> list:
    """Emit n records into a fresh InMemorySink; return the records list."""
    sink = InMemorySink()
    records = [emit(sink, **BASE_EMIT) for _ in range(n)]
    return records


# ---------------------------------------------------------------------------
# 1. Valid tape passes chain integrity
# ---------------------------------------------------------------------------

def test_valid_tape_passes():
    records = _build_tape(5)
    reader = InMemoryTapeReader(records)
    finding = check_chain_integrity(reader)
    assert finding.intact is True
    assert finding.error is None
    assert finding.broken_seq is None


def test_empty_tape_passes():
    reader = InMemoryTapeReader([])
    finding = check_chain_integrity(reader)
    assert finding.intact is True


def test_single_record_tape_passes():
    records = _build_tape(1)
    reader = InMemoryTapeReader(records)
    finding = check_chain_integrity(reader)
    assert finding.intact is True


def test_large_tape_passes():
    records = _build_tape(50)
    reader = InMemoryTapeReader(records)
    finding = check_chain_integrity(reader)
    assert finding.intact is True


# ---------------------------------------------------------------------------
# 2. Gap (deleted record) is detected
# ---------------------------------------------------------------------------

def test_gap_middle_record_detected():
    records = _build_tape(5)
    gapped = [r for r in records if r.seq != 2]
    assert len(gapped) == 4

    reader = InMemoryTapeReader(gapped)
    finding = check_chain_integrity(reader)

    assert finding.intact is False
    assert finding.error is not None
    assert "gap" in finding.error or "seq" in finding.error


def test_gap_first_record_detected():
    records = _build_tape(5)
    without_first = records[1:]

    reader = InMemoryTapeReader(without_first)
    finding = check_chain_integrity(reader)

    assert finding.intact is False
    assert finding.error is not None


def test_gap_returns_broken_seq():
    records = _build_tape(6)
    # Remove seq=3 so the gap is at expected seq=3 (we'll see seq=4 instead)
    gapped = [r for r in records if r.seq != 3]

    reader = InMemoryTapeReader(gapped)
    finding = check_chain_integrity(reader)

    assert finding.intact is False
    assert finding.broken_seq is not None
    assert finding.broken_seq == 3


# ---------------------------------------------------------------------------
# 3. Mutation (tampered field) is detected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("tool", "payments"),
    ("op", "transfer"),
    ("argsDigest", "sha256:" + "a" * 64),
    ("outcome", "denied"),
    ("envelopeHash", "sha256:" + "b" * 64),
])
def test_field_mutation_detected(field, value):
    records = _build_tape(5)
    records = list(records)
    records[2] = records[2].model_copy(update={field: value})

    reader = InMemoryTapeReader(records)
    finding = check_chain_integrity(reader)

    assert finding.intact is False
    assert finding.error is not None


def test_prevHash_mutation_detected():
    records = _build_tape(4)
    records = list(records)
    records[1] = records[1].model_copy(update={"prevHash": "sha256:" + "c" * 64})

    reader = InMemoryTapeReader(records)
    finding = check_chain_integrity(reader)

    assert finding.intact is False
    assert finding.broken_seq == 1


def test_stored_hash_tampered_detected():
    records = _build_tape(3)
    records = list(records)
    records[0] = records[0].model_copy(update={"hash": "sha256:" + "d" * 64})

    reader = InMemoryTapeReader(records)
    finding = check_chain_integrity(reader)

    assert finding.intact is False


# ---------------------------------------------------------------------------
# 4. Egress-policy drift is flagged
# ---------------------------------------------------------------------------

COMMITTED_RULES = [
    {"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0", "direction": "egress"},
    {"protocol": "tcp", "port": 80, "cidr": "0.0.0.0/0", "direction": "egress"},
]

def test_extra_live_rule_flagged_as_drift():
    # An extra OUTBOUND rule present in live but not committed is a potential egress
    # bypass — sa#52 classifies this as critical (not merely warning).
    live = COMMITTED_RULES + [
        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0", "direction": "egress"},
    ]
    source = InMemoryEgressPolicySource(committed_rules=COMMITTED_RULES, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.drifted is True
    assert finding.severity == "critical"
    assert len(finding.extra_live) == 1
    assert finding.extra_live[0]["port"] == 22
    assert finding.extra_committed == []


def test_missing_live_rule_flagged_as_drift():
    live = [COMMITTED_RULES[0]]  # port 80 rule is missing from live
    source = InMemoryEgressPolicySource(committed_rules=COMMITTED_RULES, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.drifted is True
    assert finding.severity == "warning"
    assert finding.extra_live == []
    assert len(finding.extra_committed) == 1
    assert finding.extra_committed[0]["port"] == 80


def test_both_added_and_removed_rules_detected():
    live = [
        COMMITTED_RULES[0],  # port 443 — still present
        # port 80 removed
        {"protocol": "udp", "port": 53, "cidr": "10.0.0.0/8", "direction": "egress"},  # added
    ]
    source = InMemoryEgressPolicySource(committed_rules=COMMITTED_RULES, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.drifted is True
    assert len(finding.extra_live) == 1
    assert len(finding.extra_committed) == 1


def test_completely_different_live_rules_flagged():
    live = [{"protocol": "all", "port": -1, "cidr": "0.0.0.0/0", "direction": "egress"}]
    source = InMemoryEgressPolicySource(committed_rules=COMMITTED_RULES, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.drifted is True
    assert len(finding.extra_live) == 1
    assert len(finding.extra_committed) == 2


# ---------------------------------------------------------------------------
# 5. No egress drift passes clean
# ---------------------------------------------------------------------------

def test_identical_rules_no_drift():
    source = InMemoryEgressPolicySource(
        committed_rules=COMMITTED_RULES,
        live_rules=list(COMMITTED_RULES),  # same rules
    )
    finding = check_egress_drift(source)

    assert finding.drifted is False
    assert finding.severity == "ok"
    assert finding.extra_live == []
    assert finding.extra_committed == []


def test_rule_field_order_irrelevant_no_drift():
    # Same rule with fields in different order — must NOT be reported as drift.
    committed = [{"cidr": "0.0.0.0/0", "port": 443, "protocol": "tcp"}]
    live = [{"protocol": "tcp", "cidr": "0.0.0.0/0", "port": 443}]
    source = InMemoryEgressPolicySource(committed_rules=committed, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.drifted is False


def test_empty_policy_both_sides_no_drift():
    source = InMemoryEgressPolicySource(committed_rules=[], live_rules=[])
    finding = check_egress_drift(source)

    assert finding.drifted is False
    assert finding.severity == "ok"


def test_empty_committed_with_live_rules_is_drift():
    live = [{"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"}]
    source = InMemoryEgressPolicySource(committed_rules=[], live_rules=live)
    finding = check_egress_drift(source)

    assert finding.drifted is True
    assert len(finding.extra_live) == 1


# ---------------------------------------------------------------------------
# 6. sa#52 severity model — SG layer (extra-live→critical, missing→warning)
# ---------------------------------------------------------------------------

SG_COMMITTED = [
    {"layer": "sg", "sg": "agent", "direction": "egress", "protocol": "-1",
     "ports": "all", "target": "sg:broker"},
    {"layer": "sg", "sg": "endpoint", "direction": "ingress", "protocol": "tcp",
     "ports": "443", "target": "sg:agent"},
]


def test_sg_extra_live_egress_is_critical():
    # A shadow OUTBOUND rule on the agent SG is a potential egress bypass → critical.
    planted = {"layer": "sg", "sg": "agent", "direction": "egress", "protocol": "tcp",
               "ports": "443", "target": "cidr:0.0.0.0/0"}
    source = InMemoryEgressPolicySource(
        committed_rules=SG_COMMITTED, live_rules=SG_COMMITTED + [planted],
    )
    finding = check_egress_drift(source)

    assert finding.severity == "critical"
    assert len(finding.critical_items) == 1
    item = finding.critical_items[0]
    assert item.layer == "sg"
    assert item.presence == "extra_live"
    assert item.rule == planted


def test_sg_extra_live_ingress_is_warning():
    # An extra INBOUND rule is monitored, not the confinement mechanism → warning.
    planted = {"layer": "sg", "sg": "endpoint", "direction": "ingress", "protocol": "tcp",
               "ports": "443", "target": "cidr:10.0.0.0/8"}
    source = InMemoryEgressPolicySource(
        committed_rules=SG_COMMITTED, live_rules=SG_COMMITTED + [planted],
    )
    finding = check_egress_drift(source)

    assert finding.severity == "warning"
    assert finding.critical_items == []
    assert len(finding.warning_items) == 1


def test_sg_committed_but_missing_in_live_is_warning():
    # Tighter than expected (may break broker connectivity) but not a safety regression.
    live = [SG_COMMITTED[1]]  # the agent→broker egress rule is gone from live
    source = InMemoryEgressPolicySource(committed_rules=SG_COMMITTED, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.severity == "warning"
    assert len(finding.extra_committed) == 1
    assert finding.warning_items[0].presence == "extra_committed"


def test_critical_dominates_rollup_severity():
    # A finding with both a critical and a warning item rolls up to critical.
    extra_egress = {"layer": "sg", "sg": "agent", "direction": "egress", "protocol": "-1",
                    "ports": "all", "target": "cidr:0.0.0.0/0"}
    live = [SG_COMMITTED[0], extra_egress]  # drop the ingress (warning), add egress (critical)
    source = InMemoryEgressPolicySource(committed_rules=SG_COMMITTED, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.severity == "critical"
    assert len(finding.critical_items) == 1  # the extra egress
    assert len(finding.warning_items) == 1  # the missing ingress


# ---------------------------------------------------------------------------
# 7. sa#52 severity model — netns/proxy layer (the second layer)
# ---------------------------------------------------------------------------

NETNS_COMMITTED = [
    {"layer": "netns_proxy", "kind": "default_route", "action": "blackhole"},
    {"layer": "netns_proxy", "kind": "veth", "host_ip": "10.255.255.1",
     "agent_ip": "10.255.255.2", "prefix": 30},
    {"layer": "netns_proxy", "kind": "proxy_allow", "host": "api.anthropic.com", "port": 443},
]


def test_netns_widened_allowlist_is_critical():
    # An extra reachable model host beyond the committed allowlist → critical.
    planted = {"layer": "netns_proxy", "kind": "proxy_allow",
               "host": "evil.example.com", "port": 443}
    source = InMemoryEgressPolicySource(
        committed_rules=NETNS_COMMITTED, live_rules=NETNS_COMMITTED + [planted],
    )
    finding = check_egress_drift(source)

    assert finding.severity == "critical"
    assert len(finding.critical_items) == 1
    assert finding.critical_items[0].rule["host"] == "evil.example.com"


def test_netns_missing_blackhole_is_critical():
    # Live agent netns has no blackhole default → it has a route it should not → critical.
    live = [r for r in NETNS_COMMITTED if r["kind"] != "default_route"]
    source = InMemoryEgressPolicySource(committed_rules=NETNS_COMMITTED, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.severity == "critical"
    assert len(finding.critical_items) == 1
    item = finding.critical_items[0]
    assert item.presence == "extra_committed"
    assert item.rule["kind"] == "default_route"


def test_netns_altered_blackhole_is_critical():
    # A different live default route surfaces as BOTH a missing committed blackhole and
    # an extra live route — both critical.
    live = [
        {"layer": "netns_proxy", "kind": "default_route", "action": "via:10.255.255.1"}
        if r["kind"] == "default_route" else r
        for r in NETNS_COMMITTED
    ]
    source = InMemoryEgressPolicySource(committed_rules=NETNS_COMMITTED, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.severity == "critical"
    assert len(finding.critical_items) == 2  # missing blackhole + extra non-blackhole route


def test_netns_allowlisted_host_missing_is_warning():
    # The model host is absent from the live allowlist — the model may be unreachable,
    # but this is not an egress widening → warning.
    live = [r for r in NETNS_COMMITTED if r["kind"] != "proxy_allow"]
    source = InMemoryEgressPolicySource(committed_rules=NETNS_COMMITTED, live_rules=live)
    finding = check_egress_drift(source)

    assert finding.severity == "warning"
    assert finding.critical_items == []
    assert len(finding.warning_items) == 1


def test_netns_no_drift_clean():
    source = InMemoryEgressPolicySource(
        committed_rules=NETNS_COMMITTED, live_rules=list(reversed(NETNS_COMMITTED)),
    )
    finding = check_egress_drift(source)

    assert finding.drifted is False
    assert finding.severity == "ok"


# ---------------------------------------------------------------------------
# 8. Committed snapshot artifacts load and round-trip clean
# ---------------------------------------------------------------------------

_SNAPSHOT_DIR = Path(__file__).resolve().parents[3] / "infra" / "snapshots"


@pytest.mark.parametrize("arm", ["rhel-openshell", "ec2"])
def test_committed_snapshot_loads_and_self_matches(arm):
    path = _SNAPSHOT_DIR / f"{arm}.json"
    rules = load_snapshot_rules(str(path))
    # The generator stamps which flag-gated topology the SG layer reflects, read
    # from NetworkStack's authoritative network-mode declaration (never inferred
    # from the rules — that would be circular with the assertions below).
    network_mode = json.loads(path.read_text(encoding="utf-8")).get("network_mode")
    assert network_mode in ("secure", "open"), \
        f"snapshot must declare its network_mode, got {network_mode!r}"

    # The snapshot carries both layers and is non-trivial.
    assert any(r.get("layer") == "sg" for r in rules)
    assert any(r.get("layer") == "netns_proxy" for r in rules)

    # Confinement keystone (sa#97 two-box model): the netns no longer blackholes
    # the default route — it forwards through the host veth, and deny-by-default is
    # enforced at the SG layer. So the invariants that must hold for EVERY arm are:
    # the agent SG never reaches the open internet, and the netns carries its veth.
    agent_egress = [r for r in rules if r.get("layer") == "sg"
                    and r.get("sg") == "agent" and r.get("direction") == "egress"]
    assert agent_egress, "agent SG must carry explicit egress allows"
    open_egress = any(r.get("target") == "cidr:0.0.0.0/0" for r in agent_egress)
    if network_mode == "secure":
        assert not open_egress, \
            "agent SG must not egress to the open internet — SG deny-by-default is the keystone"
    else:
        # Open mode (the flag-gated default since 2026-07-08, docs/network-security-layer.md)
        # DELIBERATELY trades SG deny-by-default back to the broker layer: the flat egress
        # must be present AND declared, so a secure-mode snapshot that accidentally grew a
        # 0.0.0.0/0 rule still fails above rather than slipping through as "open".
        assert open_egress, \
            "open-mode snapshot must carry the flat agent egress it declares"
    assert any(r.get("kind") == "veth" for r in rules), \
        "netns must carry the veth forwarding hop"

    # ec2 keeps its co-located model-proxy, so the on-box model allowlist is its
    # arm-specific keystone; rhel-openshell is a proxy-less forwarding hop to the
    # external broker service and contributes no proxy_allow.
    if arm == "ec2":
        assert any(r.get("kind") == "proxy_allow" and r.get("host") == "api.anthropic.com"
                   for r in rules)

    # A live box identical to the committed snapshot shows no drift.
    source = InMemoryEgressPolicySource(committed_rules=rules, live_rules=list(rules))
    finding = check_egress_drift(source)
    assert finding.drifted is False
    assert finding.severity == "ok"
