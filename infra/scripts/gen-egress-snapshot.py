#!/usr/bin/env python3
"""gen-egress-snapshot.py — machine-generate the committed egress snapshots (sa#52).

Writes infra/snapshots/<arm>.json for each autonomous arm. Each snapshot is the
*committed* (authoritative) egress policy the off-substrate auditor (sa#26) diffs the
live box against. It captures TWO layers (docs/egress-drift.md, docs/model-egress.md):

  layer="sg"          — the box-level security-group rules, parsed from the CDK synth
                        template (infra/cdk.out/SafeAgents-Network-<env>.template.json).
  layer="netns_proxy" — the per-agent confinement, extracted from the bootstrap scripts
                        (agent-netns-setup.sh blackhole/veth + model-proxy-stub.py allowlist).

The output is derived from those source-of-truth files, never hand-maintained: re-run
this after any `cdk synth` or any change to the bootstrap scripts, and commit the result.
CI compares the committed snapshot to a fresh run to catch un-regenerated drift.

One-line regeneration (from the repo root, after `cd infra && npx cdk synth -c environment=development`):

    python3 infra/scripts/gen-egress-snapshot.py

Stdlib only. No AWS calls, no third-party deps.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT = "development"
TEMPLATE = REPO_ROOT / "infra" / "cdk.out" / f"SafeAgents-Network-{ENVIRONMENT}.template.json"
SNAPSHOT_DIR = REPO_ROOT / "infra" / "snapshots"

# The arms whose live boxes this snapshot is diffed against. Both autonomous cloud arms
# share the one Network stack (SG layer). Their netns_proxy layer is extracted from each
# arm's OWN copy of the bootstrap scripts (sa#97). The two arms diverged with the two-box
# broker convergence (sa#35/#98):
#   - ec2 keeps a CO-LOCATED model-proxy stub, so its sources are the netns setup + the
#     proxy stub (veth + proxy_listen + proxy_allow).
#   - rhel-openshell has NO on-box proxy: the netns is a forwarding hop to the external
#     broker service, so its only source is the netns setup (veth; no proxy rules).
# Each arm declares a "netns" source and, only if it has a co-located proxy, a "proxy" one.
ARM_NETNS_SOURCES: dict[str, dict[str, str]] = {
    "rhel-openshell": {
        "netns": "safe_agents/arms/rhel_openshell/bootstrap/scripts/agent-netns-setup.sh",
    },
    "ec2": {
        "netns": "safe_agents/arms/ec2/bootstrap/scripts/agent-netns-setup.sh",
        "proxy": "safe_agents/arms/ec2/bootstrap/scripts/model-proxy-stub.py",
    },
}
ARMS = list(ARM_NETNS_SOURCES)

# Inline egress placeholder CDK emits for allowAllOutbound:false — represents the ABSENCE
# of egress, not an egress path. Excluded so it does not read as a real rule.
_DISALLOW_CIDR = "255.255.255.255/32"


# ---------------------------------------------------------------------------
# Layer 1 — security-group rules from the CDK synth template
# ---------------------------------------------------------------------------

def _sg_friendly(logical_id: str, resources: dict) -> str:
    """Map a SecurityGroup logical id to a stable, region-independent friendly name."""
    desc = resources.get(logical_id, {}).get("Properties", {}).get("GroupDescription", "")
    low = desc.lower()
    for name in ("broker", "agent", "endpoint"):
        if low.startswith(name):
            return name
    return logical_id


def _getatt_group(ref: dict) -> str | None:
    """Return the logical id of an Fn::GetAtt <id>.GroupId reference, else None."""
    if isinstance(ref, dict) and "Fn::GetAtt" in ref:
        return ref["Fn::GetAtt"][0]
    return None


def _target(props: dict, resources: dict, description: str) -> str:
    """Canonical, region-independent target for a rule (what it permits reaching)."""
    dest_sg = _getatt_group(props.get("DestinationSecurityGroupId", {}))
    if dest_sg:
        return f"sg:{_sg_friendly(dest_sg, resources)}"
    src_sg = _getatt_group(props.get("SourceSecurityGroupId", {}))
    if src_sg:
        return f"sg:{_sg_friendly(src_sg, resources)}"
    if "DestinationPrefixListId" in props:
        low = description.lower()
        if "s3" in low:
            return "prefixlist:s3"
        if "dynamodb" in low:
            return "prefixlist:dynamodb"
        return f"prefixlist:{props['DestinationPrefixListId']}"
    cidr = props.get("CidrIp")
    if cidr:
        return f"cidr:{cidr}"
    return "unknown"


def _ports(props: dict) -> str:
    proto = props.get("IpProtocol")
    if str(proto) == "-1":
        return "all"
    fp, tp = props.get("FromPort"), props.get("ToPort")
    if fp is None:
        return "all"
    return str(fp) if fp == tp else f"{fp}-{tp}"


def _sg_rule(sg: str, direction: str, props: dict, resources: dict) -> dict:
    description = props.get("Description", "")
    return {
        "layer": "sg",
        "sg": sg,
        "direction": direction,
        "protocol": str(props.get("IpProtocol")),
        "ports": _ports(props),
        "target": _target(props, resources, description),
    }


def sg_rules(template: dict) -> list[dict]:
    resources = template["Resources"]
    rules: list[dict] = []

    for _, res in resources.items():
        rtype = res["Type"]
        props = res.get("Properties", {})

        if rtype == "AWS::EC2::SecurityGroup":
            sg = _sg_friendly_self(props)
            for inline in props.get("SecurityGroupEgress", []) or []:
                if inline.get("CidrIp") == _DISALLOW_CIDR:
                    continue  # allowAllOutbound:false placeholder — not a real path
                rules.append(_sg_rule(sg, "egress", inline, resources))
            for inline in props.get("SecurityGroupIngress", []) or []:
                rules.append(_sg_rule(sg, "ingress", inline, resources))

        elif rtype == "AWS::EC2::SecurityGroupEgress":
            sg = _sg_friendly(_getatt_group(props.get("GroupId", {})) or "", resources)
            rules.append(_sg_rule(sg, "egress", props, resources))

        elif rtype == "AWS::EC2::SecurityGroupIngress":
            sg = _sg_friendly(_getatt_group(props.get("GroupId", {})) or "", resources)
            rules.append(_sg_rule(sg, "ingress", props, resources))

    # Deterministic order so the committed file is stable across runs.
    rules.sort(key=lambda r: (r["sg"], r["direction"], r["target"], r["ports"]))
    return rules


def _sg_friendly_self(props: dict) -> str:
    desc = props.get("GroupDescription", "").lower()
    for name in ("broker", "agent", "endpoint"):
        if desc.startswith(name):
            return name
    return "unknown"


# ---------------------------------------------------------------------------
# Layer 2 — netns + proxy expectations from the bootstrap scripts
# ---------------------------------------------------------------------------

def _default(text: str, var: str, fallback: str) -> str:
    """Extract a shell/python default-via-env value: VAR ... "default" or :-default."""
    # python: os.environ.get("VAR", "value")  /  shell: ${VAR:-value}
    m = re.search(rf'{var}["\']?\s*,\s*["\']([^"\']+)["\']', text)
    if m:
        return m.group(1)
    m = re.search(rf'\$\{{{var}:-([^}}]+)\}}', text)
    if m:
        return m.group(1)
    return fallback


def netns_proxy_rules(netns_script: Path, proxy_script: Path | None = None) -> list[dict]:
    netns = netns_script.read_text()

    host_ip = _default(netns, "SA_BROKER_VETH_IP", "10.255.255.1")
    agent_ip = _default(netns, "SA_AGENT_VETH_IP", "10.255.255.2")
    prefix_m = re.search(r"^PREFIX=(\d+)", netns, re.MULTILINE)
    prefix = int(prefix_m.group(1)) if prefix_m else 30
    has_blackhole = "ip route add blackhole default" in netns

    rules: list[dict] = []
    if has_blackhole:
        rules.append({"layer": "netns_proxy", "kind": "default_route", "action": "blackhole"})
    rules.append({
        "layer": "netns_proxy", "kind": "veth",
        "host_ip": host_ip, "agent_ip": agent_ip, "prefix": prefix,
    })

    # Only arms with a CO-LOCATED model-proxy stub contribute proxy_listen / proxy_allow
    # rules. An arm that forwards to the external broker (no on-box proxy) has no proxy
    # source, so its netns_proxy layer is the veth (+ blackhole, if it is a dead end).
    if proxy_script is not None:
        proxy = proxy_script.read_text()
        proxy_port = int(_default(proxy, "SA_MODEL_PROXY_PORT", "8443"))
        proxy_host = _default(proxy, "SA_BROKER_VETH_IP", host_ip)
        allowlist_raw = _default(proxy, "SA_MODEL_ALLOWLIST", "api.anthropic.com")
        rules.append({
            "layer": "netns_proxy", "kind": "proxy_listen",
            "host": proxy_host, "port": proxy_port,
        })
        for item in allowlist_raw.split(","):
            item = item.strip()
            if not item:
                continue
            host, _, port = item.partition(":")
            rules.append({
                "layer": "netns_proxy", "kind": "proxy_allow",
                "host": host, "port": int(port) if port else 443,
            })
    rules.sort(key=lambda r: (r["kind"], json.dumps(r, sort_keys=True)))
    return rules


# ---------------------------------------------------------------------------
# Assemble + write
# ---------------------------------------------------------------------------

def network_mode(template: dict) -> str:
    """The topology this snapshot was generated under, read from the AUTHORITATIVE
    declaration — the `network-mode` SSM parameter NetworkStack publishes in both
    modes ('secure' | 'open') — never inferred from the SG rules themselves (that
    would be circular with the keystone assertions that consume this field)."""
    for resource in template.get("Resources", {}).values():
        if resource.get("Type") != "AWS::SSM::Parameter":
            continue
        props = resource.get("Properties", {})
        if str(props.get("Name", "")).endswith("/network-mode"):
            value = props.get("Value")
            if value not in ("secure", "open"):
                raise SystemExit(f"unexpected network-mode value in template: {value!r}")
            return value
    raise SystemExit("no network-mode SSM parameter found in the Network template")


def build_snapshot(arm: str, mode: str, layer1: list[dict], layer2: list[dict]) -> dict:
    return {
        "schema": "safe-agents/egress-snapshot/v1",
        "arm": arm,
        "environment": ENVIRONMENT,
        # 'secure' | 'open' — which flag-gated topology the SG layer reflects
        # (docs/network-security-layer.md). Auditor tests key their keystone
        # assertions on this: deny-by-default egress is only claimed in secure mode.
        "network_mode": mode,
        "generated_by": "infra/scripts/gen-egress-snapshot.py",
        "source": {
            "sg": f"infra/cdk.out/SafeAgents-Network-{ENVIRONMENT}.template.json",
            "netns_proxy": list(ARM_NETNS_SOURCES[arm].values()),
        },
        "rules": layer1 + layer2,
    }


def main() -> int:
    if not TEMPLATE.exists():
        raise SystemExit(
            f"synth template not found: {TEMPLATE}\n"
            "Run `cd infra && npx cdk synth -c environment=development` first."
        )
    template = json.loads(TEMPLATE.read_text())
    layer1 = sg_rules(template)
    mode = network_mode(template)

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    for arm, sources in ARM_NETNS_SOURCES.items():
        # Each arm extracts its netns_proxy layer from its OWN copy of the bootstrap
        # scripts (sa#97). ec2 has a co-located proxy source; rhel forwards to the
        # external broker and has none.
        netns_rel = sources["netns"]
        proxy_rel = sources.get("proxy")
        layer2 = netns_proxy_rules(
            REPO_ROOT / netns_rel,
            (REPO_ROOT / proxy_rel) if proxy_rel else None,
        )
        snapshot = build_snapshot(arm, mode, layer1, layer2)
        out = SNAPSHOT_DIR / f"{arm}.json"
        out.write_text(json.dumps(snapshot, indent=2) + "\n")
        print(f"wrote {out.relative_to(REPO_ROOT)} ({len(snapshot['rules'])} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
