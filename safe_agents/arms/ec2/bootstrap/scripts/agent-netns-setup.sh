#!/usr/bin/env bash
# agent-netns-setup.sh — create the confined agent network namespace (safe-agents sa#35).
#
# Process-isolation confinement for the EC2 / Amazon Linux 2023 (arm64) autonomous
# arm, converged onto the TWO-BOX broker model (Option A). The netns is kept as a
# defense-in-depth PROCESS-isolation layer, but it no longer blackholes: it now
# FORWARDS through the host to the external broker SERVICE (broker.safe-agents.local),
# exactly like the proven ec2-woken box does over topology alone.
#
# Where the confinement now lives:
#   - PRIMARY guarantee = network TOPOLOGY. The box runs in the ISOLATED agent subnet
#     (no NAT) on the agent SG, whose only egress is the broker SG (+ the endpoint SG
#     for AWS interface endpoints). The box — and therefore anything in the netns —
#     physically cannot reach the internet or a connector host. This is what makes the
#     smoke-egress assertion hold.
#   - The netns is a SECOND layer: the agent runs in its own network namespace whose
#     only path out is the host veth. The host masquerades that /30 out its primary
#     interface, so netns egress is bounded by the SAME SG/subnet the host sits behind
#     (the broker, the AWS endpoints, and nothing else).
#
# What changed vs the old model (sa#97): the old netns installed a `blackhole default`
# and reached a CO-LOCATED model-proxy stub at 10.255.255.1:8443. There is no on-box
# proxy any more — the broker is its own service. So the netns gets a real default route
# via the host veth, the host enables ip_forward + MASQUERADE for the veth /30, and DNS
# is wired so the netns can resolve broker.safe-agents.local via the VPC resolver.
#
# Re-derived from the live-proven rhel-openshell copy (sa#35). The /30 + veth IP
# constants below MUST match every arm so the committed egress snapshot
# (infra/snapshots/*.json) stays valid across substrates.
#
# Runs as ROOT in the host root netns (needs CAP_NET_ADMIN), invoked by the
# agent-netns-setup.service oneshot at boot, BEFORE the agent run service. Installed
# under /opt (copied there by user-data) so the system service can exec it.
#
# Scope: NETWORK namespace + forwarding only. Filesystem isolation is sa#95.
#
# Usage:  agent-netns-setup.sh [up|down]   (default: up)
set -euo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"  # ip/iptables live in /usr/sbin

# Fail loudly if iproute is absent — without `ip` there is no netns, and a silent
# no-op would leave the agent unconfined. (Baked into the AL2023 AMI; this guard
# catches a broken/minimal image instead of trusting it.)
command -v ip >/dev/null 2>&1 || {
    echo "[agent-netns-setup] FATAL: 'ip' (iproute) not found on PATH — cannot build the netns" >&2
    exit 1
}
# Forwarding to the broker service needs MASQUERADE on the veth /30 (the /30 is not a
# VPC address, so return traffic must be SNATed to the host IP). Fail loudly if the NAT
# tool is missing — without it the netns can reach nothing and the agent is DoS'd, not
# unconfined, but we want the oneshot to fail so the operator sees the AMI gap.
command -v iptables >/dev/null 2>&1 || {
    echo "[agent-netns-setup] FATAL: 'iptables' not found — the base AMI must ship iptables-nft " \
         "so the netns can MASQUERADE to the broker service" >&2
    exit 1
}

# ── Network parameters (kept in lockstep with run-brokered.sh + the committed snapshot) ──
# A /30 point-to-point link: host side is the broker-facing veth, ns side is the agent.
# The 10.255.255.0/30 block is chosen to avoid colliding with the VPC CIDR.
NS_NAME="${SA_NETNS_NAME:-agent-ns}"
HOST_VETH="veth-broker"      # root-netns side (faces the host uplink)
NS_VETH="veth-agent"         # agent-netns side
HOST_IP="${SA_BROKER_VETH_IP:-10.255.255.1}"
NS_IP="${SA_AGENT_VETH_IP:-10.255.255.2}"
PREFIX=30
NS_CIDR="10.255.255.0/${PREFIX}"

log() { echo "[agent-netns-setup] $*"; }

# The host's uplink interface (the ENI that reaches the VPC — broker SG + AWS endpoints).
# MASQUERADE is applied to it so netns egress leaves under the host's confined SG.
uplink_iface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

teardown() {
    # Idempotent: ignore "does not exist" / "no such rule" on a clean box.
    # Remove NAT + forward rules first (they reference the veth/CIDR), then the links.
    iptables -t nat -D POSTROUTING -s "$NS_CIDR" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$HOST_VETH" -s "$NS_CIDR" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$HOST_VETH" -d "$NS_CIDR" -j ACCEPT 2>/dev/null || true
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$HOST_VETH" 2>/dev/null || true
    rm -f "/etc/netns/${NS_NAME}/resolv.conf" 2>/dev/null || true
    rmdir "/etc/netns/${NS_NAME}" 2>/dev/null || true
}

up() {
    # Start from a known-clean state so re-runs (re-deploy, restart) are idempotent.
    teardown

    ip netns add "$NS_NAME"
    ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
    ip link set "$NS_VETH" netns "$NS_NAME"

    # Host (root netns) side of the link.
    ip addr add "${HOST_IP}/${PREFIX}" dev "$HOST_VETH"
    ip link set "$HOST_VETH" up

    # Agent-netns side: bring up lo + the veth, give it its address.
    ip netns exec "$NS_NAME" ip link set lo up
    ip netns exec "$NS_NAME" ip addr add "${NS_IP}/${PREFIX}" dev "$NS_VETH"
    ip netns exec "$NS_NAME" ip link set "$NS_VETH" up

    # DEFAULT ROUTE via the host veth — the netns forwards to the broker SERVICE through
    # the host (which is itself SG-confined to the broker). This REPLACES the old
    # `blackhole default`: the netns is no longer a dead end, it is a forwarding hop whose
    # reach is bounded by the host's SG/subnet, not by a local route.
    ip netns exec "$NS_NAME" ip route add default via "$HOST_IP"

    # Host forwarding: enable ip_forward and MASQUERADE the veth /30 out the uplink so the
    # netns can reach the broker DNS name + the VPC resolver. The /30 is not a VPC address,
    # so its return traffic must be SNATed to the host IP.
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    local iface; iface="$(uplink_iface)"
    iptables -t nat -A POSTROUTING -s "$NS_CIDR" -j MASQUERADE
    iptables -A FORWARD -i "$HOST_VETH" -s "$NS_CIDR" -j ACCEPT
    iptables -A FORWARD -o "$HOST_VETH" -d "$NS_CIDR" -j ACCEPT

    # DNS for the netns: a per-netns resolv.conf (used by processes in the namespace)
    # copied from the host, so broker.safe-agents.local resolves via the same VPC resolver
    # the host uses — reachable now that the netns forwards + the host masquerades.
    install -d "/etc/netns/${NS_NAME}"
    cp -f /etc/resolv.conf "/etc/netns/${NS_NAME}/resolv.conf"

    log "netns '${NS_NAME}' up — forwards to the broker via ${HOST_IP} (uplink=${iface:-unknown}, " \
        "MASQUERADE ${NS_CIDR}); confinement is the agent SG/subnet (broker only)"
}

case "${1:-up}" in
    up)   up ;;
    down) teardown; log "netns '${NS_NAME}' down" ;;
    *)    echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
