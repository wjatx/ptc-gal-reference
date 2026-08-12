#!/usr/bin/env bash
# agent-netns-setup.sh — create the confined agent network namespace (safe-agents sa#35).
#
# Process-isolation confinement for the RHEL+OpenShell AUTONOMOUS arm, converged onto the
# TWO-BOX broker model (Option A). The netns is kept as a defense-in-depth PROCESS-isolation
# layer, but it no longer blackholes: it now FORWARDS through the host to the external broker
# SERVICE (broker.safe-agents.local), exactly like the proven EC2 arm and the ec2-woken box.
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
# What changed vs the old model: the old netns installed a `blackhole default` and reached a
# CO-LOCATED model-proxy stub at 10.255.255.1:8443. There is no on-box proxy any more — the
# broker is its own service. So the netns gets a real default route via the host veth, the host
# enables ip_forward + a nftables MASQUERADE for the veth /30, and DNS is wired so the netns can
# resolve broker.safe-agents.local via the VPC resolver.
#
# NAT tool (RHEL-specific): RHEL 9 ships nftables (`nft`) as the default firewall backend and
# does NOT reliably ship the legacy `iptables` wrapper on the marketplace AMI. So the MASQUERADE
# is written as an nft rule in a dedicated `sa-netns` table (not the compat `iptables` binary the
# EC2/AL2023 arm uses). `nft` is present on the base RHEL 9 AMI — in the isolated agent subnet
# there is no NAT route to dnf-install it at runtime, so it MUST already be baked (it is).
#
# The /30 + veth IP constants below MUST match every arm so the committed egress snapshot
# (infra/snapshots/*.json) stays valid across substrates.
#
# Runs as ROOT in the host root netns (needs CAP_NET_ADMIN), invoked by the
# agent-netns-setup.service oneshot at boot, BEFORE the agent run service. Lives under /opt
# (copied there by bootstrap.sh) so the system service can exec it without tripping SELinux
# init_t/203-EXEC (docs/rhel-host-gotchas.md).
#
# Scope: NETWORK namespace + forwarding only. Filesystem isolation is sa#95.
#
# Usage:  agent-netns-setup.sh [up|down]   (default: up)
set -euo pipefail
export PATH="/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"  # ip/nft live in /usr/sbin

# Fail loudly if iproute is absent — without `ip` there is no netns, and a silent
# no-op would leave the agent unconfined. (Baked into the RHEL 9 AMI; this guard
# catches a broken/minimal image instead of trusting it.)
command -v ip >/dev/null 2>&1 || {
    echo "[agent-netns-setup] FATAL: 'ip' (iproute) not found on PATH — cannot build the netns" >&2
    exit 1
}
# Forwarding to the broker service needs MASQUERADE on the veth /30 (the /30 is not a VPC
# address, so return traffic must be SNATed to the host IP). RHEL 9 uses nftables — fail loudly
# if `nft` is missing (a broken/minimal AMI): without it the netns can reach nothing and the
# agent is DoS'd, not unconfined, but we want the oneshot to fail so the operator sees the gap.
command -v nft >/dev/null 2>&1 || {
    echo "[agent-netns-setup] FATAL: 'nft' (nftables) not found — the RHEL 9 AMI must ship " \
         "nftables so the netns can MASQUERADE to the broker service" >&2
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
NFT_TABLE="sa-netns"         # dedicated nft table so teardown never clobbers other rules

log() { echo "[agent-netns-setup] $*"; }

# The host's uplink interface (the ENI that reaches the VPC — broker SG + AWS endpoints).
# MASQUERADE is applied to it so netns egress leaves under the host's confined SG.
uplink_iface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

teardown() {
    # Idempotent: ignore "does not exist" on a clean box. Drop the whole nft table (removes
    # both the NAT + forward chains in one shot), then the links + per-netns resolv.conf.
    nft delete table ip "$NFT_TABLE" 2>/dev/null || true
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
    # so its return traffic must be SNATed to the host IP. Written as nftables rules in a
    # dedicated table (RHEL 9 default backend); explicit forward-accept rules mirror the
    # EC2 arm's FORWARD ACCEPT (harmless if the host has no firewalld forward drop).
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    local iface; iface="$(uplink_iface)"
    nft add table ip "$NFT_TABLE"
    nft add chain ip "$NFT_TABLE" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
    nft add rule  ip "$NFT_TABLE" postrouting ip saddr "$NS_CIDR" oifname "$iface" masquerade
    nft add chain ip "$NFT_TABLE" forward '{ type filter hook forward priority filter; policy accept; }'
    nft add rule  ip "$NFT_TABLE" forward iifname "$HOST_VETH" ip saddr "$NS_CIDR" accept
    nft add rule  ip "$NFT_TABLE" forward oifname "$HOST_VETH" ip daddr "$NS_CIDR" accept

    # DNS for the netns: a per-netns resolv.conf (used by processes in the namespace)
    # copied from the host, so broker.safe-agents.local resolves via the same VPC resolver
    # the host uses — reachable now that the netns forwards + the host masquerades.
    install -d "/etc/netns/${NS_NAME}"
    cp -f /etc/resolv.conf "/etc/netns/${NS_NAME}/resolv.conf"

    log "netns '${NS_NAME}' up — forwards to the broker via ${HOST_IP} (uplink=${iface:-unknown}, " \
        "nft MASQUERADE ${NS_CIDR}); confinement is the agent SG/subnet (broker only)"
}

case "${1:-up}" in
    up)   up ;;
    down) teardown; log "netns '${NS_NAME}' down" ;;
    *)    echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
