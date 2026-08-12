# Model-egress confinement (the netns + broker-proxy design)

How an autonomous agent reaches its model (`api.anthropic.com`) while **everything else** stays
broker-only. This closes the mechanic that `ARCHITECTURE.md` invariant #2 names but does not
specify, and that `core/PORTING.md` §Open-questions #1 and sa#35 assume without resolving.

Status: **design** (decided). Implementation is sa#35 (netns) + the broker build (sa#12).

> **Note (2026-07-07).** The VPC subnet/SG references below assume the `secureNetwork: true`
> topology, which is now flag-gated and ships OFF for the current experiment floor
> (`docs/network-security-layer.md`). The netns + broker-proxy confinement this doc specifies is a
> per-arm run-path mechanism, independent of that flag, and remains the agent-confinement floor on a
> co-hosted box in either network mode.

## The carve-out, precisely

Invariant #2 (`ARCHITECTURE.md:21`): *the agent's only egress is the broker, enforced at the
network layer, never in code the agent runs — "call the API directly" must not be a path that
exists.* The one blessed exception is the agent's **own model inference** — *not a connector; the
broker mediates tools/actions, not the model's brain.*

The exception still has to be enforced at the network layer and constrained to **only** the model
endpoint. Two facts make that non-trivial:

- **`api.anthropic.com` cannot be a security-group rule.** It is Cloudflare-fronted (rotating IPs,
  no AWS managed prefix-list). SGs filter by IP/CIDR/prefix-list/SG, never by hostname. The model
  allowlist must live somewhere that speaks DNS/SNI — a proxy or a domain firewall, not an SG.
- **Confinement is a topology problem, not a firewall-rule problem** (see next section).

## Why a single box cannot SG-confine its agent

The autonomous arm is a **single box** that co-hosts the agent process and a broker sidecar
(`ARCHITECTURE.md` "ideally a different process/container/task"; today `bootstrap.sh` installs the
broker as a same-host unit). On that topology:

- Invariant #1 keeps connector credentials in the **broker**, so the **broker process makes the
  real connector calls** (Telegram, Alpaca, …) and needs broad NAT egress.
- A box-level security group governs the **whole box**. If the box must egress to connectors for
  the broker, the agent process **sharing that box inherits the same egress** — an SG cannot tell
  agent traffic from broker traffic.

So "non-broker/non-model egress is blocked for the agent" is **unsatisfiable at the SG layer on a
co-hosted box**. Separating agent-egress from broker-egress requires **process-level isolation**:
a network namespace (sa#35) on the agent arms, or the OpenShell sandbox on the dev-box arm. The
box-level SG is *not* the agent-confinement mechanism here — it only governs what the **box** (i.e.
the broker) may reach. This corrects the "box-SG floor now, netns later" sequencing: on the
single-box topology there is no meaningful box-SG agent-confinement to lay first; **the netns is
the floor.**

## The design: netns whose only route is the broker, and the broker is the model proxy

```
        ┌──────────────────────── instance (NAT-egress / broker subnet) ───────────────────────┐
        │  root netns  (NAT to internet)                                                        │
        │   ┌─────────── broker (brokerRole) ───────────┐                                       │
        │   │  :8080  brokered tool-call API  ───────────┼──▶ connector hosts  (creds here)      │
        │   │  :8443  model-inference proxy  ────────────┼──▶ api.anthropic.com:443  (allowlist) │
        │   └───────────────────▲────────────────────────┘            (+ openai/ollama if cfg)   │
        │        veth0          │ veth1                                                           │
        │   ┌───────────────────┴──── agent-ns (NO NAT) ───────────────┐                         │
        │   │  agent process (agentRole) — claude CLI + harness         │                         │
        │   │  default route: blackhole                                 │                         │
        │   │  only reachable peer: the broker veth IP (:8080, :8443)   │                         │
        │   │  HTTPS_PROXY = http://<broker-veth-ip>:8443               │                         │
        │   └───────────────────────────────────────────────────────────┘                       │
        └───────────────────────────────────────────────────────────────────────────────────────┘
```

The agent runs in `agent-ns` with a single veth to the host root netns and **no default internet
route**. The only host-side services it can reach are the broker's two surfaces:

1. **Brokered tool-call API** — all connector traffic is mediated here; connector creds never leave
   the broker (invariant #1).
2. **Model-inference proxy** — a domain-allowlisted forward proxy (`CONNECT api.anthropic.com:443`,
   plus any explicitly configured model hosts; deny all else). The agent's run path sets
   `HTTPS_PROXY` to it; the `claude` CLI honours it. The broker, in root netns with NAT, performs
   the actual TLS and **enforces the hostname allowlist** — the single egress point that
   `PORTING.md` calls for.

Net effect: the agent's *only* outbound route is the broker (literally true, even for inference),
so `PORTING.md`'s "only outbound route is the broker" and `ARCHITECTURE.md`'s "only egress is the
broker" both hold without exception. A fully compromised agent can reach the broker's tool API and
`api.anthropic.com` (its brain) and **nothing else** — no connector host is reachable by any path.

### Consequences that fall out

- **The box stays in the NAT/broker subnet** — it is *not* moved to the isolated agent subnet. The
  box needs NAT for the broker's connector + model egress; confinement is the netns, not the
  subnet. (This reverses the placement instruction in the pre-netns plan; `provision.py` already
  uses the broker subnet, so it is a rationale change, not a code change.)
- **No prebaked AMI is needed.** Bootstrap (dnf/EPEL, npm, podman, the OpenShell installer on the
  interactive profile) runs in the host **root netns** with NAT during cloud-init; the netns
  confinement is set up afterward and applies only to the agent run path.
- **The hostname allowlist lives in one place** — the broker's proxy surface — for every arm. No
  per-arm SG hostname-pinning, which is impossible anyway.

## Run-path integration (sa#35 build — implemented on the rhel-openshell autonomous arm)

- `agent-netns-setup.service` — a root **oneshot** system service (`RemainAfterExit`), running
  `/opt/safe-agents/bin/agent-netns-setup.sh` (under `/opt`, satisfying the SELinux
  `init_t`/`203/EXEC` rule in `docs/rhel-host-gotchas.md`): creates `agent-ns` + a `/30` veth pair
  (`10.255.255.1` broker side, `10.255.255.2` agent side), installs a **blackhole default** so the
  only reachable peer is the broker, brings up `lo`. `Requires=`/`After=` ordered before the agent
  service. Idempotent (teardown-first) so re-deploys/restarts are safe.
- **Token fetch is in the root netns, before entering the namespace.** Secrets Manager is *not*
  reachable from the confined netns (only the broker is), so `run-agent.sh` runs in the host root
  netns, fetches the agent's own oauth token via the instance profile, then
  `exec ip netns exec agent-ns runuser -u dev -- run.sh` drops the agent into the namespace. (This
  is why the agent service runs as root and `runuser`s back to `dev` inside — rather than systemd's
  `NetworkNamespacePath=`, which would put the whole unit, token fetch included, inside the netns.)
  The wrapper exports `HTTPS_PROXY=http://10.255.255.1:8443` and `NO_PROXY=10.255.255.1` (PATH-first,
  per the RHEL PATH gotcha) so model calls tunnel through the proxy while direct broker tool-API
  calls bypass it. All netns wiring is gated to `SA_PROFILE=autonomous`; the interactive wrapper
  execs `run.sh` directly (OpenShell confines it).
- **Limitation (in scope to note, not to solve here):** any *other* AWS-API call the agent bundle's
  `run.sh` makes (e.g. a run-record `PutItem`) has no route from inside the netns — those must be
  pre-staged in the root netns or brokered. The `claude` CLI itself needs only the injected token +
  the proxy, so `claude -p` works.
- `broker-model-proxy.service` — the stub forward proxy (`/opt/broker/model-proxy-stub.py`, stdlib
  CONNECT proxy) in the root netns, allowlisting only `api.anthropic.com:443`. The real proxy
  surface is the broker build (sa#12); the stub exercises the netns + the conformance smoke.

## Conformance assertion (the smoke that proves it)

From **inside `agent-ns`** (extends the sa#35 / `bin/smoke-agent` acceptance):

- `curl -m5 <any-connector-host>` → **network error** (unreachable). Connector reached directly =
  smoke fail.
- `curl -m5 <broker-tool-endpoint>` → **success**.
- `curl -m5 https://api.anthropic.com` **via `HTTPS_PROXY`** → **success**; the same `curl`
  **without** the proxy → **network error** (no direct model route exists either).

## Scope across arms

This is the Phase-1 "unify egress" model (sa#52 egress-drift is its drift standard; the canonical
SG snapshot covers the **box → connector/model** egress, while agent-confinement is asserted by the
netns smoke, not by an SG diff). It is identical for every autonomous arm:

- **rhel-openshell (autonomous profile)** — this design; OpenShell is gated to the *interactive*
  profile only.
- **ec2 / al2023 (sa#35)** — the originating scope; same netns + broker-proxy model.
- **fargate (sa#36)** — broker as a sidecar container, agent container with no egress but to the
  broker task; the proxy surface rides the same broker.

The **dev-box / interactive** arm keeps OpenShell with its egress policy allowing only the broker
endpoint + `api.anthropic.com` (`safe_agents/arms/rhel_openshell/openshell_policy.py`) — the application-
layer analogue of this network-layer design.
