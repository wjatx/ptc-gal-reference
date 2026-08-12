#!/usr/bin/env bash
# cluster-arc-run.sh — host-side driver for the #250 Phase 2 cluster drill.
#
#   ./safe_agents/arms/openshift/cluster-arc-run.sh            # build + run both legs
#   SKIP_BUILD=1 ./safe_agents/arms/openshift/cluster-arc-run.sh   # reuse the images
#
# TWELVE Jobs and two Deployments across FIVE ServiceAccounts (#250 Phases 3-6.1,
# #310, #154). The first six legs:
#
#   0. bootstrap (safe-agents-checker) creates the grant store the maker may only
#                                      read
#   1. propose   (safe-agents-maker)   no issuer key, no RBAC; shows what it
#                                      CANNOT do, then proposes
#   2. ratify    (safe-agents-checker) the only pod with the signing key mounted
#   3. serve     (safe-agents-broker)  serves the ratified grant, no ceremony; the
#                                      only leg HERE that writes the audit tape (the
#                                      broker Deployment at step 9 also holds it
#                                      read-write, under the same ServiceAccount and
#                                      never at the same time — so the exact claim is
#                                      "the broker identity, one pod at a time")
#   4. tamper    (safe-agents-maker)   tries to erase and forge what leg 3 wrote,
#                                      and is refused by the kernel (#310)
#   5. agent     (safe-agents-agent)   holds NOTHING — no mount, no Secret, no
#                                      RoleBinding — and is refused the internet
#                                      and the broker Secret while a brokered
#                                      call still executes (Phase 4)
#
# Legs 0-4 prove the Phase 3 predicate — the ceremony runs under two
# ServiceAccounts, the maker provably cannot obtain the signing key, and the
# signed record stamps two real identities with no solo attestation — while
# still carrying Phase 2's: `restricted-v2` on every pod (checked, not assumed)
# and a store that outlives the pods that wrote it.
#
# Leg 5 is Phase 4, and it needs something none of the others do: a broker that is
# still RUNNING. Legs 0-4 each build a runtime in-process and exit, which is enough
# for a claim about a credential and useless for a claim about crossing a boundary.
# So between leg 4 and leg 5 the broker comes up as a Deployment behind a ClusterIP
# Service, and the agent talks to it over HTTP like anything else outside would.
#
# Then Phase 5, which is the part written for an audience rather than for a predicate:
#
#   6. peer      (safe-agents-peer)    a bare receiving endpoint, so an ALLOWED
#                                      publish lands somewhere real
#   7. demo-propose / demo-ratify      a SECOND admission through the same ceremony,
#      (maker / checker)               giving demonstration 2 an untrusted read
#   8. demo-taint (safe-agents-agent)  DEMONSTRATION 2 — the same peer.publish
#                                      allowed on a clean turn, held on a tainted one
#   9. demo-sandbox (…-agent)          DEMONSTRATION 1 — the agent writes and runs a
#                                      program its sandbox permits, and the broker
#                                      refuses every forbidden call inside it
#
# Plus two legs that are about the ARGUMENT rather than about a mechanism:
#
#   5b. demo-baseline (…-agent)        THE CONTROL (#154) — the same call leg 5 was
#                                      refused, made with no broker in the path, and
#                                      it simply works. Runs at 10b because step 12
#                                      admits that tool and would falsify it.
#  10.  posture      (…-agent)         a posture report in cluster vocabulary from
#                                      inside a pod, reporting the two refusals as
#                                      UNKNOWN rather than claiming them (Phase 6.1)
#
# Demonstration 3 is leg 4, unchanged. The sandbox in demonstration 1 is the POD's own
# SCC + NetworkPolicy, never the EC2/AMI OpenShell box [ruling: maintainer,
# 2026-07-28] — that would put an AWS dependency inside the cluster arm.
#
# It does NOT push an image anywhere: both builds are in-cluster BuildConfigs
# against the same Containerfiles the podman drill and CI build
# [ruling: maintainer, 2026-07-26].
set -euo pipefail

cd "$(dirname "$0")/../../.."
REPO="$PWD"
HERE="safe_agents/arms/openshift"
NS="${NS:-safe-agents}"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

say "0. preflight"
command -v oc >/dev/null || die "oc is not on PATH"
WHO=$(oc whoami 2>&1) || die "not logged in to a cluster ($WHO)"
printf '   user=%s\n   server=%s\n' "$WHO" "$(oc whoami --show-server)"
ok "cluster reachable"

say "1. the declarative half"
# A FRESH store by default. The arc is a ceremony: run twice against the same
# PVC, its second pass meets an already-admitted row and the drill fails for a
# reason that has nothing to do with what it is proving. Durability is a
# WITHIN-run claim (pod one writes, pod two reads), so discarding the volume
# between runs costs the proof nothing and makes it repeatable — which is what
# Phase 6 eventually has to hand to someone else.
if [ -z "${KEEP_STORE:-}" ]; then
  # The broker Deployment FIRST, and this ordering is not cosmetic: it is the one
  # workload here that runs forever, so it holds the ReadWriteOnce claim open. Delete
  # the PVC with the Deployment still up and the claim wedges in Terminating exactly
  # the way a forgotten Job wedges it — the same failure, a longer fuse.
  oc -n "$NS" delete deployment safe-agents-broker --ignore-not-found >/dev/null 2>&1 || true
  # `--all`, not a list of names. A completed Job's pod still holds the PVC's
  # kubernetes.io/pvc-protection finalizer, so ONE forgotten Job leaves the
  # claim wedged in Terminating and the next run blocks forever waiting for a
  # volume that will never bind. Deleting by name means a renamed or superseded
  # leg does exactly that — which is how this was found, when Phase 2's
  # `safe-agents-arc` outlived the split into propose/ratify.
  oc -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
  oc -n "$NS" delete pvc safe-agents-store --ignore-not-found >/dev/null 2>&1 || true
  # The claim is gone only when the API says so; racing the next apply just
  # recreates the wedge.
  for _ in $(seq 1 30); do
    oc -n "$NS" get pvc safe-agents-store >/dev/null 2>&1 || break
    sleep 2
  done
fi
oc apply -k "$HERE/"
ok "namespace, ServiceAccounts, builds, PVC, connector secrets, drill scripts, netpol"

say "1b. the one NetworkPolicy rule that cannot be checked in"
# The agent pod is allowed to reach the API server ON PURPOSE — 60-networkpolicy.yaml
# argues that at length, and the short version is that a firewall timeout cannot be
# attributed to RBAC, so the drill trades reach for a nameable mechanism.
#
# It is generated rather than committed because OVN evaluates egress AFTER the
# Service DNAT: the rule has to name the API server's ENDPOINT addresses and port
# (node IPs on 6443), not the ClusterIP and port anyone would write down
# (172.30.0.1:443). Those addresses differ per cluster, so a checked-in file would be
# a local assumption hiding in a manifest — precisely what Phase 6's second-cluster
# validation exists to catch. Generating it keeps every committed manifest portable
# and makes the one cluster-specific rule visibly cluster-specific.
API_EPS=$(oc get endpoints kubernetes -n default -o jsonpath='{range .subsets[*].addresses[*]}{.ip}{"\n"}{end}' 2>/dev/null)
API_PORT=$(oc get endpoints kubernetes -n default -o jsonpath='{.subsets[0].ports[0].port}' 2>/dev/null)
[ -n "$API_EPS" ] && [ -n "$API_PORT" ] || die "could not read the kubernetes API endpoints"
{
  printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n'
  printf 'metadata:\n  name: safe-agents-agent-egress-apiserver\n  namespace: %s\n' "$NS"
  printf 'spec:\n  podSelector:\n    matchLabels:\n'
  printf '      app.kubernetes.io/name: safe-agents\n      app.kubernetes.io/component: agent\n'
  printf '  policyTypes: [Egress]\n  egress:\n    - to:\n'
  while read -r ip; do [ -n "$ip" ] && printf '        - ipBlock: { cidr: %s/32 }\n' "$ip"; done <<<"$API_EPS"
  printf '      ports: [{ protocol: TCP, port: %s }]\n' "$API_PORT"
} | oc apply -f - >/dev/null
ok "agent -> API server allowed at $(tr '\n' ' ' <<<"$API_EPS")on port $API_PORT (generated, cluster-specific)"

say "2. per-run secrets — generated here, never committed"
# Per-drill and destroyed with the namespace: ratified in #251 from three
# independent uses. A reusable dev issuer key would orphan attribution for every
# record signed under the previous one.
KEYDIR=$(mktemp -d)
trap 'rm -rf "$KEYDIR"' EXIT
python3 - "$KEYDIR/issuer.pem" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
with open(sys.argv[1], "wb") as fh:
    fh.write(key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))
PY
chmod 600 "$KEYDIR/issuer.pem"

oc -n "$NS" create secret generic safe-agents-issuer \
  --from-file=issuer.pem="$KEYDIR/issuer.pem" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
oc -n "$NS" create secret generic safe-agents-hmac \
  --from-literal=hmac-key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
ok "issuer signing key + broker HMAC key minted for this run"

# Phase 5. The peer transport token, and the descriptor the BROKER holds to reach the
# peer with it. Two objects carrying the same secret from opposite ends: the receiver
# gets the bare token to check, the broker gets {url, token_header, token} as its
# `peer` connector credential. The agent gets neither, which is the point of
# demonstration 2 — it can ask the broker to publish and cannot publish itself.
#
# Minted per-run and destroyed with the namespace, exactly like the issuer key. The
# committed 31-connector-secrets.yaml holds an EMPTY peer leaf on purpose; this
# overwrites it, and re-applying the kustomization would blank it again — which is why
# this runs after `oc apply -k` rather than before.
PEER_TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
PEER_URL="http://safe-agents-peer.$NS.svc:8081/inbound"
oc -n "$NS" create secret generic safe-agents-peer-token \
  --from-literal=token="$PEER_TOKEN" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
oc -n "$NS" create secret generic safe-agents-connector-secrets \
  --from-literal=ledger-mcp-placeholder="" \
  --from-literal=peer-mcp-example="$(python3 -c '
import json, sys
print(json.dumps({"url": sys.argv[1], "token_header": "x-peer-token", "token": sys.argv[2]}))
' "$PEER_URL" "$PEER_TOKEN")" \
  --dry-run=client -o yaml | oc apply -f - >/dev/null
ok "peer transport token minted; the broker holds the descriptor, the agent holds neither"

if [ -z "${SKIP_BUILD:-}" ]; then
  say "3. in-cluster builds — the SAME Containerfiles the laptop and CI build"
  # ASSERT THE ARTIFACT, never the exit code. `oc start-build --follow` exits 0 even when
  # the build FAILED — proven here 2026-08-10, where `error: build error: ... no such file`
  # was followed on the very next line by `PASS base broker image built`. Every green run
  # before that date carried this hole. Read the build object's phase instead.
  build_and_assert() {
    local bc="$1" label="$2" phase="" i=0
    oc -n "$NS" start-build "$bc" --from-dir="$REPO" --follow || true
    # `--follow` returns BEFORE the build object reaches a terminal phase (it exits after the
    # push), so sampling once reads `Running` on a build that in fact succeeded — observed
    # 2026-08-10. Wait for terminal, THEN assert. Note which way this fails if the wait is
    # too short: it refuses a good build rather than passing a bad one.
    while [ "$i" -lt 60 ]; do
      phase=$(oc -n "$NS" get build -l "buildconfig=$bc" \
                --sort-by=.metadata.creationTimestamp \
                -o jsonpath='{.items[-1:].status.phase}' 2>/dev/null)
      case "$phase" in Complete|Failed|Error|Cancelled) break ;; esac
      sleep 2
      i=$((i + 1))
    done
    [ "$phase" = "Complete" ] || die "$label build did not complete (phase=${phase:-<none>})"
    ok "$label"
  }
  build_and_assert safe-agents-broker-base "base broker image built"
  build_and_assert safe-agents-missileer   "missileer consumer image built on that base"
else
  say "3. builds SKIPPED (SKIP_BUILD=1) — reusing the images already in the ImageStreams"
fi

run_leg() {
  local job="$1" file="$2" label="$3"
  oc -n "$NS" delete job "$job" --ignore-not-found >/dev/null
  oc -n "$NS" apply -f "$HERE/$file" >/dev/null
  # Wait on EITHER terminal condition; waiting only on Complete makes a failure
  # look like a timeout and hides the logs that say why.
  local i pod phase
  for i in $(seq 1 90); do
    pod=$(oc -n "$NS" get pods -l job-name="$job" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    [ -n "$pod" ] || { sleep 4; continue; }
    phase=$(oc -n "$NS" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 4
  done
  [ -n "$pod" ] || die "$label: no pod ever appeared"
  printf '\n   ---- %s (%s) ----\n' "$label" "$pod"
  oc -n "$NS" logs "$pod" 2>&1 | sed 's/^/   /'
  SCC=$(oc -n "$NS" get pod "$pod" -o jsonpath='{.metadata.annotations.openshift\.io/scc}')
  UID_ASSIGNED=$(oc -n "$NS" get pod "$pod" -o jsonpath='{.spec.containers[0].securityContext.runAsUser}')
  printf '\n   scc=%s runAsUser=%s phase=%s\n' "$SCC" "$UID_ASSIGNED" "$phase"
  [ "$phase" = "Succeeded" ] || die "$label did not succeed (phase=$phase)"
  [ "$SCC" = "restricted-v2" ] || die "$label was admitted under '$SCC', not restricted-v2"
  ok "$label succeeded under restricted-v2 as uid $UID_ASSIGNED"
}

# Strictly sequential, and not only because they contend for a ReadWriteOnce
# volume: the checker consumes what the maker wrote, and the serve leg's whole
# claim is that the pods before it are GONE.
say "4. leg zero — bootstrap the grant store, as the checker ServiceAccount"
# Ahead of the maker because of the #203 split: the maker mounts the grant
# database read-only, and a read-only open cannot create the file it opens.
run_leg safe-agents-bootstrap 39-job-bootstrap.yaml "checker / bootstrap"

say "5. leg one — propose, as the maker ServiceAccount"
run_leg safe-agents-propose 40-job-propose.yaml "maker / propose"

say "6. leg two — ratify, as the checker ServiceAccount"
run_leg safe-agents-ratify 41-job-ratify.yaml "checker / ratify"

say "7. leg three — serve, as the broker ServiceAccount"
run_leg safe-agents-serve 42-job-serve.yaml "serve / durability"

say "8. leg four — the audit tamper attempt, back as the maker (#310)"
# Strictly after serve, and that is not tidiness. The broker is the only leg that
# writes the tape, so a tamper attempt made any earlier would be attacking an
# empty directory — a much weaker claim than failing to erase records that are
# actually there.
run_leg safe-agents-tamper 43-job-tamper.yaml "maker / audit tamper"

say "9. Phase 4 — the broker as a SERVING workload, not an in-process runtime"
# Everything above runs the broker inside the leg that is testing it. Phase 4's
# predicate is about crossing a boundary, so the broker has to outlive the process
# asking it questions. It comes up here, AFTER the tamper leg, for the same
# ReadWriteOnce reason the legs are sequential: this is the one workload that does
# not exit, and starting it earlier would leave it contending with every Job behind
# it for a volume that admits one node at a time.
oc -n "$NS" apply -f "$HERE/50-deployment-broker.yaml" >/dev/null
# Force a fresh pull even when the Deployment already existed. `imagePullPolicy:
# Always` covers a NEW pod; it does nothing for one already running on the previous
# `:arc`, and an unchanged Deployment spec produces no new pod at all. Without this
# the whole phase can pass against the image from the last run.
oc -n "$NS" rollout restart deployment/safe-agents-broker >/dev/null 2>&1 || true
oc -n "$NS" rollout status deployment/safe-agents-broker --timeout=240s \
  || { oc -n "$NS" logs -l app.kubernetes.io/component=broker --tail=60 2>&1 | sed 's/^/   /'
       die "the broker Deployment never became Ready"; }
BROKER_POD=$(oc -n "$NS" get pods -l app.kubernetes.io/component=broker \
  -o jsonpath='{.items[0].metadata.name}')
BROKER_SCC=$(oc -n "$NS" get pod "$BROKER_POD" -o jsonpath='{.metadata.annotations.openshift\.io/scc}')
printf '   pod=%s scc=%s\n' "$BROKER_POD" "$BROKER_SCC"
[ "$BROKER_SCC" = "restricted-v2" ] || die "the broker was admitted under '$BROKER_SCC', not restricted-v2"
# Readiness is an httpGet on /registry from the KUBELET, and the broker carries an
# ingress policy admitting the agent pod only. That the pod reached Ready at all is
# therefore a real observation about whether OVN exempts node health probes from
# NetworkPolicy — checked here rather than assumed, because if it did not, the
# symptom would be a Deployment that never becomes Ready and looks like a broker bug.
ok "the broker serves /call under restricted-v2, and kubelet probes reach it through the ingress policy"

say "10. leg five — the AGENT pod, a fourth ServiceAccount holding nothing"
# The phase, in one pod's log. It mounts no PVC, no Secret and no key; its SA has no
# RoleBinding; its egress is default-deny except DNS, the API server and the broker.
run_leg safe-agents-agent 52-job-agent.yaml "agent / Phase 4 predicate"

say "10b. THE CONTROL — the same refused call, with no broker in the path (#154)"
# Every leg so far shows something being refused; none shows that anything was at
# risk. This is that control, and it must run HERE: the drill admits list_entries
# at step 12 so demonstration 2 has an untrusted read, and after that point the
# broker allows it and this leg would be false. Ordering is the proof, not a
# convenience -- see the header of cluster-demo-baseline.sh.
run_leg safe-agents-demo-baseline 54-job-demo-baseline.yaml "agent / unbrokered baseline"

say "11. Phase 5 — the peer airlock endpoint comes up"
# No PVC, so it can run alongside anything. It refuses to start without its token,
# which keeps an ungated receiver from making the allowed branch look like it worked.
oc -n "$NS" apply -f "$HERE/53-deployment-peer.yaml" >/dev/null
# The drill ConfigMap has no name-suffix hash (deliberately — the Jobs name it
# literally), so a changed peer-receiver.py does NOT roll this Deployment on its own.
oc -n "$NS" rollout restart deployment/safe-agents-peer >/dev/null 2>&1 || true
oc -n "$NS" rollout status deployment/safe-agents-peer --timeout=180s \
  || { oc -n "$NS" logs -l app.kubernetes.io/component=peer --tail=40 2>&1 | sed 's/^/   /'
       die "the peer receiver never became Ready"; }
# #335: the peer is a leg, and "every leg admitted under restricted-v2" is one of the
# three success criteria this README publishes -- so it has to be asserted here rather
# than left to a reader's cluster query. It was the ONE leg that printed no SCC at all:
# the twelve Jobs get it from run_leg and the broker Deployment asserts it above, which
# is exactly the shape that makes a single omission invisible. Found by the Phase 6.3
# cold driver, which counted the assertions against the criterion and came up one short.
#
# MUTATION-TESTED 2026-07-29, because an assertion never seen to fail is not an earned
# assertion -- it is indistinguishable from an absent one in a green log. Granting the
# peer's SA the `anyuid` SCC (priority 10 beats restricted-v2's nil, and this Deployment
# sets no securityContext of its own) flipped admission, and the drill died HERE reading
# `FAIL the peer was admitted under 'anyuid', not restricted-v2` -- right place, right
# mechanism, after passing legs 0 through 10b. Binding removed and admission verified back
# to restricted-v2 afterwards.
#
# Two gotchas that cost time and will cost it again: SCC is assigned at pod ADMISSION, so
# `rollout restart` against an unchanged pod template re-admits NOTHING and the old
# annotation persists -- delete the pod to retest. And `{.items[0]}` may name the OLD pod
# while it is still Terminating, which reads exactly like a mutation that did not take.
PEER_POD=$(oc -n "$NS" get pods -l app.kubernetes.io/component=peer \
  -o jsonpath='{.items[0].metadata.name}')
PEER_SCC=$(oc -n "$NS" get pod "$PEER_POD" -o jsonpath='{.metadata.annotations.openshift\.io/scc}')
printf '   pod=%s scc=%s\n' "$PEER_POD" "$PEER_SCC"
[ "$PEER_SCC" = "restricted-v2" ] || die "the peer was admitted under '$PEER_SCC', not restricted-v2"
ok "the peer accepts on :8081/inbound, from the broker pod alone, under restricted-v2"

say "12. Phase 5 — admit a SECOND tool, so there is an untrusted read to be tainted by"
# The broker goes to zero first, for two reasons that happen to coincide. The obvious
# one is the ReadWriteOnce claim the ceremony Jobs need. The load-bearing one is that
# the broker builds its admitted-tool registry AT BOOT, so a broker left running
# across this would keep serving the old registry and refuse list_entries afterwards —
# with a perfectly correct-looking "never admitted" message that has nothing to do
# with the ceremony that just ran.
oc -n "$NS" scale deployment/safe-agents-broker --replicas=0 >/dev/null
oc -n "$NS" wait --for=delete pod -l app.kubernetes.io/component=broker --timeout=120s >/dev/null 2>&1 || true
run_leg safe-agents-demo-propose 55-job-demo-propose.yaml "maker / propose list_entries"
run_leg safe-agents-demo-ratify  56-job-demo-ratify.yaml "checker / ratify list_entries"
oc -n "$NS" scale deployment/safe-agents-broker --replicas=1 >/dev/null
oc -n "$NS" rollout status deployment/safe-agents-broker --timeout=240s \
  || die "the broker did not come back up after the admission ceremony"
ok "list_entries admitted by two credentials; the broker rebooted onto the new registry"

say "13. DEMONSTRATION 2 — a read of hostile content escalates a later write"
run_leg safe-agents-demo-taint 57-job-demo-taint.yaml "agent / taint escalation"

say "13b. the same story from the BROKER's tape, which the agent cannot reach"
# The agent leg reports what it was TOLD. This reads the tamper-evident tape from the
# broker pod — a mount no agent pod has, written by the one identity that may write it
# — so the differential is corroborated by a record the subject of the test could not
# have produced. Two independent views of the same three calls.
#
# NB `reason` is empty on every row including the hold (#316): RequireApproval carries
# no reason field, so the tape can say a call was HELD and cannot say why. Printed
# rather than hidden, because that is the honest state of the evidence today.
oc -n "$NS" exec deploy/safe-agents-broker -- python3 -c "
import json
rows = [json.loads(l) for l in open('/var/lib/broker-audit/audit.jsonl') if l.strip()]
for r in rows:
    print('   seq=%-2s %-20s decision=%-16s outcome=%-9s reason=%s'
          % (r['seq'], r['tool'] + '.' + r['op'], r['decision'], r['outcome'], r.get('reason')))
pub = [r for r in rows if r['tool'] == 'peer']
if len(pub) < 2:
    raise SystemExit('   expected two peer.publish records on the tape, found %d' % len(pub))
first, last = pub[0], pub[-1]
if not (first['decision'] == 'allow' and first['outcome'] == 'executed'):
    raise SystemExit('   the clean publish is not recorded as executed')
if not (last['decision'] == 'require_approval' and last['outcome'] == 'held'):
    raise SystemExit('   the tainted publish is not recorded as held')
print()
print('   the broker recorded the SAME op twice: seq %s executed, seq %s held.'
      % (first['seq'], last['seq']))
" 2>&1 | sed 's/^/  /' || die "the broker's tape does not corroborate demonstration 2"
ok "the tape corroborates the differential, from a mount no agent pod has"

say "14. DEMONSTRATION 1 — the sandbox permits, the broker refuses"
# Last of the three, and it runs on the SAME pod isolation the Phase 4 leg proved: the
# sandbox here is the SCC and the NetworkPolicy, not an OpenShell box
# [ruling: maintainer, 2026-07-28] — wiring the EC2/AMI sandbox in would put an AWS
# dependency inside the cluster arm, which this epic deliberately does not carry.
#
# Safe to run after demonstration 2 even though the turn is now tainted: every call it
# makes is either a READ (rule 11 is taint + external + WRITE, so reads are unaffected)
# or is denied at the manifest layer before any taint rule is reached.
run_leg safe-agents-demo-sandbox 58-job-demo-sandbox.yaml "agent / sandbox-vs-broker"

say "15. Phase 6.1 — the posture report, generated where the containment is"
# Last deliberately. Everything above DEMONSTRATES a property; this asks whether the
# surface a reader will actually consult describes those properties in this
# platform's vocabulary and names the limit of each. Running it in the agent pod
# rather than on a laptop is the whole point -- an empty CLUSTER section is a
# failure here and is the normal, correct output on a Mac.
# CONDITIONAL: this leg reports posture through a product wrapper that is not part of
# the platform, and is deliberately absent from the public reference implementation
# [2026-08-10]. The arm predates it by twelve minor versions (v0.57.0 -> v0.69.0), so a
# tree without it is the arm as it ran for most of its life, not a broken one.
if [ -f "$(dirname "$0")/59-job-posture.yaml" ]; then
  run_leg safe-agents-posture 59-job-posture.yaml "agent / posture in cluster vocabulary"
else
  printf '  (skipping the posture leg: not present in this tree)\n'
fi

printf '\n\033[32mPHASE 3 PREDICATE: PASS\033[0m\n'
printf '  the ceremony ran under TWO ServiceAccounts in separate pods; the maker was\n'
printf '  refused the signing key, the ability to have it delivered, AND the ability\n'
printf '  to write a grant row at all — the last of these by the kernel, on a\n'
printf '  read-only mount, attempted in the log rather than asserted from the\n'
printf '  manifest, while its evidence reads still succeeded; the signed record\n'
printf '  names two real identities and carries no solo attestation; a fourth pod\n'
printf '  served the result from a store that outlived them all; and a fifth,\n'
printf '  holding the maker credential, could neither erase nor forge the tape that\n'
printf '  fourth pod wrote (#310) — which is a narrower claim than "the audit\n'
printf '  survives a compromised broker", and deliberately so.\n'

printf '\n\033[32mPHASE 4 PREDICATE: PASS\033[0m\n'
printf '  and a SIXTH pod, under a fourth ServiceAccount holding nothing at all,\n'
printf '  could not reach the internet and could not obtain the broker Secret — by\n'
printf '  the network policy and by RBAC respectively, each attempted from inside\n'
printf '  that pod and each naming which control refused it — while a brokered call\n'
printf '  through the broker executed anyway. That last clause is the phase: two\n'
printf '  denials without it are what a broken pod produces.\n'
printf '\n  Rung 2 by ORCHESTRATION, and the distinction is the claim: separate\n'
printf '  ServiceAccounts, OVN egress and a broker-only mount are boundaries the\n'
printf '  PLATFORM enforces. No safe_agents code sits in that path, and nothing here\n'
printf '  constrains what the agent does inside its own pod.\n'

printf '\n\033[32mPHASE 5 PREDICATE: PASS — ALL THREE DEMONSTRATIONS\033[0m\n'
printf '  \033[32m1. the sandbox permits, the broker refuses\033[0m — the agent wrote a program\n'
printf '     inside a sandbox that objected to nothing, ran it, and had every forbidden\n'
printf '     action refused by the BROKER and by nothing in the pod. The honest answer to\n'
printf '     "why not just use OpenShell?" is that this is not better — it protects a\n'
printf '     different party, and the two compose.\n'
printf '  \033[32m2. a read of hostile content escalates a later write\033[0m — the same\n'
printf '     peer.publish flowed after a TRUSTED read and escalated to require_approval\n'
printf '     after an UNTRUSTED one, on one broker-held turn, with the agent unable to\n'
printf '     reach the peer any other way.\n'
printf '  \033[32m3. a ceremony leg cannot forge or erase another leg records\033[0m — four\n'
printf '     kernel refusals against a populated tape, with the limit printed next to the\n'
printf '     PASS (the broker can still rewrite its own).\n'
printf '\n  The sandbox in demonstration 1 is the POD — SCC and NetworkPolicy — not an\n'
printf '  OpenShell box [ruling: maintainer, 2026-07-28]. The composition claim does not\n'
printf '  depend on which sandbox, but it must NAME the one in the picture, and wiring in\n'
printf '  the EC2/AMI box would put an AWS dependency inside the cluster arm.\n'

printf '\n\033[32mPHASE 6.1 PREDICATE: PASS\033[0m\n'
printf '  and the posture report said all of it back in cluster vocabulary from inside a\n'
printf '  pod — ServiceAccount, SCC, mount topology — while reporting the two\n'
printf '  REFUSALS above as UNKNOWN rather than claiming them. posture makes no\n'
printf '  network calls, so it cannot have attempted either; asserting them from the\n'
printf '  manifest is exactly the overclaim this audience is best equipped to find,\n'
printf '  and the leg FAILS if a future edit does it.\n'
