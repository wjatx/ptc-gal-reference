# `arms/openshift` — the cluster arm

**Epic:** #250 (OpenShift as a deployment substrate). **Phases 2–5:** get the ceremony arc
running in a pod, prove the store survives the pod, put a second workload on the other side
of a boundary and show what it cannot reach — then demonstrate the two claims that do not
need a wrapped agent.

**If this directory was handed to you, read `BRIEF.md` first** — it states what is being
claimed, each claim's limits, what is not demonstrated, and what we are asking you to send
back. This README is the run instruction; the brief is the covering note.

This arm deploys the broker to OpenShift and runs the same ceremony arc the Mac and the
podman container run. It owns no new mechanism: the store is the sqlite arm, the secrets are
the `dir` arm (#248), the ceremony identity is the ServiceAccount arm of the #226 catalog.
What the cluster adds is *boundaries we orchestrate rather than implement* — SCC, RBAC, mount
topology, and a volume that outlives the process.

## Run it

This section is written to be completed unaided (#157). If a step turns out to be missing or
wrong, the README is what is broken — fix or file it here, never by bending the drill to match
a thin README.

**You need:**

- **Cluster admin on an OpenShift cluster.** The arm uses BuildConfigs and ImageStreams, so
  vanilla Kubernetes will not do; the internal image registry must be enabled (the consumer
  build pulls its base through `image-registry.openshift-image-registry.svc:5000`), and a
  default StorageClass must be able to bind a 1Gi ReadWriteOnce claim. Verified on OpenShift
  4.20 / OVN-Kubernetes; the one CNI-sensitive piece — the post-DNAT API-server egress rule,
  argued below — is generated from the live cluster at apply time rather than checked in.
- **On the host:** `oc` logged in (`oc whoami` answers), bash, and `python3` with the
  `cryptography` package importable — the driver mints a per-run Ed25519 issuer key locally
  before handing it to the cluster as a Secret.
- **A checkout of this repo.** The in-cluster builds upload the **working tree**
  (`oc start-build --from-dir`), so a run proves what is on disk, not what is committed.

**Then, from this directory (the script finds the repo root itself):**

```
oc login <cluster>
./cluster-arc-run.sh              # build in-cluster, run every leg
SKIP_BUILD=1 ./cluster-arc-run.sh # reuse the images already in the ImageStreams
```

A first run spends most of its time in the two in-cluster builds; `SKIP_BUILD=1` reruns skip
them. The drill discards the previous run's store by default (`KEEP_STORE=1` to keep it), so
re-running is always safe.

**One known diff, 2026-08-12 (#385).** The posture ladder's positions were renamed from "rung N"
to "posture N", so `cluster-arc-run.sh` and `cluster-posture.sh` now print `Posture 2` where the
captured log reads `Rung 2`. The log is deliberately NOT hand-corrected — editing recorded output
to match a change we made is manufacturing evidence — so it carries the old word until the next
cluster re-capture. Three lines, all prose in a `printf`; no predicate moved.

**What success looks like:** exit code 0, every leg admitted under `restricted-v2`, and four
green predicate blocks — Phases 3, 4, 5 and 6.1 — at the end. `expected-output.log` beside
this file is the complete log of a real run, captured rather than composed, to diff yours
against — **re-captured 2026-08-10 on OpenShift 4.20.30 at safe-agents 0.72.0**, full build
included, 5m39s wall clock, in a namespace that did not exist when the run began. **Wall clock is
strongly cluster-dependent and varies run to run on the same cluster** — four captures of this same
work took 19m, 9m56s, 11m56s and 5m39s, so a much faster run is not evidence the builds were
skipped. Check the two `PASS ... image built` lines instead — and note that until 2026-08-10 those
lines could not be trusted for exactly that purpose: `oc start-build --follow` exits 0 even when the
build FAILS, so a failed build printed `PASS ... image built` on the very next line. The driver now
waits for the build object to reach a terminal phase and requires `Complete`, so the line means what
it says.

Values that legitimately differ: the server URL and API endpoint IPs, **any DNS-resolved external
address** (`api.github.com` moves between runs), pod name suffixes, assigned UIDs, generated ids
(grants, intents, ledger entries), timestamps, **the audit-chain hashes** (they cover timestamps,
so they can never match), and build output. What should **not** differ: the PASS/FAIL lines, the
mechanism named in every refusal, and the decision/outcome columns of the audit tape.

**Re-capture, never edit.** If your run differs outside that list it is either a real portability
finding or a reason to re-capture from a real run — hand-patching this file to match makes it
agree with nothing. And note the invalidation surface is wider than this directory: a change
anywhere under `safe_agents/` that the drill exercises can move the output, which is how the
superseded capture went stale while this arm itself was untouched.

**Teardown:** `oc delete ns safe-agents` — everything, including the per-run secrets, goes
with the namespace. If a later run hangs waiting for the PVC, a completed Job's pod is holding
the claim's protection finalizer: `oc -n safe-agents delete jobs --all` clears it (the driver
does this itself at the top of every run).

**`SKIP_BUILD=1` only skips the image, and the split is not where you would guess.**
The drill *scripts* ride in a ConfigMap, so editing them and re-running with `SKIP_BUILD=1`
picks the changes up immediately. The *SDK* is baked into the image, so any change under
`safe_agents/` needs a rebuild. Getting this wrong is quiet rather than loud: the pod runs
happily against the previous SDK and fails somewhere unrelated to what you changed. It cost
a confusing run here — a pod on the pre-Phase-3 image fell through to the STS arm and
reported "cannot derive the ceremony identity from AWS STS", which is the correct behaviour
of code that has never heard of `BROKER_CEREMONY_IDENTITY`.

The driver applies `oc apply -k .` (everything that can exist before an image does), mints a
per-run issuer signing key, HMAC key and peer transport token, runs both BuildConfigs, then
runs the Jobs in strict order around two long-lived Deployments (the broker and the peer).
Teardown is `oc delete ns safe-agents`.

## What the legs prove

One pod is one credential under the serviceaccount arm, so the ceremony necessarily splits.
That is the point rather than an inconvenience: a pod cannot hold both halves.

| leg | ServiceAccount | shows |
|---|---|---|
| `safe-agents-bootstrap` | `safe-agents-checker` | creates the grant store, because a read-only open cannot create the file it opens and the maker's mount is read-only (#203) |
| `safe-agents-propose` | `safe-agents-maker` | identity derived by **round-trip** (`SelfSubjectReview`); the solo arm **refused** because a real identity exists here; **HTTP 403** reading the issuer Secret and **HTTP 403** creating a pod that would mount it; then proposes, and its own ratify attempt dies at the signing gate |
| `safe-agents-ratify` | `safe-agents-checker` | the only pod with the key mounted: seeds, ratifies, and verifies the record names **two distinct ServiceAccounts** with `attestation: None`; then proves **M7** by proposing and ratifying as one credential *while holding the key*, so the signing gate cannot mask the identity check |
| `safe-agents-serve` | `safe-agents-broker` | serves the ratified grant holding **neither** ceremony credential and no signing key; the only leg that writes the audit tape, and it verifies the chain it wrote |
| `safe-agents-tamper` | `safe-agents-maker` | truncate, append, unlink and replace the tape the serve leg just wrote — **four for four refused by the kernel** with EROFS *named*, then the chain re-verified byte-identical (#310) |
| `safe-agents-peer` | `safe-agents-peer` | the peer airlock endpoint `peer.publish` posts to — reachable from the **broker pod alone** |
| `safe-agents-demo-*` | maker / checker | a SECOND admission through the same ceremony, so demonstration 2 has an untrusted read to be tainted by |
| `safe-agents-demo-sandbox` | `safe-agents-agent` | **demonstration 1** — the agent authors and runs a program its sandbox permits, and the broker refuses every forbidden call in it |
| `safe-agents-demo-taint` | `safe-agents-agent` | **demonstration 2** — the same `peer.publish` allowed on a clean turn and held on a tainted one |
| `safe-agents-agent` | `safe-agents-agent` | holds **nothing** — no mount, no Secret, no RoleBinding. External egress dropped, the broker Secret refused **403**, the pod that would mount it refused **403**, and a brokered call through the broker executes anyway (Phase 4) |
| `safe-agents-demo-baseline` | `safe-agents-agent` | **the control (#154)** — the agent spawns the ledger server itself and calls the *unadmitted* tool with no broker in the path. It **works**. The identical call through the broker is refused, while a different one executes |
| `safe-agents-posture` | `safe-agents-agent` | **Phase 6.1** — a posture report generated *inside* a pod, in cluster vocabulary, and asserted to report the egress and RBAC refusals as **`unknown`** rather than claiming them |

### The control, and why it has to run at 10b

Every other leg here shows something being **refused**. None of them shows that anything was ever
at risk — which is what **#304** names: every proof in this repo is a drill we designed to pass, and
a drill in which the harm never occurs demonstrates a system saying no, not that the no mattered.

`cluster-demo-baseline.sh` is that control. Same pod, same SCC, same egress policy, same tool —
and the broker simply not in the path. The agent spawns `examples/restricted_mcp_server/server.py`
as its own stdio child, exactly the way the broker does, and calls `list_entries`. Real entry ids
come back. Then the identical call through `/call` is refused.

**Its position in the run is part of the proof.** Step 12 admits `list_entries` through a second
ceremony so demonstration 2 has an untrusted read to be tainted by; after that point the broker
*allows* it and this leg would be asserting something false. It therefore runs at **10b**,
immediately after leg five, where it is the control for that leg's refusal. Moving it later does
not make it flaky — it makes it wrong, which is worse, so the leg detects that case and says so
by name rather than merely failing.

**What it deliberately does not show,** printed on screen next to the PASS:

- **A credential being bypassed.** The ledger server needs none, so this is the *admission* half
  only. That the agent pod holds no connector secret and is refused it by RBAC is leg five; the two
  compose rather than substitute.
- **A compromised server.** `examples/restricted_mcp_server/` is the missileer archetype and has no
  dangerous op at all. `list_entries` is an ordinary, legitimate tool — which is exactly the point:
  what makes it uncallable through the broker is that nobody ratified it, not that it is missing.
- **Real harm.** The blast radius is a fictional ledger, on purpose. What is real is the mechanism.

### Why the posture leg reports `unknown` for things the drill just proved

The one line in that table worth arguing with. Steps 10 and 14 demonstrate that egress is dropped
and the Secret is refused; step 15 then runs a report that says both are **unknown**, and the leg
*fails* if a future edit "corrects" it.

That is not timidity, it is the same rule the rest of this arm runs on. `posture` makes no network
calls — a posture command that silently dialled out would be a surprising thing to run — so it
cannot have **attempted** either refusal, and a refusal is only evidence when it is attempted.
Both properties are TRUE here, which is exactly what makes the overclaim tempting: the manifest
says so, the drill says so, and the report could just repeat it. A report that repeats what the
manifests assert is a manifest summary wearing a report's clothes, and this audience is best
equipped to catch precisely that.

So the honest split is: the posture command reports what it can **observe** from inside the pod — the
ServiceAccount it runs as, the uid and capability mask the SCC left it, which authority mounts
exist — and for the two refusals it reports `unknown` and **names `cluster-agent.sh`**, which
attempts them for real a few steps earlier. The drill proves them; the report declines to take
credit for a proof it did not run.

### The audit tape is a third subPath, not a file in the working half

One `ReadWriteOnce` claim, three subPaths: `work/` (writable by every leg — it is how they hand
work to each other), `grants/` (checker-writable, #203), `audit/` (broker-writable, #310). A
mount is read-only per *container*, not per volume, which is why one claim carries three
different postures.

The tape used to live in `work/`, where every leg could rewrite every other leg's records — and
the chain does not save you there. It is **unkeyed SHA-256** (`safe_agents/broker/audit/_hash.py`), so anyone
holding write access re-chains the file end to end and it verifies clean. The read-only mount is
the control; the chain only detects an edit by someone who could not rewrite the rest.

The ceremony legs no longer set `BROKER_AUDIT_PATH` at all. They never constructed an audit
sink — only `broker_server.build_runtime` does, and the ceremony commands do not call it — and
leaving the variable aimed at a now-read-only mount would turn the first ceremony command that
*did* emit a record into a mount error rather than a policy refusal. Unset is the loud option:
a durable store with no audit sink is refused at boot by F3 (`require_named_real_backends`),
naming the variable to set.

**What the split does not buy.** The broker must write the tape, so the broker can rewrite it,
and no mount topology changes that — only off-device append-only durability does (S3 Object Lock
on the cloud floor). `cluster-tamper.sh` prints that limit next to its own PASS, because this is
exactly the claim an audience that probes overclaims will probe.

### How the "different pod" claim is made

Phase 2 got it free: the local arm's identity was `<osuser>@<shorthost>#<role>`, and in a pod the
short hostname is the pod name. A ServiceAccount username names a **credential and carries no
pod**, so that inference is gone. It is now made three ways, none of them read out of the identity
string: the serve pod cannot sign and so cannot have written the signed record it reads; each
earlier leg leaves an explicit breadcrumb naming its pod; and none of the credentials in the
stored attribution is the one the serve pod holds.

Worth knowing because the first version of this leg kept parsing for an `@` that was no longer
there — which made the comparison trivially true and the durability claim **vacuous while still
printing PASS**.

## Phase 4: the topology, and which boundary does the work

The five ceremony legs each build a broker runtime **in-process** and exit. That is enough
for a claim about what a credential can do, and useless for a claim about crossing a
boundary — so Phase 4 adds a broker `Deployment` behind a ClusterIP `Service` and a sixth
pod that talks to it over HTTP like anything outside would.

**Name the boundary, every time.** Separate ServiceAccounts, OVN egress and a broker-only
mount are boundaries the **platform** enforces. No `safe_agents` code sits in that path.
This is the standing "orchestrate existing boundaries, never implement a sandbox" rule, and
the honest consequence is that **nothing here constrains what the agent does inside its own
pod** — the agent pod even carries the SDK, because it runs the same image every other leg
does. That buys it nothing: it holds no credential, no connector secret and no mount, which
is the thesis rather than a concession. A fully compromised agent can still only ask.

**The API server is deliberately reachable from the agent pod**, and this is the least
obvious decision in the arm. A tighter policy would drop it, and the Secret refusal would
then be a *timeout* — which is also what a broken mount, a wrong namespace and a typo'd
hostname produce. Given more reach than a production envelope would grant it, the agent is
refused anyway by RBAC, with a 403 naming its ServiceAccount. That is strictly stronger than
"it could not connect", and `cluster-agent.sh` prints the trade on screen. A real deployment
should deny both; what is being demonstrated is attributability, not defence in depth.

### The post-DNAT rule, which cost this phase an hour

OVN-Kubernetes evaluates egress policy **after** the Service DNAT, against the backend
address and the **target** port. A rule written against what you typed never matches:

| want | Service says | the rule must say |
|---|---|---|
| cluster DNS | `172.30.0.10:53` | the `openshift-dns` pods, port **5353** |
| the kube API | `172.30.0.1:443` | the node **endpoint** IPs, port **6443** |
| the broker | `<svc>:8080` | the broker pod, port 8080 (unchanged) |

[verified 2026-07-28, OpenShift 4.20 / OVNKubernetes.] The failure is silent in the worst
way: the policy applies cleanly, `oc describe` shows the rule you meant, and the pod simply
resolves nothing — which reads as a broken cluster rather than a wrong port number.

Because the API-server rule names cluster-specific addresses, `cluster-arc-run.sh` **generates**
it from the live endpoints instead of committing it. Every checked-in manifest stays portable
and the one rule that is not is visibly not — which is what Phase 6's second-cluster
validation exists to catch.

**DNS is allowed on purpose, and it is load-bearing for the proof.** With DNS denied, an
external connection attempt fails at *resolution* and the drill cannot tell a dropped packet
from an unresolvable name. With it allowed, `api.github.com` resolves to a live address and
the connection to that address is then dropped — so the denial is attributable to the policy
and to nothing else.

## Phase 5: all three demonstrations

**Demonstration 2 — a read of hostile content escalates a later write.** Three calls on
one broker-held turn, from the agent pod:

| | call | verdict |
|---|---|---|
| A1 | `ledger.get_entry` — a **trusted** read (`envelope.trusted_read_sources`) | allow |
| A2 | `peer.publish` | **allow**, delivered, peer returns 200 |
| B | `ledger.list_entries` — an **untrusted** read | allow, executes, **taints the turn** |
| C | `peer.publish` again | **require_approval**, held, intent minted |

Same op, same args shape, same credential, same grant. The only thing that changed is
what the turn had read. **The order is forced and that is the property, not a
convenience:** taint is monotone and the broker-held turn is one per principal across
every `/call` (sa#136), rolling over only via `new_turn()` — an agent that could roll
its own turn would launder taint by declaring a fresh one.

A2 is the control. Without it the escalation proves nothing, because a `peer.publish`
that never worked would "escalate" identically.

**What the agent cannot observe — and what the tape now names.** The *agent* still gets no rule
name: the agent leg prints an empty `reason:`, so four different escalating rules are
indistinguishable **to the subject of the test**.

Be precise about *why*, because the obvious explanation is out of date. `RequireApproval` **does**
carry a `reason` field now (`broker/schemas/decision.py:77`), and the PDP populates it. What is
still missing is the **`/call` HTTP response path** — the drill reads `reason` off the response
body, and the broker does not put it there. So this is a transport gap, not the schema gap **#316**
was filed for; #316's item 1 is done and the issue is partly satisfied. The drill carries a tripwire
for exactly this (`cluster-demo-taint.sh`: *"reason field populated — #316 may be fixed; tighten this
check"*), and it did **not** fire in the current capture.

The *tape* is no longer silent, and this README understated it until 2026-07-29. Since the
held-call reason landed on the record as well as in the render, seq 9 reads
`peer.publish decision=require_approval outcome=held reason=tainted external write`. So the
mechanism is established by **differential** *and* corroborated **by name**, from a mount no
agent pod has — with the alternatives ruled out by construction (distinct idempotency keys, so
not a replay; a handful of calls against a 50-action cap, so not a budget). Every other row on
the tape still carries `reason=None`; it is the escalation specifically that now explains itself.

The driver then reads the tape **from the broker pod** — a mount no agent pod has — so
the differential is corroborated by a record the subject of the test could not have
produced. Watch `list_entries` across that tape: `allow/refused` at seq 1, 3 and 4, then
`allow/executed` at seq 8 after the admission ceremony. Two-key admission changing
callability, visible in the evidence rather than argued.

**The agent cannot go around it.** It is *given* the peer's DNS name in its own
environment and still cannot open a socket to it — a denial that depended on the agent
not knowing where to aim would be secrecy, not a control. The peer token is a
broker-fetched credential it never holds.

**The peer receiver is a bare endpoint**, deliberately: it checks the shared transport
token and validates the body parses as an `EventTrigger`, and that is all. No trust map,
no sender-class mapping, no dedupe, no screening — those are `examples/webhook_peer` and
the channels epic. It exists so the allowed branch lands somewhere real, because an
allow that quietly fails to execute is indistinguishable in effect from a deny.

**The published envelope is agent-authored (#315).** `stamp_outbound` — the seam that
would derive the outbound hop's label from the broker-held turn's taint — has no runtime
caller, so the provenance chain the receiver prints proves nothing and the receiver says
so on every request. This demonstration rests on the **verdict**, which never reads the
envelope.

**Demonstration 3 — a ceremony leg cannot forge or erase another leg's records** is leg
four (`cluster-tamper.sh`, #310): four kernel refusals against a populated tape, with the
limit printed beside the PASS.

**Demonstration 1 — the sandbox permits, the broker refuses.** Three acts. Act 0 proves
the sandbox is *real* (capabilities all dropped, external egress dropped) — "the sandbox
permits" means nothing if the sandbox is absent. Act 1 has the agent write a program into
its own filesystem and execute it, which the pod permits without objection. Act 2 runs the
forbidden calls **through that program**: `ledger.delete_entry` and `payments.transfer`,
both denied by the broker with the mechanism named — `no manifest entry for <tool>.<op>` —
and both perfectly legal as far as the SCC and the NetworkPolicy are concerned.

`deny` populates `reason` (unlike `require_approval`, #316), so unlike demonstration 2
this one **can** assert which control fired by name.

**The venue is the POD's own isolation** — SCC and NetworkPolicy — not an OpenShell box
[ruling: maintainer, 2026-07-28]. `arms/rhel_openshell/` is the EC2/AMI sandbox and wiring
it in would put an AWS dependency inside the cluster arm, which this epic deliberately does not
carry. The composition claim does not depend on which sandbox; the claim must simply name
the one actually in the picture.

**What it is NOT, and the drill says so on screen.** Not "the broker beats a sandbox" — it
is not better, it protects a *different party*, and the honest answer to "why not just use
OpenShell?" is that they compose. The sandbox kept the agent off the internet and out of
the kernel and had no opinion about the ledger; the broker had no opinion about `/tmp`. A
sandbox alone would have permitted every refused call, because nothing in an SCC or a
NetworkPolicy can express "may read entries, may not delete them". And the dangerous op is
**absent** from the ledger server rather than denied — the missileer archetype — so the
deny is the second line of defence and the first is that there is no delete tool at all.

## Negative proofs assert the MECHANISM (#312)

`negative-proof.sh` is sourced by the legs. `np_refuse` demands three things, not one: the
attempt did not succeed, it failed, and it failed **for the stated reason** — a refusal whose
output lacks the expected mechanism string is a failure even though the attempt failed.
`np_control` is the adjacent thing that must still work, `np_precondition` is the state the
attempt runs against, and `np_summary` fails a script that recorded refusals and declared no
control at all.

That last rule has teeth because the omission recurs: a pod that can do nothing refuses
everything and proves nothing. The four hand-rolled instances it replaced had all three
failure modes between them — the #310 tamper leg checked only exit codes, so a read-only
*root* filesystem would have printed PASS four times.

`negative-proof-selftest.sh` runs on a laptop in a second and asserts the helper **fails when
it should**. It is not ceremony: a refactor of the failure counter briefly made the
wrong-mechanism branch non-counting, so `np_refuse` would have accepted a refusal by the wrong
control while printing `WRONG MECHANISM` on screen, and every cluster drill would still have
gone green. Case A caught it immediately.

## Two things this arm does NOT claim

**The issuer key's `0600` mode is not what protects it here.** A projected Secret volume under
an fsGroup gets `0440` OR-ed into whatever `defaultMode` was requested — verified 8/8 across
requested modes on OpenShift 4.20.29 (#282). The mode is not the operator's to choose, so
`_read_local_key_file`'s check (#226) can never pass on the projection, and `cluster-ratify.sh`
stages a private 0600 copy on a memory-backed volume instead. That copy is a **compatibility
shim, not a control**: #226 models a multi-user host, and in a pod the boundary protecting the
key is the pod — SCC, RBAC on the `Secret`, and mount topology.

**`maker != checker` is not enforced by RBAC on the store, and is not on AWS either.** The
backstop on both substrates is the *signing key* plus a *write split*: MakerRole carries zero
`secretsmanager` statements ("Deliberately NO `*/issuer/*` — the maker cannot sign a record",
`infra/lib/identity-stack.ts`), and here the issuer `Secret` is mounted into the ratifying pod
alone. Since #203 closed (2026-07-28) that is **prevention for signing AND prevention for
writes** — the older "detection for writes" formulation is retired. The grant key space
(`GRANT#`/`RECORD#`/`TOOLDEF#`/`TOOLREC#`) is its own sqlite file on a read-only mount here and
`LeadingKeys`-confined on AWS, so the maker cannot write the row at all rather than writing an
unsigned one for the audit to catch later. Its *reads* stay unconditioned on purpose:
read-denied is not a stricter write-denied, it breaks evidence assembly. Phase 3 replaced the
solo attestation with real ServiceAccount identities; it did not change this split.

Be precise about what RBAC contributes, because the loose version of the claim is wrong:
**RBAC governs API access, not kubelet volume mounts.** "The maker SA cannot read the Secret"
would not by itself stop a maker-authored pod from *mounting* it. What closes the loop is both
halves together — the maker's credential can neither read the key (403) nor create the workload
that would have it delivered (403). `cluster-propose.sh` attempts both and shows the refusals.

Note there is deliberately **no RoleBinding anywhere in this arm**, including for the checker.
The checker receives the key by mount, which is what the epic's "files, not API" rule asks for: a
standing RBAC grant to read a signing key is broader authority than mounting exactly what is
needed. The plan sketched "two ServiceAccounts with two RoleBindings"; that presumed RBAC would
be the asymmetry, and it is not — the asymmetry is mount topology.

## The honest ledger

One concession belongs in the artifact itself rather than in a research study: **Praxis's
`docs/architecture/threat-model.md` is a better artifact than anything this repo has** — eight
named injection channels, each with an exposure statement, a mechanical defense, a
deterministic test, a graded eval case and a **named owner**, plus a gate that blocks any plan
feeding model context from a new untrusted source until it has a row and adversarial fixtures.
This repo has stronger *mechanism* (`broker/TAINT.md`, `channels/SCREENING.md` — taint here is
broker-held and non-strippable, where their untrusted labels never reach the envelope check),
and it has no per-channel register with owners and a shipping gate; this drill does not
substitute for one. The concession is deliberate [#250 Phase 6, work item 4]: an artifact that
names what its neighbours do better is easier to trust about what it claims for itself.

## Files

- `kustomization.yaml` — the declarative half. The Jobs are excluded on purpose: they name an
  ImageStreamTag that does not exist until the builds have run.
- `20-builds.yaml` — two BuildConfigs against the **same Containerfiles** the podman drill and
  CI build, via `dockerfilePath`. Image delivery is an in-cluster build, never a laptop push
  [ruling: maintainer, 2026-07-26]. A BuildConfig that inlined its own steps would be a
  second build path, and the drift would stay invisible until the cluster and the laptop disagreed about an
  image with the same name in both places.
- `40-job-propose.yaml` / `41-job-ratify.yaml` / `42-job-serve.yaml` — one file per leg so the
  driver can order them strictly. They contend for a ReadWriteOnce volume, the checker consumes
  what the maker wrote, and the serve leg's whole claim is that the pods before it are gone.
- `50-deployment-broker.yaml` / `51-service-broker.yaml` / `52-job-agent.yaml` /
  `60-networkpolicy.yaml` — Phase 4. The Deployment is excluded from the kustomization for the
  same reason the Jobs are (it names an ImageStreamTag that must be built first); the Service
  and the policies are **in** it, and applied early on purpose — they select pods by label, so
  applying them alongside the agent Job would leave a window in which the pod runs
  unconstrained, and a drill that passes in that window has proven nothing.

- `54-job-demo-baseline.yaml` / `cluster-demo-baseline.sh` — the control (#154). Agent SA, agent
  pod label, `workingDir: /app` so `-m examples.restricted_mcp_server.server` resolves. No new
  grant, secret or mount: a stdio child has no network surface for the egress policy to allow and
  needs no credential, which is the restrict-by-construction archetype paying off in the leg that
  was added last.
- The Phase 6.1 posture leg — **not shipped in this tree** (it reports through a product wrapper
  this repository does not include, so its Job and driver script are absent; see the note at the
  top of `kustomization.yaml`). Where it runs, it runs under the **agent**
  ServiceAccount and carries the agent's pod label, so the report is generated under the same
  SCC and the same default-deny egress policy as the workload it describes. A posture report
  produced in an unconstrained pod would observe an unconstrained pod and say so correctly,
  about the wrong thing. It declares no volume for the same reason `52-job-agent.yaml` does not,
  and its posture home is `/tmp`: an absent store is reported as absent rather than worked around.

**The broker Deployment is the one workload here that does not exit**, so it holds the
ReadWriteOnce claim open. `cluster-arc-run.sh` deletes it *before* the PVC on teardown;
skip that and the claim wedges in `Terminating` exactly the way a forgotten Job wedges it —
the same failure with a longer fuse. It also `rollout restart`s it every run, because
`imagePullPolicy: Always` governs a *new* pod and an unchanged Deployment spec produces none,
so the phase can otherwise pass against the previous run's image.

None of the Jobs declares `runAsUser`, `runAsGroup` or `fsGroup`. The platform assigns them, and the
driver *checks* the resulting `openshift.io/scc` annotation rather than assuming it. Note that a
bare `kind: Pod` created by a cluster-admin can be admitted under `anyuid` — admission evaluates
the SCCs available to the creating user as well as to the pod's ServiceAccount — which would run
it as root and prove nothing. Going through a controller is what makes the admission honest.

## Relationship to `arms/local`

`arms/local/container-arc.sh` is the same arc under rootless podman, and stays the fast inner
loop — it needs no cluster. This arm is not a replacement for it; it is the venue where the
claims that drill can only *emulate* get observed. Where the two disagree about the platform,
the pod wins.
