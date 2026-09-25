# Covering brief — what this artifact claims, and what we are asking you to do with it

If this directory was handed to you, start here. `README.md` beside this file is the complete
run instruction — it is written to be completed unaided, and if it cannot be, the README is
what is broken. This note is the other half of the hand-over: the claims the artifact makes,
each with its limits, what has *not* been demonstrated, and what we want back.

**Who this is for:** an agent-security architecture team that runs its own OpenShift cluster.
The artifact was built for that audience from the start — people who will probe overclaims and
discount anything they cannot run themselves.

## The ask

Run the drill on your own cluster, from the README alone, without asking us anything. Then tell
us **where you got stuck** — that is the deliverable. This artifact has already survived every
check we know how to design, so a clean report is the less useful outcome; the stuck points,
the steps that assumed something your cluster does differently, and the claims below your run
does not support are what we cannot produce for ourselves.

Specifically useful, in order:

1. Every place you stopped, re-read, guessed, or worked around — verbatim, including the ones
   that turned out to be your cluster rather than our artifact. Unflattering is fine; that is
   the point.
2. Any place your output breaks one of the invariants the README lists: the PASS/FAIL lines,
   the mechanism named in every refusal, and the decision/outcome columns of the audit tape. No
   reference capture ships in this tree, so those invariants are the comparison; a break in any
   of them is a real portability finding. Values on the README's may-vary list (server URLs,
   DNS-resolved addresses, pod suffixes, UIDs, generated ids, timestamps, audit-chain hashes,
   build output) are expected to differ.
3. Any numbered claim below that your run does not support — or that you can defeat on your own
   cluster.
4. For the record: OpenShift version, CNI, and wall clock (which is strongly cluster-dependent;
   runs of this same work have taken from about 150 s on OpenShift Local to 19m on OpenShift 4.20).

Send it in whatever form is cheapest for you. We will record it verbatim in the repo,
including the parts we think are wrong — a report that exists only in someone's memory of a
conversation does not count for us.

## The status of our evidence, stated plainly

Every piece of evidence this artifact carries is self-produced: the drill was designed by the
people who built the controls, so a green run proves the drill ran, not that the controls work
against someone who did not write them. The closest we have come to a cold run: a driver with
none of the building session's context completed the drill from the README alone on a second
cluster (OpenShift 4.20.30, one patch release after the cluster it was built on), in a namespace that did
not exist when the run began — 86 PASS / 0 FAIL — and found six real defects in the artifact's
prose and checks along the way, since fixed.

That run's own caveat, disclosed unprompted by the driver, is structural: it ran inside our
checkout, where this repo's instruction layer was auto-injected into its context. Its words:
*"read my 'zero blocking gaps' as an upper bound on the README's quality, not a measurement of
it."* You do not have that layer. That is why we are asking you.

## The claims, each traced to the leg that shows it

Quoted lines below are the drill's own output, copied from real runs; the README declares the
PASS/FAIL lines and named mechanisms invariant across runs, so your log should contain them
too. No claim here is sourced from prose alone.

**1. The grant ceremony cannot be completed by one credential.**
Shown by the propose and ratify legs: the maker is refused the signing key and refused creating
a pod that would mount it — "PASS the maker can neither read the key nor arrange for it to be
delivered" — its own ratify attempt dies at the signing gate ("PASS refused at M8 before
reaching M7: no key, therefore no valid ratification"), and its attempt to write a grant row at
all is "refused by the kernel with EROFS" on a read-only mount, attempted in the log rather
than asserted from the manifest. The ratify leg then proves the converse: "PASS one credential
cannot be both halves, even holding the signing key (M7)".
*Limits:* this guarantees **two credentials, one unmintable by the proposer — never two
humans**; that is an organisational control the platform evidences rather than enforces. The
maker's *reads* stay unconditioned on purpose — write-denied, not read-denied.

**2. The ceremony's output outlives every pod that produced it, and the pod serving it holds
neither ceremony credential and no signing key.**
Shown by the serve leg: "PASS whatever signed the record on this volume, it was not this pod",
"PASS the first pod's ceremony output served by a second pod, no ceremony re-run".
*Limit:* the durability is the PersistentVolumeClaim's — a platform property we orchestrate,
not one we implement.

**3. A ceremony leg cannot forge or erase another leg's records.**
Shown by the tamper leg, which attempts truncate, append, unlink and replace against the tape a
prior pod wrote: "PASS all four refused by the kernel with EROFS, on a read-only mount — not by
a check of ours", then "PASS an intact chain, verified without the writer and without a key".
*Limits, printed beside the PASS in the log itself:* **the broker can still rewrite its own
tape.** The chain is unkeyed SHA-256, so write access alone re-chains a rewritten tape and it
verifies clean; the read-only mount IS the control. This is deliberately a narrower claim than
"the audit survives a compromised broker" — see *Not demonstrated*, items 3 and 4.

**4. A pod holding nothing can still get real work done through the broker — and only through
it.**
Shown by the Phase 4 agent leg: "PASS no connector secrets, no issuer key, no store, no audit
tape in this pod"; "PASS external names resolve, and every connection to them is dropped by the
policy" (DNS is allowed on purpose, so the denial is attributable to the policy and not to
resolution failure); "PASS the API server answers this pod, and refuses it the Secret AND the
pod that would mount it" (RBAC 403s naming the ServiceAccount); and "PASS the agent's only
reachable endpoint served it, and still refused the unadmitted op".
*Limits:* this is **posture 2 by orchestration** — separate ServiceAccounts, OVN egress and a
broker-only mount are boundaries the *platform* enforces; no `safe_agents` code sits in that
path, and **nothing here constrains what the agent does inside its own pod**. The API server is
*deliberately* reachable from the agent pod so the refusal is a 403 naming the credential
rather than a timeout indistinguishable from a typo; a production envelope should deny both.
What is demonstrated is attributability, not defence in depth.

**5. The refusal mattered, because the harm is real without the broker.**
Shown by the unbrokered baseline (leg 10b), the control the other legs need: "PASS the
forbidden call SUCCEEDED with no broker in the path — this is the harm, and it is real",
followed by "PASS the same op is refused through the broker, while a different op executes — it
is ADMISSION that refuses, not a dead broker".
*Limits, printed next to the PASS:* this is the **admission half only** — the ledger server
needs no credential, so no credential bypass is shown (that the agent pod holds no connector
secret and is refused it is claim 4; the two compose rather than substitute). The server is the
missileer archetype: its dangerous op is *absent*, not denied. The blast radius is a fictional
ledger, on purpose; what is real is the mechanism.

**6. Admission changes callability, and the change is visible in evidence the subject could not
have produced.**
Shown by the second ceremony (propose/ratify of `list_entries`) and the tape read from the
broker pod — a mount no agent pod has: `list_entries` reads allow/refused at seq 1, 3 and 4,
then allow/executed at seq 8, after two credentials admitted it.

**7. A read of hostile content escalates a later external write, on the same turn, same
credential, same grant.**
Shown by the taint leg: "PASS the same external write flowed on a clean turn and escalated on a
tainted one", with "PASS the broker is the only way this agent reaches the peer at all" (the
agent is *given* the peer's DNS name and still cannot open a socket to it), and "PASS the tape
corroborates the differential, from a mount no agent pod has" — the held call's record reads
`reason=tainted external write`.
*Limits:* the *agent-facing* response carries an empty `reason`, so the four rules that could
have escalated it are indistinguishable to the subject of the test — a transport gap on the
`/call` response path (#316's remaining half). And the *published envelope is agent-authored*: the seam that
would broker-stamp outbound provenance has no runtime caller (#315), the receiver says so on
every request, and this demonstration therefore rests on the **verdict**, which never reads the
envelope. The peer receiver is deliberately a bare endpoint — transport token plus schema
validation, no trust map, no screening.

**8. The sandbox permits, the broker refuses — and they compose rather than compete.**
Shown by the sandbox leg: "PASS the pod permitted the agent to author and run code that calls
the broker", then "PASS every forbidden action was refused by the broker, and by nothing in the
sandbox" — each deny naming its mechanism (`no manifest entry for <tool>.<op>`).
*Limits:* the sandbox in the picture is the **pod** — SCC and NetworkPolicy — not a separate
sandbox product. This is not "the broker beats a sandbox": a sandbox protects the host from the
agent, the broker protects third parties the agent acts on, and nothing in an SCC or a
NetworkPolicy can express "may read entries, may not delete them". The dangerous op is absent
from the server, so the deny is the second line of defence.

**9. The posture report declines credit for proofs it did not run.**
*Not shown by this tree:* the posture leg is not shipped here, and the drill prints
`PHASE 6.1: NOT RUN` in place of this claim's predicate. The rest of this entry describes the
leg where it runs.
Shown by the posture leg: "PASS the report names this pod's identity, and reports both refusals
as UNKNOWN rather than claiming them" — the posture report makes no network calls, so it cannot
have *attempted* the egress or RBAC refusals the drill proved a few steps earlier, and a
refusal is only evidence when it is attempted. The leg fails if a future edit "corrects" the
report to claim them.

**Cross-cutting: every refusal asserts its mechanism.** The legs' negative proofs demand three
things, not one — the attempt did not succeed, it failed, and it failed *for the stated
reason* — and a refusal whose output lacks the expected mechanism string fails the drill even
though the attempt failed. The helper is itself self-tested to fail when it should.

## Not demonstrated — by name

1. **Nobody outside this repo has run this artifact.** Every run to date was ours, on clusters
   we provisioned. This brief exists to change that; until it does, treat the portability and
   README-sufficiency claims as unverified by anyone with an interest in breaking them.
2. **The coldest run to date had our instruction layer in its context** (the structural caveat
   quoted above). Its "zero blocking gaps" is an upper bound on the README's quality, not a
   measurement of it.
3. **The audit tamper answer for a compromised broker is unbuilt.** A broker that rewrites its
   own tape is currently undetectable here: the chain is unkeyed and the broker is the writer.
   The designed remedy — a witness leg recording periodic chain heads to a volume the broker
   cannot mount, detection never prevention — exists as a resolved design and zero code (#336).
4. **The cloud floor's WORM has never been observed refusing anything.** The S3 Object Lock
   tier this arm's tamper leg points at as the durable answer is GOVERNANCE mode, durable
   environments only; the development environment sets no default retention at all; the CI gate
   asserts the *configuration* (in both polarities, mutation-tested) — and no drill anywhere
   has ever attempted the delete and been refused (#334). A synth assertion is not an observed
   refusal.
5. **Outbound provenance is not broker-stamped.** `stamp_outbound` has no runtime caller
   (#315), so the provenance chain the peer prints proves nothing, and the receiver says so on
   every request.
6. **The credential half of the bypass story** (see claim 5's limit), **two humans** (see claim
   1's limit), and **real harm** — the blast radius throughout is a fictional ledger.

## If a claim fails on your cluster

That is a finding, not an inconvenience — file it exactly as you saw it. The standing rule in
the README applies to us, not to you: if a step is missing or wrong, the README is what is
broken, and we fix or file it there rather than bending the drill to match. What comes back
from you changes the published wording of the claims above; that is what your time buys.
