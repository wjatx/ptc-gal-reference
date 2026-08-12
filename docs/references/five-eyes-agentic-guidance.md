# Five Eyes joint guidance — *Careful adoption of agentic AI services*

**Status: design input (reference).** Published 2026-05-01 by six agencies across the five Five Eyes
nations: ASD's ACSC, CISA, NSA, the Canadian Centre for Cyber Security, NCSC-NZ and NCSC-UK. This
document maps that guidance clause-by-clause onto what safe-agents actually implements, then states
the gap in both directions: where we are weaker than the guidance, and where the guidance is silent
on something we have evidence for.

This lives in `docs/references/` (design inputs we build on), **not** `research/` (market awareness
under the firewall rule). A national-agency standard is a legitimate design input; the firewall
exists for competitor features, not published guidance.

## 0. Provenance and read coverage

Read directly in the 2026-07-25 session that produced this file:

- the full guidance text at `cyber.gov.au` — every substantive section: Introduction, Scope, What is
  agentic AI, Broader considerations, all five risk categories with their scenario examples, all four
  best-practice sections (Designing / Developing / Deploying / Operating), Defend against future
  risks, Conclusion, and Appendix A Design + Development. **Not read:** the per-agency resource link
  lists, and the tail of Appendix A (Deployment/Operation bullets).
- `research/CISA/CSA_research_note_cisa-agentic-ai-adoption-guide_20260517-csa-styled.pdf` in full —
  note this is a CSA "AI-assisted Rapid Research" note that has *not* undergone CSA review, and is a
  restatement, not a source.
- The NCSC-UK companion blog "Thinking carefully before adopting agentic AI" (2026-05-15) in full.

`media.defense.gov` (the canonical PDF) and direct HTTP fetches of `cyber.gov.au` were both
unreachable from our network; the guidance text was retrieved through a browser session.

Implementation claims below were verified against the tree at `v0.51.0` (commit `d486ce4`) by
reading the named files. Claims tagged `[inferred]` were not verified by a direct read.

## 1. The two statistics are not in the guidance

Press coverage of the release circulated two numbers that are widely attributed to the Five Eyes
report. **The guidance contains no survey data of any kind.** Both figures are Cloud Security
Alliance surveys published in the weeks before it:

| Claim | Source | Method |
|---|---|---|
| **82%** of enterprises found an AI agent or workflow security/IT did not know about in the past year; 41% more than once | CSA survey **commissioned by Token Security**, published 2026-04-21 | n=418 IT/security professionals, fielded Jan 2026 |
| **68%** cannot clearly distinguish AI agent activity from human activity | CSA survey **sponsored by Aembit**, published 2026-03-24 | n=228 IT/security professionals, fielded Jan 2026 |

Both are small-n, self-reported, and sponsored by identity-security vendors who sell the remedy —
Token Security sells agent discovery, Aembit sells workload identity. That does not make them wrong,
and the 82% is directionally consistent with the guidance's qualitative claims. But **anything we
publish that cites these must attribute them correctly**, or the first reader who checks will treat
the whole argument as unsourced. The guidance makes the qualitative version of both points, which is
the stronger citation for our purposes: it treats them as design defects rather than survey results.

## 2. What the guidance is

Five risk categories, each a structural property of agentic architectures rather than a vulnerability
class: **privilege**, **design and configuration**, **behaviour**, **structural**, and
**accountability**. Each carries a worked scenario. The best-practice half is organised by audience —
designing, developing, deploying, and operating — and closes with research directions and an appendix
of prerequisites.

Its overall posture is *integrationist*: agentic AI security belongs inside existing cyber security
frameworks, not in a separate discipline, because AI systems are IT systems. It recommends
incremental deployment starting from low-risk, non-sensitive tasks, and is explicit that organisations
should never grant agents broad or unrestricted access.

## 3. Clause → implementation map

Legend: **=** implemented at or above the clause · **~** implemented weaker or partially · **✗** absent.

### Identity and privilege

| Guidance clause | safe-agents | |
|---|---|---|
| Construct each agent as a "distinct principal", cryptographically anchored identity with its own keys | Principal model throughout; Ed25519 workload identity for chain signing (`channels/SIGNING.md`, #181); broker signing key resolves from Secrets Manager at cold start, never in the agent image | ~ |
| Maintain a trusted registry; bind identities to roles; **periodically reconcile against the live set of agents** | Registries exist (MCP two-key admission, grant store); **no reconciliation against running principals** | ~ |
| Deny access for any agent or key not in the trusted registry | MCP: a tool is callable only with both an image-baked namespace declaration and an HMAC'd registry row at a matching discovery hash (`broker/MCP-HOST.md` M1–M13) | = |
| Least privilege; narrowest possible scope; fine-grained control | `Envelope` + per-capability IAM roles (#175): out-of-scope actions denied by IAM, not the broker; proven live on `development` | = |
| Just-in-time credentials for high-impact actions | `CredentialProvider` seam (#173) with `StaticSecret` / `OAuthRefresh` / `assumed_role`; agent never holds the credential | = |
| Authenticate agents with fresh cryptographic proofs before every privileged call | Per-call broker decision, but authentication is transport/IAM-level, not a fresh per-call cryptographic proof | ~ |
| Authenticate all inter-agent and agent-to-service API calls using **mutual TLS** for non-repudiation | DSSE-signed provenance chain gives message-level non-repudiation; **no transport peer authentication** | ~ |
| Agents must perform **cryptographic attestation** that they run expected, unmodified code | Envelope-hash enforcement attests **config**, not code; mismatch → loud quarantine | ~ |
| Agent reputation / trust scoring; reduce trust when anomalous behaviour detected | Typed evidence + four demotion triggers is the coarse cousin; no continuous score | ~ |
| Prohibit agents from modifying their own privileges; require expiry timers and recorded grant chains | The broker structurally cannot write grants; mutation only via the ceremony CLI under STS maker≠checker; DSSE-signed PromotionRecord ledger. **`Grant` has no expiry field** (`schemas/grant.py`) | ~ |

### Policy decision and per-call evaluation

| Guidance clause | safe-agents | |
|---|---|---|
| "Centralised policy decision point" evaluated **for each request** | The broker. Pure first-match rule table over `(BrokeredCall, Facts)`, no model in the path (`pdp/engine.py`, `docs/deterministic-gate.md`) | = |
| Stale-allow failure: entitlements evaluated once at startup are exploitable | Every `/call` re-decides; nothing is cached across calls | = |
| Consider the trust level of data sources when making decisions | Deterministic source-based taint via `InputTrustMap`, never model-judged (`broker/TAINT.md` §1) | = (see §5.3) |
| Establish declarative safety contracts agents cannot override | Envelope is image-baked; store config can only select/tighten (`docs/config-provenance.md`) | = |
| Decisions about **when human approval is required** are made by designers/operators, **not delegated to the agent** | Same mechanism; the injection-power lattice is what makes this enforceable rather than aspirational | = |

### Oversight, approval, autonomy

| Guidance clause | safe-agents | |
|---|---|---|
| Prevent agents from autonomously executing high-impact actions without prior human approval | `require_approval` verb → stored Intent → owner `/approve`; release recomputes the digest independently (#198) | = |
| Human-in-the-loop for high-cost, hard-to-reverse actions | Same, keyed on the unforgeable gate-8 `sender_class` | = |
| **Quarantine requests to delete logs or audit records** pending human review | Structurally stronger: the agent has no log-write path at all — audit is written by the broker under a separate identity | = |
| Isolate agents into enclaves with **no write access to logs** | Same invariant, stated identically | = |
| Graduated autonomy; continuous evaluation to expand scope **or roll back** | GAL: three rungs, evidence-gated promotion ceremony, deterministic demotion runner (`docs/GAL.md`, `broker/grant-lifecycle.md`) | = |
| Trigger-action protocols that automatically restrict permissions on unexpected behaviour | Four `DemotionTrigger`s — `budget_breach`, `false_action`, `stale_confidence`, `corroboration_failure` — all fired live | = |
| Multi-agent consensus for moderate stakes; human-in-loop **in addition to** consensus for high stakes | `CorroborationRecord` k-of-n quorum (#192); GAL's high-blast always-human-ratification lock | = |
| Codify separation of duties with roles and delegation expiry | Operator identity plane: Maker/Checker/Promotion/Demotion/Auditor/Watcher roles (`docs/operator-identities.md`). Proposals expire; **grants do not** | ~ |
| Deploy a **secondary agent** to validate new tasks against policy before execution | Deliberately divergent — our LLM reviewer attaches findings and never gates (§6.1) | ~ |

### Tools and third-party components

| Guidance clause | safe-agents | |
|---|---|---|
| Restrict tool use to an approved allow list of tools **and versions**, regularly re-verified | MCP admission ceremony + `diff` / `bulk-propose` / `bulk-ratify` re-vet | = |
| Tool/agent **squatting** by similar names | A duplicate advertised name is uncallable regardless of hash match | = |
| Two-way tool integration lets tools return arbitrary instructions to the LLM | Response taint: a successful external read taints its turn (sa#134) | = |
| Misleading tool descriptions cause unreliable selection; "persuasive descriptions chosen more often" | Description is inside the signed `def_hash` basis (#223) — a description-only change **is** drift; deltas render verbatim and in full with a per-tool acknowledgment `--yes` cannot supply | = (see §5.6) |
| Standardise tool descriptions to avoid persuasive language | Not done — we detect description change, we do not normalise description style | ✗ |
| Maintain a trusted registry of third-party components; SBOM | Tool-level registry yes; no SBOM practice | ~ |

### Accountability and monitoring

| Guidance clause | safe-agents | |
|---|---|---|
| Unified audit logs for all inter-agent interactions | Hash-chained append-only `AuditRecord` under a separate identity | = |
| Log every agent action, not just failures or high-impact events | Every decision lands on the chain | = |
| Comprehensive artefacts documenting actions and decision process | `AuditRecord` carries the deciding rule's reason string, plus `intentId` / `storedCallDigest` / `resultDigest` receipts (#198) | = |
| Monitor identity and privilege changes; audit for drift, impersonation, misconfiguration | 19-rule grant-integrity audit, keyed and keyless, green on both floors | = |
| Cross-validate agent reports against system logs with independent monitoring | Executed-vs-approved is byte-provable from the chain alone, after the intent TTL expires | = |
| Storage-efficient logging to manage volume | Not addressed | ✗ |
| Anomaly detection flagging discrepancies between stated intent and observed behaviour | Partial — receipts prove executed==approved; no behavioural baseline | ~ |

### Resilience and availability

| Guidance clause | safe-agents | |
|---|---|---|
| Fail-safe defaults; agents stop and escalate under uncertainty | Implemented but **deliberately not as a base default** (§6.2) | ~ |
| Limit blast radius; containment mechanisms | Per-capability IAM (#175), proven live: out-of-scope calls AccessDenied by IAM | = |
| Versioning and rollback to known-good behaviour | Grant tightening + re-seed re-attestation path (#206) | = |
| Denial-of-service and **sponge attacks** exhausting compute/memory/API calls | Caps are per-op **daily** budgets; a burst inside the cap is unmetered | ✗ |
| Rate-limit components; interrupt long-running tasks | No rate limiter in the base. The campaign watchdog's throttle is **recommend-only** | ✗ |
| Graceful degradation | Not a base concern; MCP respawn policy is the nearest thing | ~ |

### Testing and evaluation

| Guidance clause | safe-agents | |
|---|---|---|
| Threat modelling with agentic taxonomies (OWASP GenAI, MITRE ATLAS) before deployment | Doctrine-driven review; no formal taxonomy pass | ~ |
| Red teaming; sandbox before production | Trigger range (sa#213) fires controls deliberately; drills run on real floors | ~ |
| **Assess agents' ability to evade** guardrails, monitors, human-in-loop and input filters | Absent — we test that controls fire, never that an agent can route around them | ✗ |
| Agent-specific evaluations; benchmark datasets | Conformance suites per contract; #177's 73,728-input differential corpus is the nearest benchmark | ~ |
| System-theoretic analysis (STPA / STPA-Sec) | Not used | ✗ |

## 4. Gap A — where we are weaker than the guidance

Ordered by how much a competent reviewer would hold them against us. All nine are filed:
FE-1 #255 · FE-2 #256 · FE-3 #257 · FE-4 #258 · FE-5 #259 · FE-6 #260 · FE-7 #261 · FE-8 #262 ·
FE-9 #263.

**Spec status (2026-07-25).** Three of these now have normative answers in the spec tier ahead of
the implementation, which is the honest place for them to be while the code catches up: FE-1 is
GAL-SPEC §6.7.6 + GAL-34 (the `lapse` arc), FE-2 is GAL-SPEC §6.11 + GAL-35 (two-direction
reconciliation), and FE-6 is stated as a deliberate divergence in PTC-SPEC §1.2 rather than left
implicit. The implementation issues stay open — a spec clause is not a shipped control, and
claiming otherwise is the exact conformance-map dishonesty §7 warns about.

Working the specs also surfaced two places where **spec text had fallen behind shipped contracts**,
both found only because the mapping forced a clause-level read: PTC-SPEC pinned the admitted
tool-definition hash to "exactly four fields" after #223 widened it to every advertised field, and
GAL-SPEC still listed a `hash` field on `Grant` that #246 removed when it moved the integrity basis
to the stored bytes. Both are corrected. The lesson generalizes past this document: a spec derived
from contracts needs a periodic re-derivation, because nothing fails when it drifts.

**FE-1 · Grants never expire.** The guidance pairs "recorded grant chains" with "explicit expiry
timers", and we have only the first half. `Grant` (`safe_agents/broker/schemas/grant.py`) carries
`level`, `envelopeHash`, `evidence`, `demotionTriggers` and `labelLatency` — no `expiresAt`. Authority
granted at `out-of-loop` persists indefinitely unless a trigger fires; nothing forces periodic
re-ratification. Proposals expire (`--ttl-hours`), which makes the omission look deliberate but it is
not documented as a decision anywhere. Recommended: an optional typed `Grant` expiry that ships unset
per the friction doctrine, with expiry-driven demotion to `lastSafeLevel` rather than deny. This is
the single clearest conformance gap and the cheapest to close.

**FE-2 · No reconciliation against the live agent population.** The guidance asks that the registry be
periodically reconciled against the set of agents actually running. Everything we reconcile is
*declared* state: MCP `diff` compares advertised tools to admitted rows; the grants audit compares
rows to ledger records. Nothing enumerates running principals and asks which have no grant, or which
grants belong to a principal that no longer exists. This is precisely the control the 82%
shadow-agent finding is about, and it is also the control a local wrapper performs at laptop scale —
that discovery sweep already exists on the wrapper side; what is missing is the cloud-side
equivalent and a scheduled comparison.

**FE-3 · No rate limiting or sponge-attack resistance.** The guidance names sponge attacks explicitly
under structural risk and recommends rate-limiting components and interrupting long-running tasks. Our
budget counters are per-principal, per-op, per-UTC-day. An agent with an 80/day cap can burn all 80
calls in ten seconds, and nothing interrupts a long-running tool call. The campaign watchdog computes
a `throttle_eligible` flag but is recommend-only — the enforced throttle seam is unbuilt (#220). This
is the availability gap in its most mundane form, and it sits oddly next to how much work we have put
into the sophisticated availability story.

**FE-4 · No evasion testing.** The guidance asks for regular assessment of an agent's ability to bypass
communication barriers, guardrails, monitors, human-in-the-loop processes and input filters. Our
entire test posture — conformance suites, the trigger range, live drills — establishes that controls
*fire when triggered*. None of it establishes that a motivated agent cannot arrange not to trigger
them. These are different questions and we have zero coverage of the second. Given that the platform's
whole claim is "a fully compromised agent can still only ask", the absence of adversarial testing
*of that claim* is the most intellectually serious gap on this list, even though FE-1 is more visible.

**FE-5 · Config attestation is not code attestation.** The guidance asks that agents prove they run
expected, unmodified code. Envelope-hash enforcement proves the *policy* an agent runs under is the
one in force; the image-baked manifest constrains what config can name. Neither establishes that the
running image is the built image. Note the naming collision: `ceremony_identity.attestation_for()` is
a local-solo identity marker, unrelated. Closing this properly means image signing and admission
verification, which is a deployment-layer concern more than a base-platform one — worth stating as
scope rather than silently omitting.

**FE-6 · No transport-level mutual authentication.** The guidance asks for mTLS on all inter-agent and
agent-to-service calls. We sign the provenance chain instead, which is arguably better for relay
topologies — a signature survives hops that a TLS session does not — but signing is **per-envelope**,
so a relay re-packages and upstream signatures are not carried. There is no peer authentication at
the transport layer at all. The honest position is that we chose a different mechanism for the same
property and should say so, not claim conformance.

**FE-7 · Multi-level Biba is a two-level projection.** `broker/TAINT.md` §1.1 adopts the five-level
lattice as vocabulary while enforcing a single boundary. The guidance's structural-risk category is
almost entirely about differentiated trust between agents, tools and retrieval sources — the case the
projection collapses. Already declared and tracked to the signed-provenance work; listed for
completeness.

**FE-8 · Memory-layer taint deferred.** The guidance names memory as a first-class component and
poisoned environments as an attack vector. `broker/TAINT.md` §8 defers the memory half to the memory
epic. A write into memory on a tainted turn, read back on a clean turn, is an unclosed laundering path.

**FE-9 · No SBOM practice, no STPA, no log-volume sizing, no description normalisation.** Four small
ones. SBOM and description normalisation are cheap. STPA/STPA-Sec is genuinely interesting: our review
practice is per-component and doctrine-driven, and system-theoretic analysis is designed to find
exactly the interaction-level findings that method misses. Log-volume sizing is real operational debt
the guidance is right to flag.

## 5. Gap B — what the guidance does not cover that we have evidence for

This is the contribution list. Each item is something the guidance either omits entirely or states as
an aspiration without a mechanism, where we have a mechanism, a live proof, or both.

**5.1 · Forced abstention is an availability attack, and its safety is polarity-dependent.** The
guidance recommends fail-safe defaults where agents stop and escalate under uncertainty. That silently
assumes **abstain-is-safe** polarity. For an agent whose job is to act on demand — a monitor, an
alerting system, a safety interlock — a forced abstention causes the exact harm the agent exists to
prevent, so "tainted → stop" is not a safe default, it is the attack. An adversary who cannot make an
agent do the wrong thing can still make it do nothing, and the guidance's own recommended control is
the lever. Our position (`docs/friction-doctrine.md` §Availability, sa#159): polarity must be
re-derived per agent and never baked into a platform, and the floor's answer is a deterministic
dead-man's-switch that observes *that* an agent went silent and never judges *why* — a timestamp
comparison cannot be prompt-injected. Mechanism ships as an Envelope knob that is OFF unless set; the
polarity→default derivation lives consumer-side. **This is the single most valuable thing we can
contribute**, because the guidance's recommendation is actively wrong for a class of high-consequence
agents and nothing in the document flags it.

**5.2 · Human approval queues are a denial-of-service surface against human attention.** The guidance
recommends human-in-the-loop for high-impact actions and never notes the second-order effect: an
attacker who can trigger many calls converts one injection into a flood of approval pages, and the
real approval hides in the noise. Our discipline is **de-amplify, never shed** — dedup coalesces
identical pending intents; a queue-depth cap raises an alarm but the broker still holds every intent,
because shedding under flood is the forced-abstention harm from 5.1 wearing a different hat.

**5.3 · "Consider the trust level of data sources" is an instruction to the model, which is the thing
being attacked.** The guidance's controlled-context section asks LLM agents to weigh source trust when
deciding. A persuasive injection scores "safe" exactly when it is most dangerous, so a model-judged
trust assessment fails precisely under attack. Our answer is structural: source-based taint from a
deterministic trust-map lookup, non-strippable within a turn, with **broker-owned turn identity** so
an agent cannot declare a fresh turn to shed taint before a write, and no taint-clearing API reachable
from agent code at all. The general principle — *never put a probabilistic classifier on the safety
path* — is stated in the guidance nowhere, and is contradicted by its own secondary-agent-validator
recommendation (§6.1).

**5.4 · "Operators decide when approval is required, not the agent" needs a config-provenance lattice
to be enforceable.** The guidance states this principle well and gives no mechanism for *where
configuration lives*. An agent that can write the file naming its own approval thresholds has been
delegated the decision regardless of what policy says. Our lattice (`docs/config-provenance.md`, #186):
anything that can name code to run is honored only from the image-baked manifest; store-loaded config
may only select or tighten, never mint; mutation is ceremony-gated; secrets are bare leaves. We learned
this the hard way — #197/#199 was a wrong-authority mint from an implicit fallback manifest that left a
promoted grant quarantine-dead for an hour. Worth contributing as the *implementation requirement*
behind their principle.

**5.5 · A registry is one key, not two, because discovery output is untrusted input.** The guidance says
maintain a trusted registry and deny anything not in it. It does not observe that if the registry is
populated from tool discovery, an attacker who controls discovery controls the registry. Our two-key
admission requires an image-baked namespace declaration **and** an HMAC'd row at a matching discovery
hash: the store can select or tighten, never mint a callable tool.

**5.6 · The countermeasure for drift review is reviewer complacency, not invisibility.** The guidance
correctly identifies that persuasive tool descriptions get chosen more often, and recommends
standardising description style. It stops there. The harder problem is *re-vetting*: when a server's
tools drift, a reviewer approving a batch will skim. So description deltas — the model-facing injection
vector — render verbatim and in full and require a per-tool acknowledgment that a blanket `--yes`
cannot supply, while schema deltas are machine-summarised and cosmetic churn is a count. Proven live: a
poisoned description was refused under `--yes` alone with the row unmoved. The related finding
(#232/TL11a) is that a newly-required field on a **remote** tool is a disclosure escalation, because an
input schema is an exfiltration-channel spec enumerating what the vendor receives per call.

**5.7 · Maker≠checker guarantees two credentials, not two humans.** The guidance recommends separation
of duties without saying what the control actually delivers. Ours compares STS credential ARNs, so it
guarantees one credential the proposer cannot mint — an organisational control the platform
*evidences* rather than *enforces*. Standards language that implies two humans oversells every
implementation of it.

**5.8 · A promotion is not done until the promoted grant acts once.** The guidance's graduated-autonomy
section has no completion criterion. We adopted one after a live incident: a grant promoted under a
silently-substituted manifest was quarantine-dead from ratification and nobody knew, because nothing
exercised it. Ceremony success is not evidence the authority works.

**5.9 · Empirical policy-language data for the "centralised policy decision point".** The guidance
recommends a centralised PDP evaluated per request and names no candidate. We ported our 14-rule table
to Cedar and Rego and ran all **73,728** reachable inputs against each and against the real engine
(#177). A direct Cedar port preserves first-match ordering on **71.27%** of inputs; exactness requires
hand-flattening to mutually exclusive guards at 7.3× the policy terms, which Cedar's own validator does
not check. A two-verb permit/forbid alphabet cannot express a value-producing outcome, and there is no
quantifier, so provenance-chain reasoning is unreachable. Rego matched exactly in 81 lines with all
five verbs native. This is the kind of measurement a standards body cannot easily produce and would
plausibly want.

**5.10 · Authenticity is not count-trust.** From the sa#161 watchdog work: a signed sender identity
tells you *who* sent a message, not *how many times* — unless the dedupe key is bound into the
signature. We bind the canonicalised channel identity into the signed context (SIGNING.md S1b) so
mutating either half of the dedupe key breaks the signature. Otherwise a correlation control built on
authenticated identity is reflected-DoS bait: we proved this live, producing a transport-token campaign
for forgery events that cryptographically *claimed* a signer's key, where the claimed signer appeared
nowhere in the attribution.

**5.11 · Integrity must indict tampering, never evolution.** The guidance recommends cryptographic
integrity checks on task definitions and constraints. Naive implementation — hash a parsed structure,
re-serialise to verify — cries tamper on legitimate schema growth, which teaches operators to stop
evolving the schema and calls the freeze prudence. Our rule (#246): the **stored bytes** are the
integrity basis — serialise once, bind the hash to that string, verify verbatim, verify-then-parse. We
found this by shipping the bug: widening a type moved an HMAC basis and every pre-widening proposal
failed as a tamper.

**5.12 · Sub-agents are a trust zone, not N identities.** The guidance repeatedly frames sub-agent
spawning as a risk requiring per-agent identity. Our counter-position (`docs/subagent-identity.md`):
the agent zone is the principal, because egress pinning is enforced at the network layer, not
per-process. This asks nothing of the harness, which is why the floor works with off-the-shelf agent
frameworks. Note this is also a **divergence** from the distinct-principal clause and should be
presented as a reasoned alternative, not as conformance — see §6.3.

## 6. Deliberate divergences

Distinct from §5: these are places we do something *different*, where the guidance's recommendation is
defensible and ours needs an argument.

**6.1 · The secondary validator does not gate.** The guidance recommends deploying a secondary agent to
validate new tasks against policy before execution. We built that reviewer (#58) and deliberately made
it **findings-attach-never-gate**: any reviewer failure degrades to a recorded `reviewer_error`, never
a gate flip in either direction, and it ships OFF. The reasoning is 5.3 — a probabilistic classifier on
the safety path is a new thing for the attacker to fool, and a validator that can be talked into
approving is worse than no validator because it manufactures confidence. Our multi-agent consensus is
the deterministic k-of-n `CorroborationRecord` instead. This is a real disagreement with a specific
clause and should be argued, not elided.

**6.2 · Fail-safe defaults are consumer-derived, not base defaults.** Per 5.1. The mechanism exists;
the polarity does not ship.

**6.3 · One principal per zone, not per agent.** Per 5.12.

## 7. Using this for a contribution back

The contribution posture that fits the LF framing (controls engineering + reference implementation,
never "platform"): the guidance is a **risk taxonomy with best practices**, and what it lacks is a
conformance target — there is no way to say an implementation *meets* it. The three assets we would
bring are (a) the clause→mechanism map in §3 as evidence that the guidance is implementable end to end,
(b) the §5 items as gaps in the guidance itself with live proofs attached, and (c) the PTC and GAL
specs as the normative artifacts the guidance's identity and autonomy-lifecycle clauses would need to
become testable.

Sequencing matters. §5.1 (forced abstention) is the item to lead with, because it is a correction
rather than an addition and it is well-evidenced. §5.9 (the Cedar/Rego differential) is the item most
likely to be *used*, because it answers a question a standards body has to answer and cannot cheaply
measure. Everything in §4 should be closed, or explicitly scoped out with reasoning, before we make the
approach — arriving with a conformance map that has four `✗` rows in it invites the reviewer to audit
us instead of reading us.

## Sources

- ASD ACSC / CISA / NSA / CCCS / NCSC-NZ / NCSC-UK, *Careful adoption of agentic AI services*,
  2026-05-01 — https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services
  (canonical PDF: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF)
- NCSC-UK, *Thinking carefully before adopting agentic AI*, 2026-05-15 —
  https://www.ncsc.gov.uk/blogs/thinking-carefully-before-adopting-agentic-ai
- Cloud Security Alliance, *Five Eyes Issue First Joint Agentic AI Security Guidance*, 2026-05-17 —
  `research/CISA/` (AI-assisted, not CSA-reviewed; restatement only)
- Cloud Security Alliance / Token Security, *82% of enterprises have unknown AI agents in their
  environments*, 2026-04-21 — n=418
- Cloud Security Alliance / Aembit, *More than two-thirds of organizations cannot clearly distinguish
  AI agent from human actions*, 2026-03-24 — n=228
