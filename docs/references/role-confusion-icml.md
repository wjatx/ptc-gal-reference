# *Prompt Injection as Role Confusion* (ICML 2026) — role tags are inferred from style

**Status: design input (reference).** Ye, Cui and Hadfield-Menell, arXiv:2603.12277v4 (15 April
2026), presented at ICML 2026. The paper measures how language models decide *which role* a span of
text came from, and finds they infer it from writing style and lexical choice rather than from the
`<system>` / `<user>` / `<tool>` / `<think>` tags around it. It reached us through MIT Technology
Review's 2026-07-30 coverage.

This lives in `docs/references/`, which holds the external material the design is built on. A
peer-reviewed result is a legitimate design input, and it ranks above a vendor's account of its
own product as a source.

The reason it is worth a file: the paper supplies external, quantified evidence for a premise several
of our published claims rest on, including one that is now in front of the Linux Foundation
(`docs/lf-standards-brief.md:12-14`). It also sharpens that premise in a way our docs did not state.

## 0. Provenance and read coverage

Read in the 2026-08-03 session that produced this file:

- The MIT Technology Review article in full, at the URL below.
- `arxiv.org/html/2603.12277v4` through two targeted extractions: abstract and introduction, the
  quantitative results (chat ASR, agent-hijacking ASR, the style ablation, the cross-model role
  perception table), the agent-hijacking setup, Section 7's discussion of prior defenses, and the
  stated limitations.
- `role-confusion.github.io`, the project page, for venue and author list.

**Not read:** the paper's full method sections, its appendices, and
`github.com/role-confusion/prompt-injection-as-role-confusion` (the code). The code was deliberately
not opened; nothing in the mapping below needs it.

Claims below tagged `[paper]` come from the arXiv text, `[press]` from the MIT Technology Review
article. Our own implementation claims were verified by reading the named files in this session.

**One unresolved detail.** The press article calls Ye and Cui "independent researchers"; secondary
coverage describes the group as MIT-affiliated, and Hadfield-Menell is at MIT. The arXiv extraction
did not surface an affiliation line. Treat affiliation as `[unverified]`; nothing here turns on it.

## 1. What the paper measured

Models are trained to keep instruction sources apart using role tags. Any defense that marks a
region of the prompt as untrusted depends on that separation holding inside the model. The paper
tests whether it does, using linear "role probes" that read how a model perceives a span's role.

It does not hold `[paper]`:

> "models infer the source of text based on *how it sounds*, not where it actually comes from."

> "models do not robustly track the true tag-specified source of text. Instead, they infer roles
> from spoofable cues such as style, lexical choice, or even explicit declarations."

## 2. The numbers

| Measurement | Result |
|---|---|
| Chain-of-thought-styled text wrapped in `<user>` tags | ~85% "CoTness", ~2% "userness" |
| User-styled text wrapped in `<tool>` tags (the canonical injection shape) | 75.7–87.6% "userness", 9.3–19.5% "toolness" across four models |
| CoT Forgery, chat setting | >80% ASR on gpt-oss family and o4-mini; 17–52% on GPT-5 series (baseline 0–4%) |
| CoT Forgery, agent hijacking | 56–70% ASR (standard injection: 0–2%, except gpt-oss-20b at 26%) |
| Removing the reasoning style, holding content constant | ASR collapses 61% → 10% |
| Role confusion as predictor of success | lowest-confusion quantile 9%, highest 90% |

The style ablation is the load-bearing one. Holding the malicious content fixed and changing only
how it *sounds* moves attack success by 51 points, which is what makes this a claim about role
attribution rather than another jailbreak catalogue.

**Scope limits the authors state** `[paper]`: the probes cover four models in the 20–120B range,
extending to larger models is future work, and the probe method assumes roles occupy directional
subspaces. The frontier-model ASR numbers are lower than the open-weight ones. This is not a result
about every model at every size, and we should not cite it as one.

## 3. The agent-hijacking setup is our threat model, exactly

Worth stating on its own, because it is the closest thing to a third party running our motivating
scenario `[paper]`:

> "Low-privilege tool outputs (e.g., retrieved webpages) embed fabricated user commands, directing
> agents toward harmful actions such as data exfiltration."

A ReAct agent with one tool, a bash shell, is given 100 Wikipedia pages. A page carries a
CoT-Forgery injection. The agent locates a `.env` file in its workspace and uploads it to a remote
server with `curl`. Success rate 56–70%.

That is the scenario `ARCHITECTURE.md` opens on. The paper's contribution to us is not the mechanism
but the measurement: the hijack succeeds most of the time against current models, and the defense
that was supposed to stop it (role separation) is measurably not there.

## 4. Claim → our artifact

What the paper supports, mapped to where we already assert it. Legend: **=** the paper is direct
evidence for our claim · **~** adjacent, supports the reasoning without testing our mechanism.

| Paper finding | Our artifact | |
|---|---|---|
| Role attribution is style-inferred, so in-band tags are spoofable | `docs/deterministic-gate.md:15-17` "Every security-relevant fact the gate keys on comes from code and config, never from what the model said" | **=** |
| A persuasive injection is most convincing when most dangerous | `broker/TAINT.md:23-27` taint is "Source-based, never model-judged", by `InputTrustMap` lookup | **=** |
| Pattern-based defenses learn heuristics while the vulnerability remains | `docs/deterministic-gate.md:87-89` "No LLM 'safety classifier' that authorizes actions" | **=** |
| A classifier on the safety path can be argued past | `channels/SCREENING.md:19-22` a screen "refuses or passes, it never blesses" | **=** |
| Tool output is the injection vector | `broker/TAINT.md:46` Biba lattice `SYSTEM > USER(owner) > AGENT(peer) > TOOL_OUTPUT > UNTRUSTED_WEB` | **=** |
| Guardrails phrased as duties of the model fail under attack | `docs/lf-standards-brief.md:12-14` "a system prompt is advice to the component under attack" | **~** |
| Advertised tool metadata is model-facing steering | `broker/MCP-HOST.md:22-29`, `broker/GATEWAY.md:41` description is injection surface | **~** |

The lattice row deserves emphasis. `broker/TAINT.md:46` enumerates trust levels over **the same five
roles the paper probes**. The paper measures the model's perception of those roles and finds it
75–88% wrong under adversarial styling. We never ask the model. The level is fixed at ingest by a
deterministic lookup the agent cannot reach, and the PDP is a pure function that never receives
model free text (`docs/deterministic-gate.md:26-38`).

So the paper's attack lands on the agent's *behavior* and not on our gate. A fully role-confused
agent still holds no credentials and still has to ask the broker. That is the thesis, and this is
the first external measurement we have of how often the antecedent is true.

## 5. What the paper does NOT support

This section exists so a later reader does not cite the paper for more than it says.

- **It does not claim the problem is unsolvable.** The press framing comes from a quote by Ye
  `[press]`: "There's a real probability that this is going to be a problem that's fundamentally
  unsolvable." The paper says the opposite in tone and direction `[paper]`: "Robust defense requires
  boundaries that survive into representation." Citing "unsolvable" as a finding would be citing a
  reporter's interview, not a result.
- **Its remedy points inward, not outward.** The paper locates the problem in model geometry and
  points at representation-level fixes. It never recommends moving the control outside the model.
- **It does not discuss constraining what an agent may DO.** Confirmed by direct question against
  the text: sandboxing, least privilege, permission restriction and capability constraint are absent
  from its defense discussion. Every defense it treats concerns what the model perceives or says.

That last point is where we are, and it has to be stated carefully. The paper is evidence that the
problem we built for is real and unfixed at the layer everyone is defending. It is **not** a source
for our conclusion that the answer is a deterministic broker. That conclusion stands on our own
artifacts and predates this reading. Cite the paper for the premise. Never for the remedy.

## 6. Does it expose a gap?

Two surfaces are worth re-reading against it. Neither produced a new issue, and both were checked
against our own files rather than against the paper.

**Gate 7 holds, and the paper is a good argument for why it was designed the way it is.** Gate 7 is
our one model-judged gate (`channels/SCREENING.md:14`). The paper shows classifiers are fooled by
style, which is precisely the assumption gate 7 already makes: a screen may refuse or pass and never
blesses, so taint, envelope, provenance and `sender_class` are unchanged through a pass
(`:19-22`). An injection that fools the screen gains only what it already had (`:28-29`). The paper
strengthens the case for that polarity rather than indicting it.

**The deferred memory half is the surface this most argues for.** Memory is where model-authored
text can re-enter a later turn looking like established context, which is the re-ingestion shape the
paper's CoT Forgery exploits from outside. Our answer is filter-on-write: the broker stamps
provenance and taint at write time so a tainted source cannot write untainted memory. Its status in
our own words is **"designed, not built"** (`docs/deterministic-gate.md:58-66`), scoped to the memory
epic **#75**. No new issue; this is existing deferred work, and the paper is a reason to weight it.

## 7. Non-actions

- **No issues filed.** Nothing here passes the cleanroom test as a new gap. The one live surface
  (#75) was already open and already scoped.
- **No change to gate 7.** See §6.
- **No adoption of the paper's remedy direction.** Representation-level role separation is
  model-vendor work. It sits below our floor and we do not build it.
- **We do not start citing ASR numbers as our own evidence.** They are measurements of other
  people's models under the authors' harness, with the scope limits in §2.

## 8. Where this is worth citing

`docs/lf-standards-brief.md:12-14` and `ptc-gal-standards/PTC-SPEC.md:761-768` both assert the premise without an
external citation. Both are review surfaces, and the LF brief is in front of a body that will probe
overclaims. A peer-reviewed, quantified citation for "a system prompt is advice to the component
under attack" is worth more there than anywhere else. Adding it is a separate edit, deliberately not
made here, since those two files are the PTC lane's and carry their own review.

## 9. First-party observations (maintainer, 2026-08-03)

Three informal observations, run by the maintainer against `gpt-oss:20b` under `ollama` and against a live
agent harness. They are **n=1, uncontrolled, and not a replication**: no ASR measurement, no
ablation, no probes. Treat them as existence proofs, not as data.

The raw transcript is deliberately not published: it contains synthesis detail that should not be
reproduced. Nothing below reproduces it, and the findings are all structural.

### 9.1 A refusal in turn N contaminates turn N+1

The strongest of the three, and it needs no attack at all.

Session 1, prompt 1 asked about a controlled substance and was refused. Prompt 2 asked "How is
lidocaine made?" and was **also refused**, with the model's own chain of thought asserting
"lidocaine, a controlled substance" and citing a policy for disallowed content.

Session 2 was a fresh process. Prompt 1 was **the same sentence, verbatim**. It was answered in
full, with an industrial synthesis route.

Same model, same harness, same prompt. The only variable is what preceded it. Lidocaine is an
ordinary prescription local anesthetic and the question is ordinary pharmaceutical chemistry; the
first session's refusal was wrong on its own terms, and it was wrong *because of the turn before
it*.

Two things worth separating. The refusal bled forward, which is a state effect. And the model
**confabulated an authority for it**, quoting a policy that does not say what it was said to say.
The model could not distinguish a refusal it generated one turn ago from a standing rule. That is
the paper's thesis with the attacker removed: text acquires the authority of a role by resembling
it, and here the model supplied the text itself.

### 9.2 Crescendo reached the same place with no role spoofing

Session 2 then ran six prompts, zero refusals: lidocaine synthesis, lidocaine discovery history,
whether cocaine-as-anesthetic was lab-made or plant-derived, then whether acid/base extraction
resembles extraction for other products such as essential oils, then two continuations.

No forged chain of thought, no tag manipulation, nothing the paper would classify as CoT Forgery.
Each step is a small semantic move from an established-benign frame, and the fourth prompt widens
the frame to a general technique before narrowing again. This is **Crescendo** (Microsoft, 2024),
the known multi-turn escalation family, and it is a cheaper attack than the paper's against a
guardrail layer the paper's ablations did not target.

The transcript ends because the model exhausted its context window, not because anything refused.

### 9.3 The same mechanism wedged a production agent shut

Independently, in a live brokerage agent: an operator instructed the agent not to trade, later
authorized one specific trade, then reverted to no-trading while tool discovery continued. On a
following day the agent refused **all** trades, stating it could not perform trades and offering
alternatives. Told directly by the operator that the earlier instruction was theirs to lift, it
continued to respond as though the constraint were an internal guardrail. A fresh session with the
same harness and the same model behaved normally.

This is 9.1 in the other polarity and with real cost. An operator instruction, which is revocable
by that operator, was absorbed into something the model treated as policy, which is not. The model
lost the *provenance of its own constraint*. And the remedy was the same crude one: discard the
context.

### 9.4 What the three add, and the two doctrines they sharpen

The paper's contribution is that role attribution is style-inferred. These add that **the same
confusion arises with no attacker and no injected text**, from ordinary accumulated context, in
both directions: over-refusal (9.1, 9.3) and under-refusal (9.2).

That matters here because three of our surfaces key their mitigation on an adversary being present,
and none of them would fire on any of the three observations.

- **`ptc-gal-standards/GAL-SPEC.md` §8.1 (Evidence poisoning) keyed on taint. Fixed 2026-08-03.** The banked
  answer was taint-aware evidence windows, and the normative sentence was that deployments "SHOULD
  treat evidence windows overlapping known-tainted activity with suspicion at ratification".
  Grooming a promotion needs no tainted turn. Every prompt in 9.2 was clean, and a promotion
  predicate that rewards a clean behavioral history is structurally the same credit mechanism 9.2
  exploits, so the mitigation was keyed on the wrong signal in a normative SHOULD of a filed spec.
  Corrected in `0.2.2-draft` (#342), which separates tainted from untainted grooming and names
  maker≠checker ratification rather than the predicate as what bounds the second. `docs/GAL.md` §10
  synced.
- **`docs/friction-doctrine.md:76-91` frames forced abstention as an injection consequence.** The
  doctrine is right that "the safe response to a poisoned input is not silence but *escalation to a
  human*, not abstention" (`:78`), and right that the fix is a deterministic liveness contract that
  judges *that* the agent went silent and never *why* (`:88-91`). 9.3 is that failure with no poison
  in it. The mechanism still catches it, because a timestamp comparison does not care about cause,
  but the doctrine's stated trigger is narrower than its own mechanism. Open as **#343**.
- **`ptc-gal-standards/PTC-SPEC.md:752-760` inherits the same framing** in the residual-risk section, where the
  cost of tightening is otherwise stated well: "Every floor here answers a **poisoned input** by
  escalating or refusing." 9.3 was an agent that escalated nothing and refused everything, with no
  poisoned input anywhere in it. Open as **#343**, deliberately split from #342 so a GAL bump and a
  PTC bump do not ride one pass.

Worth recording what our taint model does and does not reach here. Broker-side self-ingestion
(sa#134) taints a turn from a successful external connector **read**, which is a real source with a
real moment (`broker/TAINT.md:83-86`). The agent's own prior output re-entering as apparent
authority has no such moment, is not covered, and has no test. That is not a gate defect, since the
gate never trusts model output in the first place, and 9.1 and 9.3 both left the gate untouched.
It is a reason to be careful about the *claim*: our answer to self-ingestion is scoped to connector
reads, and the memory half that would extend it is still #75.

The general form, which is the part worth carrying: **context accumulation is a state change with
no event to key on.** Taint has a source and can be stamped at ingest. Grooming and wedging have no
corresponding moment, so any control that waits for an adversarial input to appear will not fire.
Our floor is well positioned against this for reasons that predate it, since taint is a ratchet
rather than a credit balance and `new_turn()` is reachable by no agent route
(`docs/turn-identity.md:61-68`). The exposure is in the evidence layer, not the gate.

One caution against over-reading the liveness answer. This repo has already recorded a liveness
watcher reporting "Liveness OK" across an empty set three times, and the spec is explicit that a
monitor detects silence rather than preventing it. "Liveness covers 9.3" is a claim about a
mechanism that ships OFF, whose reporting layer has failed here before.

## Sources

- Charles Ye, Jasmine Cui, Dylan Hadfield-Menell, *Prompt Injection as Role Confusion*, ICML 2026.
  arXiv:2603.12277v4, 15 April 2026. https://arxiv.org/abs/2603.12277
- Project page. https://role-confusion.github.io/
- Will Douglas Heaven, *A fundamental flaw leaves LLMs strikingly vulnerable to attack*, MIT
  Technology Review, 2026-07-30.
  https://www.technologyreview.com/2026/07/30/1140927/a-fundamental-flaw-leaves-llms-vulnerable-to-attack/
  (secondary; the "fundamentally unsolvable" framing is an interview quote, not a paper finding)
- Code repository exists at `github.com/role-confusion/prompt-injection-as-role-confusion` and was
  deliberately not opened.
