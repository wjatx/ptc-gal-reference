# The Connectivity-Orthogonal Trust-Context Standard for AI Agents: Landscape Survey and Reference Architecture

## TL;DR
- **No single unified "connectivity-orthogonal trust context standard" exists today.** There is no ratified or even consolidated draft standard that defines how source-taint, provenance chain, and sender-class ride as one non-repudiable envelope across an agent boundary and get deterministically gated. You must assemble it from primitives spanning three layers.
- **The primitives are mature enough to build on now:** signed provenance (W3C VC 2.0, SD-JWT-VC, in-toto/DSSE, C2PA, Sigstore) for the non-repudiation layer; capability/IFC and taint models (CaMeL, Biba integrity lattice, DLM) plus deterministic policy engines (Cedar, OPA/Rego) for the gating layer. The gap is the SEAM — a standardized signed "trust-context envelope" that a deterministic PDP consumes — and that seam is exactly where you should build proprietary value.
- **Recommended architecture:** carry sender-class + provenance chain + taint labels as a **DSSE-wrapped, in-toto-style signed attestation (or SD-JWT-VC)** that travels in an A2A extension / MCP `_meta` field orthogonally to transport, and gate every tool call with a **Cedar or OPA PDP evaluating a Biba-style integrity lattice** — deny-by-default when low-integrity (untrusted-web-tainted) data would influence a high-integrity action, following the CaMeL control/data-flow separation pattern.

## Key Findings
1. **The three layers exist independently; the seam is unstandardized.** Cryptographic provenance (Layer A) and deterministic policy (Layer B) are both production-grade, but no standard specifies how a *signed* trust context is *consumed by a policy engine at an agent boundary* (Layer C). This is the industry's genuine white space.
2. **CaMeL is the closest thing to a design template for deterministic gating on taint.** Its capabilities + dataflow model with a privileged/quarantined LLM split and a custom interpreter that attaches provenance metadata to every value is the reference IFC pattern — but it is in-process, has no wire format, and provides no cryptographic non-repudiation.
3. **Verifiable Credentials + SD-JWT-VC and the in-toto/DSSE/C2PA family are the only mature, transport-orthogonal, cryptographically non-repudiable carriers** — but they were designed for issuer→holder claims (VCs) or media/software artifacts (C2PA/in-toto), not agent-message taint. Repurposing them for sender-class + provenance chain is straightforward and is what AP2 already does for payment mandates.
4. **Connectivity standards (MCP, A2A) are adding identity/auth but not taint/provenance.** MCP's 2025-06-18 revision made servers OAuth 2.1 resource servers; A2A added optionally JWS-signed Agent Cards. Both are transport-coupled bearer-token/identity mechanisms, not dataflow-labeling systems.
5. **Workload identity (WIMSE WIT, SPIFFE) is the best transport-orthogonal identity substrate** for sender-class of *agent/workload* principals, but does not itself model source-taint or a data-provenance chain.
6. **Deterministic gating is achievable today**; probabilistic (LLM-judge) defenses are explicitly what the mature primitives (Cedar, OPA, CaMeL, Biba lattice) avoid.

## Details

### Layer A — Cryptographic non-repudiation (signed provenance / attestation)

**W3C Verifiable Credentials (VC) Data Model 2.0** — Reached W3C Recommendation status in 2025 (reported May 15, 2025). Transport-orthogonal data-format standard; cryptographically signed (Data Integrity proofs or JOSE/COSE secured with JWT/SD-JWT). Models an issuer→holder→verifier claim chain — a natural fit for **sender-class** (issuer asserts "this principal is a human user / agent / tool") and for an **authorization/provenance chain** (chained credentials). Does NOT natively model source-taint of data content. Non-repudiation: yes. Maturity: ratified.

**Decentralized Identifiers (DIDs) 1.0** — W3C Recommendation (2022). Transport-orthogonal identifier layer under VCs; provides the cryptographic key material to which sender-class assertions bind. Non-repudiation: enables it. Maturity: ratified.

**SD-JWT and SD-JWT-VC** — `draft-ietf-oauth-selective-disclosure-jwt` (SD-JWT) and `draft-ietf-oauth-sd-jwt-vc`. SD-JWT adds selective disclosure + holder binding to JWTs; SD-JWT-VC profiles VCs on top. Both IETF drafts (SD-JWT may have reached RFC status recently — verify). Transport-orthogonal, JOSE-based, signed. Excellent carrier for a compact signed trust-context token that rides in any header or metadata field. Addresses sender-class and claim chains; not source-taint. Maturity: draft (base SD-JWT possibly newly ratified).

**in-toto Attestation Framework + DSSE (Dead Simple Signing Envelope)** — Production standards (CNCF/OpenSSF ecosystem). in-toto's Statement/Predicate model is a general signed-metadata container; DSSE is the signature envelope. This is arguably the *best structural fit* for a "provenance chain envelope" because the predicate can carry an arbitrary trust-context schema (sender-class, taint labels, transformation history) and DSSE gives detached, transport-orthogonal signing. Non-repudiation: yes (core purpose). Maturity: production. Designed for software supply chain, not agent messages — but directly repurposable.

**SLSA (Supply-chain Levels for Software Artifacts)** — v1.0 (Build track L1–L3; Source track added later). A *framework of assurance levels*, not a wire format; uses in-toto/DSSE underneath. Relevant as a maturity-model analogy for "trust levels" but not a message-provenance carrier itself. Maturity: v1.0 ratified.

**Sigstore (Fulcio + Rekor)** — Production keyless-signing + transparency-log system. Rekor's append-only transparency log is the most relevant piece for agents: it provides *auditable, tamper-evident provenance* independent of transport. Could anchor an agent-message provenance ledger. Non-repudiation: yes + public verifiability. Maturity: production.

**C2PA / Content Credentials 2.x** — Published spec (now under a Linux Foundation joint development foundation); C2PA is the manifest spec, "Content Credentials" the CAI/Adobe user-facing brand. Designed for *media asset* provenance (cryptographically signed manifests binding assertions to content, with an ingredient/provenance chain). Application to agent-message provenance is exploratory, not a ratified profile — but its ingredient-chain model is conceptually the media analog of an agent provenance chain. Non-repudiation: yes. Maturity: published spec; agent application nascent.

**JWT/JWS/COSE** — Foundational IETF signing primitives (RFCs). Transport-orthogonal, non-repudiable. Everything above is built on these; a minimal implementation could carry a signed trust-context claim set as a plain JWS/COSE object. Maturity: ratified.

### Layer B — Runtime gating / deterministic policy

**CaMeL — "Defeating Prompt Injections by Design"** (arXiv:2503.18813, March 2025; Google DeepMind + ETH Zürich; authors include Edoardo Debenedetti, Ilia Shumailov, Nicholas Carlini, Florian Tramèr et al.). CaMeL = *Capabilities for Machine Learning*. Builds on Simon Willison's **dual-LLM pattern**: a **privileged LLM (P-LLM)** sees only trusted user input and emits a *plan as code*; a **quarantined LLM (Q-LLM)** parses untrusted data into structured values but never controls flow. A **custom Python interpreter** executes the plan and attaches **capabilities (taint/provenance metadata)** to every value; **security policies are checked deterministically** at each sensitive tool call. This is the canonical deterministic-gating-on-taint template — it gates on the provenance+permission capabilities attached to data, so injected instructions in untrusted data cannot alter control flow. In-process only; **no wire format, no cryptographic non-repudiation.** Maturity: academic + reference implementation. Addresses taint, provenance, and sender-class (trusted-vs-untrusted source) directly.

**Dual-LLM pattern (Willison)** — The architectural precursor to CaMeL: strict separation of a privileged planner from a quarantined content-handler. Design pattern, not a standard. Deterministic control-flow separation.

**Information Flow Control / label-based lattice security** — **Bell-LaPadula** (confidentiality: no read-up/write-down), **Biba** (integrity: no read-down/write-up), and the **Decentralized Label Model (DLM, Myers & Liskov)**. For prompt-injection/taint the relevant model is **Biba integrity**: untrusted-web content is *low integrity* and must not flow into *high-integrity* actions (e.g., sending mail, spending money) without an explicit endorsement/declassification step. This lattice is the formal foundation for deterministic taint gating and maps cleanly onto policy-engine rules. Maturity: mature theory (1970s–90s), newly relevant to agents.

**Open Policy Agent (OPA) / Rego** — CNCF graduated. General-purpose, transport-agnostic policy decision point (PDP). Deterministic. Can gate agent/tool calls on any supplied attributes including taint labels and sender-class — but does not itself *produce* provenance; it consumes it. 2025 ecosystem work applies it to MCP tool gating. Maturity: production.

**Cedar / Amazon Verified Permissions** — AWS open-source policy language + managed PDP. Deterministic, verifiable (designed for analyzability), transport-agnostic. AWS positioned Cedar/AVP for agent and MCP tool authorization in 2025 (including Bedrock AgentCore). Best fit if the user is AWS-centric. Same property as OPA: consumes trust context, doesn't produce it. Maturity: production.

**Capability-based security for agents** — The general model CaMeL instantiates: unforgeable tokens granting specific rights, checked at the boundary. Deterministic by nature. Maturity: mature theory, emerging agent application.

**Deterministic prompt-injection defenses** — Beyond CaMeL, academic work includes StruQ and SecAlign (system-prompt/data separation via training — these are model-level, probabilistic, not deterministic gating) and planner/executor sandboxes. The deterministic branch (CaMeL, capability/IFC sandboxes) is distinct from probabilistic detectors and LLM-judge approaches, which the user explicitly wants to avoid.

### Layer C — The seam (signed provenance consumed by deterministic gate)

No standard defines this seam. The closest real-world instance is **Google's Agent Payments Protocol (AP2)** (announced September 2025 as an A2A extension, MCP-compatible): it carries **Mandates as Verifiable Credentials** — an **Intent Mandate** (user authorizes an agent under constraints) and a **Cart Mandate** (cryptographic approval of a specific cart) — creating a signed, non-repudiable, auditable authorization chain that downstream parties verify before acting. This is a domain-specific proof-of-concept of exactly the pattern the user wants (signed trust context → deterministic verification gate), scoped to payments. Generalizing AP2's "signed VC mandate + verify-before-act" pattern beyond payments is the single most promising path to Layer C.

### Connectivity standards and their trust/security evolution

**MCP authorization** — The 2025-06-18 spec revision classified MCP servers as OAuth 2.1 **Resource Servers**, required **Protected Resource Metadata (RFC 9728)** for auth-server discovery and **Resource Indicators (RFC 8707)** to bind tokens to specific servers (mitigating confused-deputy/token-passthrough), and removed the earlier "MCP server as its own auth server" pattern. Added **Elicitation** (structured mid-session user input). No native message provenance, signing, or taint tracking; auth is bearer-token/OAuth. Transport-coupled (JSON-RPC over stdio/Streamable HTTP). The `_meta` field is the natural place to smuggle a transport-orthogonal trust envelope. Maturity: active spec.

**A2A (Agent2Agent)** — Announced by Google April 2025; donated to the Linux Foundation June 2025 (partners include Microsoft, AWS, Salesforce, SAP, ServiceNow). **Agent Cards** are JSON discovery documents; the spec defines an optional **JWS `signatures` field** for card authenticity. A declared **extensions mechanism** (URI-identified, optionally required) advertised in the Agent Card is the natural hook for a trust-context extension. Signed Agent Cards give *card* authenticity, not per-message non-repudiation, and A2A is not a taint/provenance model. Transport: HTTP + JSON-RPC/SSE/gRPC. Maturity: LF open protocol, actively evolving.

### Emerging drafts, vendor & consortium proposals

**IETF WIMSE (Workload Identity in Multi-System Environments)** — Active WG. Drafts include `draft-ietf-wimse-arch` and `draft-ietf-wimse-s2s-protocol`, defining the **WIMSE Identity Token (WIT)** — a JWT-based, proof-of-possession-bound, **transport-orthogonal** workload credential carried in headers that survives proxies, plus service-to-service call protection. Generalizes/complements **SPIFFE/SPIRE** (CNCF graduated; SVIDs). This is the best standards-track substrate for the *agent/workload sender-class* portion of trust context and carries some interest in call-chain context. Non-repudiation: yes (signed + PoP). Does not model source-taint or data provenance chain. Maturity: IETF drafts.

**Microsoft Entra Agent ID** — Announced at Build May 2025 (public preview); gives agents first-class Entra directory identities governable like service principals (Conditional Access, lifecycle, audit). Identity + governance, not a per-message provenance/taint envelope. Non-repudiation: audit-trail level. Maturity: preview (GA timing to verify).

**OpenID Foundation** — 2025 work on AI-agent / non-human identity (an AI-identity community effort + whitepapers leveraging OAuth/OIDC/VCs for agents). Proposal/whitepaper stage; frames agent authentication, not a signed trust-context envelope.

**W3C PROV / PROV-O** — Mature provenance ontology (2013 Rec). Transport-orthogonal RDF model of entities/activities/agents; conceptually ideal for a *provenance chain* schema, but not inherently signed (would pair with VCs/attestations for non-repudiation) and has no adopted agent-specific profile. Maturity: ratified ontology, no agent profile.

**CSA MAESTRO** — 7-layer threat-modeling framework for agentic AI (Cloud Security Alliance, Ken Huang, early 2025). Descriptive threat model; identifies the need for trust boundaries/provenance but specifies no wire format.

**OWASP** — **Top 10 for LLM Applications 2025** keeps **LLM01: Prompt Injection** at #1; the **Agentic Security Initiative** published agentic threats-and-mitigations guidance (2025) with an agentic threat taxonomy (memory poisoning, tool misuse, privilege compromise, cascading failures). Guidance, not standards.

## Recommendations

**Verdict on the core question:** Build, don't buy — assemble from primitives. There is no single standard; anyone claiming otherwise is selling a proprietary bundle. The buildable architecture:

**Stage 1 — Model the trust lattice (design first, deterministic).** Adopt a **Biba-style integrity lattice**: define integrity levels (e.g., `SYSTEM > USER > AGENT > TOOL_OUTPUT > UNTRUSTED_WEB`) and a sender-class taxonomy. Rule: data at level *L* may not influence a tool call requiring level *> L* without an explicit, logged endorsement/declassification. This is your deterministic gate's core semantics and is transport-independent.

**Stage 2 — Define the signed trust-context envelope (Layer A+C seam).** Carry three fields — **sender-class**, **provenance chain** (ordered list of {principal, transform, input-refs}), and **taint labels** — in a signed envelope. Recommended: **DSSE-wrapped in-toto-style attestation** for rich provenance-chain payloads, or **SD-JWT-VC** for compact, selectively-disclosable tokens. Sign with JWS/COSE keyed to a **DID or SPIFFE/WIMSE WIT** workload identity. Anchor high-value chains in a **Sigstore/Rekor-style transparency log** for auditability. This envelope is transport-orthogonal: it rides in an **A2A extension** or **MCP `_meta`** field but is verifiable independent of either.

**Stage 3 — Deterministic PDP at every boundary (Layer B).** At each tool/agent boundary, a **Cedar (if AWS/Verified Permissions) or OPA/Rego** PDP: (1) verifies the envelope signature and identity binding; (2) reconstructs taint/integrity level from the provenance chain; (3) evaluates lattice rules deny-by-default. No LLM in the decision path.

**Stage 4 — Enforce control/data-flow separation at runtime (CaMeL pattern).** Structure the agent as a **privileged planner** (trusted input only) + **quarantined content handlers** (untrusted data → structured values with propagated taint), executed through an interpreter/orchestrator that attaches provenance to every value and calls the PDP before side effects.

**Benchmarks that change the recommendation:** (a) If IETF/W3C or the Linux Foundation ratifies a transport-orthogonal agent trust-context envelope, adopt it and retire the proprietary schema. (b) If AP2's signed-mandate pattern is generalized beyond payments into an A2A trust extension, build on it directly. (c) If MCP adds native signed provenance to `_meta`, migrate the envelope there. (d) If staying AWS-native, default to Cedar/Verified Permissions; if multi-cloud/portable, default to OPA.

## Caveats
- **Tooling limitation:** live web search was unavailable during this research; findings rest on model knowledge with confidence flags. Verify before committing: current A2A version and exact JWS Agent Card field; Entra Agent ID GA status; any 2026 MCP spec revision; current WIMSE draft revision numbers; SD-JWT RFC number/status; latest C2PA point release and SLSA version; the exact OIDF agentic-identity WG/whitepaper; CaMeL's full author list and follow-ups.
- **The hardest unsolved problem is the seam, not the primitives.** No standard reconciles a *cryptographically signed* provenance chain with a *deterministic policy evaluation* at an agent boundary; you are building on the frontier.
- **Declassification/endorsement is the classic IFC hard problem.** Deciding *when* untrusted-tainted data may be endorsed to influence a privileged action is where most real bugs will live; over-restrictive lattices break usability, over-permissive ones reintroduce injection.
- **Provenance-chain integrity across transforms** (especially LLM summarization/transformation of tainted content) is not solved by any signing standard — the signature proves who signed, not that taint was correctly propagated through a model.
- Treat CSA MAESTRO / OWASP as threat taxonomies, not architectures; treat CaMeL as a research template, not a production framework.