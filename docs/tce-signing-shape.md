# The outbound trust-context signing shape — a design note (#170)

> **Status: design note — decide, don't build.** This note lands the *shape* decision for signing the
> outbound trust-context envelope (the "TCE" of `docs/PTC.md` §6, name provisional pending the
> maintainer's standards-body naming pass). No code ships here; the build is Phase 4 of the PTC epic (#167). Contract/floor tiering per
> `docs/contract-vs-reference.md` is decided when the build lands, not here.
>
> Companion to `docs/PTC.md` §6 (Layer A — signing) and §7 (content model), `channels/PUBLISH.md`
> (the unsigned outbound seam this signs), and `docs/deterministic-gate.md` (the gate that consumes
> the verified chain). Traces to `auto-agents` on non-repudiable cross-broker trust.

## What this decides, and what it doesn't

The outbound provenance chain (`channels/PUBLISH.md`) is today **unsigned**: a receiving broker trusts
the chain because it trusts the transport (a shared secret to a pre-declared peer). That is enough for
`safe-agents ↔ safe-agents` over a private transport, but it does not survive a hostile intermediary,
does not compose across a wider mesh, and is not *non-repudiable* — a receiver cannot later prove which
broker asserted a hop. PTC §9 makes this the binding constraint on autonomy: a live-brokerage
`trade.place` stays in-loop precisely because the mesh cannot yet *prove* its premise. Signing is what
moves the rung.

This note decides the **signing shape** — the envelope format and what identity the signature keys on.
It does **not** decide the wire schema of the chain itself (that is the normative spec, #178, held for
naming clearance), nor implement verification (Phase 4), nor solve propagation-through-transform (the
banked §8 problem — a signature proves *who signed*, never that taint was correctly propagated).

## The two candidates (from PTC §6)

| | **DSSE + in-toto statement** | **SD-JWT-VC** |
|---|---|---|
| Native unit | an *attestation over a predicate* — a statement about a subject | a *verifiable credential* — claims about a subject, selectively disclosable |
| Fit for a provenance **chain/index** | strong — the chain is exactly an in-toto-style predicate (`subject` = the payload digest, `predicate` = the hop labels + sources) | awkward — a chain is not a natural VC claim-set; you'd encode it into claims |
| Selective disclosure | none native (sign the whole statement) | native — least-disclosure per claim, each reveal cryptographically bound |
| Compactness | JSON envelope, not tuned for size | compact token, designed to travel in headers |
| Multi-sig / multi-hop | first-class (DSSE carries multiple signatures) | single-issuer per credential |
| Ecosystem | Sigstore / SLSA / supply-chain; Rekor transparency log drops in | OpenID / digital-wallet / eIDAS |
| Crypto substrate | JWS or COSE over the DSSE PAE | JWS |

## Decision

**Use both — at different layers — and do not force one format to do the other's job.**

1. **Sign the provenance chain (the index) with a DSSE envelope wrapping an in-toto-style statement.**
   The chain is a predicate about a subject: `subject` = the payload digest(s) the envelope already
   carries (`EventTrigger.payload_digest`), `predicate` = the ordered hops (zone, source, label,
   evidence, ts). DSSE is the best structural fit for a chain predicate (PTC §6), its PAE signing is
   simple and language-portable, and its native multi-signature support is exactly right for a chain
   that accretes a hop — and a signature — **per broker** as it crosses the mesh. Each sending broker
   adds its own signature over the chain-as-it-left-that-zone; a receiver verifies the whole stack.

2. **Reserve SD-JWT-VC for the §7 content drill-down, not the chain signature.** PTC §7's layered
   disclosure — resolving *upstream source content* on drill-down, least-disclosure by default, each
   reveal an audited access event — is the problem SD-JWT-VC was built for. Keeping it at the content
   layer means the always-propagating index stays a compact, PII-safe DSSE statement, while the
   heavier selective-disclosure machinery only appears when someone actually drills into content. This
   matches the §7 discipline: replay the *index* to trace; resolve *content* in layers.

3. **Key the signature on a workload identity, resolved by the broker, never the agent.** The signing
   key belongs to the *broker* (the separate audit identity), consistent with the whole platform floor
   — the agent holds no credential and cannot sign. Concretely: a SPIFFE/SVID or WIMSE workload
   identity where the broker runs with an attestable identity (the AWS execution role → SVID path),
   falling back to a DID for meshes without a SPIFFE trust domain. The signature's subject-key binding
   is what lets a receiver map a hop to *which broker* asserted it — the non-repudiation §9 needs.

4. **Anchor high-value chains in a Sigstore/Rekor-style transparency log — optional, consumer-tiered.**
   For the highest-blast cross-mesh actions, an inclusion proof in an append-only log turns "this
   broker signed" into "this broker signed *and cannot later deny it*." This is a knob, not a floor:
   most chains never need it, and it shipping OFF matches the friction doctrine
   (`docs/friction-doctrine.md`).

### Why not one format for everything

- **SD-JWT-VC for the chain** would force a chain (an ordered, multi-signer predicate) into a
  single-issuer claim-set, and pay for selective-disclosure machinery on every hop of an index that is
  already contentless and always fully propagated. Wrong tool for the index.
- **DSSE for content drill-down** would have no selective disclosure — every drill-down would reveal
  the whole statement, breaking the §7 least-disclosure discipline and its per-reveal audit.

The two live at different layers of §7 (index vs. content) and the format follows the layer.

## What this unblocks and what stays open

- **Unblocks Phase 4** (TCE signing build): the shape is settled, so the build is "implement the DSSE
  statement over the existing chain + broker-keyed signing + airlock verification," not a fresh format
  bake-off.
- **Unblocks sa#161** (the campaign watchdog): it needs trustworthy cross-broker lineage, which is
  exactly what a verified DSSE chain provides.
- **Moves the §9 rung:** once the airlock verifies signatures and rejects forged/unsigned chains,
  a live-brokerage `trade.place` can come off in-loop to require-approval (the rung-tracks-provenance
  rule).
- **Still open (not this note):** the chain wire schema (#178, held for naming), the Cedar/OPA PDP
  expression (#177), and — permanently out of signing's reach — propagation-through-transform (§8).
  A signature is necessary for cross-mesh trust and sufficient for *non-repudiation of who asserted a
  hop*; it is never sufficient for *correctness of the assertion*.

## Open sub-decisions to settle at build time

- **JWS vs COSE for the DSSE signature.** JWS is the lower-friction default (JSON-native, matches the
  JSON envelope); COSE only if a consumer needs compact CBOR on a constrained transport. Default JWS,
  leave COSE a reference option.
- **SPIFFE trust-domain vs DID as the primary identity.** SPIFFE where the deployment has an
  attestable workload identity (the common `safe-agents` case on AWS); DID as the mesh-interop
  fallback. Decide per the first two brokers that actually federate.
- **Per-hop vs whole-chain signature accretion.** Leaning per-hop (each broker signs the chain state as
  it leaves that zone) so a receiver can attribute every hop; confirm against the DSSE multi-sig
  semantics when building.
