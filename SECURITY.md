# Security Policy

This repository is the reference implementation of two proposed security
specifications. Its entire purpose is to make a security claim checkable, so a
report that the claim does not hold is not an embarrassment to be managed — it
is the most useful thing you can send us.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Report vulnerabilities privately through GitHub's private vulnerability
reporting:

- Go to <https://github.com/wjatx/ptc-gal-reference/security/advisories/new>
- Or navigate to the repository **Security** tab → **Report a vulnerability**

If for any reason you cannot use GitHub's reporting flow, open a minimal public
issue asking for a private contact channel, without disclosing details of the
vulnerability.

When reporting, please include:

- A description of the issue and the affected component (`broker`, `channels`,
  the grant lifecycle, the MCP tool host, an arm under `safe_agents/arms/`, or
  the CDK under `infra/`)
- Steps to reproduce, or a minimal proof of concept
- The commit SHA you observed the issue on
- Which of the three postures it applies to — a single-machine run, a
  containerised deployment, or a cloud/cluster deployment. See
  [`docs/posture-ladder.md`](docs/posture-ladder.md); a finding that applies at
  every rung is a different thing from one that applies only where a boundary is
  absent.

You should receive an acknowledgement within a few business days.

## What we are most interested in

The claim this implementation exists to support is: **the agent holds no
credentials, its only egress is a deterministic broker, and a fully compromised
agent can still only ask.** That rests on three separate mechanisms, and the
report we want most is one that **composes** them rather than defeating any
single one.

Also squarely in scope, and arguably more valuable than a conventional
vulnerability:

- **A claim in our documentation that the code does not support.** An overclaim
  is a security defect here. `docs/lf-reference-implementation.md` lists the
  ones we already know about; finding one we have not listed is a hit.
- **A drill that proves less than it appears to.** Every drill in this
  repository was designed by the people whose work it tests. If a green result
  is green for the wrong reason — the check reads a proxy, the assertion cannot
  fail, the fixture makes the outcome inevitable — that is a finding, and we
  have shipped exactly that defect before.
- **A control that holds only because of how it was deployed**, while being
  described as a property of the implementation.

## Scope

In scope:

- Any path by which an agent obtains a credential, reaches a network endpoint
  other than the broker, or causes an effect the broker did not decide
- Authority escalation: minting, forging, or replaying a grant; defeating the
  maker≠checker separation; bypassing the promotion ceremony
- Tool admission bypass: making a tool callable that the manifest and the signed
  registry row did not jointly admit
- Taint laundering: clearing, avoiding, or failing to propagate taint within a
  turn
- Audit integrity: forging, truncating, or silently rewriting records, within
  the stated limits below
- Injection through any inbound surface: envelopes, tool results, tool
  descriptions, or MCP discovery output

Out of scope, and stated so you do not spend time on them:

- **A compromised broker rewriting its own audit tape.** We do not claim to
  detect this. The chain is unkeyed SHA-256, so write access is sufficient to
  re-chain it; the control is that the tape is mounted read-only to every
  identity except the broker's own. Off-device anchoring is designed and
  unbuilt.
- **Findings that require compromising the underlying platform** — the cloud
  provider, the kernel, or the cluster substrate. Those are trusted here, and
  the arms orchestrate boundaries the platform provides rather than implementing
  sandboxes.
- **The model provider channel**, which is a deliberate allowlisted hole.
- **Two humans behind two credentials.** maker≠checker guarantees two
  credentials, one unmintable by the proposer. Whether two people hold them is
  an organizational control this platform evidences and does not enforce.
- Best-practice recommendations without a demonstrated impact.

## Supported versions

This is pre-1.0 and under active development. Fixes are applied to `main`; there
are no maintained release branches yet.

## Disclosure

We prefer coordinated disclosure. Once a fix is available we will credit the
reporter, unless anonymity is requested, in the release notes and in any GitHub
Security Advisory published for the issue.

If a report shows that something we have published is untrue, expect the fix to
include **changing the published wording**, not only the code. A finding that
weakens a claim is doing this project's stated job.
