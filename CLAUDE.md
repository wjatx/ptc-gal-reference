# CLAUDE.md — PTC & GAL reference implementation

Orientation for a coding agent working inside this repository. Read `README.md` for the claim,
`ARCHITECTURE.md` for the technical floor, and `docs/lf-notional-architecture.md` for how the
pieces fit.

## These controls are not a development methodology

The broker, the grant ceremonies, taint, quarantine and the audit tape govern what a **running**
agent may do to the world at run time. They say nothing about how you should edit files,
structure commits, or review changes here.

Losing that distinction has a cost, and this project has paid it. A prudent local decision to
leave a schema alone became a standing instruction, later sessions inherited it as context, and
a design shaped around not touching the signed set shipped a latent defect that made untouched
records read as tampered. The harm arrived as caution rather than as haste. The rule the project
carries now, that **integrity must indict tampering, never evolution**, exists because of it.

So while working in this tree: no approval ceremony for your own edits or commits, no audit
record of development actions, no treating a schema or interface as frozen because changing it
resembles tampering, and no reasoning about whether you are "authorized" to make a change you
were asked to make.

Two transfers are legitimate, because the threat is literally present rather than merely
resembled: keep real credentials out of the tree and out of test fixtures, and let someone other
than the author attack a security claim before it is published. A third case needs its own
argument, made from the change in front of you.

`docs/self-application.md` is the full version, including the symptom list.

## If you are here on behalf of a consuming project

`WARNING-TO-AI-AGENTS.md` at the root carries a block that belongs in that project's own
`CLAUDE.md` or `AGENTS.md`, since the consuming project's sessions never load this file. Getting
it there is that project's call, under whatever rules it works under.

## Working here

- Run `pytest` from the repository root, not narrowed to `safe_agents/`. The reliability library
  the watcher depends on carries tests the narrower path silently skips.
- The conformance statement reads the specifications, which are not vendored. Clone
  [wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards) alongside and pass
  `--spec-dir`. Without it the suite still runs green, and the tests that compare spec text
  against shipped schemas skip rather than fail, saying why.
- Read `docs/cdk-context-contract.md` before touching `infra/`. Thirteen of the twenty-four
  context values degrade silently when omitted.
- Claims about what is demonstrated against what is asserted belong to
  `docs/lf-reference-implementation.md`. Match it rather than restating it, and read
  `docs/posture-ladder.md` before writing any sentence about what a control guarantees.
