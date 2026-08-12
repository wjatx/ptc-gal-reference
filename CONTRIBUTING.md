# Contributing to the PTC & GAL reference implementation

Thanks for your interest. This guide covers how the repo is laid out, how to set
up a development environment, the conventions we follow, and how to file issues
and PRs.

If anything here is unclear, file an issue and tag it `documentation` — that is a
good first contribution in itself.

**The most valuable contribution to this repository is a finding, not a
feature.** This is the implementation behind two proposed security
specifications, and its stated problem is that every drill in it was designed by
the people whose work it tests. A report that a control does not hold, that a
document claims more than the code does, or that a green test proves less than it
appears to is worth more to us than a new capability. See
[`SECURITY.md`](SECURITY.md) for how to report the ones that should not be public
first.

## Repo layout in one paragraph

One installable Python package, `safe_agents/`, containing the broker (the gate,
the grant store, the ceremonies, the audit tape, the MCP tool host), the inbound
airlock under `channels/`, and the substrate arms under `arms/`. The normative
contract documents live in the top-level `broker/`, `channels/`, `core/`,
`audit/` and `registry/` directories as markdown, beside the code they govern.
`docs/` holds doctrine, the threat model, the posture ladder and the operator
runbooks; `infra/` is AWS CDK; `examples/` holds worked consumers. Start with
[`docs/lf-notional-architecture.md`](docs/lf-notional-architecture.md) for how
the pieces fit and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the technical floor.

## How this repository relates to its source

**This tree is extracted from a private working repository by a declared
manifest.** You should know what that means before you spend an afternoon on a
patch:

- **Your contribution lands here, in `main`.** This repository is where PRs are
  opened, reviewed and merged, including ours.
- **We back-port accepted contributions into the private source before the next
  extraction.** The extraction rebuilds this tree from the source, so a change
  that exists only here would be reverted by the next one. Preventing that is our
  job, not yours: a sync check lists every commit here that is not yet
  represented in the source, and the extraction is blocked while that list is
  non-empty.
- **If you ever see a PR from us that reverts your merged change, that is a bug
  in our process.** Say so on the PR. We would rather hear it loudly.
- **Three files are generated and cannot be edited here:** `README.md`,
  `LICENSE`, and `pyproject.toml`. They are produced by the extraction rather
  than copied, so an edit to them would be overwritten. File an issue describing
  the change instead and we will make it at the source.

Nothing else in this tree is generated. Everything under `safe_agents/`,
`docs/`, the contract directories, `examples/` and `infra/` is ordinary source
you can edit in place.

## Setting up a dev environment

One venv, one install:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python3 -m pytest
```

The suite is a few thousand tests and needs no cloud account, no container
runtime, and no credentials. Run `pytest` from the repository root rather than
narrowing it to `safe_agents/` — the reliability library the watcher depends on
carries tests the narrower path silently skips.

Some tests skip when the specifications are not present. They live in
[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards) and are not
vendored here; clone them alongside and pass `--spec-dir` to run the conformance
extractor. The skips name the repository in their reason.

To exercise the broker rather than test it, see "Watch it refuse something" in
the [README](README.md).

## Filing issues

Issues are for actionable work items. Use GitHub Discussions for questions and
ideas.

A good issue here states **what you observed**, **what you expected**, and
**which posture rung you were on** — a single-machine run, a container, or a
cloud/cluster deployment. That last one matters more in this project than in
most: several controls are enforced by a platform boundary rather than by code,
so a finding that applies at every rung is a different and more serious thing
than one that applies only where a boundary is absent.
[`docs/posture-ladder.md`](docs/posture-ladder.md) is the referent.

If you believe the finding should not be public yet, follow
[`SECURITY.md`](SECURITY.md) instead.

## Submitting pull requests

1. **Read the relevant contract document first.** Most subsystems have one:
   `broker/SCHEMAS.md`, `broker/MCP-HOST.md`, `broker/CONNECTOR-AUTH.md`,
   `channels/TRUST-MAPPING.md`, `channels/SCREENING.md`, `core/RUNNER-CONTRACT.md`.
   These are normative — the code is expected to match them, and where it does
   not, that is a defect in one of the two rather than a matter of taste.
2. **Create a branch off `main`.** Branch names: `<subsystem>/<short-description>`
   (e.g. `broker/fix-turn-rollover`) or `issue-NN-<short-description>`.
3. **Keep PRs small and single-purpose.** If a change grows past roughly 500
   lines of non-generated diff, consider splitting it.
4. **Run the suite locally before opening the PR.** Not `--collect-only`: that
   proves imports resolve and nothing more. We have shipped a break that survived
   an entire session of collect-only verification.
5. **Do not commit secrets.** Run `gitleaks detect --source .` before pushing if
   you have it.
6. **Open the PR with a clear description** linking the issue and naming the
   contract document you read.
7. **Expect review from a maintainer**, and expect the review to start with the
   design rather than the diff.
8. **Be ready to iterate.** We optimize for the right design, not the fastest
   merge.

## Commit messages

Conventional commit format with a subsystem prefix:

```
subsystem: Description in imperative mood

Optional body explaining the *why*, with context a future maintainer
reading the log will need.

Closes #NN.
```

Imperative mood: "Add foo", not "Adds foo" or "Added foo". The body explains why;
the diff explains what.

If your commit was assisted by an AI tool, add an `Assisted-by:` trailer (e.g.
`Assisted-by: Claude Code (Opus 5)`). Do **not** add `Co-authored-by:` trailers
for AI tools — the human author is the author of record. `Co-authored-by:` is
fine, and encouraged, for human pairing.

**Commit author identity.** Your commits' `Author` field must be your real Git
identity, not an automation or agent tool's identity. If your tooling commits
under a bot account by default, set `git config user.name` and
`git config user.email` for this repository before pushing.

This project does not require a DCO sign-off or a CLA; contributions are accepted
under the inbound=outbound Apache-2.0 terms below. `Signed-off-by:` trailers are
optional.

## Testing discipline

A green suite is weaker evidence than it looks, and this project has the scars to
be specific about how:

**Assert the artifact, never a proxy for it.** A guard that reads an exit code
instead of the thing it guards can be inert while looking correct. This repository
shipped `cmd --follow || die "build failed"` for months against a command that
exits 0 whatever the build does — a failed build printed `PASS ... image built` on
the very next line. When you add a check, ask what it *reads*, not whether a check
exists.

**Run the suite, do not collect it.** `pytest --collect-only` proves imports
resolve. It does not prove a fixture exists, and a missing fixture is exactly what
a packaging change breaks.

**A drill you designed will pass.** If you add a control and a test for it, break
the control on purpose and confirm the test goes red *naming the right mechanism*,
then restore it. A test that passes both ways is not testing what you think.

**Name the rung.** A test that proves a control at rung 3 proves nothing about
rung 1, where the boundary it depends on does not exist.

## Documentation expectations

The contract documents in `broker/`, `channels/`, `core/`, `audit/` and
`registry/` are normative. If your change alters behavior they describe, change
them in the same PR — a doc that overclaims the code is a defect in this project,
not a cosmetic issue.

If your change makes one of our published claims less true, say so in the PR.
Weakening a claim to what survives is a valid and welcome outcome.

## License

By contributing, you agree that your contributions are licensed under the
Apache-2.0 License that covers this repository (inbound=outbound). See
[`LICENSE`](LICENSE).

The specifications are licensed separately, under the Community Specification
License 1.0, and live in
[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards).
