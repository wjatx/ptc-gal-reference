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

## How this repository is maintained

**This repository is the canonical home for the implementation.** Work lands here,
in `main`, and stays here. Nothing regenerates this tree, nothing is copied in from
elsewhere, and no process reverts a merged change.

That was not always true. Until 2026-08-23 this tree was cut from a private working
repository by a declared manifest, and contributions had to be back-ported there
before the next cut or they would be silently erased. **That extraction is retired.**
The private repository holds the design corpus, the working history and unreleased
concepts behind this implementation; it no longer produces this tree, and this tree
no longer waits on it.

What that means for you as a contributor:

- **Your contribution lands here and is durable.** Once merged to `main` it is part
  of the implementation. There is no second tree it has to survive.
- **Every file in this repository is ordinary source you can edit in place**,
  including `README.md`, `LICENSE`, `pyproject.toml`, `CONTRIBUTING.md`,
  `SECURITY.md` and `CODE_OF_CONDUCT.md`. These six were previously generated and
  could not be edited here. That restriction is gone.
- **The specifications live elsewhere and are governed separately.** PTC and GAL are
  maintained at [wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards)
  under the Community Specification License 1.0. A change to what a clause *requires*
  belongs there. A change to how this implementation *satisfies* a clause belongs
  here. When the two disagree, the specification is authoritative and the mismatch is
  a bug in this repository.

## Setting up a dev environment

One venv, one install:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python3 -m pytest
```

On native Windows, in PowerShell, with Python 3.12 or later from python.org or
`winget install Python.Python.3.12`:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

If PowerShell refuses to run `Activate.ps1`, allow local scripts for your user
once with `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or skip activation
and call `.venv\Scripts\python.exe` directly. Use `python`, not `python3`: on
Windows the latter is usually the Microsoft Store stub. A handful of tests skip
there, each naming the POSIX tool it needs (`pgrep`, `bash`, or the runner-contract
harness's shell scripts). CI runs this same path on Windows and macOS.

The suite is a few thousand tests and needs no cloud account, no container
runtime, and no credentials. Run `pytest` from the repository root rather than
narrowing it to `safe_agents/` — the reliability library the watcher depends on
carries tests the narrower path silently skips.

Some tests skip when the specifications are not present. They live in
[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards) and are not
vendored here. The skips name that repository in their reason.

To turn those skips into assertions, clone the specifications to `spec/` in this
repository's root, which is where the tests look:

```bash
git clone --depth 1 https://github.com/wjatx/ptc-gal-standards spec
```

That is what CI does, and it is worth doing locally before you change a schema:
without it the run is green having checked nothing about conformance. A sibling
checkout elsewhere on disk does not work for the tests. The standalone conformance
extractor is separate and does take a path:
`python3 -m safe_agents.contract.spec_clauses --spec-dir DIR`.

To exercise the broker rather than test it, see "Watch it refuse something" in
the [README](README.md).

## Filing issues

Issues are for actionable work items. Use GitHub Discussions for questions and
ideas.

A good issue here states **what you observed**, **what you expected**, and
**which posture you were on** — a single-machine run, a container, or a
cloud/cluster deployment. That last one matters more in this project than in
most: several controls are enforced by a platform boundary rather than by code,
so a finding that applies at every posture is a different and more serious thing
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

**Name the posture.** A test that proves a control at posture 3 proves nothing
about posture 1, where the boundary it depends on does not exist.

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
