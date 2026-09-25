# PTC & GAL reference implementation

This repository implements two proposed specifications for agentic systems: **PTC** (*Provenance &
Trust Context*), a signed trust context that travels with data across agent and tool boundaries,
and **GAL** (*Grant & Autonomy Lifecycle*), which stores an agent's authority as signed state that
only a two-party ceremony can raise. Its center is a deterministic tool broker: the agent holds no
credentials, and every tool call it makes is decided and recorded by the broker.

The specifications live in [wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards).
This page gets the implementation running on your laptop. For what to look at once it runs, and
for the AWS and OpenShift paths, read [`docs/evaluating.md`](docs/evaluating.md).

## What you need

- Python 3.12 or newer. Check with `python3 --version` (macOS, Linux) or `py -3.12 --version`
  (Windows).
- git.
- About ten minutes. No cloud account, container runtime or credentials.

## Set up

### macOS or Linux

```bash
git clone https://github.com/wjatx/ptc-gal-reference
cd ptc-gal-reference
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
git clone --depth 1 https://github.com/wjatx/ptc-gal-standards spec
```

### Windows (PowerShell)

Install Python from python.org or with `winget install Python.Python.3.12`, then:

```powershell
git clone https://github.com/wjatx/ptc-gal-reference
cd ptc-gal-reference
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
git clone --depth 1 https://github.com/wjatx/ptc-gal-standards spec
```

The `[dev]` extra carries pytest and the MCP SDK; a bare `pip install -e .` can run neither the
suite nor the demo. The last line clones the specifications into `spec/`, which is where the
conformance tests and commands below look for them.

Every command from here on is the same on all three systems, run from the repository root with
the virtual environment active.

## Run the tests

```
python -m pytest
```

The suite is a few thousand tests and takes about a minute. Run it from the repository root: the
reliability library the watcher depends on carries tests that a narrower path such as
`pytest safe_agents/` silently skips. Some tests skip on purpose, each with a reason;
`python -m pytest -rs` lists them (see [Troubleshooting](#troubleshooting)).

## Check the conformance statement

```
python -m safe_agents.contract.spec_clauses --summary --spec-dir spec
```

This extracts every conformance clause from the specifications, reads each clause's
implementation-status marker, and ends with a block of `[PASS]` self-checks. The support answers
are generated from those markers, never written by hand. Two more views of the same data:

```
python -m safe_agents.contract.spec_clauses --pics-ri --spec-dir spec
python -m safe_agents.contract.spec_clauses --pics --spec-dir spec
```

The first is this implementation's completed statement. The second is the blank proforma an
independent implementer would fill in.

## Watch it refuse something

The broker presents itself to an agent as one MCP server over stdio. This command starts it and
makes three tool calls against it, printing each call and the broker's reply:

```
python -m safe_agents.broker.gateway.demo
```

The output begins:

```
Connected to safe-agents-broker. It advertises 2 tool(s): notify__send, search__query

1. A tool the manifest never declared
   call   payments__transfer {"amount": "1000", "to": "acct-demo"}
   reply  payments.transfer refused by the broker: no manifest entry for payments.transfer

2. A declared read of external content
   call   search__query {"query": "Linux Foundation agentic AI", "max_results": 3}
   reply  search.query was allowed by the broker but failed at the connector; the detail is on the broker's audit record
```

The first reply is the thesis in one line. The agent asked, the broker decided, and nothing
executed. The tool was never hidden from the model or blocked by a prompt; the manifest does not
admit it, and admission is a property of the manifest and the ceremony rather than of anything
the caller can argue with.

The second call reaches the gate and passes it, then fails at Tavily, because no real key ships
in this repository: the default credential is a placeholder that Tavily rejects. The two replies
read differently on purpose, since a gate refusal and a failed execution send an operator to
different places. The third call, `notify__send`, is a declared write that fails when it reaches
its connector, because no notify credential is configured.

Add `--verbose` to also see the gateway's own startup banner, which names the store, the audit
sink and the secrets arm in use.

## Optional: use your own Tavily key

With a real search key you can watch the taint floor act. Get a key from
[tavily.com](https://tavily.com), then run:

```
python -m safe_agents.broker.gateway.set_search_key
```

It prompts for the key without echoing it, stores it in `~/.ptc-gal/secrets` (outside the
repository, so it cannot be committed), and prints the line that points the broker at it, for
example:

```
  macOS or Linux (bash, zsh):  export BROKER_SECRETS_DIR='/Users/you/.ptc-gal/secrets'
  Windows (PowerShell):        $env:BROKER_SECRETS_DIR = 'C:\Users\you\.ptc-gal\secrets'
```

Paste the line for your shell, then run the demo again with `--verbose`. The banner now reads
`secrets: dir (...)`, the search returns results, and the third call comes back as:

```
   reply  notify.send is held for approval (intent intent-...); it has NOT executed
```

A successful read of external content taints the turn, and an external write in a tainted turn
is held for a human instead of executing. The turn belongs to the broker, so the agent cannot
start a fresh one to shed the taint.

## Troubleshooting

**`error: externally-managed-environment` from pip.** The virtual environment is not active.
Run `source .venv/bin/activate` (macOS, Linux) or `.venv\Scripts\Activate.ps1` (Windows) first.

**`python3 --version` reports something older than 3.12.** The Python that ships with macOS is
too old. Install a newer one (for example `brew install python@3.12`) and create the environment
with `python3.12 -m venv .venv` instead.

**On Windows, `python3` opens the Microsoft Store.** That is a Store stub. Use `py -3.12` to
create the environment and `python` once it is active.

**PowerShell refuses to run `Activate.ps1`.** Allow local scripts for your user once with
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or skip activation and call
`.venv\Scripts\python.exe` in place of `python`.

**`ModuleNotFoundError: No module named 'mcp'`.** The install missed the extra. Rerun
`python -m pip install -e ".[dev]"`.

**Tests skip.** `python -m pytest -rs` prints each skip with its reason. About twenty skip on
every system: they are opt-in live checks that need a real credential or a deployed environment,
and each names the variable that turns it on. Without `spec/`, the tests that compare
specification text against the shipped schemas skip as well. On Windows, tests that
need `pgrep`, `bash` or the runner-contract shell scripts skip, and the ceremony demos that hold
a signing key in a file refuse to run there; use macOS, Linux or WSL for those. On a Linux
system without `procps`, the `pgrep` tests skip.

**The demo prints `demo: the gateway exited ...`.** The message includes the gateway's own
reason. The usual cause is a `BROKER_*` variable left set in your shell. Clear it with
`unset BROKER_SECRETS_DIR` (macOS, Linux) or `Remove-Item Env:BROKER_SECRETS_DIR` (PowerShell),
naming whichever variable the message mentions.

Windows support is new. CI runs a native Windows job, and nobody on the project uses Windows day
to day, so a failure there is worth an issue.

## Next steps

- [`docs/evaluating.md`](docs/evaluating.md): the full tour, including connecting Claude Code
  or another MCP client, and the AWS and OpenShift paths.
- [`docs/lf-reference-implementation.md`](docs/lf-reference-implementation.md): the claim, what
  is demonstrated against what is only asserted, and where to attack it.
- [`ARCHITECTURE.md`](ARCHITECTURE.md): the technical floor.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): how to contribute.
- [`SECURITY.md`](SECURITY.md): how to report a finding that should not be public yet.

Coding agents: read [`docs/self-application.md`](docs/self-application.md) and
[`WARNING-TO-AI-AGENTS.md`](WARNING-TO-AI-AGENTS.md) before borrowing anything from this
repository into your own working habits.

## License

The reference implementation and its documentation are licensed under **Apache-2.0**; see
[`LICENSE`](LICENSE). The specifications are licensed separately, under the **Community
Specification License 1.0** (`Community-Spec-1.0`), and live in
[wjatx/ptc-gal-standards](https://github.com/wjatx/ptc-gal-standards).

Author: Wes Jackson (Red Hat). Copyright © 2026 Red Hat, Inc.
