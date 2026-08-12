"""release_cli.py — release ONE held intent from a terminal (#301).

The out-of-band approval seam has existed since sa#176, but every caller of it was
a cloud path: an owner-adapter EventTrigger through a channels drain. On a laptop
there is no channel, so a held call was held until its TTL expired and the golden
path dead-ended at the exact moment the control worked. This is the local arm of
that seam.

**Why this lives base-side.** The same reasoning that put the MCP mouth in the
broker rather than in the product wrapper [ruling: maintainer, 2026-07-25, #283]:
releasing a held call is a broker operation on broker state, and a consumer that
reimplemented it would be a second writer of the thing the broker owns. The
wrapper contributes the product
surface (`example-wrapper approve`), which is a thin launcher — exactly as `example-wrapper gateway` is.

**Why read, render, confirm and execute all happen HERE.** WYSIWYE is a claim
about the bytes the human saw. Rendering in one process and executing in another
puts a store round-trip between the two, and the whole point of materializing an
intent is that no such gap exists. One process, one read, one execution.

**What this is NOT.** It is not a ceremony. Per the 2026-07-29 ruling the release
shape is one command under one identity: there is one human here and no second
credential, so importing maker != checker would be theatre — the proposer and the
ratifier would be the same person flipping a flag, which GAL §8 already refuses to
call two parties. See POLARITY below, which that ruling requires be stated out loud.

**POLARITY: act-safe.** Choosing a one-command release IS choosing a safe-default
polarity, and #308 is right that shipping one silently is the failure. The wrapper assumes
the costlier outcome is the BLOCKED call, not the executed one: a developer whose
tool call is stuck has a broken product, and a coding agent sits far closer to
act-safe than the trading agent the doctrine was sharpened on. A ceremony here
would have shipped abstain-safe by default without anyone deciding to. That is a
CONSUMER decision, re-derived per agent, and it is emphatically not in the base's
policy — this module is mechanism, and the polarity is recorded here and in
`example-wrapper posture` because the ladder forbids an unmarked claim.

Rung 1 (`docs/posture-ladder.md`): anyone who can run this command is the operator.
The release is attributed honestly (`local-solo:` — see local_release_identity),
never authenticated.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys

from safe_agents.broker.approval.types import IntentView
from safe_agents.broker.ceremony_identity import local_release_identity

# Exit codes, matching the wrapper CLI's convention so a launcher can pass them through.
EXIT_OK = 0
EXIT_NOT_RELEASED = 1  # the operator declined, or execution failed
EXIT_REFUSED = 2  # nothing to release: unknown, not pending, misconfigured


def render_intent(view: IntentView) -> str:
    """The approval prompt's body — what the human is agreeing to execute.

    `rendered_for_human` is broker-rendered from the typed BrokeredCall via the PDP
    and the agent never supplies it, so it is the one summary line that cannot be
    staged by a compromised agent. `args_digest` rides with it because the render is
    a summary and the digest is the identity of the bytes.
    """
    lines = [
        "",
        "  HELD CALL",
        f"    intent      {view.intent_id}",
        f"    principal   {view.agent_id}",
        f"    tool.op     {view.tool}.{view.op}",
        f"    argsDigest  {view.args_digest}",
        f"    held at     {view.ts}",
        f"    expires     {view.expiry}",
        "",
        f"  {view.rendered_for_human}",
        "",
        "  Releasing executes the STORED call above — not anything the agent has",
        "  said since. It does not change the grant: the next such call is held",
        "  again. Tell the agent the write is DONE rather than to retry it, or it",
        "  will ask for a second one.",
        "",
    ]
    return "\n".join(lines)


def _confirm(prompt: str) -> bool:
    """Ask on the terminal. A non-interactive stdin is a NO, never an implied yes.

    The friction doctrine's gate-vs-log rule cuts the other way for a prompt that
    cannot be answered: if this is running where nobody can type, the safe reading
    of silence is that no human approved, and `--yes` is how a human says so in
    advance.
    """
    if not sys.stdin.isatty():
        print(
            "REFUSED: stdin is not a terminal, so nobody can answer this prompt. "
            "Pass --yes to state the approval up front.",
            file=sys.stderr,
        )
        return False
    try:
        answer = input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return False
    return answer.strip().lower() in ("y", "yes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.approval.release_cli",
        description="Release one held intent, executing the call the broker stored.",
    )
    parser.add_argument("intent_id", help="the held intent to release")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the confirmation prompt (the approval is still recorded)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the outcome as JSON on stdout"
    )
    args = parser.parse_args(argv)

    # Imported here, not at module scope: argparse must be able to answer --help
    # without booting a runtime, and a boot refusal should surface as a refusal
    # rather than as an import-time traceback.
    from safe_agents.broker.api import build_runtime  # noqa: PLC0415
    from safe_agents.broker.prototype.boot_config import (  # noqa: PLC0415
        BrokerConfigError,
        load_named_manifest,
    )

    try:
        # Derived BEFORE the runtime is built: on the dynamo arm this refuses, and
        # refusing before constructing connectors means a misdirected release never
        # spawns anything.
        approver = local_release_identity()
        # `load_named_manifest` is what the GATEWAY resolves through, deliberately:
        # the release must build over the same manifest that held the call, and two
        # resolvers are two chances to disagree about which agent this is.
        #
        # Composed with stdout redirected to stderr, as the gateway does — the
        # banner is diagnostics, and it must not land in --json output or ahead of
        # the render.
        with contextlib.redirect_stdout(sys.stderr):
            runtime, _sink = build_runtime(load_named_manifest())
    except BrokerConfigError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    try:
        view = runtime.describe_intent(args.intent_id)
        if view is None:
            print(
                f"REFUSED: no held intent {args.intent_id!r} for this principal. "
                "It may have expired (holds have a TTL), already been actioned, or "
                "belong to a different agent.",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        if view.status != "pending":
            print(
                f"REFUSED: intent {args.intent_id!r} is {view.status!r}, not pending "
                "— nothing to release. An intent is actioned exactly once.",
                file=sys.stderr,
            )
            return EXIT_REFUSED

        if not args.json:
            print(render_intent(view))
        if not args.yes and not _confirm(f"  Release as {approver}? [y/N] "):
            print("NOT RELEASED — the intent is still held.", file=sys.stderr)
            return EXIT_NOT_RELEASED

        result = runtime.approve_intent(args.intent_id, approved_by=approver)
    finally:
        # Reap connector-held children (MCP-HOST.md M20). The release spawns its own,
        # since it runs in a different process from the gateway.
        runtime.close()

    if args.json:
        print(
            json.dumps(
                {
                    "intentId": result.intent_id,
                    "executed": result.executed,
                    "approvedBy": approver if result.executed else None,
                    "rejectionReason": result.rejection_reason,
                }
            )
        )
    elif result.executed:
        print(f"RELEASED — {view.tool}.{view.op} executed, approvedBy {approver}")
        print("  The audit tape now carries the hold and this release; see `example-wrapper audit`.")
    else:
        print(
            f"NOT RELEASED: {result.rejection_reason or 'the broker refused'}",
            file=sys.stderr,
        )

    return EXIT_OK if result.executed else EXIT_NOT_RELEASED


if __name__ == "__main__":  # pragma: no cover — process entry point
    sys.exit(main())
