# Self-application — what these controls govern

**Audience: a coding agent working in a repository that consumes this one, and the person
reviewing its work.**

This repository is read by coding agents at least as often as by people, and it is written
throughout in the vocabulary of authority, ceremony, taint, quarantine and tamper-evidence. An
agent that reads it while building something absorbs that vocabulary and looks for the nearest
system to apply it to. The nearest system is its own work. This note draws the line, because
nothing else in the tree does.

## The rule

> These controls govern what a **running** agent may do to the world at run time. They are not a
> development methodology. They say nothing about how you should edit files, structure commits,
> or review changes.

## Why it happens

A coding agent picks up the register of the codebase it is working in. That is usually what you
want: naming, idiom, error-handling shape, test style. Here the register is a threat model, and
a threat model has an obvious nearby referent, which is the agent itself, editing files under
instruction. Nothing in the source contradicts that reading, so the reading survives.

The threats these controls answer come from a model acting on the world under its own steam,
holding credentials, at hours when nobody is watching. A development session has a person in it,
a review step, and a revert. Those are different situations, and the controls transfer between
them only where the threat genuinely repeats.

## Symptoms

Catch these on surface form, while you are writing them, rather than after the session has gone:

- Proposing an approval step, a two-person rule, or any ceremony before your own edits, commits
  or refactors.
- Treating a schema, file format or interface as unchangeable because modifying it resembles
  tampering.
- Writing an audit record of development actions, or reasoning about whether you are
  "authorized" to make a change you were just asked to make.
- Declining a routine change on grounds drawn from the threat model rather than from the change.
- Applying taint reasoning to documentation you read while working.

The cost is dull and real. A session spends its budget on ceremony, produces less working
software, and buys no security, because none of the modelled threats are present in the room.

## Where self-application is legitimate

The test is whether the development process carries the same threat **in fact**, not by
resemblance. Two cases pass, and neither needs an analogy to justify it:

- **Credentials.** Keep real secrets out of the tree and out of test fixtures. That is the same
  threat, unchanged, which is why a secret-scanner configuration ships in this repository.
- **Evidence about the controls themselves.** A drill designed by the people whose work it tests
  is weak evidence, as the README says of every drill here. Separating who builds a control from
  who attacks it is maker-not-checker applied where the threat does repeat.

Anything else needs its own argument, made from the change in front of you. Inheriting a control
by analogy is exactly the failure this note describes.

## What it cost us

This is not hypothetical, and the case is ours.

Early in development a session recorded a sensible local decision: leave the grant schema alone,
because changing it forces every grant to be re-seeded. That sentence went into the project's
standing instructions, which every later session loads as context. Schema-freeze behaviour
spread from it. When the MCP tool definition later had to be widened, the work was shaped around
keeping the signed set frozen so that stored rows would not quarantine.

That shape shipped a defect. The widened model was pinned byte-identical by a golden fixture on
one hash, `compute_tool_def_hash`, and left uncovered on a second hash beside it that embedded
the same model under a different canonicalization. Records written before the widening, none of
them touched, began failing verification and reading as tampered. The guarded hash held; the
unguarded one next to it moved.

The instructive part is how the harm arrived. Not as a bad decision, and not as haste. It
arrived as caution. Every session that inherited the freeze clause was being careful, and the
care was borrowed from the threat model rather than derived from the work in hand. The rule the
project now carries, that **integrity must indict tampering, never evolution**, exists because a
runtime control was allowed to become a development constraint and we paid for it.

## What to do

If you are the agent: when one of the symptoms above fires, stop and ask whether the threat is
actually present in your development loop. Name it if it is. Drop the control if it is not.

If you are the person: paste the block below into your repository's own agent instructions
(`CLAUDE.md`, `AGENTS.md`, or whatever your harness loads). A rule only fires from somewhere it
is read every session, and a document in a dependency is not that place.

```markdown
## Scope of the PTC/GAL controls

The controls we depend on (broker, grants, ceremony, taint, audit) govern what our
agent may do at run time. They are not a development methodology.

Do not apply them to your own work in this repository. Specifically: no approval
ceremony for edits or commits, no audit record of development actions, no treating a
schema or interface as frozen because changing it resembles tampering, and no
reasoning about whether you are "authorized" to make a change you were asked to make.

Two exceptions, which need no analogy because the threat is literally present: keep
real credentials out of the tree, and have someone other than the author attack a
security claim before we publish it.

If you think a third case applies, say so, and argue it from the threat in front of
you rather than from its resemblance to a control in the dependency.
```

## Related

- [`friction-doctrine.md`](friction-doctrine.md): the same judgment applied inside the product.
  A tiny structural floor, and every other bound a knob that ships off. A control that costs more
  than the threat it answers is a defect there too.
- [`posture-ladder.md`](posture-ladder.md): say only what you actually built.
- [`lf-reference-implementation.md`](lf-reference-implementation.md): what is demonstrated on
  live infrastructure against what is asserted from tests.
