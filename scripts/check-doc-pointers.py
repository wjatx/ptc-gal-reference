#!/usr/bin/env python3
"""Find dead file pointers in the standing-doc layer.

The standing layer — CLAUDE.md, ARCHITECTURE.md, README.md, the per-subdir READMEs
and docs/ — is read constantly and verified almost never. This catches the half of
its rot a machine CAN check: a backticked path that no longer resolves. It cannot
catch a well-formed sentence that quietly became false; that is the judgment half,
and nothing here should be mistaken for covering it.

Run:  python3 scripts/check-doc-pointers.py     (exit 1 if any pointer is dead)

## Why the filters are the interesting part

A naive version of this flags dozens of docs and gets switched off within a week.
Three classes of match are NOT pointers, and each has to be excluded or the signal
drowns:

* **Elisions.** Docs say `engine.py` or `classify.py` meaning "the engine module",
  not a repo-relative path. Anything without a `/` is prose.
* **Sibling repos.** `auto-agents/book/ch41` names a repository that lives beside
  this one; the path is right and correctly absent here.
* **Partial paths.** `broker/tests/test_x.py` where the first segment is not a real
  top-level directory is a fragment, not a location.
* **Generated files.** `infra/cdk.context.json` is written by the tool that uses it and
  is gitignored, so a runbook that tells the reader to clear it names a path that is
  correctly absent from any checkout. A path git ignores is treated like a sibling repo.

Line numbers are deliberately NOT checked. They rot honestly as code moves, and
failing on them trains people to disable the check.

## Two filters that used to hide the rot they were written to find

Kept here because each was a real miss, and a reimplementation without them would
report a confident, wrong, low number.

* **The `:line` suffix.** An earlier pointer regex required the backtick to *end* at
  the extension, so `broker/runtime/pep.py:456,1222` — the citation convention used
  throughout these docs — never matched at all. That hid 17 dead pointers, 13 of them
  in `docs/threat-model.md`, which is the document written for outsiders to check
  these claims against the code. The suffix is now optional, matched, and still not
  verified.
* **The "partial path" filter.** Dropping anything whose first segment is not a real
  top-level directory also dropped `grants/proposals.py`, which is not a fragment —
  it is `safe_agents/broker/grants/proposals.py` with two segments missing. That hid
  16 more. A candidate is called a fragment only if it resolves *nowhere*, including
  nowhere under `safe_agents/`. Resolving somewhere is what distinguishes rot from
  prose, and it yields the suggested fix for free.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Repositories that live beside this one. A path under these is another repo's file
#: and is correct precisely by being absent here.
SIBLING_REPOS = {"auto-agents"}

#: Directories whose contents are historical record, not standing instruction. They
#: are allowed to name files that have since moved — that is what a dated record is.
EXCLUDED_DOCS = {"archive", "archives"}

#: A backticked path, with the `:line` / `:line,line` / `:line-line` citation suffix
#: allowed and discarded. The suffix is deliberately not verified — see the module
#: docstring on why line numbers are out of scope — but it must be *matched*, or
#: every cited-code pointer in the corpus is invisible to this check.
_POINTER = re.compile(
    r"`([A-Za-z0-9_./-]+\.(?:py|ts|md|yaml|yml|sh|toml|json|tmpl))(?::[0-9,-]+)?`"
)


def standing_docs() -> list[Path]:
    """The docs read as instruction rather than as history."""
    docs = [ROOT / "CLAUDE.md", ROOT / "ARCHITECTURE.md", ROOT / "README.md"]
    docs += sorted((ROOT / "docs").glob("*.md"))
    docs += sorted(
        p for p in ROOT.glob("*/README.md") if p.parent.name not in EXCLUDED_DOCS
    )
    return [p for p in docs if p.exists()]


def top_level_dirs() -> set[str]:
    return {p.name for p in ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")}


def _git_ignored(candidate: str) -> bool:
    """Whether git ignores `candidate`: a generated or local file, correctly absent."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", candidate],
        cwd=ROOT,
        check=False,
        stderr=subprocess.DEVNULL,  # an absolute path is outside the repo: not ignored
    )
    return result.returncode == 0


def _relocated(candidate: str) -> str | None:
    """Where `candidate` actually lives under `safe_agents/`, if anywhere.

    This is the whole discriminator between rot and prose. `grants/proposals.py`
    resolves to `safe_agents/broker/grants/proposals.py`, so it is a doc that lost
    its prefix; `grants/nonexistent.py` resolves nowhere, so it is prose. A unique
    hit is a fix we can suggest; an ambiguous one is still rot, just not auto-fixable.
    """
    hits = sorted(ROOT.glob(f"safe_agents/**/{candidate}"))
    if not hits:
        return None
    if len(hits) > 1:
        return "AMBIGUOUS: " + ", ".join(str(h.relative_to(ROOT)) for h in hits[:3])
    return str(hits[0].relative_to(ROOT))


def dead_pointers() -> tuple[list[tuple[Path, int, str, str]], int]:
    """Return (dead, checked). `dead` is (doc, line number, path, suggested fix)."""
    topdirs = top_level_dirs()
    dead: list[tuple[Path, int, str, str]] = []
    checked = 0

    for doc in standing_docs():
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            for match in _POINTER.finditer(line):
                candidate = match.group(1)
                if "/" not in candidate:
                    continue  # elision: prose naming a module, not a location
                if candidate.split("/", 1)[0] in SIBLING_REPOS:
                    continue  # another repo; the path is right and correctly absent
                checked += 1

                if (ROOT / candidate).exists():
                    continue
                # A README may point at a sibling the way a reader would walk there:
                # `references/x.md` from docs/, `../ARCHITECTURE.md` from core/.
                if (doc.parent / candidate).exists():
                    continue
                if _git_ignored(candidate):
                    continue  # generated or local; absent from every checkout by design

                fix = _relocated(candidate)
                if fix is None:
                    # Resolves nowhere. Under a real top-level dir this is a genuine
                    # dead pointer; otherwise it is the prose-fragment class.
                    if candidate.split("/", 1)[0] in topdirs:
                        dead.append((doc.relative_to(ROOT), lineno, candidate, "UNRESOLVED"))
                    continue
                dead.append((doc.relative_to(ROOT), lineno, candidate, fix))

    return dead, checked


def main() -> int:
    dead, checked = dead_pointers()
    print(f"standing docs: {len(standing_docs())}   repo-relative pointers checked: {checked}")

    if not dead:
        print("no dead pointers")
        return 0

    print(f"\nDEAD POINTERS: {len(dead)}\n")
    for doc, lineno, path, fix in dead:
        print(f"  {doc}:{lineno}  {path}")
        print(f"      lives at: {fix}")
    print(
        "\nTriage before fixing — three of the four classes are not bugs:\n"
        "  real rot        the file moved; fix the path (find where it lives first)\n"
        "  [retired]       the doc names a deleted file to say 'do not recreate this'\n"
        "  [planned]       aspirational or templated\n"
        "  false positive  fix THIS script, not the doc — a noisy check gets disabled"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
