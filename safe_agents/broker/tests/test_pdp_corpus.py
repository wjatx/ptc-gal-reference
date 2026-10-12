"""The exhaustive differential corpus over the deterministic policy gate.

`test_pdp.py` is the hand-picked case table — it says *what the rules mean*. This file
is its complement: it says *what the gate does everywhere*. It enumerates the ENTIRE
reachable input space of ``decide()`` — every combination of every field any rule
predicate reads — runs each one through the real engine, canonicalizes the
``(input, decision)`` pairs, and pins a single SHA-256 over the whole corpus.

**Why it exists.** The policy-language decision (2026-07-20) was to keep the custom pure PDP rather
than adopt Cedar or OPA/Rego. That decision was settled by a differential spike that ran
ported rule tables against this same exhaustive corpus (Cedar A 71.27%, Cedar B 100.00%,
Rego 100.00% — `docs/PTC.md` §5). The spike was treated as disposable and never
committed, so the evidence `docs/lf-standards-brief.md` cites had no runnable artifact
behind it. This is that artifact, rebuilt and committed.

**What the golden digest buys.** It is a conformance seed: any alternative
gate implementation that claims to be our gate must reproduce ``GOLDEN_CORPUS_DIGEST``
over the same enumeration. And in the other direction, a behaviour change to
``engine.py`` moves the digest — so a policy change surfaces as a deliberate re-mint
with a reviewed diff, never as silent drift.

------------------------------------------------------------------------------
TWO CAVEATS. Both are load-bearing; both were nearly lost with the original spike.
------------------------------------------------------------------------------

**1. This covers the FACT space, not the CALL space.** The sweep varies every ``Facts``
field the engine reads, and on the call side exactly the four fields a rule *predicate*
reads (see ``_CALL_AXES`` / ``_FACT_AXES``). Everything else on the ``BrokeredCall`` is
held constant — most importantly ``args`` (the one model-authored field) and the
``ConfidenceArtifact`` internals, which reach the PDP only pre-reduced to the boolean
``Facts.confidence_below_bar``. That is sound *because those fields reach only the
rendered intent, never a predicate*. **If a future rule reads `args`, or reads the
artifact rather than the reduced boolean, this corpus silently under-covers** — it
would keep passing while testing a projection of the real input space.
``test_swept_axes_match_the_engines_read_surface`` is the tripwire for exactly that: it
AST-walks ``engine.py`` and fails if any read is neither a swept axis nor a declared
constant. Do not weaken it into a subset check.

Note the read surface is wider than the predicates: ``Facts.human_reachable`` is read by
the ``_approval_or_deny`` polarity seam, which rule *actions* call — so it moves the
verb (approval vs deny) without appearing in any predicate. That is why the guard walks
the whole module rather than the rule table alone, and why the axis list is derived from
what the engine reads, not from what the rule comments say it reads.

**2. This proves EQUIVALENCE to `engine.py`, never CORRECTNESS.** The Python engine is
the oracle; the corpus is its complete behavioural fingerprint. A reimplementation that
reproduces the digest matches *our gate*. It does not thereby match the spec, and
neither does ours — if a rule is wrong, the corpus pins the wrong behaviour just as
faithfully. `test_pdp.py`'s case table and `docs/PTC.md` §5 carry the intent claims;
this file carries only the totality claim.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import itertools
import json
import math
from typing import Any

import pytest

from safe_agents.broker.pdp import Facts, decide
from safe_agents.broker.pdp import engine as engine_module
from safe_agents.broker.schemas import BrokeredCall
from safe_agents.broker.schemas.common import AutonomyLevel

# ---------------------------------------------------------------------------
# Golden pin
# ---------------------------------------------------------------------------

# SHA-256 over the sorted, newline-joined canonical "<input> => <decision>" lines of
# the FULL corpus. This is the conformance target for an alternative gate.
#
# If this moves, the gate's behaviour changed. That is a POLICY change, not a test
# update: re-mint it only alongside the rule-table diff that caused it, and say in the
# commit message which rule moved and which decisions changed. `_corpus_lines()` is the
# whole basis, so a diff of two runs' line lists localizes the change exactly.
#
# Re-mint history — each entry says what moved and how that was ESTABLISHED, because
# "the digest changed and I looked at it" is not evidence:
#
#   e974d0f9… -> b6b788df…  (2026-07-29)  REPRESENTATION ONLY, no decision moved.
#     RequireApproval gained an optional `reason`, so the 800 require_approval lines
#     serialize one extra key. Verified by recomputing the corpus with that key
#     stripped from every decision: the result reproduces e974d0f9… exactly, and the
#     verb distribution is unchanged (deny 62816 / abstain 6912 / allow 3008 /
#     require_approval 800 / transform 192). The rule table was not touched.
#     NB this pin covers the decision's SERIALIZATION, so a field addition moves it
#     without any behaviour changing — a golden pin protects what it pins.
#
#   b6b788df… -> edec2f9e…  (2026-09-19)  INTENT-ID PAYLOAD ONLY, no decision moved.
#     _intent_id now binds the principal (agentId#skill#user#tier) instead of leaving
#     it recoverable only through the broker-owned turnId. The corpus freezes every
#     id input, so all 800 require_approval lines carry one id, which moved from
#     intent-18883c559acadaa3 to intent-faa0dbc9295d1a65. Verified by recomputing
#     the corpus before and after with renderedIntent.id stripped from every
#     decision: both reproduce 4da302d5… exactly, and the verb distribution is
#     unchanged (deny 62816 / abstain 6912 / allow 3008 / require_approval 800 /
#     transform 192). The rule table was not touched.
GOLDEN_CORPUS_DIGEST = "edec2f9e6f350a6bdb4020530e9cbba6aa818433f0d567fa7097219143ddb8bc"

# The ON slice of the composed-destination control (PTC-52): the same 73,728 points
# with Facts.destination_composed=True. The base digest above is the OFF slice and is
# deliberately NOT re-minted: that it still reproduces is the proof that adding the
# control moved no decision while it is off. Minted 2026-10-11 with the rule
# tainted_composed_destination; which points differ from the OFF slice, and how, is
# asserted rule-by-rule in test_on_slice_moves_only_tainted_composed_points.
GOLDEN_DESTINATION_ON_DIGEST = "b274b715a2a8b62fc5834ae7539c0995c5350ffef9b0bb8cae006d47d96353b7"

# The ON slice of the harness-tool hold (#168): the same 73,728 points with
# Facts.harness_class_held=True. As for the composed-destination slice, the base
# digest is its OFF slice and is NOT re-minted. Minted 2026-10-12 with the rule
# tainted_harness_hold; which points differ from the OFF slice, and how, is asserted
# point by point in test_harness_on_slice_moves_only_tainted_points.
GOLDEN_HARNESS_HOLD_ON_DIGEST = "741aeff25efb6e7b59a728b9f451dfcdb6a428e54ea818dc609a3697cae389e8"

# The historical figure from the policy-language spike, published in docs/PTC.md §5,
# docs/lf-standards-brief.md and spec/PTC-SPEC.md. Asserted here so the cited number
# and the running artifact cannot drift apart silently.
EXPECTED_CORPUS_SIZE = 73_728


# ---------------------------------------------------------------------------
# The input space — one axis per field a rule predicate reads
# ---------------------------------------------------------------------------

# BrokeredCall axes. `reversible` is a THREE-valued field (bool | None) and the rules
# distinguish all three: transform_to_safer_op guards `is not False`,
# external_irreversible guards `is False`, so None behaves like True at both — but
# that is an outcome
# to be swept, not an assumption to be encoded by collapsing the axis.
_CALL_AXES: dict[str, tuple[Any, ...]] = {
    "effect": ("read", "write"),
    "external": (False, True),
    "reversible": (True, False, None),
    "tainted": (False, True),
}

# Axis name → the BrokeredCall attribute path that axis varies. The corpus builds calls
# by keyword, but the coverage tripwire compares against what the engine's AST reads.
_CALL_AXES_PATHS: dict[str, str] = {
    "effect": "manifest.effect",
    "external": "manifest.external",
    "reversible": "manifest.reversible",
    "tainted": "taint.tainted",
}

# Facts axes. `transform_op` is `str | None`; the rules only test `is not None`, so two
# points span it — a second distinct string adds no reachable behaviour, it only
# changes the Transform payload.
_FACT_AXES: dict[str, tuple[Any, ...]] = {
    "grant_present": (True, False),
    "grant_level": (
        AutonomyLevel.in_loop,
        AutonomyLevel.on_loop,
        AutonomyLevel.out_of_loop,
    ),
    "error_budget_breached": (False, True),
    "cap_budget_breached": (False, True),
    "escalation_budget_available": (True, False),
    "human_reachable": (True, False),
    "transform_op": (None, "draft"),
    "read_source_trusted": (False, True),
    "query_bytes_exceeded": (False, True),
    "query_egress_breached": (False, True),
    "confidence_below_bar": (False, True),
}

# Facts fields added after the published corpus was fixed. Each is swept as its own
# slice over the whole base space, never folded into _FACT_AXES: the OFF value (the
# first point) reproduces GOLDEN_CORPUS_DIGEST and the published 73,728 unchanged,
# and every other value is a further slice with its own pin.
#
#   destination_composed ...... PTC-52, rule tainted_composed_destination. The PIP folds
#                               Envelope.escalate_composed_destinations, the image-baked
#                               ToolOp.destination_arg and the agent's args into this one
#                               boolean, so args still never reach a predicate.
#   harness_class_held ........ #168, rule tainted_harness_hold. The PIP folds
#                               Envelope.tainted_harness_hold and the reserved
#                               coordinate's op into this one boolean, so the engine
#                               parses no op string.
_EXTENSION_FACT_AXES: dict[str, tuple[Any, ...]] = {
    "destination_composed": (False, True),
    "harness_class_held": (False, True),
}

# Held constant across the whole sweep, with the reason each one is safe to freeze.
# Read this list as the artifact's declared blind spot.
#
#   BrokeredCall.args ......... model-authored and opaque to every predicate. Its
#                               invariance is pinned separately and adversarially by
#                               test_decide_is_invariant_to_model_supplied_args.
#   BrokeredCall.principal .... reaches only _intent_id and the rendered-intent string,
#                               never a predicate.
#   BrokeredCall.session ...... turnId feeds _intent_id (the intent ID), never a predicate.
#   BrokeredCall.ts ........... same — _intent_id only.
#   BrokeredCall.tool / .op ... same — _intent_id and the rendered string only.
#   taint.sources ............. the predicates read the derived `tainted` flag only.
#   Facts.quarantined ......... consumed by the PEP for loud surfacing; no
#   Facts.quarantine_reason ... predicate reads either (a quarantined grant arrives as
#                               grant_present=False, which IS swept).
#   ConfidenceArtifact ........ never reaches the PDP; the PIP reduces it to the swept
#                               boolean Facts.confidence_below_bar.
#
# Freezing the _intent_id inputs is what makes the digest stable; they are varied
# nowhere here on purpose, and their effect on the ID is pinned in test_pdp.py.
_CONSTANTS = {
    "principal": {"agentId": "agent-1", "skill": "email", "user": "alice", "tier": "B"},
    "session": {"turnId": "turn-1", "ingestedSources": []},
    "ts": "2026-06-28T00:00:00Z",
    "tool": "corpus",
    "op": "exercise",
    "args": {},
    "taint_sources": [],
}


def _call(effect: str, external: bool, reversible: bool | None, tainted: bool) -> BrokeredCall:
    """Materialize one corpus point on the BrokeredCall side."""
    return BrokeredCall.model_validate(
        {
            "principal": _CONSTANTS["principal"],
            "tool": _CONSTANTS["tool"],
            "op": _CONSTANTS["op"],
            "args": _CONSTANTS["args"],
            "manifest": {
                "tool": _CONSTANTS["tool"],
                "op": _CONSTANTS["op"],
                "effect": effect,
                "external": external,
                "reversible": reversible,
            },
            "taint": {"tainted": tainted, "sources": _CONSTANTS["taint_sources"]},
            "session": _CONSTANTS["session"],
            "ts": _CONSTANTS["ts"],
        }
    )


def _json_safe(value: Any) -> Any:
    """Enum → its value; everything else already serializes."""
    return value.value if isinstance(value, AutonomyLevel) else value


def _canonical(obj: Any) -> str:
    """The repo's canonical JSON basis: sorted keys, compact separators, ASCII."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _axis_points(axes: dict[str, tuple[Any, ...]]) -> list[dict[str, Any]]:
    """Full cross-product of the named axes, as a list of kwarg dicts."""
    names = list(axes)
    return [dict(zip(names, combo)) for combo in itertools.product(*(axes[n] for n in names))]


def _corpus_lines(extension: dict[str, Any] | None = None) -> list[str]:
    """Run the whole reachable input space through decide(); return canonical lines.

    One line per point: ``<canonical input> => <canonical decision>``. Sorted by the
    caller, so the digest does not depend on iteration order — an alternative
    implementation may enumerate in any order and still reproduce it.

    ``extension`` fixes extension axes (``_EXTENSION_FACT_AXES``) for a whole slice
    and names them in each line's input. None is the base space: every extension
    field at its Facts default and absent from the lines, which is the published
    corpus exactly.
    """
    extension = extension or {}
    calls = [(kw, _call(**kw)) for kw in _axis_points(_CALL_AXES)]
    facts_points = [
        ({**kw, **extension}, Facts(**kw, **extension)) for kw in _axis_points(_FACT_AXES)
    ]

    lines: list[str] = []
    for call_kw, call in calls:
        call_key = {k: _json_safe(v) for k, v in call_kw.items()}
        for facts_kw, facts in facts_points:
            facts_key = {k: _json_safe(v) for k, v in facts_kw.items()}
            decision = decide(call, facts)
            lines.append(
                _canonical({"call": call_key, "facts": facts_key})
                + " => "
                + _canonical(decision.model_dump(mode="json"))
            )
    return lines


def _digest(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def corpus() -> list[str]:
    """The full corpus, computed once for the module."""
    return _corpus_lines()


@pytest.fixture(scope="module")
def destination_on_slice() -> list[str]:
    """The base space again with the composed-destination fact on (PTC-52)."""
    return _corpus_lines({"destination_composed": True})


@pytest.fixture(scope="module")
def harness_on_slice() -> list[str]:
    """The base space again with the harness-tool hold fact on (#168)."""
    return _corpus_lines({"harness_class_held": True})


# ---------------------------------------------------------------------------
# The coverage tripwire — caveat 1, made executable
# ---------------------------------------------------------------------------


# The BrokeredCall fields the engine reads but the corpus deliberately freezes: they
# reach only _intent_id and the rendered-human string, never a predicate, so they change
# a Decision's PAYLOAD and never its verb. Freezing them is what makes the digest stable.
_HELD_CONSTANT_CALL_FIELDS = {
    "args",
    "op",
    "principal.agentId",
    "principal.skill",
    "principal.tier",
    "principal.user",
    "session.turnId",
    "tool",
    "ts",
}


def _engine_reads() -> dict[str, set[str]]:
    """AST-walk engine.py and return the fields it reads off its two input types.

    Returns ``{"predicate_call", "predicate_facts", "any_call", "any_facts"}``. The
    predicate sets are verb-determining; the ``any_*`` sets add what the rule actions
    and the ``_approval_or_deny`` / ``_approval`` / ``_intent_id`` helpers read.

    Deliberately reads the SOURCE rather than trusting a hand-maintained list: the
    failure this guards against is a new rule reading a field nobody remembered to add
    to the sweep, and a hand-maintained list fails in exactly that case. Parameters are
    classified by annotation where one exists, and by position inside ``Rule(...)``
    where they are bare lambdas — never by naming convention.
    """
    tree = ast.parse(inspect.getsource(engine_module))
    reads: dict[str, set[str]] = {
        "predicate_call": set(),
        "predicate_facts": set(),
        "any_call": set(),
        "any_facts": set(),
    }

    def _absorb(
        node: ast.Lambda | ast.FunctionDef,
        call_arg: str,
        facts_arg: str | None,
        *,
        predicate: bool,
    ) -> None:
        body = node.body if isinstance(node, ast.Lambda) else node
        found: dict[str, set[str]] = {call_arg: set()}
        if facts_arg:
            found[facts_arg] = set()
        for sub in ast.walk(body):
            if not isinstance(sub, ast.Attribute):
                continue
            parts: list[str] = []
            cursor: ast.expr = sub
            while isinstance(cursor, ast.Attribute):
                parts.append(cursor.attr)
                cursor = cursor.value
            if isinstance(cursor, ast.Name) and cursor.id in found:
                found[cursor.id].add(".".join(reversed(parts)))
        for name, paths in found.items():
            maximal = {p for p in paths if not any(q.startswith(p + ".") for q in paths)}
            bucket = "call" if name == call_arg else "facts"
            reads[f"any_{bucket}"] |= maximal
            if predicate:
                reads[f"predicate_{bucket}"] |= maximal

    rule_count = 0
    for node in ast.walk(tree):
        # Rule(predicate=lambda c, f: ..., action=lambda c, f: ...) — positional by
        # Rule's declared Callable[[BrokeredCall, Facts], ...] signature.
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Rule":
            rule_count += 1
            for keyword in node.keywords:
                if keyword.arg not in ("predicate", "action"):
                    continue
                assert isinstance(keyword.value, ast.Lambda), (
                    f"Rule.{keyword.arg} must stay an inline lambda for this guard to see it"
                )
                args = [a.arg for a in keyword.value.args.args]
                assert len(args) == 2, "Rule lambdas take exactly (call, facts)"
                _absorb(keyword.value, args[0], args[1], predicate=keyword.arg == "predicate")
        # Annotated module-level helpers (_intent_id, _approval, _approval_or_deny).
        elif isinstance(node, ast.FunctionDef):
            typed = {
                a.arg: a.annotation.id
                for a in node.args.args
                if isinstance(a.annotation, ast.Name)
            }
            call_args = [n for n, t in typed.items() if t == "BrokeredCall"]
            facts_args = [n for n, t in typed.items() if t == "Facts"]
            if call_args:
                _absorb(node, call_args[0], facts_args[0] if facts_args else None, predicate=False)

    assert rule_count == len(engine_module.RULES), "AST rule count must match the live table"
    return reads


def test_swept_axes_match_the_engines_read_surface() -> None:
    """The corpus must sweep EXACTLY what moves a decision — no more, no less.

    This is caveat 1 turned into a failing test. A new rule that reads `c.args`, or a
    `ConfidenceArtifact` field, or any Facts field not in `_FACT_AXES`, turns this red;
    without it the corpus would keep passing while covering a strict projection of the
    real input space, and the golden digest would certify a smaller claim than it
    appears to. Extend the axes (and re-mint the digest) rather than relaxing this.

    Three claims, in the order they matter:
      1. every Facts field the engine reads ANYWHERE is swept — Facts has no rendering
         role, so a Facts read is always decision-bearing (`human_reachable` is read only
         by the polarity seam, and it flips the verb);
      2. the call fields a PREDICATE reads are exactly the swept call axes — these are
         the verb-determining ones;
      3. every other call field the engine reads is a declared constant, so a new action
         reading a new call field cannot slip in unremarked.
    """
    reads = _engine_reads()
    assert set(_CALL_AXES_PATHS) == set(_CALL_AXES), "every call axis needs a declared path"
    swept_call = set(_CALL_AXES_PATHS.values())

    swept_facts = set(_FACT_AXES) | set(_EXTENSION_FACT_AXES)
    assert reads["any_facts"] == swept_facts, (
        "the engine reads Facts fields the corpus does not sweep (or vice versa): "
        f"reads={sorted(reads['any_facts'])} swept={sorted(swept_facts)}"
    )
    assert reads["predicate_call"] == swept_call, (
        "rule predicates read BrokeredCall fields the corpus does not sweep "
        f"(or vice versa): reads={sorted(reads['predicate_call'])} swept={sorted(swept_call)}"
    )
    assert reads["any_call"] - swept_call == _HELD_CONSTANT_CALL_FIELDS, (
        "the engine reads a BrokeredCall field that is neither swept nor a declared "
        "constant — the corpus under-covers until it is classified: "
        f"unclassified={sorted(reads['any_call'] - swept_call - _HELD_CONSTANT_CALL_FIELDS)}"
    )


# ---------------------------------------------------------------------------
# Cardinality — the total is auditable, not asserted
# ---------------------------------------------------------------------------


def test_input_space_cardinality_decomposes_to_the_published_figure() -> None:
    """The corpus size is the product of the per-axis cardinalities, and it is 73,728.

    Decomposition (2^10 × 3 fact points × 2 × 2 × 3 × 2 call points):
      call:  effect 2 · external 2 · reversible 3 · tainted 2               =     24
      facts: grant_present 2 · grant_level 3 · error_budget_breached 2
             · cap_budget_breached 2 · escalation_budget_available 2
             · human_reachable 2 · transform_op 2 · read_source_trusted 2
             · query_bytes_exceeded 2 · query_egress_breached 2
             · confidence_below_bar 2                                       =  3,072
      total  24 × 3,072                                                     = 73,728
    """
    call_size = math.prod(len(v) for v in _CALL_AXES.values())
    facts_size = math.prod(len(v) for v in _FACT_AXES.values())
    assert call_size == 24
    assert facts_size == 3_072
    assert call_size * facts_size == EXPECTED_CORPUS_SIZE
    # Every axis point must be distinct, or the "product" is an overcount.
    for name, points in {**_CALL_AXES, **_FACT_AXES, **_EXTENSION_FACT_AXES}.items():
        assert len(set(points)) == len(points), f"duplicate axis point on {name}"
    # Each extension axis's first point is its OFF value, the Facts default, so the
    # base space above IS that axis's OFF slice.
    defaults = Facts(
        grant_present=True,
        grant_level=AutonomyLevel.in_loop,
        error_budget_breached=False,
        cap_budget_breached=False,
        escalation_budget_available=True,
        human_reachable=True,
    )
    for name, points in _EXTENSION_FACT_AXES.items():
        assert getattr(defaults, name) == points[0], f"{name}: first point must be the default"


# ---------------------------------------------------------------------------
# The corpus itself
# ---------------------------------------------------------------------------


@pytest.mark.corpus
def test_corpus_is_total_and_digest_is_pinned(corpus: list[str]) -> None:
    """Every reachable input is exercised, and the whole corpus hashes to the pin."""
    assert len(corpus) == EXPECTED_CORPUS_SIZE
    assert len(set(corpus)) == EXPECTED_CORPUS_SIZE, "duplicate corpus point — axes overlap"
    assert _digest(corpus) == GOLDEN_CORPUS_DIGEST, (
        "the gate's behaviour over the exhaustive input space changed. This is a policy "
        "diff, not a stale test: re-mint the pin only with the rule-table change that "
        "caused it, and record which decisions moved."
    )


@pytest.mark.corpus
def test_corpus_is_deterministic(corpus: list[str]) -> None:
    """Re-running the whole space must reproduce it exactly — same inputs, same outputs.

    `test_pdp.py::test_decide_is_deterministic` makes this claim on one input; this
    makes it on all 73,728, which is the form an alternative implementation has to meet.
    """
    assert _corpus_lines() == corpus


@pytest.mark.corpus
def test_corpus_exercises_all_five_verbs(corpus: list[str]) -> None:
    """A total sweep of a five-verb gate must produce all five verbs."""
    verbs = {json.loads(line.split(" => ", 1)[1])["kind"] for line in corpus}
    assert verbs == {"allow", "deny", "transform", "require_approval", "abstain"}


# ---------------------------------------------------------------------------
# The composed-destination slice (PTC-52)
# ---------------------------------------------------------------------------


@pytest.mark.corpus
def test_destination_on_slice_is_total_and_digest_is_pinned(destination_on_slice: list[str]) -> None:
    """The ON slice covers the whole base space and hashes to its own pin."""
    assert len(destination_on_slice) == EXPECTED_CORPUS_SIZE
    assert len(set(destination_on_slice)) == EXPECTED_CORPUS_SIZE
    assert _digest(destination_on_slice) == GOLDEN_DESTINATION_ON_DIGEST, (
        "the composed-destination rule's behaviour changed over the whole input space; "
        "re-mint only with the rule-table change that caused it."
    )


_COMPOSED_REASON = "tainted composed destination: decided as an external write"


@pytest.mark.corpus
def test_on_slice_moves_only_tainted_composed_points(
    corpus: list[str], destination_on_slice: list[str]
) -> None:
    """Point by point, the ON slice differs from the OFF slice exactly where the rule says.

    A point moves if and only if: the turn is tainted, the call is not an external
    write (the standing cut already holds those, under its own reason), the cap is not
    breached, and no earlier rule decided it (no grant; a write's error-budget or
    confidence rules; a read's egress bound). Every moved point is held through the
    polarity seam and names the rule: require_approval with a human, deny with the
    seam's suffix without one. Nothing that did not move may have changed at all.
    """
    off = {line.split(" => ", 1)[0]: line.split(" => ", 1)[1] for line in corpus}
    moved = 0
    for line in destination_on_slice:
        key, decided = line.split(" => ", 1)
        point = json.loads(key)
        call, facts = point["call"], point["facts"]
        assert facts.pop("destination_composed") is True
        off_decision = off[_canonical({"call": call, "facts": facts})]
        is_write = call["effect"] == "write"
        earlier_rule_decides = (
            not facts["grant_present"]
            or (is_write and (facts["error_budget_breached"] or facts["confidence_below_bar"]))
            or (
                not is_write
                and (facts["query_bytes_exceeded"] or facts["query_egress_breached"])
            )
        )
        should_move = (
            call["tainted"]
            and not (call["external"] and is_write)
            and not facts["cap_budget_breached"]
            and not earlier_rule_decides
        )
        decision = json.loads(decided)
        if not should_move:
            assert decided == off_decision, point
            continue
        assert decision.get("reason", "").startswith(_COMPOSED_REASON), point
        if facts["human_reachable"]:
            assert decision["kind"] == "require_approval", point
        else:
            assert decision == {
                "kind": "deny",
                "reason": _COMPOSED_REASON + "; no human reachable for approval",
            }, point
        if decided != off_decision:
            moved += 1
    # Not vacuous: the rule must actually move a large part of the space.
    assert moved > 1_000


# ---------------------------------------------------------------------------
# The harness-tool hold slice (#168)
# ---------------------------------------------------------------------------


@pytest.mark.corpus
def test_harness_on_slice_is_total_and_digest_is_pinned(harness_on_slice: list[str]) -> None:
    """The ON slice covers the whole base space and hashes to its own pin."""
    assert len(harness_on_slice) == EXPECTED_CORPUS_SIZE
    assert len(set(harness_on_slice)) == EXPECTED_CORPUS_SIZE
    assert _digest(harness_on_slice) == GOLDEN_HARNESS_HOLD_ON_DIGEST, (
        "the harness-tool hold's behaviour changed over the whole input space; "
        "re-mint only with the rule-table change that caused it."
    )


_HARNESS_REASON = "tainted harness hold: the envelope holds this tool class on a tainted turn"


@pytest.mark.corpus
def test_harness_on_slice_moves_only_tainted_points(
    corpus: list[str], harness_on_slice: list[str]
) -> None:
    """Point by point, the ON slice differs from the OFF slice exactly where the rule says.

    A point is decided by the rule if and only if: the turn is tainted, the cap is
    not breached, and no earlier rule decided it (no grant; a write's error-budget or
    confidence rules; a read's egress bound). Unlike the composed-destination rule,
    an external write is NOT left to the standing cut: the hold names itself whatever
    effect and external the consumer declared. Every such point is held through the
    polarity seam under this rule's reason: require_approval with a human, deny with
    the seam's suffix without one. Nothing else may have changed at all.
    """
    off = {line.split(" => ", 1)[0]: line.split(" => ", 1)[1] for line in corpus}
    moved = 0
    for line in harness_on_slice:
        key, decided = line.split(" => ", 1)
        point = json.loads(key)
        call, facts = point["call"], point["facts"]
        assert facts.pop("harness_class_held") is True
        off_decision = off[_canonical({"call": call, "facts": facts})]
        is_write = call["effect"] == "write"
        earlier_rule_decides = (
            not facts["grant_present"]
            or (is_write and (facts["error_budget_breached"] or facts["confidence_below_bar"]))
            or (
                not is_write
                and (facts["query_bytes_exceeded"] or facts["query_egress_breached"])
            )
        )
        decided_here = (
            call["tainted"] and not facts["cap_budget_breached"] and not earlier_rule_decides
        )
        decision = json.loads(decided)
        if not decided_here:
            assert decided == off_decision, point
            continue
        assert decision.get("reason", "").startswith(_HARNESS_REASON), point
        if facts["human_reachable"]:
            assert decision["kind"] == "require_approval", point
        else:
            assert decision == {
                "kind": "deny",
                "reason": _HARNESS_REASON + "; no human reachable for approval",
            }, point
        assert decided != off_decision, point
        moved += 1
    # Not vacuous: the rule must actually move a large part of the space.
    assert moved > 1_000
