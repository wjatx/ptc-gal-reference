"""sa#137 exit predicate — read rung-gating + cap + query-exfil bound.

Before sa#137 the PDP's rule 2 (``read_allow_by_scope``) waved through ANY granted
read regardless of grant rung and BEFORE the cap rule, so ``default_level: in-loop``
on a read gated nothing and reads were uncapped; the agent-composed ``search.query``
string also egressed to the provider unbounded (a covert exfil channel). This suite
proves the four closures:

  1. an in-loop external read from an untrusted source is rung-gated (routed through
     the single polarity seam ``_approval_or_deny``): require_approval with a human,
     deny without;
  2. the same read from a ``trusted_read_sources`` source is allowed;
  3. reads now draw the shared capacity budget;
  4. an over-cap / over-budget query string is denied before it egresses;
  and the load-bearing regression guard: a TRUSTED read does not self-taint the turn
  (so a later external write is not escalated) while an UNTRUSTED read still does
  (sa#134/136 preserved).

The engine-level tests drive the pure ``decide()`` with crafted Facts; the PIP tests
drive the real ``_make_pip`` (byte-length + counter derivation); the runtime tests
drive the full PEP (metering + taint coupling).
"""

from __future__ import annotations

import io
import json

import pytest

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import InMemorySink
from safe_agents.broker.enforcement import InMemoryStore, scoped_counter_key
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.manifest import CATALOG, ToolOpTable
from safe_agents.broker.pdp import decide
from safe_agents.broker.pdp.engine import _approval_or_deny
from safe_agents.broker.prototype.broker_server import _make_pip
from safe_agents.broker.runtime import AgentRequest, BrokerRuntime, Doer, FakeSecretsProvider
from safe_agents.broker.schemas import BrokeredCall, Session, Taint, ToolOp
from safe_agents.broker.schemas.common import AutonomyLevel
from safe_agents.broker.taint import build_trust_map
from safe_agents.broker.tests.scaffold import (
    ENVELOPE_HASH,
    PRINCIPAL,
    make_grant,
    make_pip,
    run_threaded_turn,
)
from safe_agents.connectors import SearchConnector

_GRANT_HASH_KEY = b"test-hmac-key"
# make_grant() stamps this envelopeHash; the PIP must be told the same in-force hash
# so the seeded grant reads back clean (not quarantined).
_IN_FORCE_HASH = "test-envelope-hash"

CREDENTIAL = json.dumps({"provider": "tavily", "api_key": "test-key"})

# This suite exercises search.query/notify.send (both in CATALOG) plus two domain
# writes (calendar.create_event, payments.transfer) removed from the base CATALOG by
# #171 — a local table carrying their old classifications for the fallback-rule matrix.
_OPTABLE = ToolOpTable([
    *CATALOG,
    ToolOp(tool="calendar", op="create_event", effect="write", external=False, reversible=True),
    ToolOp(tool="payments", op="transfer", effect="write", external=True, reversible=False),
])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _call(tool: str, op: str, *, tainted: bool = False, args: dict | None = None) -> BrokeredCall:
    """Materialize a BrokeredCall for (tool, op) with the REAL manifest entry."""
    entry = _OPTABLE.entry(tool, op)
    assert entry is not None, f"no manifest entry for {tool}.{op}"
    sources = ["email:untrusted"] if tainted else []
    return BrokeredCall(
        principal=PRINCIPAL,
        tool=tool,
        op=op,
        args=args if args is not None else {"query": "x"},
        manifest=entry,
        taint=Taint(tainted=tainted, sources=sources),
        session=Session(turnId="t", ingestedSources=sources),
        ts="2026-07-07T00:00:00Z",
    )


def _seeded_store(action_class: str, level: AutonomyLevel) -> InMemoryGrantStore:
    store = InMemoryGrantStore(hmac_key=_GRANT_HASH_KEY)
    store.put_grant(make_grant(action_class, level=level))
    return store


class _FakeHTTPResponse:
    def __init__(self, payload: dict) -> None:
        self._body = io.BytesIO(json.dumps(payload).encode())

    def read(self, *args):
        return self._body.read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeUrlopen:
    def __init__(self) -> None:
        self.requests: list = []
        self.payload: dict = {"results": []}

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _FakeHTTPResponse(self.payload)


@pytest.fixture
def fake_urlopen(monkeypatch) -> _FakeUrlopen:
    fake = _FakeUrlopen()
    monkeypatch.setattr("urllib.request.urlopen", fake)
    return fake


class _FakeNotifyConnector:
    def execute(self, tool: str, op: str, args, credential: str):
        return {"tool": tool, "op": op, "sent": True}


def _taint_runtime(
    sink: InMemorySink,
    enforcement_store: InMemoryStore,
    *,
    trusted_read_sources: list[str] | None = None,
) -> BrokerRuntime:
    """A runtime serving search.query (read) + notify.send (write), used to prove the
    read→write taint coupling. Uses the fixed make_pip (taint lives in the PEP, not the
    PIP), so the read is allowed at on-loop and the write's escalation is decided purely
    by whether the read self-tainted the turn."""
    doer = Doer(
        connectors={"search": SearchConnector(), "notify": _FakeNotifyConnector()},
        secrets=FakeSecretsProvider({"search": CREDENTIAL, "notify": "test-notify-credential"}),
    )
    return BrokerRuntime(
        principal=PRINCIPAL,
        grants=[make_grant("search.query"), make_grant("notify.send")],
        optable=_OPTABLE,
        doer=doer,
        pip=make_pip(grant_present=True),
        enforcement_store=enforcement_store,
        intent_store=InMemoryIntentStore(),
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=ENVELOPE_HASH,
        counter_cap=100.0,
        trusted_read_sources=trusted_read_sources,
    )


# ---------------------------------------------------------------------------
# 1. In-loop external read rung-gate (routed through the polarity seam)
# ---------------------------------------------------------------------------


def test_in_loop_untrusted_external_read_requires_approval():
    call = _call("search", "query")
    facts = make_pip(grant_level=AutonomyLevel.in_loop)(call)  # read_source_trusted=False
    assert decide(call, facts).kind == "require_approval"


def test_in_loop_untrusted_external_read_denies_when_no_human():
    call = _call("search", "query")
    facts = make_pip(grant_level=AutonomyLevel.in_loop, human_reachable=False)(call)
    decision = decide(call, facts)
    assert decision.kind == "deny"
    assert decision.reason.endswith("; no human reachable for approval")


# ---------------------------------------------------------------------------
# 2. Trusted source bypasses the rung-gate
# ---------------------------------------------------------------------------


def test_in_loop_trusted_external_read_is_allowed():
    call = _call("search", "query")
    facts = make_pip(grant_level=AutonomyLevel.in_loop, read_source_trusted=True)(call)
    assert decide(call, facts).kind == "allow"


def test_on_loop_external_read_is_allowed_without_trust():
    """A read held at on-loop needs no per-read approval — the rung-gate only binds
    in-loop grants."""
    call = _call("search", "query")
    facts = make_pip(grant_level=AutonomyLevel.on_loop)(call)
    assert decide(call, facts).kind == "allow"


# ---------------------------------------------------------------------------
# 3. Reads now draw the shared capacity budget
# ---------------------------------------------------------------------------


def test_read_draws_the_cap_budget():
    call = _call("search", "query")
    # on-loop so the rung-gate does not fire first — isolate the cap rule for reads.
    facts = make_pip(grant_level=AutonomyLevel.on_loop, cap_budget_breached=True)(call)
    decision = decide(call, facts)
    assert decision.kind == "deny"
    assert decision.reason == "capacity budget breached"


# ---------------------------------------------------------------------------
# 4. Query-egress bound (per-call byte cap + per-period cumulative budget)
# ---------------------------------------------------------------------------


def test_read_over_query_byte_cap_is_denied():
    call = _call("search", "query")
    facts = make_pip(grant_level=AutonomyLevel.on_loop, query_bytes_exceeded=True)(call)
    decision = decide(call, facts)
    assert decision.kind == "deny"
    assert decision.reason == "query egress bound exceeded"


def test_read_over_query_egress_budget_is_denied():
    call = _call("search", "query")
    facts = make_pip(grant_level=AutonomyLevel.on_loop, query_egress_breached=True)(call)
    decision = decide(call, facts)
    assert decision.kind == "deny"
    assert decision.reason == "query egress bound exceeded"


# ---------------------------------------------------------------------------
# PIP derivation — the real _make_pip computes the read-gating facts
# ---------------------------------------------------------------------------


def test_pip_read_source_trusted_from_envelope_list():
    store = _seeded_store("search.query", AutonomyLevel.on_loop)
    trusted_pip = _make_pip(
        store, InMemoryStore(), 100.0, _IN_FORCE_HASH,
        trusted_read_sources=["connector:search.query"],
    )
    untrusted_pip = _make_pip(store, InMemoryStore(), 100.0, _IN_FORCE_HASH)
    assert trusted_pip(_call("search", "query")).read_source_trusted is True
    assert untrusted_pip(_call("search", "query")).read_source_trusted is False


def test_pip_query_bytes_exceeded_uses_utf8_byte_length():
    store = _seeded_store("search.query", AutonomyLevel.on_loop)
    pip = _make_pip(store, InMemoryStore(), 100.0, _IN_FORCE_HASH, max_query_bytes=4)
    # "éé" is 2 characters but 4 UTF-8 bytes — at the cap, not over.
    assert pip(_call("search", "query", args={"query": "éé"})).query_bytes_exceeded is False
    # "ééé" is 3 characters but 6 UTF-8 bytes — a char-count check would miss this.
    assert pip(_call("search", "query", args={"query": "ééé"})).query_bytes_exceeded is True


def test_pip_query_egress_breached_reads_cumulative_counter():
    store = _seeded_store("search.query", AutonomyLevel.on_loop)
    enforcement = InMemoryStore()
    pip = _make_pip(
        store, enforcement, 100.0, _IN_FORCE_HASH, query_egress_budget=50.0
    )
    # Below budget → not breached.
    assert pip(_call("search", "query")).query_egress_breached is False
    # Push cumulative spend to the budget → the NEXT read is breached.
    enforcement.try_increment_counter(
        scoped_counter_key(PRINCIPAL, "search", "query", "query_bytes"), 50.0, 1e18
    )
    assert pip(_call("search", "query")).query_egress_breached is True


# ---------------------------------------------------------------------------
# PEP metering — a successful read increments the egress-byte counter
# ---------------------------------------------------------------------------


def test_pep_meters_egress_bytes_after_successful_read(fake_urlopen):
    fake_urlopen.payload = {"results": []}
    sink = InMemorySink()
    enforcement = InMemoryStore()
    runtime = _taint_runtime(sink, enforcement)
    # "héllo": h,e,l,l,o are 1 byte each, é is 2 bytes → 6 UTF-8 bytes.
    response = runtime.handle_request(
        AgentRequest(tool="search", op="query", args={"query": "héllo"})
    )
    assert response.decision_kind == "allow"
    assert (
        enforcement.read_counter(scoped_counter_key(PRINCIPAL, "search", "query", "query_bytes"))
        == 6.0
    )


# ---------------------------------------------------------------------------
# Regression guard (load-bearing) — trusted read must NOT taint; untrusted still does
# ---------------------------------------------------------------------------


def test_untrusted_read_taints_and_escalates_next_write(fake_urlopen):
    """sa#134/136 preserved: with no trusted_read_sources, the external read
    self-taints the turn, so a later external write escalates to require_approval."""
    fake_urlopen.payload = {"results": []}
    sink = InMemorySink()
    runtime = _taint_runtime(sink, InMemoryStore(), trusted_read_sources=[])

    response_1, response_2, ctx = run_threaded_turn(
        runtime,
        AgentRequest(tool="search", op="query", args={"query": "nvidia"}),
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    )
    assert response_1.decision_kind == "allow"
    assert response_2.decision_kind == "require_approval"
    assert ctx.tainted is True
    assert "connector:search.query" in ctx.to_taint().sources


def test_trusted_read_does_not_taint_and_next_write_is_not_escalated(fake_urlopen):
    """The knob's point: a read from a consumer-declared trusted source does NOT
    self-taint the turn, so an untainted external write in the same turn is allowed —
    the ONLY difference from the untrusted case above is trusted_read_sources."""
    fake_urlopen.payload = {"results": []}
    sink = InMemorySink()
    runtime = _taint_runtime(
        sink, InMemoryStore(), trusted_read_sources=["connector:search.query"]
    )

    response_1, response_2, ctx = run_threaded_turn(
        runtime,
        AgentRequest(tool="search", op="query", args={"query": "nvidia"}),
        AgentRequest(tool="notify", op="send", args={"message": "alert"}),
    )
    assert response_1.decision_kind == "allow"
    assert response_2.decision_kind == "allow"
    assert ctx.tainted is False
    assert "connector:search.query" not in ctx.to_taint().sources


# ---------------------------------------------------------------------------
# Structural — every autonomy-fallback rule dispatches through the ONE polarity seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "description, call, facts_kwargs",
    [
        # read rung-gate (sa#137): in-loop external read from an untrusted source.
        ("read_rung_gate", _call("search", "query"), {"grant_level": AutonomyLevel.in_loop}),
        # in_loop_write: an in-loop internal write.
        (
            "in_loop_write",
            _call("calendar", "create_event", args={"title": "x"}),
            {"grant_level": AutonomyLevel.in_loop},
        ),
        # external_irreversible: a high-blast external write.
        (
            "external_irreversible",
            _call("payments", "transfer", args={"amount": 1}),
            {"grant_level": AutonomyLevel.on_loop},
        ),
        # tainted_external_write: an external write on a tainted turn.
        (
            "tainted_external_write",
            _call("notify", "send", tainted=True, args={"message": "x"}),
            {"grant_level": AutonomyLevel.on_loop},
        ),
    ],
)
def test_all_fallback_rules_route_through_the_single_polarity_seam(description, call, facts_kwargs):
    """Every rule that must fall back when it cannot act autonomously routes through
    ``_approval_or_deny``: require_approval with a human, deny WITH the helper's exact
    "; no human reachable for approval" suffix without one. A rule that baked its own
    literal would not carry that suffix — this is the deterministic seam check."""
    reachable = make_pip(human_reachable=True, **facts_kwargs)(call)
    assert decide(call, reachable).kind == "require_approval", description

    unreachable = make_pip(human_reachable=False, **facts_kwargs)(call)
    decision = decide(call, unreachable)
    assert decision.kind == "deny", description
    assert decision.reason.endswith("; no human reachable for approval"), description


def test_approval_or_deny_is_the_seam_symbol():
    """Guard the seam's identity: the helper exists and is imported from the engine —
    the polarity-design workstream will make THIS one function dispatch on
    Envelope.polarity, so callers must keep routing through it, not re-implement it."""
    assert callable(_approval_or_deny)
