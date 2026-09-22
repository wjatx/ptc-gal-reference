"""broker_server.py — local-Mac prototype of the broker's tool-call API (sa#98).

Run on your Mac:   python3 -m safe_agents.broker.prototype.broker_server      (from the repo root)
Then in another terminal:   python3 -m safe_agents.broker.prototype.fake_agent

What this IS:
  A stdlib http.server wrapping a real ``BrokerRuntime`` (the tested library) with
  in-memory fakes (no AWS). It exposes the **tool-call API** — the agent<->broker
  surface that does not exist yet — so we can SEE the round-trip, the protocol, and
  the marshaling, and find out what falls out before committing to the AWS deploy.

  Every agent-specific value — principal, granted action classes, connectors, the
  per-run cap, the risk envelope — is read from an ``AgentManifest`` (broker-debaking
  P2, sa#113), NOT baked into this module. ``build_runtime(manifest)`` consumes it;
  the checked-in default is ``example_manifest.yaml`` (override with BROKER_MANIFEST).

What is REAL here (sa#39/#98 — the local/Mac arm made real):
  - Stores: BROKER_STORE=dynamo uses the real DynamoStore / DynamoIntentStore /
    DynamoDBGrantStore against DynamoDB Local (same code as AWS). The PIP reads the
    grant (presence + level) from the grant store and the cap-budget fact from the
    real counter — no fixed Facts.
  - Audit: a real local-file, hash-chained FileAuditSink (BROKER_AUDIT_PATH). It is
    the honest local analog of S3 Object Lock — see _file_sink.py for why it is not
    tamper-evident without off-device sync.
  - Secrets: a real LocalFileSecretsProvider reads the broker's credentials from a
    0600 JSON file (BROKER_SECRETS_FILE) the host populates from the macOS Keychain.
  - Connectors: resolved by name from connector_registry.py — GitHubConnector
    (github.whoami), AlpacaConnector (alpaca.read), and TelegramConnector
    (notify.send), all real, live calls.

Backend selection (sa#36 — the SAME image runs local OR on AWS Fargate, chosen purely
by env). Three INDEPENDENT switches; see safe_agents/arms/fargate/BROKER_ENV.md for the full
AWS-mode contract:

  Concern  | local/Mac arm                       | AWS Fargate arm
  ---------|-------------------------------------|---------------------------------------
  stores   | BROKER_STORE=dynamo + BROKER_TABLE  | BROKER_STORE=dynamo + BROKER_GRANTS_TABLE
           |   (single table, DynamoDB Local)    |   / BROKER_COUNTERS_TABLE / BROKER_INTENTS_TABLE
  audit    | BROKER_AUDIT_PATH (local file)      | BROKER_AUDIT_BUCKET (+ BROKER_AUDIT_PREFIX) S3 WORM
  secrets  | BROKER_SECRETS_FILE (0600 JSON)     | BROKER_SECRETS=secretsmanager (+ BROKER_SECRET_PREFIX)
           |   or BROKER_SECRETS_DIR (one file   |
           |   per leaf — the container arm)     |

  Each store table falls back to BROKER_TABLE when its per-store var is unset, so the
  single-table local layout and the three-table AWS layout share one code path.
  BROKER_STORE=memory (the default) keeps in-memory stores + InMemorySink +
  FakeSecretsProvider so the surface constructs with no AWS / Keychain / network.

What is still NOT real here:
  - No model-inference proxy here (the :8443 CONNECT proxy is already solved by
    model-proxy-stub.py / #97). This prototype is only the *tool-call* surface.
  - BROKER_STORE=memory keeps in-memory stores + FakeSecretsProvider + InMemorySink
    so the surface constructs with no AWS / Keychain / network (CI + quick smoke).
  - All three wired connectors (github, alpaca, notify) are real, live calls — no
    stub connectors remain in this deployment (see #A5, safe-agents-adoption).
  - Plain JSON-over-HTTP is used here as the simplest protocol to feel out. The
    house standard (FastMCP) is the likely production choice — this prototype is
    where we decide whether MCP earns its weight over plain HTTP for this surface.

Protocol (prototype):
  GET  /registry  -> [{"tool","op"}, ...]   the capability-scoped registry the agent may see
  POST /call      {"tool","op","args","idempotency_key"} -> BrokerResponse json
  GET  /audit     -> [{"seq","decision","outcome"}, ...]  PROTOTYPE-ONLY debug view of the
                     broker-private audit tape; production NEVER exposes this to the agent.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from collections.abc import Callable

    from safe_agents.broker.envelope.store import EnvelopeStore
    from safe_agents.broker.schemas.evidence import DemotionSignal

from safe_agents.broker.approval import InMemoryIntentStore
from safe_agents.broker.audit import FileAuditSink, InMemorySink, S3ObjectLockSink
from safe_agents.broker.delegation.pool import resolve_tree_pool
from safe_agents.broker.delegation.store import SubGrantStore
from safe_agents.broker.enforcement import InMemoryStore, scoped_counter_key
from safe_agents.broker.grants.store import DynamoDBGrantStore, InMemoryGrantStore
from safe_agents.broker.grants.term import effective_level
from safe_agents.broker.pdp import Facts
from safe_agents.broker.prototype.boot_config import (
    DEFAULT_COUNTER_CAP,
    DEFAULT_MANIFEST_PATH,
    DEV_HMAC_KEY,
    BrokerConfigError as BrokerConfigError,  # re-exported (#205 R5 extraction)
    is_dynamo_arm,
    load_agent_manifest as load_agent_manifest,  # re-exported
    load_named_manifest,
    require_named_real_backends,
    require_sanctioned_grant_load,
    resolve_counter_cap,
    resolve_hmac_key,
    resolve_manifest_path,
    resolve_secrets_arm,
    resolve_secrets_dir,
    resolve_secrets_file,
    resolve_sqlite_db_path,
    sqlite_grants_open_options,
    resolve_store_arm,
)
from safe_agents.broker.prototype.connector_registry import resolve_connectors
from safe_agents.broker.prototype.mcp_construction import (
    build_mcp_connectors,
    native_mcp_server_ids,
)
from safe_agents.broker.manifest import ToolOpTable
from safe_agents.broker.runtime import (
    AgentRequest,
    BrokerRuntime,
    Doer,
    build_credential_strategies,
    DirSecretsProvider,
    FakeSecretsProvider,
    LazyBotoSecretsProvider,
    LocalFileSecretsProvider,
    SecretsProvider,
    marshal_connector_result,
)
from safe_agents.broker.schemas import (
    AgentManifest,
    BrokeredCall,
    Grant,
    compute_envelope_hash,
    meets_bar,
)
from safe_agents.broker.schemas.common import AutonomyLevel, CounterPeriod, Principal
from safe_agents.broker.schemas.envelope import Confidence
from safe_agents.broker.taint import build_trust_map

# ---------------------------------------------------------------------------
# Build a real BrokerRuntime with in-memory fakes (mirrors broker/tests/test_runtime.py)
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)

# The #205 named-config-or-refuse boot seam lives in boot_config.py (extracted for
# size, R5); this module re-exports the public names so existing import surfaces
# (`from broker_server import BrokerConfigError, load_agent_manifest, ...`) keep
# working. The private-name aliases are the pre-#205 spelling.
_DEFAULT_MANIFEST_PATH = DEFAULT_MANIFEST_PATH
_DEFAULT_COUNTER_CAP = DEFAULT_COUNTER_CAP
_DEV_HMAC_KEY = DEV_HMAC_KEY
_is_dynamo_arm = is_dynamo_arm
_resolve_manifest_path = resolve_manifest_path
_get_manifest = load_named_manifest


def _resolve_granted_classes(manifest: AgentManifest) -> list[str]:
    """The action classes to serve/seed: BROKER_GRANT_CLASSES override, else the
    manifest's ``grant_classes``.

    BROKER_GRANT_CLASSES (comma-separated) is a HARNESS override — the local arm
    (run-local.sh) narrows to github.whoami, the one class whose credential the
    local host provisions, so its smoke run has a real, deny-free allow path. Unset
    (production / Fargate) = the manifest's ``grant_classes``. Shared by
    build_runtime and the out-of-band ``seed_grants`` CLI so both agree on exactly
    which classes to write/read.
    """
    override = [
        c.strip() for c in os.environ.get("BROKER_GRANT_CLASSES", "").split(",") if c.strip()
    ]
    return override or list(manifest.grant_classes)


def _require_principal(manifest: AgentManifest) -> Principal:
    """Return ``manifest.principal`` or fail loudly if the manifest omits it.

    The broker has NO default principal (de-baking P2, sa#113) — a manifest without
    a ``principal:`` block cannot build a runtime and must not silently default one.
    """
    if manifest.principal is None:
        raise ValueError(
            "manifest.principal is required to build the runtime — the broker has no "
            "default principal (de-baking P2, sa#113). Set the `principal:` block in "
            "the manifest."
        )
    return manifest.principal


def _make_grant(action_class: str, principal: Principal, envelope_hash: str) -> Grant:
    return Grant.model_validate(
        {
            "principal": principal.model_dump(mode="json"),
            "actionClass": action_class,
            "level": AutonomyLevel.on_loop,
            # The real in-force envelope hash — the grant is issued UNDER this
            # envelope, so it must match what the PIP verifies against at decision
            # time (a mismatch quarantines the grant, sa#122).
            "envelopeHash": envelope_hash,
            "promotedBy": "human-reviewer",
            "evidence": "proto-evidence-ref",
            "ts": "2026-06-28T00:00:00Z",
            "lastSafeLevel": "in-loop",
            "demotionTriggers": [],
            "demotionReason": None,
            "labelLatency": "PT1H",
            "ownerId": "owner@example.com",
        }
    )


def _is_missing_secret(exc: Exception) -> bool:
    """True when ``exc`` means 'this secret does not exist' for any backing provider.

    Local providers raise KeyError (unknown name) or FileNotFoundError (no file);
    Secrets Manager raises a botocore ClientError whose Error.Code is
    ``ResourceNotFoundException``. We match the boto case by inspecting the response
    dict so botocore need not be importable in the AWS-free test environment. Any
    other failure (AccessDenied, network, throttling) is NOT a missing secret and
    must surface — a real github credential failure stays visible.
    """
    if isinstance(exc, (KeyError, FileNotFoundError)):
        return True
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code") == "ResourceNotFoundException"
    return False


class _PrefixedSecrets:
    """Maps a secret *leaf* to its Secrets Manager secret id under a prefix.

    With BROKER_SECRET_PREFIX set, ``fetch_secret("github")`` resolves to
    ``"<prefix>/connectors/github"`` — matching the brokerRole IAM grant on
    ``*/connectors/*`` (sa#11 Identity stack). Without a prefix the name passes
    through unchanged, so a flat secret id still works.

    The input is always treated as a leaf, whether it comes from the default
    ``leaf == tool-name`` mapping or from a manifest ``connector_secrets`` override
    (sa#164): an override value of ``"track-feed-token"`` fetches
    ``"<prefix>/connectors/track-feed-token"``, NOT the bare value. This is why a
    ``connector_secrets`` value must be a bare leaf, never a pre-prefixed path —
    doing so would double the prefix. Keeping it a leaf also keeps the fetched id
    inside the ``<prefix>/connectors/*`` grant regardless of environment.
    """

    def __init__(self, inner: SecretsProvider, prefix: str) -> None:
        self._inner = inner
        self._prefix = prefix.rstrip("/")

    def fetch_secret(self, secret_name: str) -> str:
        full = f"{self._prefix}/connectors/{secret_name}" if self._prefix else secret_name
        return self._inner.fetch_secret(full)


class _OverlaySecrets:
    """A real/primary secrets provider with a dev-stub fallback for the stub tools.

    Backend-agnostic generalization of the old file-only overlay: ``primary`` is the
    real provider for this arm (LocalFileSecretsProvider on the Mac arm, or
    Secrets Manager via LazyBotoSecretsProvider on AWS), and ``fallback`` supplies
    throwaway dev values for the calendar/payments/crm StubConnectors. Those stubs
    ignore their credential, so falling back keeps them out of the real secret store
    rather than forcing placeholder entries into it; github always resolves through
    the primary.
    """

    def __init__(self, primary: SecretsProvider, fallback: SecretsProvider) -> None:
        self._primary = primary
        self._fallback = fallback

    def fetch_secret(self, secret_name: str) -> str:
        try:
            return self._primary.fetch_secret(secret_name)
        except Exception as exc:  # noqa: BLE001 — re-raised below unless it's a miss
            if _is_missing_secret(exc):
                return self._fallback.fetch_secret(secret_name)
            raise


def _make_pip(
    grant_store,
    enforcement_store,
    counter_cap: float,
    in_force_hash: str,
    trusted_read_sources: list[str] | None = None,
    max_query_bytes: int | None = None,
    query_egress_budget: float | None = None,
    confidence_knob: Confidence | None = None,
    counter_period: CounterPeriod = "utc-day",
    clock: Callable[[], datetime.datetime] | None = None,
    sub_grant_store=None,
):
    """Build the real PIP: per call, read grant (presence + level) from the grant
    store and the cap-budget fact from the real counter. The counter_key MUST match
    the one the PEP uses in handle_request — both call
    enforcement.scoped_counter_key (principal + tool.op + UTC day), which is what
    makes caps per-principal per-op DAILY budgets rather than global lifetime spend.

    sa#137 — three read-gating knobs are threaded from the envelope (all defaulted so
    the older 4-arg callers keep working):
      - ``trusted_read_sources``: source ids whose external reads are trusted; the PIP
        sets ``read_source_trusted`` for a read whose ``connector:{tool}.{op}`` id is
        in the set, bypassing the in-loop read rung-gate. The SAME set drives the PEP's
        taint-skip — one envelope list, consulted in both halves.
      - ``max_query_bytes`` / ``query_egress_budget``: bound the ``egress_arg`` value
        (the agent-composed query string) — per-call UTF-8 byte cap and per-period
        cumulative byte budget. The PIP only READS the ``…:query_bytes`` counter (it
        runs twice per request and MUST stay side-effect-free); the PEP does the single
        metered increment after a successful read.

    #184 — the ``confidence_knob`` (``Envelope.confidence``) drives two more facts,
    both read-only:
      - ``confidence_below_bar = not meets_bar(call.confidence, confidence_knob)`` — the
        per-call bar (None knob ⇒ always meets ⇒ never below-bar, OFF).
      - ``error_budget_breached`` — was hardcoded False since the scaffold; now, when the
        knob sets ``error_budget_tolerance``, it reads the ``…:error_budget`` counter the
        PEP meters and compares against the tolerance, making the latent rules 2/3 real.

    ``in_force_hash`` is the real content-hash of the envelope currently in force
    (``compute_envelope_hash(manifest.envelope)``). The PIP verifies each grant's
    ``envelopeHash`` against it: a grant issued under a DIFFERENT envelope is
    quarantined (sa#122), reusing the same signal the HMAC-mismatch path uses.

    The PIP is PURE (no I/O beyond the injected stores, no logging/audit): a
    quarantined grant is not surfaced here but reported UP via the returned Facts
    (quarantined / quarantine_reason). The PEP owns surfacing it exactly once
    (sa#124) — the pip is invoked twice per request (initial decision + enforce()
    premise revalidation), so any emit here would double-log every tamper event.

    #255 — certification term (GAL §6.7.6). ``grant_level`` is the grant's
    EFFECTIVE level at the evaluation instant (``grants.term.effective_level``):
    once a grant's ``certifiedUntil`` has passed it acts at ``lastSafeLevel``
    whether or not the lapse writer has run — an idle grant nobody sweeps is the
    case the arc exists for. Pure: no write, and the broker gains no grant-store
    write. The instant comes from ``clock`` — injectable for tests, the wall
    clock by default — read once per pip call. It is NEVER derived from the
    grant's ``ts`` or any ledger record: those say when something was written,
    and a quiet log writes nothing."""

    def _now() -> datetime.datetime:
        return clock() if clock is not None else datetime.datetime.now(datetime.UTC)

    def pip(call: BrokeredCall) -> Facts:
        result = grant_store.get_grant(call.principal, f"{call.tool}.{call.op}")
        # A quarantined grant (HMAC mismatch) is never authoritative — treat as
        # absent for the PDP, but carry the quarantine SIGNAL up on the Facts so
        # the PEP can distinguish it from a merely-ungranted capability and surface
        # it loudly at its single detection point (sa#124).
        grant = result.grant if not result.quarantined else None
        quarantined = result.quarantined
        quarantine_reason = result.quarantine_reason

        # sa#122 — envelope-hash verification. An HMAC-clean grant whose
        # ``envelopeHash`` does not match the envelope now in force was issued under
        # a different (e.g. changed/rotated) envelope. Reuse the sa#124 quarantine
        # signal — treat it as absent AND report the mismatch up so the PEP surfaces
        # it once and denies. No new decision path: same Facts.quarantined channel.
        if grant is not None and grant.envelopeHash != in_force_hash:
            quarantined = True
            quarantine_reason = (
                f"envelope hash mismatch: grant issued under {grant.envelopeHash} "
                f"but in-force {in_force_hash}"
            )
            grant = None

        grant_present = grant is not None
        # When no grant, level is unused (rule 1 denies on grant_present); default safe.
        # With a grant: the EFFECTIVE level at this instant (#255) — a passed
        # certification term acts at lastSafeLevel before any lapse is written.
        grant_level = (
            effective_level(grant, _now()) if grant is not None else AutonomyLevel.in_loop
        )

        # Same principal+period derivation the PEP increments with — the two MUST
        # agree or the cap rule evaluates a different counter than enforce() draws.
        counter_key = scoped_counter_key(
            call.principal, call.tool, call.op, "counter", period=counter_period
        )
        spent = enforcement_store.read_counter(counter_key)

        # #11 -- the delegation-tree pool. Resolved through the ONE helper the
        # PEP also draws with, so the fact and the draw can never key different
        # coordinates. None when delegation is not configured, which is why an
        # undelegated deployment reads exactly one counter as before.
        #
        # Folded into the EXISTING cap_budget_breached fact rather than added as
        # a new Facts field, deliberately. A new field the PDP reads would have to
        # join test_pdp_corpus's swept axes and re-mint the golden digest -- a
        # policy change surfacing as a reviewed diff -- and no rule here is
        # changing: "a capacity bound for this call is spent" already denies. The
        # PEP names WHICH bound refused, since only it can tell them apart.
        tree_draw = resolve_tree_pool(
            call.principal,
            call.tool,
            call.op,
            sub_grant_store=sub_grant_store,
            own_cap=counter_cap,
            period=counter_period,
        )
        tree_breached = (
            tree_draw is not None
            and enforcement_store.read_counter(tree_draw.key) >= tree_draw.cap
        )

        # sa#137 — read-gating facts. Computing them unconditionally is fine; the
        # read-path rules key on manifest.effect=="read", so they are inert for writes.
        trusted = trusted_read_sources or []
        read_source_trusted = f"connector:{call.tool}.{call.op}" in trusted

        # Query-egress bound: only meaningful when the op declares an egress_arg and
        # that arg carried a string. UTF-8 byte length (not char count) is what
        # actually crosses the wire. Both checks are read-only.
        query_bytes_exceeded = False
        query_egress_breached = False
        egress_arg = call.manifest.egress_arg
        if egress_arg is not None and isinstance(call.args, dict):
            arg_val = call.args.get(egress_arg)
            if isinstance(arg_val, str):
                if max_query_bytes is not None and len(arg_val.encode("utf-8")) > max_query_bytes:
                    query_bytes_exceeded = True
                if query_egress_budget is not None:
                    spent_bytes = enforcement_store.read_counter(
                        scoped_counter_key(
                            call.principal,
                            call.tool,
                            call.op,
                            "query_bytes",
                            period=counter_period,
                        )
                    )
                    query_egress_breached = spent_bytes >= query_egress_budget

        # #184 — below-bar fact: the deterministic bar predicate over the (already
        # validated) artifact on the call. A None knob/bar ⇒ meets_bar True ⇒ never
        # below-bar (OFF). Read-only.
        confidence_below_bar = not meets_bar(call.confidence, confidence_knob)

        # #184 — cumulative error-budget breach. Was hardcoded False since the scaffold
        # (rules 2/3 latent); now real when the knob sets a tolerance: read the
        # …:error_budget counter the PEP meters and compare. Read-only — same
        # side-effect-free discipline as the query-bytes read above.
        error_budget_breached = False
        if confidence_knob is not None and confidence_knob.error_budget_tolerance is not None:
            spent_budget = enforcement_store.read_counter(
                scoped_counter_key(
                    call.principal,
                    call.tool,
                    call.op,
                    "error_budget",
                    period=counter_period,
                )
            )
            error_budget_breached = spent_budget >= confidence_knob.error_budget_tolerance

        return Facts(
            grant_present=grant_present,
            grant_level=grant_level,
            error_budget_breached=error_budget_breached,
            cap_budget_breached=(spent >= counter_cap) or tree_breached,
            escalation_budget_available=True,
            human_reachable=True,
            transform_op=None,
            quarantined=quarantined,
            quarantine_reason=quarantine_reason,
            read_source_trusted=read_source_trusted,
            query_bytes_exceeded=query_bytes_exceeded,
            query_egress_breached=query_egress_breached,
            confidence_below_bar=confidence_below_bar,
        )

    return pip


_VALID_ENVELOPE_LOAD_MODES = ("manifest", "store")


def _resolve_envelope_load_mode() -> str:
    """Resolve where the in-force risk envelope comes from (sa#136 Slice B).

    ``BROKER_ENVELOPE_LOAD`` is the canonical control, default ``manifest``:
      - ``manifest`` — derive the in-force envelope from ``manifest.envelope``: the
        envelope authored into the deployment manifest is the one in force. Today's
        behavior, unchanged.
      - ``store`` — load the in-force envelope from the DynamoDB envelope store at
        startup (co-located in the grants table; seeded out-of-band FIRST by
        ``broker.prototype.seed_envelope``). A missing envelope fails fast at boot —
        the exact fail-closed posture ``BROKER_GRANT_LOAD="read"`` takes on a missing
        grant. The broker never silently defaults an envelope.
    """
    mode = os.environ.get("BROKER_ENVELOPE_LOAD", "manifest").strip().lower()
    if mode not in _VALID_ENVELOPE_LOAD_MODES:
        raise ValueError(
            f"BROKER_ENVELOPE_LOAD={mode!r} is invalid; expected one of "
            f"{_VALID_ENVELOPE_LOAD_MODES}"
        )
    return mode


def _resolve_grants_table_name() -> str:
    """The grants table name: ``BROKER_GRANTS_TABLE`` else the single-table
    ``BROKER_TABLE`` (defaulting to the local single-table layout).

    Shared by the store switch and the envelope-store resolution — the envelope is
    co-located in the grants table (broker/envelope/store.py), so both MUST resolve
    the SAME physical table name.
    """
    return os.environ.get("BROKER_GRANTS_TABLE") or os.environ.get(
        "BROKER_TABLE", "safe-agents-broker-local"
    )


_VALID_GRANT_LOAD_MODES = ("seed", "read", "skip")


def _resolve_grant_load_mode() -> str:
    """Resolve the grant-load mode from env (sa#36 Phase C1).

    ``BROKER_GRANT_LOAD`` is the canonical control, default ``seed``:
      - ``seed`` — the LOCAL/Mac arm: write each grant then read it back (one process
        owns both write and read, so the stored HMAC matches).
      - ``read`` — the AWS ``brokerRole`` arm: READ-ONLY. brokerRole cannot write grants
        (maker-checker: grant writes are promotionRole's job), so the grants must have
        been seeded out-of-band first (``broker.prototype.seed_grants``).
      - ``skip`` — load nothing, empty registry (construction smoke only).

    ``BROKER_SKIP_GRANT_LOAD`` is kept as a back-compat alias for ``skip`` so anything
    already relying on it keeps working; when set it wins.
    """
    skip_alias = os.environ.get("BROKER_SKIP_GRANT_LOAD")
    if skip_alias not in (None, "", "0"):
        return "skip"
    mode = os.environ.get("BROKER_GRANT_LOAD", "seed").strip().lower()
    if mode not in _VALID_GRANT_LOAD_MODES:
        raise ValueError(
            f"BROKER_GRANT_LOAD={mode!r} is invalid; expected one of {_VALID_GRANT_LOAD_MODES}"
        )
    return mode


def _load_grants(
    grant_store,
    mode: str,
    principal: Principal,
    grant_classes: list[str],
    in_force_hash: str,
) -> list[Grant]:
    """Build the served-registry grant list per the resolved grant-load ``mode``.

    The served registry is built from the returned list; the PIP re-reads each grant
    per call. The three modes (see ``_resolve_grant_load_mode``):

      - ``seed`` — ``put_grant`` then ``get_grant`` each class. Writing then reading via
        the same store guarantees the stored HMAC hash matches.
      - ``read`` — ``get_grant`` ONLY (no write); brokerRole is read-only on the grants
        table. A class whose grant is absent or quarantined is omitted with a loud
        WARNING — fail-closed, the PIP denies what is not loaded.
      - ``skip`` — load nothing (empty registry).
    """
    if mode == "skip":
        return []
    grants: list[Grant] = []
    for action_class in grant_classes:
        if mode == "seed":
            grant_store.put_grant(_make_grant(action_class, principal, in_force_hash), None)
        result = grant_store.get_grant(principal, action_class)
        if result.grant is not None and not result.quarantined:
            grants.append(result.grant)
        elif mode == "read":
            reason = "quarantined (HMAC mismatch)" if result.quarantined else "absent"
            logger.error(
                "read mode: grant for action_class=%s %s; omitting from served "
                "registry (fail-closed: the PIP denies what is not loaded). Was "
                "broker.prototype.seed_grants run against this table with write "
                "creds and the matching HMAC key?",
                action_class, reason,
            )
    return grants


def build_runtime(
    manifest: AgentManifest,
    *,
    envelope_store: "EnvelopeStore | None" = None,
    on_demotion_signal: "Callable[[DemotionSignal], None] | None" = None,
    sub_grant_store: "SubGrantStore | None" = None,
) -> tuple[BrokerRuntime, InMemorySink | FileAuditSink | S3ObjectLockSink]:
    """Compose a BrokerRuntime from a manifest + three INDEPENDENT, env-selected backends.

    Every agent-specific value — principal, granted action classes, connectors, the
    per-run counter cap — comes from ``manifest`` (an AgentManifest), never from a
    module constant (de-baking P2, sa#113). The SAME image runs unchanged on the
    local/Mac arm or on AWS Fargate; only the environment differs (sa#36). The three
    backend switches are orthogonal:

      1. Stores  — BROKER_STORE=memory (default) | dynamo. In dynamo mode each store
         resolves its own table from BROKER_{GRANTS,COUNTERS,INTENTS}_TABLE, falling
         back to the single BROKER_TABLE (the local arm's single-table layout). AWS
         passes the three separate table names; both reuse the same DynamoStore code.
      2. Audit   — BROKER_AUDIT_BUCKET -> S3 Object Lock; else BROKER_AUDIT_PATH ->
         local hash-chained file; else in-memory.
      3. Secrets — BROKER_SECRETS selects from a CLOSED catalog (#248,
         boot_config.resolve_secrets_arm): secretsmanager -> AWS Secrets Manager;
         dir -> one file per secret leaf under BROKER_SECRETS_DIR (the container
         shape); file -> 0600 JSON blob at BROKER_SECRETS_FILE; fake -> in-memory
         fakes. Unset keeps the pre-#248 implicit resolution (the path variable
         selects the arm); an UNRECOGNIZED value refuses rather than falling
         through to fakes.

    Orthogonal to those three backends, ``BROKER_ENVELOPE_LOAD`` (manifest|store,
    default manifest) selects the SOURCE of the in-force risk envelope: ``manifest``
    reads ``manifest.envelope``; ``store`` loads it from the DynamoDB envelope store
    (co-located in the grants table, seeded out-of-band first) and fails fast if none
    is seeded. ``envelope_store`` is an optional injected store for tests; production
    leaves it None and builds a DynamoDBEnvelopeStore from the resolved grants table.

    ``sub_grant_store`` is the broker-owned store of derived authority (#11).
    Passing one turns on the delegation-tree budget pool: every call then also
    draws a counter shared by the whole tree rooted at its grant, which is the
    only bound that constrains SIBLINGS. Left None (the default) no pool is
    drawn and behaviour is unchanged, so this is opt-in per deployment. Under the
    per-zone runtime model each zone builds its own runtime from its own
    image-baked manifest and they SHARE this store, which is how a parent and its
    children reach the same pool while remaining separate principals.

    See safe_agents/arms/fargate/BROKER_ENV.md for the full AWS-mode env contract.
    """
    # --- Manifest-derived, agent-specific config (no baked constants) -------
    principal = _require_principal(manifest)
    granted_classes = _resolve_granted_classes(manifest)

    # #171 — the per-agent ToolOp table travels IN the manifest, not a base global.
    # The broker resolves every (tool, op) against this table; the base composition
    # path names no op. A grant for a class with no matching tool_ops entry is inert
    # (no table entry ⇒ the PEP denies the call), so the manifest must classify every
    # op it grants.
    optable = ToolOpTable.from_manifest(manifest)

    # --- The in-force risk envelope: manifest-authored (default) or store-loaded ---
    # BROKER_ENVELOPE_LOAD=store loads the envelope the broker will ACTUALLY enforce
    # from the DynamoDB envelope store (co-located in the grants table; seeded
    # out-of-band FIRST by broker.prototype.seed_envelope). A missing envelope raises
    # EnvelopeNotFoundError and fails the boot — the same fail-closed posture
    # BROKER_GRANT_LOAD="read" takes on a missing grant. Everything envelope-derived
    # below (hash, cap, the sa#137 knobs) is taken from this ONE envelope, so there is
    # never a mixed derivation. In the default 'manifest' mode this is manifest.envelope
    # exactly as before. principal / grant_classes / connectors stay manifest-sourced.
    envelope_load_mode = _resolve_envelope_load_mode()
    if envelope_load_mode == "store":
        from safe_agents.broker.envelope.read import load_inforce_envelope  # noqa: PLC0415

        active_store = envelope_store
        envelope_source_label: str
        if active_store is not None:
            envelope_source_label = "injected"
        elif resolve_store_arm() == "sqlite":
            # The envelope co-locates with grants on every backend: same db
            # file here, same table on Dynamo.
            from safe_agents.broker.envelope.sqlite_store import (  # noqa: PLC0415
                SqliteEnvelopeStore,
            )

            envelope_source_label = f"db={resolve_sqlite_db_path()}"
            active_store = SqliteEnvelopeStore(resolve_sqlite_db_path())
        else:
            from safe_agents.broker.envelope.store import (  # noqa: PLC0415
                DynamoDBEnvelopeStore,
            )

            envelope_source_label = f"table={_resolve_grants_table_name()}"
            active_store = DynamoDBEnvelopeStore(table_name=_resolve_grants_table_name())
        envelope = load_inforce_envelope(active_store, principal)
        print(f"[broker] envelope load mode: store ({envelope_source_label})")
    else:
        envelope = manifest.envelope
        print("[broker] envelope load mode: manifest")

    # The real content-hash of the risk envelope in force (sa#122). Computed
    # DYNAMICALLY from the in-force envelope — every seeded grant is issued
    # under it, the PIP verifies grants against it, and it is stamped into every
    # AuditRecord. No literal placeholder anywhere.
    in_force_hash = compute_envelope_hash(envelope)

    # Per-op counter cap from the envelope. #205 (F4, boot_config.resolve_counter_cap):
    # the generic fallback is honored only when NO granted class is write-effect —
    # an envelope governing granted writes must NAME its daily cap. The refusal
    # message is envelope-source-aware: a store-loaded envelope is fixed by
    # re-seeding (seed_envelope), not by editing the manifest.
    counter_cap = resolve_counter_cap(
        envelope, granted_classes, optable, principal, envelope_load_mode
    )

    # sa#137 — read-gating knobs from the SAME envelope. trusted_read_sources drives
    # both the PIP's rung-gate fact and the PEP's taint-skip (one list, both halves);
    # max_query_bytes / query_egress_budget bound the query-string exfil channel.
    trusted_read_sources = envelope.trusted_read_sources
    max_query_bytes = envelope.max_query_bytes
    query_egress_budget = envelope.query_egress_budget

    # sa#160 — approval-queue de-amplification knob from the SAME envelope. None
    # (unset) = OFF: the PEP hold path is byte-identical to before.
    approval_queue = envelope.approval_queue

    # #184 — calibrated-uncertainty knob from the SAME in-force envelope. None (unset)
    # = OFF: no below-bar gate, no error-budget metering. Threaded to both the PIP (the
    # below-bar + breach facts it derives) and the runtime (the single metered write).
    confidence_knob = envelope.confidence

    # Connectors resolve by NAME against the manifest's connector_providers first,
    # then the base registry (connector_registry.py) — the one sanctioned injection
    # seam (sa#141). An unknown name fails closed (UnknownConnectorError); a broken
    # provider fails closed too (ConnectorProviderError). Provider paths come ONLY
    # from the image-baked manifest object — the envelope store loads an Envelope,
    # which has no provider/import-path field, so store contents can never reach
    # this argument.
    #
    # #221: names whose mcp_servers declaration carries spawn config are NATIVE —
    # excluded here and constructed by build_mcp_connectors below (after the
    # secrets provider exists, since spawn-time credential resolution needs it).
    # The manifest validator has already refused a native name that also has a
    # connector_providers entry, so the split is unambiguous.
    native_mcp = native_mcp_server_ids(manifest)
    connectors = resolve_connectors(
        [name for name in manifest.connectors if name not in native_mcp],
        providers=manifest.connector_providers,
    )

    # Grant-store HMAC key (#205 F2, boot_config.resolve_hmac_key). The fixed dev
    # key is honored ONLY on the local/memory arm; the real-store arm must NAME the
    # key the ceremony writes with (the write side, grants/_commands_common.py,
    # already refuses; this restores read/write symmetry).
    hmac_key = resolve_hmac_key()

    # --- Switch 1: stores ---------------------------------------------------
    # memory: in-process fakes (CI + smoke). dynamo: the REAL stores — DynamoDB Local
    # on the Mac arm, real DynamoDB on AWS (same code; boto3 reads the endpoint from
    # AWS_ENDPOINT_URL_DYNAMODB, unset on AWS = real service). Stores are lazy: no AWS
    # call happens at construction (only _load_grants below touches the grant table).
    enforcement_store: object
    intent_store: object
    grant_store: object
    # Resolved BEFORE any store is constructed so the #205 F5 refusal
    # (seed-at-boot on the durable local arm) fires before the sqlite boot
    # sweep can even bootstrap the database schema — fail toward touching
    # nothing, never toward a half-initialized durable trust store.
    grant_load_mode = _resolve_grant_load_mode()
    require_sanctioned_grant_load(grant_load_mode)
    if resolve_store_arm() == "sqlite":
        # The durable LOCAL arm (product-wrapper Phase 1): one named broker.db behind the
        # same three store Protocols, keyed exactly like the Dynamo items. The
        # db path comes from boot_config's ONE resolution seam (named or
        # refuse) — no module here reads BROKER_SQLITE_PATH itself.
        from safe_agents.broker.approval.sqlite_store import (  # noqa: PLC0415
            SqliteIntentStore,
        )
        from safe_agents.broker.enforcement.sqlite_store import (  # noqa: PLC0415
            SqliteEnforcementStore,
        )
        from safe_agents.broker.grants.sqlite_store import (  # noqa: PLC0415
            SqliteGrantStore,
        )

        db_path = resolve_sqlite_db_path()
        enforcement_store = SqliteEnforcementStore(db_path)
        # Same key surface as the grant store (#349): the intent rows carry an
        # HMAC over their stored frozen-call bytes, verified before any release.
        intent_store = SqliteIntentStore(db_path, hmac_key=hmac_key)
        # The grant space is the checker's (#203). This process reads it and —
        # under BROKER_GRANT_LOAD=read, the deployed mode — never writes it, so
        # it takes the same read-only mount the maker does. `seed` mode still
        # writes, and would refuse loudly on a read-only mount rather than
        # silently seeding nothing.
        grant_store = SqliteGrantStore(hmac_key=hmac_key, **sqlite_grants_open_options())
        # Bounded-lag privacy sweep, NOT correctness (sa#213): DynamoDB gets
        # expired-item deletion from its TTL daemon; sqlite has no daemon, so
        # the boot sweep is where an expired intent's payload stops lingering
        # at rest. approve() still checks each intent's expiry predicate at
        # use, swept or not — a failed sweep can never widen authority, so it
        # logs and continues rather than failing the boot.
        try:
            swept = intent_store.sweep_expired()
            if swept:
                print(f"[broker] swept {swept} expired intent(s) from {db_path}")
        except Exception:  # noqa: BLE001 — hygiene must never block the boot
            logger.warning(
                "expired-intent sweep failed on %s; continuing (expiry is a "
                "predicate at use, so unswept rows cannot widen authority)",
                db_path,
                exc_info=True,
            )
        store_label = f"sqlite ({db_path})"
    elif is_dynamo_arm():
        from safe_agents.broker.approval import DynamoIntentStore  # noqa: PLC0415
        from safe_agents.broker.enforcement import DynamoStore  # noqa: PLC0415

        # One BROKER_TABLE (local single-table) OR three separate AWS tables.
        base_table = os.environ.get("BROKER_TABLE", "safe-agents-broker-local")
        grants_table = _resolve_grants_table_name()  # same name the envelope store uses
        counters_table = os.environ.get("BROKER_COUNTERS_TABLE") or base_table
        intents_table = os.environ.get("BROKER_INTENTS_TABLE") or base_table
        enforcement_store = DynamoStore(counters_table)  # counters + idem + ledger
        intent_store = DynamoIntentStore(intents_table, hmac_key=hmac_key)
        grant_store = DynamoDBGrantStore(hmac_key=hmac_key, table_name=grants_table)
        endpoint = os.environ.get("AWS_ENDPOINT_URL_DYNAMODB", "default")
        store_label = (
            f"DynamoDB (grants={grants_table}, counters={counters_table}, "
            f"intents={intents_table}) via {endpoint}"
        )
    else:
        enforcement_store = InMemoryStore()
        intent_store = InMemoryIntentStore(hmac_key=hmac_key)
        grant_store = InMemoryGrantStore(hmac_key=hmac_key)
        store_label = "in-memory"

    # --- Switch 2: audit sink (independent of BROKER_STORE) -----------------
    sink: InMemorySink | FileAuditSink | S3ObjectLockSink
    audit_bucket = os.environ.get("BROKER_AUDIT_BUCKET")
    audit_path = os.environ.get("BROKER_AUDIT_PATH")
    if audit_bucket:
        audit_prefix = os.environ.get("BROKER_AUDIT_PREFIX", "audit/")
        # Resume the S3 chain on startup (sa#104): read the MAX existing
        # audit/*.json key + its record hash so a restarted long-lived broker
        # continues the SAME contiguous, verify_chain-valid tape instead of
        # resetting seq to 0 (which would collide with existing objects under
        # Object Lock and fork the hash chain). The S3 analog of
        # FileAuditSink.resuming — see _s3_sink.py. The listing/reading identity
        # holds s3:ListBucket + s3:GetObject; the writing identity stays
        # s3:PutObject-only.
        sink = S3ObjectLockSink.resuming(audit_bucket, key_prefix=audit_prefix)
        audit_label = f"s3 ({audit_bucket}/{audit_prefix})"
    elif audit_path:
        sink = FileAuditSink.resuming(audit_path)
        audit_label = f"file ({audit_path})"
    else:
        sink = InMemorySink()
        audit_label = "memory"

    # --- Switch 3: secrets provider (independent) --------------------------
    # Non-memory modes wrap the real provider in _OverlaySecrets so the stub
    # connectors fall back to dev values; github resolves through the primary.
    secrets: SecretsProvider
    stub_fallback = FakeSecretsProvider(
        {"calendar": "cred-calendar", "payments": "cred-payments", "crm": "cred-crm"}
    )
    secret_prefix = os.environ.get("BROKER_SECRET_PREFIX", "")
    secrets_arm = resolve_secrets_arm()
    if secrets_arm == "secretsmanager":
        # No region argument: boto3 resolves it (AWS_REGION / AWS_DEFAULT_REGION
        # / config / task metadata) and fails loudly if nothing does. A literal
        # fallback here would silently target the wrong region off us-east-1.
        boto_secrets: SecretsProvider = LazyBotoSecretsProvider()
        if secret_prefix:
            boto_secrets = _PrefixedSecrets(boto_secrets, secret_prefix)
        secrets = _OverlaySecrets(boto_secrets, stub_fallback)
        # The region is boto3's to resolve, so report what was CONFIGURED rather
        # than inventing a value: an env-named region is a fact, its absence means
        # boto3 will resolve or refuse at first use.
        configured_region = (
            os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "resolved by boto3"
        )
        secrets_label = (
            f"secretsmanager (region={configured_region}, prefix={secret_prefix or '<none>'})"
        )
    elif secrets_arm == "dir":
        # #248 — one file per secret leaf, the shape every container platform
        # projects. BROKER_SECRET_PREFIX is deliberately NOT composed here: the
        # mount root plays the prefix's role, and a prefixed name would no longer
        # be a leaf (DirSecretsProvider refuses one).
        secrets_dir = resolve_secrets_dir()
        secrets = _OverlaySecrets(DirSecretsProvider(str(secrets_dir)), stub_fallback)
        secrets_label = f"dir ({secrets_dir})"
    elif secrets_arm == "file":
        secrets_file = resolve_secrets_file()
        secrets = _OverlaySecrets(LocalFileSecretsProvider(secrets_file), stub_fallback)
        secrets_label = f"file ({secrets_file})"
    else:
        secrets = FakeSecretsProvider(
            {
                "calendar": "cred-calendar",
                "payments": "cred-payments",
                "crm": "cred-crm",
                "github": "cred-github-fake",
                # Fake-but-well-formed: SearchConnector validates the credential
                # SHAPE before any HTTP, so this must be valid JSON — a call on
                # this arm then fails at the real API as a clean, audited deny
                # (like github's fake token), not an uncaught KeyError.
                "search": '{"provider": "tavily", "api_key": "cred-search-fake"}',
            }
        )
        secrets_label = "fake"

    print(f"[broker] store backend: {store_label}")
    print(f"[broker] audit sink: {audit_label}; secrets: {secrets_label}")
    # #205 (F3, boot_config.require_named_real_backends): a REAL (dynamo) store
    # paired with a non-durable audit sink or fake credentials is never a
    # sanctioned combination. Was a warn-and-continue; now a refusal at boot.
    require_named_real_backends(audit_label, secrets_label)

    # Grant loading is controlled by BROKER_GRANT_LOAD (seed|read|skip), default seed:
    #   - seed: the LOCAL arm writes+reads each grant. With dynamo stores this is the ONE
    #     place build_runtime touches AWS for a write (the grant table must exist).
    #   - read: the AWS brokerRole arm READS pre-seeded grants only — brokerRole is
    #     read-only on the grants table, so the grants must already be present (seeded
    #     out-of-band by broker.prototype.seed_grants). Absent/quarantined classes are
    #     omitted, fail-closed.
    #   - skip: load nothing (empty registry), construction smoke only.
    # BROKER_SKIP_GRANT_LOAD=1 stays a back-compat alias for skip.
    print(f"[broker] grant load mode: {grant_load_mode}")
    if grant_load_mode == "skip":
        print("[broker] WARNING: grant load mode 'skip' — grants NOT seeded/loaded; "
              "served registry will be EMPTY (construction smoke only)", file=sys.stderr)
    grants: list[Grant] = _load_grants(
        grant_store, grant_load_mode, principal, granted_classes, in_force_hash
    )

    # Secret-leaf mapping (sa#141): manifest connector_secrets overrides the default
    # leaf == tool-name mapping (empty dict preserves the old behavior). The value is a
    # leaf; when `secrets` is a _PrefixedSecrets it resolves under <prefix>/connectors/
    # (sa#164) — so the override is a bare leaf, not a pre-prefixed secret id.
    connector_secret_names = dict(manifest.connector_secrets)
    # Credential-resolution strategies (#173): compile the manifest connector_auth
    # block into a per-tool CredentialProvider. An empty block yields an empty map,
    # so every tool falls back to StaticSecret in the Doer — byte-for-byte the old
    # behavior. A malformed/unimplemented strategy fails loudly here, at broker build.
    credential_strategies = build_credential_strategies(manifest.connector_auth)
    # #221 — native MCP connectors, constructed HERE (not at the resolve_connectors
    # site) because spawn-time credential resolution needs the secrets provider and
    # the compiled strategies above. Construction is AWS-free and lazy; the child
    # spawns (and its credential resolves) at first dispatch on the connector's
    # own loop. A spawnable server with no named registry table refuses loudly.
    if native_mcp:
        connectors.update(
            build_mcp_connectors(
                manifest,
                secrets=secrets,
                credential_strategies=credential_strategies,
                secret_name_for=lambda tool: connector_secret_names.get(tool, tool),
            )
        )
    doer = Doer(
        connectors=connectors,
        secrets=secrets,
        secret_name_for=lambda tool: connector_secret_names.get(tool, tool),
        credential_strategies=credential_strategies,
    )

    runtime = BrokerRuntime(
        principal=principal,
        grants=grants,
        optable=optable,
        doer=doer,
        pip=_make_pip(
            grant_store,
            enforcement_store,
            counter_cap,
            in_force_hash,
            trusted_read_sources=trusted_read_sources,
            max_query_bytes=max_query_bytes,
            query_egress_budget=query_egress_budget,
            confidence_knob=confidence_knob,
            counter_period=manifest.counter_period,
            sub_grant_store=sub_grant_store,
        ),
        enforcement_store=enforcement_store,  # type: ignore[arg-type]
        intent_store=intent_store,  # type: ignore[arg-type]
        audit_sink=sink,
        trust_map=build_trust_map(trusted_prefixes=["internal:"]),
        envelope_hash=in_force_hash,
        counter_cap=counter_cap,
        trusted_read_sources=trusted_read_sources,
        approval_queue=approval_queue,
        confidence_knob=confidence_knob,
        on_demotion_signal=on_demotion_signal,
        # #212 — the manifest-named counter period: image-baked, authority-shaping,
        # threaded to BOTH the PEP (writer) and the PIP (reader) from this ONE field
        # so the two can never bucket at different periods.
        counter_period=manifest.counter_period,
        # #11 -- the delegation-tree pool store, threaded to BOTH the PEP (which
        # draws) and the PIP (which reads) from this ONE argument, for the same
        # reason counter_period is: two sources would let the fact and the draw
        # disagree about which pool bounds the call. None disables the pool, so a
        # deployment that does not delegate is unchanged.
        sub_grant_store=sub_grant_store,
    )
    return runtime, sink


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

# The default manifest is a checked-in example artifact (behavior-preserving; see
# example_manifest.yaml), NOT a real consumer's own manifest. Point elsewhere with
# BROKER_MANIFEST=/path/to/manifest.yaml. #205: the example-manifest fallback is
# honored ONLY on the local/memory arm; the real-store arm (BROKER_STORE=dynamo)
# refuses a defaulted manifest — an implicit fallback manifest is a wrong-authority
# mint (#197/#199; docs/config-provenance.md).
#
# LOAD-ONCE: unlike the (pre-#205) import-time load, the manifest is resolved
# LAZILY on first use — so importing this module never touches the manifest file
# or refuses — but the first successful resolution is CACHED as the real module
# attribute ``_MANIFEST``. One process, one manifest object: every consumer (the
# server boot, the grants ceremony's grant classes AND its envelope hash) sees the
# SAME bytes, never two loads of a file that changed in between (the #199 shape).
# Tests monkeypatch.setattr the materialized attribute exactly as before.


def resolve_manifest() -> AgentManifest:
    """The one manifest this process builds and ceremonies from, loaded ONCE.

    First call resolves BROKER_MANIFEST (refusing a dynamo-arm default with
    :class:`BrokerConfigError` — fail toward loading nothing) and caches the
    result as the module attribute ``_MANIFEST``; later calls — and attribute
    reads via ``broker_server._MANIFEST`` — return that same object. A refusal
    caches nothing, so fixing the env and retrying works."""
    manifest = globals().get("_MANIFEST")
    if manifest is None:
        manifest = load_named_manifest()
        globals()["_MANIFEST"] = manifest
    return manifest


def __getattr__(name: str):  # PEP 562 — lazy, load-once module attribute
    """``broker_server._MANIFEST`` materialized on first access via
    ``resolve_manifest`` (#205): loading at import time both forced a load
    store-mode ceremonies never need and froze the env read; loading per-access
    broke the one-consistent-object invariant. On the dynamo arm with
    BROKER_MANIFEST unset, access RAISES BrokerConfigError (never a proxy)."""
    if name == "_MANIFEST":
        return resolve_manifest()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# The server's runtime is built LAZILY, not at import time: other bindings (the
# channels drain worker, the seed scripts) import this module for build_runtime /
# _MANIFEST and must not construct the example-manifest runtime — under store/read
# backends that would touch AWS as a pure import side effect. main() forces the
# build before serving, so the server path still fails loudly at startup.
_RUNTIME = None
_SINK = None


def _server_runtime():
    global _RUNTIME, _SINK
    if _RUNTIME is None:
        # resolve_manifest honors a monkeypatched/materialized _MANIFEST; a fresh
        # boot resolves the operator-named manifest — refusing a dynamo-arm
        # default (BrokerConfigError) before anything is built.
        _RUNTIME, _SINK = build_runtime(resolve_manifest())
    return _RUNTIME, _SINK


def _wire_result(result):
    """Marshal a connector result for the JSON wire.

    Delegates to the ONE marshal (``runtime.connector``): this boundary found
    the need first (#221's floor drill), enforce()'s audit path found it second
    (#247's local drill), and a third copy would have been the point at which
    the two could drift.
    """
    return marshal_connector_result(result)


class _Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        runtime, sink = _server_runtime()
        if self.path == "/registry":
            self._json(200, [{"tool": t.tool, "op": t.op} for t in runtime.served_registry()])
        elif self.path == "/audit":
            # PROTOTYPE-ONLY: production keeps the audit tape broker-private.
            # The S3 (AWS-mode) sink is write-only here — it has no records() reader
            # (reading the WORM tape is a separate-identity job), so report that.
            if not hasattr(sink, "records"):
                self._json(200, {"note": "audit sink is write-only (S3); no debug read view"})
            else:
                self._json(200, [
                    {"seq": r.seq, "decision": r.decision, "outcome": r.outcome}
                    for r in sink.records()
                ])
        else:
            self._json(404, {"error": f"no such path: {self.path}"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/call":
            self._json(404, {"error": f"no such path: {self.path}"})
            return
        length = int(self.headers.get("content-length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            self._json(400, {"error": f"bad json: {exc}"})
            return
        if "tool" not in payload or "op" not in payload:
            self._json(400, {"error": "request must include 'tool' and 'op'"})
            return
        request = AgentRequest(
            tool=payload["tool"],
            op=payload["op"],
            args=payload.get("args", {}),
            # #184 — the raw confidence artifact (a dict), validated by handle_request;
            # the broker never trusts its shape. Absent key ⇒ None ⇒ no artifact.
            confidence=payload.get("confidence"),
            idempotency_key=payload.get("idempotency_key"),
        )
        # No turn_context is passed: the runtime threads its OWN broker-held turn
        # across every /call (sa#136), so taint from an external read in one request
        # rides into a later request's write. The agent cannot supply a turn_context
        # over HTTP, and its idempotency_key no longer sets the turn id, so it cannot
        # launder taint by declaring a fresh turn.
        #
        # handle_request already turns a connector failure into a clean deny + audits it.
        # This guard is the outer backstop: any UNEXPECTED error (a bug in marshaling, a
        # store outage) returns a generic 500 with no traceback or secret in the body —
        # the detail stays server-side in the log, never on the wire to the agent.
        try:
            runtime, _ = _server_runtime()
            resp = runtime.handle_request(request)
        except Exception as exc:  # noqa: BLE001 — never leak internals to the client
            print(f"[broker] ERROR handling /call: {type(exc).__name__}: {exc}", file=sys.stderr)
            self._json(500, {"error": "internal broker error"})
            return
        # Marshal BrokerResponse -> json. Note what is ABSENT: no credential, no
        # connector handle, no audit sink — the agent-facing surface is confined.
        self._json(200, {
            "decision_kind": resp.decision_kind,
            "result": _wire_result(resp.result),
            "idempotent": resp.idempotent,
            "intent_id": resp.intent_id,
            "reason": resp.reason,
        })

    def log_message(self, fmt, *args) -> None:  # quieter logs
        print(f"[broker] {self.address_string()} {fmt % args}")


def main() -> None:
    runtime, _ = _server_runtime()  # build (and fail) at startup, not first request
    host = os.environ.get("BROKER_HOST", "127.0.0.1")
    port = int(os.environ.get("BROKER_PORT", "8080"))
    # SINGLE-THREADED, and this is a correctness requirement rather than a
    # simplification. It was `ThreadingHTTPServer` until #250 Phase 4 put a real
    # second workload in front of it, which is when the mismatch finally bit.
    #
    # The runtime it serves is documented as NOT thread-safe by design -- see
    # `runtime/pep.py::_session_turn`: "one runtime serves one principal ... assumes
    # calls are serialized per principal", and two concurrent /call requests can mint
    # two TurnContexts and drop one's taint, or snapshot taint before a sibling's read
    # self-ingests it. Both are FAIL-OPEN. A threading server was therefore always
    # violating the contract of the thing underneath it; the prototype's single agent
    # just happened to issue calls sequentially, so nothing ever collected on it.
    #
    # What finally collected was the sqlite arm: its connections are single-thread
    # (substrate: "Connections are single-thread ... each store instance holds its
    # own"), so a per-request thread reaching the store raises ProgrammingError and
    # /call returns 500. That crash is the LOUD version of the same bug, and it is
    # the reason to fix this here rather than in the store -- making the substrate
    # thread-safe would have silenced the 500 and left the taint race running, which
    # is trading a visible failure for an invisible one in the fail-open direction.
    #
    # So do not restore threading to regain concurrency. Concurrent /call needs
    # per-session turn isolation in the PEP first (tracked in docs/turn-identity.md);
    # until that exists, serialized requests are what the runtime actually promises.
    srv = HTTPServer((host, port), _Handler)
    print(f"[broker] tool-call API on http://{host}:{port}  (registry: {len(runtime.served_registry())} ops)")
    print("[broker] try:  python3 -m safe_agents.broker.prototype.fake_agent")

    # Graceful SIGTERM (the Fargate stop-task path, MCP-HOST.md M20): stop
    # accepting requests, then reap connector-held children BEFORE the process
    # exits — inside the task's stop grace window, never abandoned to the
    # container teardown. shutdown() must run off the serve_forever thread.
    def _on_sigterm(_signum, _frame) -> None:
        print("[broker] SIGTERM: draining, then closing connectors", flush=True)
        threading.Thread(target=srv.shutdown, name="broker-shutdown", daemon=True).start()

    signal.signal(signal.SIGTERM, _on_sigterm)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[broker] bye")
    finally:
        runtime.close()
        print("[broker] connectors closed; children reaped before exit", flush=True)


if __name__ == "__main__":
    main()
