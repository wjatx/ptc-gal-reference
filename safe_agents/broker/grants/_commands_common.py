"""CLI plumbing for the grant-ceremony command surface (grants/commands.py, #123).

Argparse wiring plus the store / manifest / envelope-hash resolution main()
binds — split out so commands.py stays the readable ceremony surface. Nothing
here is imported by the command functions themselves (they are store-injected
and AWS-free); only commands.main() consumes this module.
"""

from __future__ import annotations

import argparse

from safe_agents.broker.grants.runner import (
    RunnerConfigError,
    _ceremony_hmac_key,
    _resolve_table_name,
)
from safe_agents.broker.prototype.boot_config import (
    grant_load_suppressed,
    resolve_sqlite_db_path,
    resolve_store_arm,
)
from safe_agents.broker.schemas.common import AutonomyLevel, DemotionTrigger, Principal


def _build_proposal_store(table_name: str | None):
    """Proposal store on the selected arm, under the SAME HMAC key seam as
    runner._build_stores (#247)."""
    hmac_key = _ceremony_hmac_key()
    if resolve_store_arm() == "sqlite":
        from safe_agents.broker.grants.sqlite_ceremony_stores import (  # noqa: PLC0415
            SqliteProposalStore,
        )

        return SqliteProposalStore(hmac_key, resolve_sqlite_db_path())

    from safe_agents.broker.grants.proposals import DynamoDBProposalStore  # noqa: PLC0415

    return DynamoDBProposalStore(hmac_key=hmac_key, table_name=_resolve_table_name(table_name))


def _build_ack_store(table_name: str | None):
    """Acknowledgment store (#196) on the selected arm, co-located with the grants.

    No HMAC seam on either arm: an acknowledgment's integrity is its REQUIRED
    issuer DSSE signature — the audit applies nothing that does not verify.
    """
    if resolve_store_arm() == "sqlite":
        from safe_agents.broker.grants.sqlite_ceremony_stores import (  # noqa: PLC0415
            SqliteAcknowledgmentStore,
        )

        return SqliteAcknowledgmentStore(resolve_sqlite_db_path())

    from safe_agents.broker.grants.acknowledgments import (  # noqa: PLC0415
        DynamoDBAcknowledgmentStore,
    )

    return DynamoDBAcknowledgmentStore(table_name=_resolve_table_name(table_name))


def _resolve_envelope_hash(principal: Principal, table_name: str | None) -> str:
    """The in-force envelope hash, honoring BROKER_ENVELOPE_LOAD like seed_grants:
    'store' reads the seeded envelope for this principal (seed_envelope must have
    run first); the default 'manifest' hashes the manifest's envelope block —
    but ONLY when the manifest's principal IS ``principal`` (#199): stamping a
    ceremony under a different manifest's envelope mints a grant the broker
    quarantines on first exercise (sa#122), so a mismatch is refused, never
    guessed."""
    # Keep the broker_server import side-effect-free, exactly as seed_grants does.
    with grant_load_suppressed():
        from safe_agents.broker.envelope.read import (  # noqa: PLC0415
            EnvelopeNotFoundError,
            load_inforce_envelope,
        )
        from safe_agents.broker.envelope.sqlite_store import (  # noqa: PLC0415
            SqliteEnvelopeStore,
        )
        from safe_agents.broker.envelope.store import (  # noqa: PLC0415
            DynamoDBEnvelopeStore,
        )
        from safe_agents.broker.prototype.broker_server import (  # noqa: PLC0415
            _resolve_envelope_load_mode,
            resolve_manifest,
        )
        from safe_agents.broker.schemas import compute_envelope_hash  # noqa: PLC0415

    if _resolve_envelope_load_mode() == "store":
        # Store mode never consults the manifest — no manifest resolution (and no
        # dynamo-arm manifest refusal) happens on this path.
        store = (
            SqliteEnvelopeStore(resolve_sqlite_db_path())
            if resolve_store_arm() == "sqlite"
            else DynamoDBEnvelopeStore(table_name=_resolve_table_name(table_name))
        )
        try:
            return compute_envelope_hash(load_inforce_envelope(store, principal))
        except EnvelopeNotFoundError as exc:
            raise RunnerConfigError(
                "BROKER_ENVELOPE_LOAD=store but no envelope is seeded — run "
                f"seed_envelope against the table FIRST. ({exc})"
            ) from exc
    # Manifest mode: resolve the process-wide load-once manifest explicitly —
    # on the dynamo arm an unset BROKER_MANIFEST refuses here (BrokerConfigError,
    # surfaced cleanly by commands.main) before anything is stamped.
    _MANIFEST = resolve_manifest()
    if _MANIFEST.principal != principal:
        manifest_id = (
            _MANIFEST.principal.agentId if _MANIFEST.principal is not None else "<none>"
        )
        raise RunnerConfigError(
            f"refusing to stamp the envelope hash for principal {principal.agentId!r} "
            f"from the BROKER_MANIFEST manifest, whose principal is {manifest_id!r} — "
            "a hash from the wrong manifest mints a grant the broker quarantines on "
            "first exercise (sa#122; #199). Either export BROKER_MANIFEST=<the "
            f"manifest for {principal.agentId!r}> or set BROKER_ENVELOPE_LOAD=store "
            "to read the seeded in-force envelope."
        )
    return compute_envelope_hash(_MANIFEST.envelope)


def _manifest_context(table_name: str | None):
    """(principal, granted_classes, envelope_hash, grant_templates) from the SAME
    manifest the broker builds from (BROKER_MANIFEST) — seed and the broker must
    agree on exactly which classes exist and under which envelope hash."""
    with grant_load_suppressed():
        from safe_agents.broker.prototype.broker_server import (  # noqa: PLC0415
            _make_grant,
            _require_principal,
            _resolve_granted_classes,
            resolve_manifest,
        )

    # The load-once manifest: the SAME object _resolve_envelope_hash's manifest
    # mode hashes, so grant classes and envelope hash can never come from two
    # different reads of the manifest file (#199's dead-grant shape).
    _MANIFEST = resolve_manifest()
    principal = _require_principal(_MANIFEST)
    granted_classes = _resolve_granted_classes(_MANIFEST)
    envelope_hash = _resolve_envelope_hash(principal, table_name)
    templates = [_make_grant(c, principal, envelope_hash) for c in granted_classes]
    return principal, granted_classes, envelope_hash, templates


def _add_principal_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--principal-agent-id", required=True)
    parser.add_argument("--skill", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--tier", required=True, choices=["A", "B", "C", "D"])
    parser.add_argument("--action-class", required=True, help="'tool.op', e.g. email.send")


def _add_table_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--table-name",
        help="grants table (default: BROKER_GRANTS_TABLE / GRANTS_TABLE_NAME env)",
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.grants.commands",
        description=(
            "Grant-ceremony command surface (#123): the sanctioned mutation path for "
            "the grants store. Runs under the caller's ambient credentials "
            "(PromotionRole in production); identity is derived from STS, never asserted."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    seed = sub.add_parser(
        "seed",
        help="bootstrap: manifest-driven floor grants + bootstrap ledger records "
        "(never overwrites)",
    )
    _add_table_arg(seed)
    seed.add_argument(
        "--zone", help="signer zone for the issuer DSSE signature (default: ISSUER_SIGNING_ZONE)"
    )

    reseed = sub.add_parser(
        "re-seed",
        help="re-attest HMAC-clean grants under the NEW in-force envelope hash "
        "(same level; HMAC-tamper quarantine is refused)",
    )
    _add_table_arg(reseed)

    propose = sub.add_parser("propose", help="maker: build, predicate-check and store a proposal")
    _add_principal_args(propose)
    _add_table_arg(propose)
    propose.add_argument(
        "--target-level", required=True, choices=[level.value for level in AutonomyLevel]
    )
    propose.add_argument(
        "--evidence-bundle", required=True, help="ref to the covered-distribution evidence"
    )
    propose.add_argument("--owner-id", required=True, help="the named accountable human")
    propose.add_argument(
        "--label-latency", required=True, help="ISO-8601 duration until ground truth, e.g. PT1H"
    )
    propose.add_argument(
        "--demotion-trigger",
        action="append",
        choices=[t.value for t in DemotionTrigger],
        help="repeatable; demotion triggers carried onto the raised grant",
    )
    propose.add_argument(
        "--last-safe-level",
        choices=[AutonomyLevel.in_loop.value, AutonomyLevel.on_loop.value],
        default=AutonomyLevel.in_loop.value,
        help="demotion target carried onto the raised grant (default: the in-loop floor)",
    )
    propose.add_argument(
        "--artifact-json",
        required=True,
        metavar="PATH",
        help="path to the ConfidenceArtifact JSON (#184)",
    )
    propose.add_argument(
        "--covered",
        action="store_true",
        default=False,
        help="assert covered-distribution soundness (deliberate; default False)",
    )
    propose.add_argument(
        "--provenance-maturity",
        required=True,
        choices=["taint-bit", "lineage", "signed-lineage"],
    )
    propose.add_argument(
        "--period",
        choices=["utc-day", "utc-hour"],
        default="utc-day",
        help="counter period the evidence buckets at (#212). MUST match the "
        "manifest's counter_period — a mismatch reads disjoint keys and yields "
        "zero evidence (fail toward less authority). Default utc-day is "
        "byte-for-byte the pre-#212 coordinate.",
    )
    propose.add_argument(
        "--window-periods",
        "--window-days",
        dest="window_periods",
        type=int,
        default=1,
        help="period span the evidence counters sum over (default 1: the current "
        "period only). --window-days is the pre-#212 spelling of the same span. "
        "Out of range is refused by the counter-window read.",
    )
    propose.add_argument("--window-n", required=True, type=int)
    propose.add_argument("--min-observations", required=True, type=int)
    propose.add_argument("--threshold", required=True, type=float)
    propose.add_argument(
        "--budget-tolerance",
        type=float,
        help="when set, the error_budget counter is read into an ErrorBudget term",
    )
    propose.add_argument(
        "--ttl-hours", required=True, type=float, help="proposal expiry from now"
    )
    propose.add_argument(
        "--certified-until",
        default=None,
        metavar="ISO8601_UTC",
        help="optional certification term for the raised grant (GAL §6.7.6), an "
        "explicit UTC instant such as 2026-12-31T00:00:00+00:00. Once it passes the "
        "grant lapses to its last-safe level. Ratified by the checker as part of the "
        "proposal; nothing can extend it later except a new promotion. Default: no "
        "term.",
    )
    propose.add_argument("--effect", required=True, choices=["read", "write"])
    propose.add_argument("--external", action="store_true", default=False)
    propose.add_argument("--reversible", choices=["true", "false"], default=None)
    propose.add_argument(
        "--counters-table",
        help="counters table for the evidence counters (default: BROKER_COUNTERS_TABLE env)",
    )

    ratify = sub.add_parser("ratify", help="checker: run the maker-checker ceremony")
    _add_principal_args(ratify)
    _add_table_arg(ratify)
    ratify.add_argument("--proposal-id", required=True)
    ratify.add_argument(
        "--zone", help="signer zone for the issuer DSSE signature (default: ISSUER_SIGNING_ZONE)"
    )
    ratify.add_argument(
        "--allow-unsigned",
        action="store_true",
        default=False,
        help=(
            "explicitly permit storing an UNSIGNED PromotionRecord when no issuer "
            "signing key is configured (without this flag, unsigned ratify refuses)"
        ),
    )

    reject = sub.add_parser("reject", help="checker declines: burn the stored proposal")
    _add_principal_args(reject)
    _add_table_arg(reject)
    reject.add_argument("--proposal-id", required=True)

    acknowledge = sub.add_parser(
        "acknowledge",
        help="disposition a TRUE audit finding with a signed waiver record (#196); "
        "never edits the flagged item",
    )
    _add_table_arg(acknowledge)
    acknowledge.add_argument("--rule", required=True, help="the audit rule the finding fired")
    acknowledge.add_argument(
        "--coordinate", required=True, help="the finding's coordinate, exactly as reported"
    )
    acknowledge.add_argument(
        "--detail",
        required=True,
        help="the finding's detail string, EXACTLY as reported — the waiver binds to "
        "its digest, so a new finding at the same coordinate is never auto-waived",
    )
    acknowledge.add_argument(
        "--rationale", required=True, help="why this true finding is accepted as-is"
    )
    acknowledge.add_argument(
        "--zone", help="signer zone for the issuer DSSE signature (default: ISSUER_SIGNING_ZONE)"
    )

    tighten = sub.add_parser(
        "tighten",
        help="voluntary tightening: any level -> in-loop, always permitted; "
        "appends a tightening-typed PromotionRecord (issuer-signed when a "
        "signing key is configured)",
    )
    _add_principal_args(tighten)
    _add_table_arg(tighten)
    tighten.add_argument(
        "--zone", help="signer zone for the issuer DSSE signature (default: ISSUER_SIGNING_ZONE)"
    )
    tighten.add_argument(
        "--evidence",
        default="voluntary tightening",
        help="short free-text rationale for the ledger record "
        "(default: 'voluntary tightening')",
    )

    return parser.parse_args(argv)
