"""#252 — the grants audit reports the same thing on sqlite as on DynamoDB.

The auditor was split correctly from the start: ``dataset_from_items`` has
always been backend-agnostic and only the LOADER touched AWS. So after the
grants-sqlite slice (#247), every grants store family had a local arm except
the thing that audits them — the #267 second-arm shape, right at site #1 and
silently absent at site #2. ``load_dataset_sqlite`` closes it.

Two legs, because they fail differently:

**Same items, both loaders.** Identical raw items planted in each backend must
produce identical findings. This is the loader test proper: it isolates the
re-merge of ``pk``/``sk`` (the substrate keeps them in columns) from anything
the stores do, and it is what catches a loader that quietly drops a column the
parser dispatches on.

**Real write paths, both backends.** The same logical state seeded through
``DynamoDBGrantStore``/``SqliteGrantStore`` and their record stores. This is
the one that catches item-SHAPE divergence rather than loader bugs: boto3's
resource layer returns ``Decimal`` for numbers where the sqlite substrate
stores JSON, so a rule reading a numeric attribute directly would pass on one
arm and fail on the other. (It does not today — every attribute the parser
reads is a string, and the grant/record payloads are opaque JSON strings — but
asserting it is what makes that fact durable rather than incidental.)

Findings are compared as ``(rule, coordinate, detail)`` triples: a differential
suite that compared only rule NAMES would go green on an audit that named the
wrong grant.
"""

from __future__ import annotations

import pytest

from safe_agents.broker import sqlite_substrate as substrate
from safe_agents.broker.grants.audit import (
    GRANT_TAMPER,
    LEDGER_COUNTERPART,
    load_dataset,
    load_dataset_sqlite,
    run_audit,
)

# Fixtures come from the auditor's own suite rather than being restated here:
# one definition of each item shape means a drift in the stored layout moves
# both suites together instead of leaving this one asserting a stale shape.
from safe_agents.broker.tests import test_grants_audit as _audit_suite
from safe_agents.broker.tests.test_grants_audit import (
    _GRANT_PK,
    ACTION_CLASS,
    HMAC_KEY,
    _grant_item,
    _issuer_signer_and_resolver,
    _make_grant,
    _make_record,
    _proposal_item,
    _seed_clean_state,
    _table,
)

#: The moto table fixture, re-bound so pytest resolves it by name here too.
table_name = _audit_suite.table_name

boto3 = pytest.importorskip("boto3", reason="the Dynamo leg needs boto3")

from safe_agents.broker.grants.sqlite_store import (  # noqa: E402
    SqliteGrantStore,
    SqlitePromotionRecordStore,
)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "broker.db"


def _plant(db_path, items) -> None:
    """Write raw items into a local broker.db exactly as the stores would key them.

    The mirror of ``table.put_item(Item=...)``: pk/sk into their columns, every
    other attribute into the item map — which is precisely the split the loader
    has to undo.
    """
    conn = substrate.open_connection(db_path)
    try:
        with substrate.transaction(conn):
            for item in items:
                attrs = {k: v for k, v in item.items() if k not in ("pk", "sk")}
                substrate.put_new_item(conn, item["pk"], item["sk"], attrs)
    finally:
        conn.close()


def _findings(report) -> set[tuple[str, str, str]]:
    """Findings as comparable triples — rule, coordinate AND detail.

    Comparing rule names alone would pass an audit that flagged the right rule
    against the wrong coordinate, which is the failure a differential suite is
    supposed to be able to see.
    """
    return {(v.rule, v.coordinate, v.detail) for v in report.violations}


def _seed_sqlite_clean_state(db_path, signer) -> None:
    """The sqlite twin of ``_seed_clean_state`` — the SAME logical state through
    the real local write paths, so the comparison is store-shape to store-shape
    rather than fixture to fixture."""
    # on-loop, matching its ledger — see _seed_clean_state (#255).
    SqliteGrantStore(hmac_key=HMAC_KEY, db_path=db_path).put_grant(
        _make_grant(level="on-loop")
    )

    record_store = SqlitePromotionRecordStore(db_path)
    record_store.put_record(_make_record())
    promotion = _make_record("promotion", ts="2026-07-02T00:00:00+00:00")
    record_store.put_record(promotion, signature=signer.sign_record(promotion))

    # The auditor never parses the proposal payload, so an opaque data string
    # is a faithful fixture — same choice the Dynamo seeder makes.
    _plant(db_path, [_proposal_item()])


# ---------------------------------------------------------------------------
# Leg 1 — identical items, both loaders
# ---------------------------------------------------------------------------


def test_identical_items_produce_identical_findings(table_name, db_path):
    """The loader test proper: same items in, same report out."""
    signer, resolver = _issuer_signer_and_resolver()
    _seed_clean_state(table_name, signer)

    dynamo = load_dataset(_table(table_name))
    _plant(db_path, [dict(i) for i in _table(table_name).scan()["Items"]])
    sqlite = load_dataset_sqlite(db_path)

    assert (
        sqlite.grants,
        sqlite.records,
        sqlite.proposals,
        sqlite.envelopes,
        sqlite.acknowledgments,
        sqlite.parse_violations,
    ) == (
        dynamo.grants,
        dynamo.records,
        dynamo.proposals,
        dynamo.envelopes,
        dynamo.acknowledgments,
        dynamo.parse_violations,
    )

    kwargs = dict(hmac_key=HMAC_KEY, record_key_resolver=resolver)
    assert _findings(run_audit(sqlite, **kwargs)) == _findings(run_audit(dynamo, **kwargs))


def test_loader_remerges_the_key_columns(db_path):
    """Without pk/sk back in the map the parser dispatches on nothing.

    Called out separately because its failure mode is a CLEAN audit of an empty
    dataset — an integrity check that reports zero violations because it read
    zero items is worse than one that crashes.
    """
    _plant(db_path, [_grant_item(), _proposal_item()])

    dataset = load_dataset_sqlite(db_path)

    assert len(dataset.grants) == 1
    assert len(dataset.proposals) == 1
    # sk is the proposal's id — dropped, every proposal would audit as "<unknown>"
    assert dataset.proposals[0].proposal_id == "prop-1"
    assert dataset.proposals[0].coordinate == _GRANT_PK.removeprefix("GRANT#") + f"#{ACTION_CLASS}"


def test_sqlite_loader_reads_every_item_kind(db_path):
    """A filtered read would silently exempt whatever the filter missed."""
    _plant(db_path, [_grant_item(), _proposal_item()])
    _plant(db_path, [{"pk": "COUNTER#agent-audit#email.send", "sk": "2026-07-26", "n": 3}])

    dataset = load_dataset_sqlite(db_path)

    # The foreign kind is IGNORED by the parser, not by the loader — same as a
    # Scan, which cannot skip it either. It must not become an UNPARSEABLE_ITEM.
    assert dataset.parse_violations == ()
    assert len(dataset.grants) == 1


def test_empty_database_audits_empty_rather_than_crashing(db_path):
    report = run_audit(load_dataset_sqlite(db_path), hmac_key=HMAC_KEY)

    assert report.violations == ()
    assert (report.grants_examined, report.records_examined, report.proposals_examined) == (0, 0, 0)


# ---------------------------------------------------------------------------
# Leg 2 — real write paths on both backends
# ---------------------------------------------------------------------------


def test_real_write_paths_agree_across_backends(table_name, db_path):
    """Store-shape to store-shape: the leg that would catch a Decimal-vs-JSON
    divergence in anything the rules read."""
    signer, resolver = _issuer_signer_and_resolver()
    _seed_clean_state(table_name, signer)
    _seed_sqlite_clean_state(db_path, signer)

    kwargs = dict(hmac_key=HMAC_KEY, record_key_resolver=resolver)
    dynamo_report = run_audit(load_dataset(_table(table_name)), **kwargs)
    sqlite_report = run_audit(load_dataset_sqlite(db_path), **kwargs)

    assert _findings(sqlite_report) == _findings(dynamo_report) == set()
    assert sqlite_report.skipped_rules == dynamo_report.skipped_rules == ()
    assert (
        sqlite_report.grants_examined,
        sqlite_report.records_examined,
        sqlite_report.proposals_examined,
    ) == (
        dynamo_report.grants_examined,
        dynamo_report.records_examined,
        dynamo_report.proposals_examined,
    )


def test_tamper_is_flagged_identically_on_both_backends(table_name, db_path):
    """A green differential proves agreement on clean state only. The rules
    that matter are the ones that FIRE, so the same tamper must produce the
    same finding — including the same detail string."""
    signer, resolver = _issuer_signer_and_resolver()
    _seed_clean_state(table_name, signer)
    _seed_sqlite_clean_state(db_path, signer)

    tampered = _table(table_name).get_item(
        Key={"pk": _GRANT_PK, "sk": f"CLASS#{ACTION_CLASS}"}
    )["Item"]["data"].replace('"alice"', '"mallory"')

    _table(table_name).update_item(
        Key={"pk": _GRANT_PK, "sk": f"CLASS#{ACTION_CLASS}"},
        UpdateExpression="SET #data = :tampered",
        ExpressionAttributeNames={"#data": "data"},
        ExpressionAttributeValues={":tampered": tampered},
    )
    conn = substrate.open_connection(db_path)
    try:
        with substrate.transaction(conn):
            attrs = substrate.get_item(conn, _GRANT_PK, f"CLASS#{ACTION_CLASS}")
            attrs["data"] = tampered
            substrate.update_existing_item(conn, _GRANT_PK, f"CLASS#{ACTION_CLASS}", attrs)
    finally:
        conn.close()

    kwargs = dict(hmac_key=HMAC_KEY, record_key_resolver=resolver)
    sqlite_findings = _findings(run_audit(load_dataset_sqlite(db_path), **kwargs))
    dynamo_findings = _findings(run_audit(load_dataset(_table(table_name)), **kwargs))

    assert sqlite_findings == dynamo_findings
    # The tamper renames the grant's user, so it loses its ledger too — both
    # rules must fire on both arms, or the agreement above is agreement on
    # silence.
    assert {rule for rule, _, _ in sqlite_findings} == {GRANT_TAMPER, LEDGER_COUNTERPART}


def test_keyless_mode_skips_the_same_rules_on_sqlite(table_name, db_path):
    """Skipping must be loud and IDENTICAL — a local audit that quietly ran
    fewer rules would report a cleaner floor than a cloud one."""
    signer, resolver = _issuer_signer_and_resolver()
    _seed_clean_state(table_name, signer)
    _seed_sqlite_clean_state(db_path, signer)

    sqlite_report = run_audit(load_dataset_sqlite(db_path), record_key_resolver=resolver)
    dynamo_report = run_audit(load_dataset(_table(table_name)), record_key_resolver=resolver)

    assert sqlite_report.skipped_rules == dynamo_report.skipped_rules
    assert sqlite_report.skipped_rules != ()
