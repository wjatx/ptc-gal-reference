"""The retired `Envelope.allowlists` block (#135): refusal and hash consequence.

The block was declared as a default-deny scope of the tools an agent may see,
and no decision read it. It is gone. Two invariants are pinned here, and every
failure message names the one it belongs to:

  A1  The field is gone and the key is REFUSED by name at every load path, with
      a message that says it was retired, that what an agent may call comes
      from its grants, and that names #135. `Envelope` is `extra="forbid"`, so
      an unknown key is refused whether or not the named refusal exists. The
      tests therefore assert the message, not only that validation failed: a
      test that checked the failure alone would pass with the named refusal
      deleted.
  A2  Removing the field changes the hash of EVERY envelope, including one that
      never set it, because the hash covers the whole dump and the old dump
      carried `"allowlists": null`. A grant stamped under an old hash is
      quarantined until `re-seed` re-attests it. That `re-seed` refuses without
      the issuer signing key is pinned in `test_grants_reattestation_signing.py`.

The operator-facing paths (broker boot, the ceremony, the seed CLI, the audit
finding) are pinned in `test_envelope_allowlists_retired_paths.py`.
The pipeline preflight that used to key on this field is pinned beside the
preflight, in `safe_agents/pipeline/tests/test_validate_manifest.py`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from pydantic import ValidationError

from safe_agents.broker import schemas
from safe_agents.broker.enforcement import InMemoryStore
from safe_agents.broker.envelope import (
    DynamoDBEnvelopeStore,
    InMemoryEnvelopeStore,
    load_inforce_envelope,
    seed_envelope,
)
from safe_agents.broker.grants.acknowledgments import WAIVABLE_RULES
from safe_agents.broker.grants.audit import (
    GRANT_ENVELOPE_IN_FORCE,
    dataset_from_items,
    run_audit,
)
from safe_agents.broker.grants.store import InMemoryGrantStore
from safe_agents.broker.manifest import CATALOG_TABLE
from safe_agents.broker.prototype.broker_server import _make_pip
from safe_agents.broker.schemas import (
    AgentManifest,
    BrokeredCall,
    Envelope,
    Session,
    Taint,
    compute_envelope_hash,
)
from safe_agents.broker.schemas import envelope as envelope_module
from safe_agents.broker.tests.allowlists_retired_scaffold import (
    A1,
    A2,
    RETIRED_VALUES,
    in_memory_store_holding,
    refusing_the_retired_key,
    sqlite_store_holding,
    stored_dump_before_retirement,
)
from safe_agents.broker.tests.scaffold import PRINCIPAL, make_grant

REPO_ROOT = Path(__file__).resolve().parents[3]

# The hash of `Envelope(polarity="abstain")` before the field was removed.
# Kept as a literal so the change in the hash is a recorded fact and not only a
# comparison between two values computed by the code under test.
_MINIMAL_HASH_BEFORE = "sha256:6599616c5aad7b595d35e3bb3d87d7d4c0f47bf7225c32fb610cba55d7e0534d"
# The same envelope now. A change to this value re-quarantines every grant in
# every deployment, so it moves only with a deliberate, documented change.
_MINIMAL_HASH_NOW = "sha256:d6bb46f9a7f8714a063646e6dfe180d80dc8a2ac619d5964b29c67065f814fb0"


def _canonical_hash(dump: dict) -> str:
    """`compute_envelope_hash`'s canonicalization, applied to a raw dict."""
    serialized = json.dumps(dump, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(serialized.encode()).hexdigest()


# ---------------------------------------------------------------------------
# A1: the field and its model are gone
# ---------------------------------------------------------------------------


def test_envelope_has_no_allowlists_field():
    assert "allowlists" not in Envelope.model_fields, f"{A1}: Envelope still declares the field"
    assert "allowlists" not in Envelope(polarity="abstain").model_dump(mode="json"), (
        f"{A1}: the envelope dump still carries the key"
    )


@pytest.mark.parametrize("module", [envelope_module, schemas], ids=["envelope", "schemas"])
def test_allowlists_model_is_removed(module):
    assert not hasattr(module, "Allowlists"), f"{A1}: {module.__name__} still exports Allowlists"


# ---------------------------------------------------------------------------
# A1: the key is refused by name at every load path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", RETIRED_VALUES)
def test_envelope_refuses_the_key_whatever_its_value(value):
    block = {"polarity": "abstain", "allowlists": value}

    with refusing_the_retired_key("Envelope.model_validate"):
        Envelope.model_validate(block)

    # The stores read with model_validate_json, a separate entry point.
    with refusing_the_retired_key("Envelope.model_validate_json"):
        Envelope.model_validate_json(json.dumps(block))


def test_the_named_refusal_is_not_the_generic_extra_key_error():
    """`extra="forbid"` refuses any unknown key. The retired key must be
    refused by the named validator first, or the operator is told only that an
    input was not permitted."""
    with refusing_the_retired_key("Envelope.model_validate") as retired:
        Envelope.model_validate({"polarity": "abstain", "allowlists": None})
    assert "Extra inputs are not permitted" not in retired.message, (
        f"{A1}: the retired key fell through to the generic extra-key refusal"
    )

    with pytest.raises(ValidationError) as unknown:
        Envelope.model_validate({"polarity": "abstain", "never_a_field": None})
    assert "retired" not in str(unknown.value), (
        f"{A1}: an unrelated unknown key is being reported as the retired field"
    )


def test_agent_manifest_refuses_an_envelope_that_carries_the_key():
    with refusing_the_retired_key("AgentManifest.model_validate"):
        AgentManifest.model_validate(
            {"envelope": {"polarity": "abstain", "allowlists": {"tools": ["notify.send"]}}}
        )


def test_seed_refuses_a_yaml_that_carries_the_block_and_writes_nothing(tmp_path):
    manifest = tmp_path / "agent.yaml"
    manifest.write_text(
        yaml.safe_dump({"envelope": {"polarity": "abstain", "allowlists": {"tools": []}}}),
        encoding="utf-8",
    )
    store = InMemoryEnvelopeStore()

    with refusing_the_retired_key("seed_envelope"):
        seed_envelope(store, manifest, PRINCIPAL)

    assert store.get_envelope(PRINCIPAL) is None, (
        f"{A1}: seed wrote an envelope after dropping the retired block"
    )


@pytest.mark.parametrize("backend", ["memory", "sqlite", "dynamo"])
def test_a_row_stored_before_the_retirement_is_refused_on_read(backend, tmp_path):
    """Every envelope the old serializer stored carries the key, as null when
    the block was never set. Each store's read refuses such a row by name. It
    neither drops the key nor reports the row as absent."""
    stored = stored_dump_before_retirement(Envelope(polarity="abstain"))
    where = f"the {backend} envelope store read"

    if backend == "dynamo":
        table = MagicMock()
        table.get_item.return_value = {"Item": {"data": stored}}
        with patch("boto3.resource") as resource:
            resource.return_value.Table.return_value = table
            with refusing_the_retired_key(where):
                load_inforce_envelope(DynamoDBEnvelopeStore(table_name="grants"), PRINCIPAL)
    else:
        store = (
            in_memory_store_holding(stored)
            if backend == "memory"
            else sqlite_store_holding(stored, tmp_path)
        )
        with refusing_the_retired_key(where):
            load_inforce_envelope(store, PRINCIPAL)


def _shipped_manifests() -> list[Path]:
    roots = [REPO_ROOT / "agents", REPO_ROOT / "examples", REPO_ROOT / "safe_agents"]
    return sorted(path for root in roots for path in root.rglob("*.yaml"))


def test_no_shipped_manifest_carries_the_block():
    """Each shipped manifest with an `envelope:` block loads under the schema
    that refuses the key, so none of them can still be carrying it."""
    loaded = 0
    for path in _shipped_manifests():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue  # CloudFormation templates use tags safe_load rejects
        if not isinstance(raw, dict) or not isinstance(raw.get("envelope"), dict):
            continue
        assert "allowlists" not in raw["envelope"], f"{A1}: {path} still sets the retired block"
        Envelope.model_validate(raw["envelope"])
        loaded += 1
    # A sweep that finds nothing proves nothing. Nineteen manifests carried the
    # block when it was retired, and one shipped without it.
    assert loaded >= 20, f"{A1}: the manifest sweep found only {loaded} envelopes"


# ---------------------------------------------------------------------------
# A2: the hash of every envelope changed, and what that costs
# ---------------------------------------------------------------------------


def test_the_minimal_envelope_hash_is_pinned_and_differs_from_before():
    now = compute_envelope_hash(Envelope(polarity="abstain"))
    assert now == _MINIMAL_HASH_NOW, (
        f"{A2}: the hash of an envelope that sets nothing but polarity moved to {now}. "
        "Every stored grant is quarantined by this until re-seed re-attests it."
    )
    assert now != _MINIMAL_HASH_BEFORE, (
        f"{A2}: an envelope that never set the field hashes as it did before the "
        "retirement, so the documented re-seed requirement is wrong"
    )


def test_the_old_hash_is_the_new_dump_plus_the_null_the_field_used_to_write():
    """The whole difference between the two bases is one key. This is why an
    envelope that never set the block is affected: the old dump carried the
    key as null and the hash covers the dump."""
    dump = Envelope(polarity="abstain").model_dump(mode="json")
    assert _canonical_hash(dump) == _MINIMAL_HASH_NOW, f"{A2}: the hash basis is not the dump"
    assert _canonical_hash({**dump, "allowlists": None}) == _MINIMAL_HASH_BEFORE, (
        f"{A2}: the pre-retirement hash is no longer explained by the removed key alone"
    )


def _call(action_class: str) -> BrokeredCall:
    tool, op = action_class.split(".")
    return BrokeredCall(
        principal=PRINCIPAL,
        tool=tool,
        op=op,
        args={"message": "hi"},
        manifest=CATALOG_TABLE.entry(tool, op),
        taint=Taint(tainted=False, sources=[]),
        session=Session(turnId="allowlists-retired", ingestedSources=[]),
        ts="2026-07-06T00:00:00Z",
    )


def test_a_grant_stamped_before_the_retirement_is_quarantined():
    """The cost of the hash change at the decision point: the grant is intact,
    its HMAC verifies, and the broker treats it as absent."""
    store = InMemoryGrantStore(hmac_key=b"test-hmac-key")
    store.put_grant(
        make_grant("notify.send").model_copy(update={"envelopeHash": _MINIMAL_HASH_BEFORE})
    )
    in_force = compute_envelope_hash(Envelope(polarity="abstain"))
    pip = _make_pip(store, InMemoryStore(), 100.0, in_force_hash=in_force)

    facts = pip(_call("notify.send"))

    assert facts.quarantined is True and facts.grant_present is False, (
        f"{A2}: a grant stamped under the pre-retirement hash is still served"
    )
    assert "envelope hash mismatch" in (facts.quarantine_reason or ""), (
        f"{A2}: the quarantine does not name the envelope hash as its cause"
    )


def test_the_audit_names_the_stale_grant_and_the_finding_is_waivable():
    """Once the envelope row is seeded again, the audit reports each grant
    still under the old hash. That finding is the expected state between the
    upgrade and `re-seed`, so it is one the acknowledgment ceremony may waive."""
    envelope = Envelope(polarity="abstain")
    grant = make_grant("notify.send").model_copy(update={"envelopeHash": _MINIMAL_HASH_BEFORE})
    principal_key = "#".join(PRINCIPAL.model_dump().values())
    items = [
        {"pk": f"GRANT#{principal_key}", "sk": "notify.send", "data": grant.model_dump_json()},
        {"pk": f"ENVELOPE#{principal_key}", "sk": "V0", "data": envelope.model_dump_json()},
    ]

    report = run_audit(dataset_from_items(items))

    stale = [v for v in report.violations if v.rule == GRANT_ENVELOPE_IN_FORCE]
    assert len(stale) == 1, f"{A2}: the audit did not report the grant under the old hash"
    assert "re-seed" in stale[0].detail, f"{A2}: the finding does not name re-seed as the remedy"
    assert GRANT_ENVELOPE_IN_FORCE in WAIVABLE_RULES, (
        f"{A2}: the upgrade-window finding is no longer in the waivable vocabulary"
    )
