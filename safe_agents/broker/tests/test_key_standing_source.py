"""One role's standing source (GAL-41, #179): accepting, ageing, and the env contract.

What this file pins, in four groups:

  accept       what refresh accepts and what it refuses, and that a refusal
               leaves the accepted document in force
  age          the as-of is the earlier of the fetch and issuedAt (#176's rule),
               the document is not established from as-of + max age, and a skew
               bound moves that end earlier, never later
  env          the location, the authority keys and the age are bound at deploy;
               no default age; a per-agent age may only shorten; a key shared
               with the third role refuses
  ceremony     the standing command signs the next version, one way only, and
               refuses without the standing authority's key
"""

from __future__ import annotations

import ast
import datetime
import json
from pathlib import Path

import pytest

from safe_agents.broker.grants import issuer_keys, standing_command, standing_keys
from safe_agents.broker.grants import key_standing as ks
from safe_agents.broker.grants import standing_source as ss
from safe_agents.broker.grants.record_signing import (
    RECORD_SIGNER_WITHDRAWN,
    canonical_record_payload,
    verify_record_by_type,
)
from safe_agents.broker.schemas.clock_skew import skew_bound
from safe_agents.broker.tests.test_key_standing import T0, _promotion, keypair
from safe_agents.channels.keys import key_resolver_from_map

HOUR = datetime.timedelta(hours=1)


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def authority():
    signer, pem = keypair("authority-1")
    return signer, pem


@pytest.fixture
def issuer_keys_pems():
    return {name: keypair(name) for name in ("issuer-a", "issuer-b")}


def _doc(previous, keys, signer, issued_at):
    return ks.next_document(previous, role="issuer", keys=keys, issued_at=issued_at, signer=signer)


def _source(served, authority_pem, *, clock, max_age=HOUR):
    raw = ks.public_key_raw(authority_pem)
    return ss.StandingSource(
        role="issuer",
        fetch=lambda: served["text"],
        source_label="test",
        authority=key_resolver_from_map({"authority-1": authority_pem}),
        authority_key_ids=frozenset({"authority-1"}),
        authority_public_keys=frozenset({raw}),
        max_age=max_age,
        clock=clock,
    )


@pytest.fixture
def chain(authority, issuer_keys_pems):
    """v1 (a, b active), v2 (a withdrawn), and a source serving whatever ``served`` holds."""
    signer, pem = authority
    keys = ks.add_key({}, "issuer-a", issuer_keys_pems["issuer-a"][1])
    keys = ks.add_key(keys, "issuer-b", issuer_keys_pems["issuer-b"][1])
    v1 = _doc(None, keys, signer, T0)
    v2 = _doc(v1, ks.withdraw_key(v1.keys, "issuer-a", "keyCompromise", T0 + HOUR), signer,
              T0 + HOUR)
    served = {"text": ks.sign_standing_document(v1, signer)}
    clock = Clock(T0 + datetime.timedelta(minutes=5))
    return {
        "signer": signer, "pem": pem, "v1": v1, "v2": v2, "served": served, "clock": clock,
        "source": _source(served, pem, clock=clock), "issuers": issuer_keys_pems,
    }


# ---------------------------------------------------------------------------
# Accept
# ---------------------------------------------------------------------------


def test_a_withdrawal_reaches_the_verifier_and_is_never_forgotten(chain):
    source, served = chain["source"], chain["served"]
    assert source.refresh().verdict == ss.STANDING_ACCEPTED
    assert source.standing_of("issuer-a", chain["clock"].now).verdict == ss.IN_STANDING
    served["text"] = ks.sign_standing_document(chain["v2"], chain["signer"])
    chain["clock"].now = T0 + HOUR + datetime.timedelta(minutes=1)
    assert source.refresh().verdict == ss.STANDING_ACCEPTED
    standing = source.standing_of("issuer-a", chain["clock"].now)
    assert (standing.verdict, standing.entry.withdrawnReason) == (ss.WITHDRAWN, "keyCompromise")
    assert source.standing_of("issuer-b", chain["clock"].now).verdict == ss.IN_STANDING
    # Far past the age, a withdrawal is still a withdrawal and not "not established".
    assert source.standing_of("issuer-a", T0 + 1000 * HOUR).verdict == ss.WITHDRAWN
    assert source.key_state("issuer-a") == ks.KEY_WITHDRAWN


def test_a_replayed_older_document_is_refused_and_the_newer_stays_in_force(chain):
    source, served = chain["source"], chain["served"]
    served["text"] = ks.sign_standing_document(chain["v2"], chain["signer"])
    chain["clock"].now = T0 + HOUR
    assert source.refresh().verdict == ss.STANDING_ACCEPTED
    served["text"] = ks.sign_standing_document(chain["v1"], chain["signer"])
    load = source.refresh()
    assert (load.verdict, load.version) == (ks.STANDING_WITHDRAWAL_DROPPED, 2)
    assert source.document == chain["v2"]
    assert source.standing_of("issuer-a", chain["clock"].now).verdict == ss.WITHDRAWN


def test_a_same_version_rewrite_is_a_rollback(chain):
    source, served = chain["source"], chain["served"]
    source.refresh()
    rewrite = ks.KeyStandingDocument(**{**chain["v1"].model_dump(), "issuedAt": "2026-10-01T00:30:00+00:00"})
    served["text"] = ks.sign_standing_document(rewrite, chain["signer"])
    assert source.refresh().verdict == ks.STANDING_ROLLBACK
    assert source.document == chain["v1"]


@pytest.mark.parametrize(
    "served_text",
    [
        "unsigned",
        "wrong_authority",
        "not_json",
    ],
)
def test_an_unsigned_or_foreign_document_is_never_accepted(served_text, chain):
    source, served = chain["source"], chain["served"]
    if served_text == "unsigned":
        envelope = json.loads(served["text"])
        envelope["signatures"] = []
        served["text"] = json.dumps(envelope)
    elif served_text == "wrong_authority":
        other, _ = keypair("authority-1")  # same key id, different key
        served["text"] = ks.sign_standing_document(chain["v1"], other)
    else:
        served["text"] = "{}"
    load = source.refresh()
    assert not load.accepted
    assert source.document is None
    assert source.standing_of("issuer-b", chain["clock"].now).verdict == ss.NOT_ESTABLISHED


@pytest.mark.parametrize("listed_by", ["key_id", "key_bytes"])
def test_the_source_refuses_a_document_listing_a_standing_authority_key(listed_by, chain):
    """A key that both signed records and decided their standing could restore its own."""
    if listed_by == "key_id":
        entry = ks.KeyStandingEntry(publicKey=keypair("other")[1], state="active")
        keys = {**chain["v1"].keys, "authority-1": entry}
    else:
        keys = ks.add_key(chain["v1"].keys, "issuer-x", chain["pem"])
    listing = _doc(None, keys, chain["signer"], T0)
    chain["served"]["text"] = ks.sign_standing_document(listing, chain["signer"])
    load = chain["source"].refresh()
    assert (load.verdict, chain["source"].document) == (ks.STANDING_AUTHORITY_KEY_LISTED, None)


def _relisted(chain, keys, version):
    """A document signed by the authority, built past next_document's own checks."""
    document = ks.KeyStandingDocument(
        role="issuer", version=version, issuedAt=ks.format_standing_instant(T0 + 2 * HOUR),
        signer=ks.StandingSigner(keyId="authority-1", zone="zone-test"), keys=keys,
    )
    return ks.sign_standing_document(document, chain["signer"])


@pytest.mark.parametrize("held", ["v1", "v2", "nothing"])
def test_a_withdrawn_keys_bytes_under_a_new_key_id_are_refused(held, chain):
    """Withdrawal is terminal for the key, not only for its id: listed again as
    active under another id, the compromised private key would sign records
    that verify under an entry in standing."""
    source, served = chain["source"], chain["served"]
    if held != "nothing":
        served["text"] = ks.sign_standing_document(chain[held], chain["signer"])
        assert source.refresh().accepted
    pem = chain["issuers"]["issuer-a"][1]
    renamed = ks.KeyStandingEntry(publicKey=pem, state="active")
    beside = _relisted(chain, {**chain["v2"].keys, "issuer-a2": renamed}, 3)
    instead = _relisted(
        chain, {"issuer-b": chain["v2"].keys["issuer-b"], "issuer-a2": renamed}, 3
    )
    expected = {
        "v1": (ks.STANDING_KEY_DUPLICATED, ks.STANDING_KEY_REBOUND),
        "v2": (ks.STANDING_KEY_DUPLICATED, ks.STANDING_WITHDRAWAL_DROPPED),
        "nothing": (ks.STANDING_KEY_DUPLICATED, None),
    }[held]
    for text, verdict in zip((beside, instead), expected):
        served["text"] = text
        load = source.refresh()
        if verdict is None:
            # A fresh process has seen nothing to compare with: the restart limit.
            assert load.accepted
            continue
        assert load.verdict == verdict
        assert source.document == (chain[held] if held != "nothing" else None)


def test_a_failed_fetch_is_a_verdict_and_the_accepted_document_stays(chain):
    source = chain["source"]
    source.refresh()

    def broken():
        raise OSError("gone")

    source._fetch = broken
    load = source.refresh()
    assert (load.verdict, load.version) == (ss.STANDING_UNREADABLE, 1)
    assert source.standing_of("issuer-b", chain["clock"].now).verdict == ss.IN_STANDING


def test_the_same_bytes_again_change_nothing(chain):
    source = chain["source"]
    source.refresh()
    first = source.as_of()
    chain["clock"].now += HOUR / 4
    assert source.refresh().verdict == ss.STANDING_UNCHANGED
    assert source.as_of() == first


# ---------------------------------------------------------------------------
# Age
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("issued_offset", "fetch_offset", "expect_as_of_offset"),
    [
        (datetime.timedelta(0), datetime.timedelta(minutes=5), datetime.timedelta(0)),
        # issuedAt in the future (a fast clock) cannot make it younger than its fetch
        (datetime.timedelta(hours=3), datetime.timedelta(minutes=5), datetime.timedelta(minutes=5)),
    ],
)
def test_the_as_of_is_the_earlier_of_issued_at_and_the_fetch(
    issued_offset, fetch_offset, expect_as_of_offset, chain
):
    document = _doc(None, dict(chain["v1"].keys), chain["signer"], T0 + issued_offset)
    chain["served"]["text"] = ks.sign_standing_document(document, chain["signer"])
    chain["clock"].now = T0 + fetch_offset
    chain["source"].refresh()
    expected = T0 + expect_as_of_offset
    assert chain["source"].as_of().as_of == expected
    assert chain["source"].horizon() == expected + HOUR


def test_standing_ends_at_as_of_plus_max_age_and_not_a_moment_later(chain):
    source = chain["source"]
    source.refresh()  # issued T0, fetched T0+5m: as-of T0, horizon T0+1h
    just_before = T0 + HOUR - datetime.timedelta(microseconds=1)
    assert source.standing_of("issuer-b", just_before).verdict == ss.IN_STANDING
    assert source.standing_of("issuer-b", T0 + HOUR).verdict == ss.NOT_ESTABLISHED
    gone = source.standing_of("nobody", T0 + datetime.timedelta(minutes=10))
    assert gone.verdict == ss.UNKNOWN_KEY


def test_a_skew_bound_ends_standing_earlier_never_later(chain):
    source = chain["source"]
    source.refresh()
    at = T0 + HOUR - datetime.timedelta(minutes=2)
    assert source.standing_of("issuer-b", at).verdict == ss.IN_STANDING
    late = source.standing_of("issuer-b", at, skew=skew_bound(180))
    assert late.verdict == ss.NOT_ESTABLISHED


def test_before_any_document_standing_is_not_established(chain):
    assert chain["source"].standing_of("issuer-b", T0).verdict == ss.NOT_ESTABLISHED
    assert chain["source"].horizon() is None


def test_a_naive_evaluation_instant_is_refused(chain):
    with pytest.raises(ValueError):
        chain["source"].standing_of("issuer-b", datetime.datetime(2026, 10, 1))


# ---------------------------------------------------------------------------
# Env contract
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_ambient_env(monkeypatch):
    for role_env in issuer_keys.ALL_ROLE_ENVS:
        for name in issuer_keys.role_env_names(role_env):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def deployed(chain, tmp_path, monkeypatch):
    """The issuer's standing document and the authority keys, as files bound by env."""
    doc_file = tmp_path / "issuer-standing.json"
    doc_file.write_text(chain["served"]["text"], encoding="utf-8")
    authority_file = tmp_path / "authority.json"
    authority_file.write_text(json.dumps({"authority-1": chain["pem"]}), encoding="utf-8")
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_FILE_ENV, str(doc_file))
    monkeypatch.setenv(issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV, "3600")
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_FILE_ENV, str(authority_file))
    return {"doc_file": doc_file, "authority_file": authority_file}


def test_with_no_standing_env_there_is_no_source():
    assert standing_keys.resolve_standing_source(issuer_keys.ISSUER_ROLE_ENV) is None
    assert standing_keys.resolve_standing_sources() == {}


def test_a_configured_source_reads_only_the_deploy_bound_location(deployed):
    source = standing_keys.resolve_standing_source(issuer_keys.ISSUER_ROLE_ENV)
    assert source.source_label == f"{issuer_keys.ISSUER_STANDING_FILE_ENV}={deployed['doc_file']}"
    assert source.max_age == HOUR
    assert source.refresh().verdict == ss.STANDING_ACCEPTED


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV: None}, "no default"),
        ({issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV: "0"}, "positive"),
        ({issuer_keys.ISSUER_STANDING_MAX_AGE_SECONDS_ENV: "1h"}, "whole number"),
        ({issuer_keys.ISSUER_STANDING_PARAM_ENV: "/p"}, "exactly one"),
        ({issuer_keys.ISSUER_VERIFY_KEYS_FILE_ENV: "/m.json"}, "flat verify-key"),
        ({issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_FILE_ENV: None}, "never accepted"),
    ],
)
def test_configuration_errors_refuse_at_startup(change, match, deployed, monkeypatch):
    for name, value in change.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match=match):
        standing_keys.resolve_standing_source(issuer_keys.ISSUER_ROLE_ENV)


@pytest.mark.parametrize(("per_agent", "ok"), [(1800, True), (3600, True), (3601, False)])
def test_a_per_agent_age_may_only_shorten(per_agent, ok, deployed):
    if ok:
        source = standing_keys.resolve_standing_source(
            issuer_keys.ISSUER_ROLE_ENV, per_agent_max_age_seconds=per_agent
        )
        assert source.max_age == datetime.timedelta(seconds=per_agent)
    else:
        with pytest.raises(issuer_keys.IssuerSigningConfigError, match="only shorten"):
            standing_keys.resolve_standing_sources(
                per_agent_max_age_seconds={"issuer": per_agent}
            )


def test_a_per_agent_age_for_an_unconfigured_source_refuses():
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="bounds nothing"):
        standing_keys.resolve_standing_source(
            issuer_keys.ISSUER_ROLE_ENV, per_agent_max_age_seconds=60
        )


def test_the_manifest_carries_the_issuer_standing_age_under_its_input_name():
    from typing import get_args

    from safe_agents.broker.schemas.common import InputName

    assert standing_keys.STANDING_INPUT_NAMES == {"issuer": "issuer_standing"}
    assert "issuer_standing" in get_args(InputName)


def test_the_record_resolvers_carry_standing_and_a_withdrawn_key_is_its_own_verdict(
    chain, deployed
):
    v2_text = ks.sign_standing_document(chain["v2"], chain["signer"])
    deployed["doc_file"].write_text(v2_text, encoding="utf-8")
    resolvers = issuer_keys.resolve_record_key_resolvers()
    record = _promotion("2026-09-01T00:00:00+00:00")
    signed_by = {name: pair[0] for name, pair in chain["issuers"].items()}
    results = {
        key_id: verify_record_by_type(
            canonical_record_payload(record),
            signed_by[key_id].sign_record(record),
            record_type="promotion",
            resolvers=resolvers,
        )
        for key_id in ("issuer-a", "issuer-b")
    }
    assert results["issuer-a"].reason == RECORD_SIGNER_WITHDRAWN
    assert results["issuer-b"].ok
    assert issuer_keys.resolve_issuer_verify_keys()("issuer-a") is not None


def test_an_unacceptable_configured_document_fails_closed_for_the_audit(deployed):
    deployed["doc_file"].write_text("{}", encoding="utf-8")
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="not accepted"):
        issuer_keys.resolve_record_key_resolvers()


def test_a_standing_authority_key_in_a_role_map_refuses(chain, deployed, monkeypatch, tmp_path):
    evaluator_map = tmp_path / "evaluator.json"
    evaluator_map.write_text(json.dumps({"evaluator-x": chain["pem"]}), encoding="utf-8")
    monkeypatch.setenv(issuer_keys.EVALUATOR_VERIFY_KEYS_FILE_ENV, str(evaluator_map))
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="standing-authority key"):
        issuer_keys.resolve_record_key_resolvers()


def test_one_key_under_two_ids_in_two_roles_refuses(chain, deployed, monkeypatch, tmp_path):
    evaluator_map = tmp_path / "evaluator.json"
    shared = json.dumps({"evaluator-x": chain["issuers"]["issuer-b"][1]})
    evaluator_map.write_text(shared, encoding="utf-8")
    monkeypatch.setenv(issuer_keys.EVALUATOR_VERIFY_KEYS_FILE_ENV, str(evaluator_map))
    with pytest.raises(issuer_keys.IssuerSigningConfigError, match="different key ids"):
        issuer_keys.resolve_record_key_resolvers()


def test_the_standing_modules_read_no_store():
    """The pinned source is deploy-bound: nothing in these modules can load one from a store."""
    grants = Path(standing_keys.__file__).parent
    for module in ("key_standing.py", "standing_source.py", "standing_keys.py"):
        tree = ast.parse((grants / module).read_text(encoding="utf-8"))
        imported = {
            node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        } | {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
             for alias in node.names}
        assert not any(
            name and any(part in name for part in ("store", "ceremony", "proposals", "acknowledg"))
            for name in imported
        ), (module, imported)


# ---------------------------------------------------------------------------
# The ceremony
# ---------------------------------------------------------------------------


def _run(argv, chain, *, signer="default", now=T0 + 2 * HOUR):
    args = standing_command._parse_args(argv)
    written = {}
    code = standing_command.standing_command(
        args,
        signer=chain["signer"] if signer == "default" else signer,
        authority=standing_keys.resolve_standing_authority_keys(),
        now=now,
        write=lambda kind, location, text: written.update({location: text}),
    )
    return code, written


def test_withdraw_signs_the_next_version_and_a_verifier_accepts_it(chain, deployed):
    code, written = _run(
        ["withdraw", "--role", "issuer", "--key-id", "issuer-b", "--reason", "privilegeWithdrawn",
         "--expect-version", "1"],
        chain,
    )
    assert code == 0
    text = written[str(deployed["doc_file"])]
    document, _ = ks.verify_standing_envelope(
        text, authority=key_resolver_from_map({"authority-1": chain["pem"]}), role="issuer"
    )
    assert (document.version, document.keys["issuer-b"].state) == (2, "withdrawn")
    assert document.issuedAt == ks.format_standing_instant(T0 + 2 * HOUR)


@pytest.mark.parametrize(
    "argv",
    [
        ["retire", "--role", "issuer", "--key-id", "issuer-b", "--reason", "keyCompromise"],
        ["hold", "--role", "issuer", "--key-id", "issuer-b"],
        ["reinstate", "--role", "issuer", "--key-id", "issuer-b"],
        ["withdraw", "--role", "issuer", "--key-id", "issuer-b", "--reason", "certificateHold"],
    ],
)
def test_there_is_no_hold_and_no_reinstatement(argv):
    with pytest.raises(SystemExit):
        standing_command._parse_args(argv)


def test_a_backward_move_is_refused_by_the_ceremony(chain, deployed, capsys):
    v2_text = ks.sign_standing_document(chain["v2"], chain["signer"])
    deployed["doc_file"].write_text(v2_text, encoding="utf-8")
    code, written = _run(
        ["retire", "--role", "issuer", "--key-id", "issuer-a", "--reason", "superseded",
         "--expect-version", "2"], chain
    )
    assert (code, written) == (1, {})
    assert "only an active key retires" in capsys.readouterr().out


@pytest.mark.parametrize("command", [
    ["reissue"],
    ["add", "--key-id", "issuer-c", "--public-key-file", "PEM"],
    ["retire", "--key-id", "issuer-b", "--reason", "superseded"],
])
def test_the_ceremony_never_builds_on_a_replayed_older_document(
    command, chain, deployed, capsys, tmp_path
):
    """v2 withdrew issuer-a and v1 was written back to the source. Built on, v1
    would be re-signed as v2 or v3 with a fresh issuedAt and issuer-a active,
    and a process that had not seen the withdrawal would accept it."""
    pem_file = tmp_path / "issuer-c.pem"
    pem_file.write_text(keypair("issuer-c")[1], encoding="utf-8")
    argv = [part if part != "PEM" else str(pem_file) for part in command]
    deployed["doc_file"].write_text(
        ks.sign_standing_document(chain["v1"], chain["signer"]), encoding="utf-8"
    )
    code, written = _run([*argv[:1], "--role", "issuer", *argv[1:], "--expect-version", "2"],
                         chain)
    assert (code, written) == (1, {})
    assert "not the expected version 2" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        standing_command._parse_args(["reissue", "--role", "issuer"])


def test_the_ceremony_never_builds_on_a_document_newer_than_expected(chain, deployed, capsys):
    """--expect-version must match exactly, in both directions.

    The source serves v2, issued by someone other than this operator, and the
    operator expects v1. Building on v2 would sign a change the operator never
    saw the basis of, so a newer document is refused as an older one is."""
    deployed["doc_file"].write_text(
        ks.sign_standing_document(chain["v2"], chain["signer"]), encoding="utf-8"
    )
    code, written = _run(["reissue", "--role", "issuer", "--expect-version", "1"], chain)
    assert (code, written) == (1, {}), (
        "the version check accepted a current document newer than --expect-version"
    )
    out = capsys.readouterr().out
    assert "is version 2, not the expected version 1" in out, (
        f"refused, but not by the version check: {out!r}"
    )


def test_the_ceremony_refuses_without_the_standing_authority(chain, deployed):
    issuer_signer = chain["issuers"]["issuer-a"][0]
    for signer in (None, issuer_signer):
        code, written = _run(["reissue", "--role", "issuer", "--expect-version", "1"], chain,
                             signer=signer)
        assert (code, written) == (1, {})


def test_init_refuses_where_a_document_exists_and_reissue_moves_only_the_version(
    chain, deployed, tmp_path
):
    pem_file = tmp_path / "new.pem"
    pem_file.write_text(keypair("issuer-c")[1], encoding="utf-8")
    code, _ = _run(
        ["init", "--role", "issuer", "--key-id", "issuer-c", "--public-key-file", str(pem_file)],
        chain,
    )
    assert code == 1
    code, written = _run(["reissue", "--role", "issuer", "--expect-version", "1"], chain)
    document, _ = ks.verify_standing_envelope(
        written[str(deployed["doc_file"])],
        authority=key_resolver_from_map({"authority-1": chain["pem"]}),
        role="issuer",
    )
    assert (code, document.version, document.keys) == (0, 2, chain["v1"].keys)


def test_main_writes_the_file_atomically_through_the_configured_source(
    chain, deployed, monkeypatch, tmp_path
):
    key_file = tmp_path / "authority.pem"
    from cryptography.hazmat.primitives import serialization

    key_file.write_text(
        chain["signer"]._private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        encoding="utf-8",
    )
    key_file.chmod(0o600)
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_SIGNING_KEY_FILE_ENV, str(key_file))
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_SIGNING_KEY_ID_ENV, "authority-1")
    monkeypatch.setenv(issuer_keys.STANDING_AUTHORITY_SIGNING_ZONE_ENV, "zone-test")
    code = standing_command.main(
        ["retire", "--role", "issuer", "--key-id", "issuer-a", "--reason", "superseded",
         "--expect-version", "1"]
    )
    assert code == 0
    source = standing_keys.resolve_standing_source(issuer_keys.ISSUER_ROLE_ENV)
    assert source.refresh().verdict == ss.STANDING_ACCEPTED
    assert source.document.keys["issuer-a"].state == "retired"
