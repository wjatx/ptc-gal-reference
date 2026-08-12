"""test_ceremony_identity.py — #226: the solo-identity ceremony resolver.

The wall this closes: on a Mac with no AWS credentials the ceremony's identity
derivation raised ``NoCredentialsError`` before any store call, so the sqlite
arm could persist a ceremony's output while no ceremony could produce it.

The clauses pinned here are the ones that keep the local arm from becoming a
way to weaken the floor rather than a way to reach it:

  S1  ONE resolver — both ceremony command modules delegate to it, so the two
      ceremonies cannot drift on who may run them.
  S2  Explicit opt-in — no AWS credentials with the var unset REFUSES with a
      pointer; it NEVER falls back silently (the #197/#199 shape).
  S3  Closed catalog — the var selects a ROLE from a fixed set; it can never
      name an identity. The `who` half stays derived (no --as, on any arm).
  S4  Structurally unusable against the real floor — the local arm is REFUSED
      on BROKER_STORE=dynamo, so a solo-attested record cannot reach the cloud
      tables. (dynamo-vs-not, deliberately NOT is_durable_arm: sqlite IS the
      local floor.)
  S5  Honest attribution — the identity string says `local-solo:` on its face
      AND the ledger record carries a typed marker DERIVED from it, so the two
      can never disagree.
  S6  The invariant survives — the proposer still cannot ratify in ONE action,
      including when the derived host half churns between the two invocations
      (a laptop that changed networks must not slip a same-role ratify past an
      equality check).
  S7  The STS arm is untouched — an ambient credential resolves byte-for-byte
      as before, and its records carry no attestation marker.
"""
from __future__ import annotations

import pytest

from safe_agents.broker import ceremony_identity as ci
from safe_agents.broker.grants import commands as grants_commands
from safe_agents.broker.mcp import commands as mcp_commands
from safe_agents.broker.mcp.signing import McpAdmissionRecord
from safe_agents.broker.prototype.boot_config import BrokerConfigError
from safe_agents.broker.schemas import PromotionRecord
from safe_agents.broker.schemas.common import AutonomyLevel, Principal

_ENV_VARS = (
    "BROKER_LOCAL_IDENTITY",
    "BROKER_STORE",
    "BROKER_SQLITE_PATH",
    "BROKER_CEREMONY_IDENTITY",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path):
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # Point the projected-token paths at somewhere that does not exist, so a
    # test run INSIDE a pod (the CI container job, a cluster drill) behaves
    # identically to one on a laptop. Without this the local-arm tests would
    # hit the #250 "a real identity was available" refusal and fail for a
    # reason that has nothing to do with what they pin.
    monkeypatch.setattr(ci, "SA_TOKEN_PATH", str(tmp_path / "absent" / "token"))
    monkeypatch.setattr(ci, "SA_CA_PATH", str(tmp_path / "absent" / "ca.crt"))
    yield


def _project_token(monkeypatch, tmp_path, token: str = "tok") -> None:
    """Stage a projected ServiceAccount volume the way a kubelet would."""
    volume = tmp_path / "sa"
    volume.mkdir(exist_ok=True)
    (volume / "token").write_text(token, encoding="utf-8")
    (volume / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setattr(ci, "SA_TOKEN_PATH", str(volume / "token"))
    monkeypatch.setattr(ci, "SA_CA_PATH", str(volume / "ca.crt"))
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")


def _review_returning(username: str):
    """A stand-in for the ONE network call, shaped like a real response."""

    def _post(token, url, ca_path):  # noqa: ARG001
        return {"status": {"userInfo": {"username": username, "uid": "abc"}}}

    return _post


def _principal() -> Principal:
    return Principal(agentId="solo-agent", skill="s", user="u", tier="B")


# --------------------------------------------------------------------------
# S1 — one resolver, both ceremonies
# --------------------------------------------------------------------------


def test_both_ceremony_modules_delegate_to_the_one_resolver(monkeypatch):
    """The duplicated derivation is gone: extending one copy can no longer
    leave the other ceremony without the local arm."""
    monkeypatch.setattr(ci, "resolve_ceremony_identity", lambda session=None: "sentinel")
    monkeypatch.setattr(
        grants_commands, "resolve_ceremony_identity", lambda session=None: "sentinel"
    )
    monkeypatch.setattr(
        mcp_commands, "resolve_ceremony_identity", lambda session=None: "sentinel"
    )
    assert grants_commands._caller_identity() == "sentinel"
    assert mcp_commands._caller_identity() == "sentinel"


# --------------------------------------------------------------------------
# S2 — explicit opt-in; absent credentials refuse, never fall back
# --------------------------------------------------------------------------


def test_no_credentials_with_var_unset_refuses_with_a_pointer(monkeypatch):
    """The measured wall, now a refusal that TELLS the operator the way out —
    and never a silent substitution of who ran the ceremony."""
    import boto3
    from botocore.exceptions import NoCredentialsError

    def _no_creds(*_a, **_kw):
        raise NoCredentialsError()

    monkeypatch.setattr(boto3, "client", _no_creds)
    with pytest.raises(BrokerConfigError) as exc:
        ci.resolve_ceremony_identity()
    message = str(exc.value)
    assert "BROKER_LOCAL_IDENTITY" in message
    assert "maker" in message and "checker" in message
    # It must not merely complain — it must refuse to guess.
    assert "refusing to guess" in message


def test_missing_boto3_refuses_the_same_way(monkeypatch):
    """`pip install example-wrapper` need not drag in boto3; the absence is a config
    refusal with the same pointer, not an ImportError traceback."""
    import builtins

    real_import = builtins.__import__

    def _no_boto3(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("No module named 'boto3'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_boto3)
    with pytest.raises(BrokerConfigError) as exc:
        ci.resolve_ceremony_identity()
    assert "BROKER_LOCAL_IDENTITY" in str(exc.value)


# --------------------------------------------------------------------------
# S3 — closed catalog; identity is selected-by-role, never asserted
# --------------------------------------------------------------------------


def test_local_arm_mints_distinct_prefixed_identities_per_role(monkeypatch):
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    maker = ci.resolve_ceremony_identity()
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "checker")
    checker = ci.resolve_ceremony_identity()

    assert maker != checker
    assert maker.startswith(ci.LOCAL_IDENTITY_PREFIX)
    assert checker.startswith(ci.LOCAL_IDENTITY_PREFIX)
    assert maker.endswith("#maker")
    assert checker.endswith("#checker")
    # The derived `who` half is shared — the roles are what differ.
    assert maker.rsplit("#", 1)[0] == checker.rsplit("#", 1)[0]


@pytest.mark.parametrize(
    "value",
    [
        "arn:aws:sts::123456789012:assumed-role/Admin/maintainer",  # the tempting one
        "maintainer",
        "MAKER",
        "maker,checker",
        "safe_agents.evil:Identity",  # an import path, the #186 failure shape
    ],
)
def test_a_value_outside_the_catalog_is_refused(monkeypatch, value):
    """"Just let them pass an identity string" is the convenience that becomes
    an injection seam — the var selects a role, it never names an identity."""
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", value)
    with pytest.raises(BrokerConfigError) as exc:
        ci.resolve_ceremony_identity()
    assert "CLOSED" in str(exc.value)


def test_derived_halves_cannot_forge_identity_structure(monkeypatch):
    """A username carrying the reserved separators must not be able to
    fabricate a different role or prefix inside the identity string."""
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    monkeypatch.setattr(ci.getpass, "getuser", lambda: "evil#checker@host")
    monkeypatch.setattr(ci.socket, "gethostname", lambda: "h")
    identity = ci.resolve_ceremony_identity()
    assert ci.local_role_of(identity) == "maker"
    assert identity.count("#") == 1


def test_hostname_is_short_normalized(monkeypatch):
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    monkeypatch.setattr(ci.getpass, "getuser", lambda: "maintainer")
    monkeypatch.setattr(ci.socket, "gethostname", lambda: "macbook.local")
    assert ci.resolve_ceremony_identity() == "local-solo:maintainer@macbook#maker"


# --------------------------------------------------------------------------
# S4 — structurally unusable against the real floor
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["maker", "checker"])
def test_local_arm_is_refused_on_the_dynamo_arm(monkeypatch, role):
    """The failure mode to make impossible, not discouraged: a solo-attested
    record reaching the cloud grants/registry tables."""
    monkeypatch.setenv("BROKER_STORE", "dynamo")
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", role)
    with pytest.raises(BrokerConfigError) as exc:
        ci.resolve_ceremony_identity()
    assert "BROKER_STORE=dynamo" in str(exc.value)
    assert "MakerRole" in str(exc.value)


@pytest.mark.parametrize("arm", ["memory", "sqlite"])
def test_local_arm_is_honored_on_both_local_arms(monkeypatch, arm):
    """The gate is dynamo-vs-not, NOT is_durable_arm — sqlite is precisely the
    floor this exists for, so keying on durability would refuse the whole
    point (F1-F3's predicate is the wrong one to copy here)."""
    monkeypatch.setenv("BROKER_STORE", arm)
    monkeypatch.setenv("BROKER_SQLITE_PATH", "/tmp/unused-broker.db")
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    assert ci.resolve_ceremony_identity().endswith("#maker")


# --------------------------------------------------------------------------
# S5 — honest attribution, derived not asserted
# --------------------------------------------------------------------------


def test_attestation_is_derived_from_the_identity(monkeypatch):
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "checker")
    local = ci.resolve_ceremony_identity()
    assert ci.attestation_for(local) == ci.SOLO_ATTESTATION == "solo-local"
    assert ci.attestation_for("arn:aws:sts::1:assumed-role/CheckerRole/maintainer") is None


def test_records_accept_the_marker_and_default_to_absent():
    """Additive-optional on BOTH ledger record types: a pre-#226 record parses
    untouched (the field's absence means the IAM-backed STS arm), and the
    vocabulary is closed."""
    base = dict(
        recordType="promotion",
        actionClass="ledger.append",
        principal=_principal(),
        fromLevel=AutonomyLevel.in_loop,
        toLevel=AutonomyLevel.on_loop,
        evidence="e",
        predicate="p",
        proposedBy="local-solo:maintainer@mb#maker",
        ratifiedBy="local-solo:maintainer@mb#checker",
        envelopeHash="h",
        ts="2026-07-25T00:00:00+00:00",
    )
    assert PromotionRecord(**base).attestation is None
    assert PromotionRecord(**base, attestation="solo-local").attestation == "solo-local"
    with pytest.raises(Exception):
        PromotionRecord(**base, attestation="two-humans-definitely")

    mcp_base = dict(
        recordType="admission",
        serverId="s",
        toolName="t",
        defHash="d",
        proposedBy="local-solo:maintainer@mb#maker",
        ratifiedBy="local-solo:maintainer@mb#checker",
        ts="2026-07-25T00:00:00+00:00",
    )
    assert McpAdmissionRecord(**mcp_base).attestation is None
    assert (
        McpAdmissionRecord(**mcp_base, attestation="solo-local").attestation == "solo-local"
    )


def test_two_local_roles_satisfy_the_schema_validator_without_relaxing_it():
    """The maker != checker schema backstop is UNTOUCHED by #226: two distinct
    local roles satisfy it natively, so honesty comes from the marker rather
    than from loosening the invariant."""
    record = PromotionRecord(
        recordType="promotion",
        actionClass="ledger.append",
        principal=_principal(),
        fromLevel=AutonomyLevel.in_loop,
        toLevel=AutonomyLevel.on_loop,
        evidence="e",
        predicate="p",
        proposedBy="local-solo:maintainer@mb#maker",
        ratifiedBy="local-solo:maintainer@mb#checker",
        envelopeHash="h",
        ts="2026-07-25T00:00:00+00:00",
        attestation="solo-local",
    )
    assert record.proposedBy != record.ratifiedBy


# --------------------------------------------------------------------------
# S6 — the proposer still cannot ratify in ONE action
# --------------------------------------------------------------------------


def test_same_role_is_the_same_operator_even_across_a_host_change():
    """The hole an equality check leaves open: a hostname is not stable state
    (macOS flips it on network changes), so a laptop that moved between
    propose and ratify would otherwise slip an identical ROLE past `==`."""
    assert ci.is_same_operator(
        "local-solo:maintainer@macbook#maker", "local-solo:maintainer@office#maker"
    )
    assert not ci.is_same_operator(
        "local-solo:maintainer@macbook#maker", "local-solo:maintainer@office#checker"
    )


def test_identical_identities_are_the_same_operator_on_either_arm():
    arn = "arn:aws:sts::1:assumed-role/MakerRole/maintainer"
    assert ci.is_same_operator(arn, arn)
    assert ci.is_same_operator("local-solo:maintainer@mb#maker", "local-solo:maintainer@mb#maker")


def test_distinct_sts_identities_remain_a_valid_pair():
    """S7's other half: the local rule must not leak into the STS arm."""
    assert not ci.is_same_operator(
        "arn:aws:sts::1:assumed-role/MakerRole/maintainer",
        "arn:aws:sts::1:assumed-role/CheckerRole/maintainer",
    )


# --------------------------------------------------------------------------
# S7 — the STS arm is untouched
# --------------------------------------------------------------------------


def test_sts_arm_resolves_the_caller_arn_unchanged(monkeypatch):
    arn = "arn:aws:sts::123456789012:assumed-role/MakerRole/maintainer"

    class _Client:
        def get_caller_identity(self):
            return {"Arn": arn}

    class _Session:
        def client(self, _name):
            return _Client()

    assert ci.resolve_ceremony_identity(_Session()) == arn
    assert ci.attestation_for(arn) is None
    assert ci.local_role_of(arn) is None


# --------------------------------------------------------------------------
# S8 — the arm selector is a CLOSED catalog, and unset is byte-for-byte the
#      pre-#250 two-way dispatch
# --------------------------------------------------------------------------


def test_unset_selector_reproduces_the_pre_phase3_dispatch(monkeypatch):
    """The whole back-compat claim, pinned: adding a third arm moved nothing.

    Every existing caller — the Mac drills, the container drill, both floors'
    operator roles — leaves BROKER_CEREMONY_IDENTITY unset, and a record's
    attribution must not shift underneath them.
    """
    assert ci.resolve_ceremony_arm() == "sts"
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    assert ci.resolve_ceremony_arm() == "local"


@pytest.mark.parametrize(
    "value", ["serviceaccounts", "k8s", "kubernetes", "SERVICEACCOUNT", "solo", "local-solo"]
)
def test_an_arm_outside_the_catalog_is_refused(monkeypatch, value):
    """A typo must REFUSE, never fall through to the default dispatch — the arm
    decides what a signed record's attribution means.

    Case is NOT normalized: 'SERVICEACCOUNT' refuses. A catalog that quietly
    accepts variants is a catalog whose membership is a matter of opinion.
    """
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", value)
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_arm()
    assert "not a recognized ceremony identity arm" in str(excinfo.value)


@pytest.mark.parametrize("value", ["sts ", " local", "  serviceaccount  "])
def test_surrounding_whitespace_is_tolerated(monkeypatch, value):
    """Deliberate, and distinct from the case rule above: a value arriving from
    a YAML env block or a shell heredoc routinely carries a stray space, and
    refusing that would be a refusal about typography rather than authority."""
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", value)
    assert ci.resolve_ceremony_arm() == value.strip()


def test_the_selector_can_name_an_arm_but_never_an_identity(monkeypatch, tmp_path):
    """The catalog is arms, not identities: naming the arm still leaves the WHO
    to be derived by round-trip."""
    _project_token(monkeypatch, tmp_path)
    monkeypatch.setattr(
        ci, "_post_selfsubjectreview", _review_returning("system:serviceaccount:ns:maker")
    )
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    assert ci.resolve_ceremony_identity() == "system:serviceaccount:ns:maker"


# --------------------------------------------------------------------------
# S9 — the serviceaccount arm DERIVES by round-trip, never by parsing its own
#      credential
# --------------------------------------------------------------------------


def test_the_identity_comes_from_the_authority_not_the_token(monkeypatch, tmp_path):
    """The token's own contents are NOT the identity.

    A JWT whose `sub` claims one thing while the API server says another must
    yield the API server's answer. This is the property that distinguishes a
    derivation from an assertion, and it is why an expired or hand-written
    token cannot name its own bearer.
    """
    _project_token(monkeypatch, tmp_path, token="a.hand.written.jwt.claiming.admin")
    monkeypatch.setattr(
        ci, "_post_selfsubjectreview", _review_returning("system:serviceaccount:ns:lowly")
    )
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    assert ci.resolve_ceremony_identity() == "system:serviceaccount:ns:lowly"


def test_the_projected_token_is_what_gets_presented(monkeypatch, tmp_path):
    """The call carries the projected token and the projected CA — not the
    system trust store, which could not validate a cluster-internal cert and
    whose use would make 'derived' meaningless."""
    _project_token(monkeypatch, tmp_path, token="projected-token-value")
    seen = {}

    def _post(token, url, ca_path):
        seen.update(token=token, url=url, ca_path=ca_path)
        return {"status": {"userInfo": {"username": "system:serviceaccount:ns:sa"}}}

    monkeypatch.setattr(ci, "_post_selfsubjectreview", _post)
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    ci.resolve_ceremony_identity()

    assert seen["token"] == "projected-token-value"
    assert seen["ca_path"] == ci.SA_CA_PATH
    assert seen["url"].startswith("https://10.0.0.1:443/")
    assert seen["url"].endswith("/apis/authentication.k8s.io/v1/selfsubjectreviews")


def test_an_ipv6_apiserver_is_bracketed(monkeypatch, tmp_path):
    _project_token(monkeypatch, tmp_path)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "fd02::1")
    seen = {}

    def _post(token, url, ca_path):  # noqa: ARG001
        seen["url"] = url
        return {"status": {"userInfo": {"username": "system:serviceaccount:ns:sa"}}}

    monkeypatch.setattr(ci, "_post_selfsubjectreview", _post)
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    ci.resolve_ceremony_identity()
    assert seen["url"].startswith("https://[fd02::1]:443/")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"status": {}},
        {"status": {"userInfo": {}}},
        {"status": {"userInfo": {"username": ""}}},
        {"status": {"userInfo": {"username": "   "}}},
        {"status": None},
        "not even a dict",
    ],
)
def test_an_unnamed_review_response_refuses(monkeypatch, tmp_path, payload):
    """The API server answers an unauthenticated request without naming anyone.
    Stamping that as an empty identity would be worse than not running."""
    _project_token(monkeypatch, tmp_path)
    monkeypatch.setattr(ci, "_post_selfsubjectreview", lambda *a, **k: payload)
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_identity()
    assert "no userInfo.username" in str(excinfo.value)


def test_a_failed_round_trip_refuses_rather_than_degrading(monkeypatch, tmp_path):
    """No fallback to the solo arm and no fallback to a parsed claim: a ceremony
    that cannot establish who is running it writes nothing."""
    _project_token(monkeypatch, tmp_path)

    def _boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(ci, "_post_selfsubjectreview", _boom)
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")  # must NOT rescue it
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_identity()
    assert "could not derive the ceremony identity" in str(excinfo.value)
    assert "local-solo" not in str(excinfo.value)


def test_the_arm_refuses_outside_a_pod(monkeypatch):
    """Named on a laptop, there is no workload identity to derive."""
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_identity()
    assert "no projected ServiceAccount token" in str(excinfo.value)


def test_a_token_with_no_apiserver_refuses(monkeypatch, tmp_path):
    _project_token(monkeypatch, tmp_path)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST")
    monkeypatch.setenv("BROKER_CEREMONY_IDENTITY", "serviceaccount")
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_identity()
    assert "KUBERNETES_SERVICE_HOST" in str(excinfo.value)


# --------------------------------------------------------------------------
# S10 — the solo arm is REFUSED wherever a real identity was available
# --------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["maker", "checker"])
def test_the_solo_arm_is_refused_when_a_projected_token_exists(monkeypatch, tmp_path, role):
    """The sibling of the dynamo gate. Two local roles are a flag one process
    flips; two ServiceAccounts are two credentials."""
    _project_token(monkeypatch, tmp_path)
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", role)
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_identity()
    message = str(excinfo.value)
    assert "projected ServiceAccount token is present" in message
    assert "BROKER_CEREMONY_IDENTITY=serviceaccount" in message


def test_the_refusal_names_the_deliberate_escape_hatch(monkeypatch, tmp_path):
    """A pod that removed its own identity source on purpose is a legitimate
    solo case — but it must be an explicit act, not a default."""
    _project_token(monkeypatch, tmp_path)
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    with pytest.raises(BrokerConfigError) as excinfo:
        ci.resolve_ceremony_identity()
    assert "automountServiceAccountToken: false" in str(excinfo.value)


def test_an_empty_token_file_is_not_a_real_identity(monkeypatch, tmp_path):
    """An empty projection must not block the solo arm — it is not an identity
    source, and refusing in its favour would fail toward writing nothing for no
    gain."""
    _project_token(monkeypatch, tmp_path, token="   ")
    monkeypatch.setenv("BROKER_LOCAL_IDENTITY", "maker")
    assert ci.resolve_ceremony_identity().startswith("local-solo:")


# --------------------------------------------------------------------------
# S11 — a ServiceAccount ceremony carries NO solo attestation, and two SAs are
#       two operators
# --------------------------------------------------------------------------


def test_a_serviceaccount_identity_carries_no_attestation():
    """`attestation` is DERIVED from the identity string, so this cannot drift:
    only the local arm's prefix produces the solo marker."""
    assert ci.attestation_for("system:serviceaccount:safe-agents:safe-agents-checker") is None
    assert ci.is_local_identity("system:serviceaccount:safe-agents:safe-agents-checker") is False
    assert ci.local_role_of("system:serviceaccount:safe-agents:safe-agents-checker") is None


def test_two_serviceaccounts_are_not_the_same_operator():
    maker = "system:serviceaccount:safe-agents:safe-agents-maker"
    checker = "system:serviceaccount:safe-agents:safe-agents-checker"
    assert ci.is_same_operator(maker, checker) is False
    assert ci.is_same_operator(maker, maker) is True


def test_a_serviceaccount_name_containing_a_role_word_is_not_a_local_role():
    """`local_role_of` splits on '#', which a SA username never contains — so a
    ServiceAccount literally named ...#checker cannot impersonate the local
    arm's role comparison."""
    a = "system:serviceaccount:ns:maker"
    b = "system:serviceaccount:ns:checker"
    assert ci.is_same_operator(a, b) is False
