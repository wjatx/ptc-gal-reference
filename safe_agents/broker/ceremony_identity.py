"""ceremony_identity.py — the ONE resolver for a ceremony operator's identity (#226).

Both ceremony command surfaces — the grant ceremony
(``safe_agents.broker.grants.commands``) and the MCP admission ceremony
(``safe_agents.broker.mcp.commands``) — stamp *who proposed* and *who ratified*
into an append-only, issuer-signed record. On the cloud floor that identity is
an STS credential ARN and maker != checker is backed by IAM: the maker's
credentials cannot mint the checker's.

A solo developer on a Mac has no STS. Before this module the derivation died at
``NoCredentialsError`` before any store call, so the local (sqlite) arm could
persist a ceremony's output while no ceremony could be run to produce it — the
product-wrapper Phase-1 wall.

What this module adds is a LOCAL identity arm, deliberately shaped like #205's
``resolve_hmac_key`` fallback:

* **Explicit opt-in.** ``BROKER_LOCAL_IDENTITY`` must be NAMED. Absent AWS
  credentials never silently select it: an unset var with no ambient
  credentials REFUSES with a pointer, because silently substituting the
  identity a record is stamped with is exactly the #197/#199 wrong-authority
  shape.
* **A closed catalog, never a free string.** The var selects a ROLE from
  :data:`LOCAL_ROLES`; the operator cannot assert an arbitrary identity. The
  *who* half stays DERIVED (OS user + short hostname), exactly as the STS arm
  derives it from the credential — there is still no ``--as``.
* **Structurally unusable against the real floor.** The local arm is REFUSED on
  ``BROKER_STORE=dynamo``, so a solo-attested record can never reach the cloud
  grants/registry tables. NB the gate is dynamo-vs-not, deliberately NOT
  ``is_durable_arm``: sqlite is precisely the local floor this exists for.

A cluster has a third answer, and it is a REAL one (#250 Phase 3). Self-managed
OpenShift has no IRSA, but every pod carries a projected ServiceAccount token —
audience-bound, short-lived, and not mintable by the workload that holds it. So
``BROKER_CEREMONY_IDENTITY=serviceaccount`` derives the identity the same way the
STS arm does: by ROUND-TRIP TO THE AUTHORITY (``SelfSubjectReview``), never by
parsing the credential the process is holding. Two ServiceAccounts are two
credentials, so maker != checker stops being solo-attested — and the solo arm is
consequently REFUSED wherever such a token exists, the sibling of the dynamo
gate below.

What the serviceaccount arm does NOT buy on its own is store-write exclusion —
that is the write split's job, and since #203 (closed 2026-07-28) it is
PREVENTION on both substrates: on the cloud floor MakerRole's ``UpdateItem`` is
LeadingKeys-confined to ``PROPOSAL#*`` (``infra/lib/identity-stack.ts``) and the
maker cannot READ THE ISSUER KEY (zero secretsmanager statements), so it can
neither write the checker's key space nor produce a validly SIGNED record; the
cluster reproduces both with the checker key space on a read-only mount (kernel
refusal) and the issuer Secret mounted into the ratifying pod alone. The honest
shape is **prevention for signing AND prevention for writes** — never an
unqualified "RBAC refuses".

What this module does NOT do is pretend the local guarantee is unchanged. At N=1
the two identities are two roles one operator flips between; GAL §8 already holds that
maker != checker guarantees two credentials, never two humans, and that the
audit trail must record that truthfully. So the identity string SAYS it (the
``local-solo:`` prefix) and the ledger record carries a typed ``attestation``
marker DERIVED from that string — never asserted separately, so the two can
never disagree.

The invariant that survives intact is the one that matters: **the proposer
cannot ratify in ONE action** (ruling: GAL §8, locked 2026-07-14 via #202).
Two invocations, with a deliberate identity switch between them, remain
required — see :func:`is_same_operator`.
"""

from __future__ import annotations

import getpass
import os
import socket

from safe_agents.broker.prototype.boot_config import BrokerConfigError

# The env var that NAMES the local ceremony role. Unset = the STS arm.
LOCAL_IDENTITY_ENV = "BROKER_LOCAL_IDENTITY"

# The env var that NAMES which identity arm is in force, over a CLOSED catalog
# (#250 Phase 3). Unset keeps the pre-Phase-3 two-way dispatch byte-for-byte.
#
# A third arm is the point at which the old implicit fall-through stops carrying
# its meaning: "BROKER_LOCAL_IDENTITY set ? local : STS" was readable while there
# were two arms, but "else STS" would now mean "else guess between two remote
# authorities". This selector is the same idiom as BROKER_STORE and
# BROKER_SECRETS — it SELECTS from a closed set and can never name code.
CEREMONY_IDENTITY_ENV = "BROKER_CEREMONY_IDENTITY"
CEREMONY_ARMS = ("sts", "local", "serviceaccount")

# The kubelet's projected ServiceAccount volume. These paths are fixed by
# Kubernetes, not by us — deliberately NOT configurable: a settable token path is
# a settable identity, which is the whole thing this module refuses to allow.
# (Module-level so tests can monkeypatch them; there is no env override.)
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105
SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# The CLOSED catalog of local ceremony roles. Config SELECTS from this set; it
# can never name an identity (docs/config-provenance.md, #186). Two entries is
# the whole point: maker and checker are the two halves of the ceremony.
LOCAL_ROLES = ("maker", "checker")

# The role stamped into `approvedBy` when a held intent is RELEASED on the local
# floor (#301). Deliberately outside LOCAL_ROLES: releasing a held call is not a
# ceremony half. Per the 2026-07-29 ruling the local release is one command under
# one identity, so there is no maker/checker pair to name here — and widening the
# ceremony catalog to hold it would smuggle a third ceremony role into a closed set
# that means something else.
LOCAL_RELEASE_ROLE = "owner"

# Every local identity carries this prefix, so the honesty of the attribution
# survives a reader who has never heard of the `attestation` field: raw record
# JSON shows `"proposedBy": "local-solo:..."` on its face.
LOCAL_IDENTITY_PREFIX = "local-solo:"

# The typed marker stamped into the ledger record, derived from the prefix.
SOLO_ATTESTATION = "solo-local"

# Printed by a ceremony command that ratified under the local arm. The record
# is the durable statement; this is the operator-facing one.
SOLO_ATTESTATION_NOTICE = (
    "ATTESTATION: solo-local — ONE operator held both ceremony credentials "
    "(two local roles, no IAM between them); no second party reviewed this. "
    "The signed record says so."
)

# Characters that structure a local identity string. Stripped from the derived
# halves so `local-solo:<user>@<host>#<role>` stays unambiguously parseable.
_RESERVED = ("@", "#", ":")


def _sanitize(raw: str) -> str:
    """Collapse reserved separators and whitespace so the derived halves cannot
    forge extra structure in the identity string."""
    return "".join(
        "-" if ch in _RESERVED or ch.isspace() else ch for ch in raw.strip()
    )


def _derive_operator() -> str:
    """``<osuser>@<shorthost>`` — the DERIVED half of a local identity.

    The hostname is short-normalized (``macbook``, not ``macbook.local``)
    because macOS flips the mDNS suffix on network changes, and an identity
    that churns underneath the operator would silently weaken the maker !=
    checker comparison. :func:`is_same_operator` closes that hole for good by
    comparing roles, but a stable string is worth having anyway: it is what a
    human reads in the ledger.
    """
    try:
        user = _sanitize(getpass.getuser())
    except Exception:  # noqa: BLE001 — no passwd entry / no LOGNAME is survivable
        user = ""
    try:
        host = _sanitize(socket.gethostname().split(".")[0])
    except Exception:  # noqa: BLE001 — same posture
        host = ""
    return f"{user or 'unknown-user'}@{host or 'unknown-host'}"


def _local_identity(role: str) -> str:
    """Resolve the named local role to a ceremony identity, or REFUSE.

    Three refusals, all failing toward writing nothing: the role is not in the
    closed catalog, a real workload identity was available and declined (a
    projected ServiceAccount token), or the real (dynamo) floor is in force.
    """
    # Lazy: the STS arm must not pay for the boot-config import chain, and this
    # keeps ceremony_identity importable from anywhere in the broker package.
    from safe_agents.broker.prototype.boot_config import (  # noqa: PLC0415
        is_dynamo_arm,
        resolve_store_arm,
    )

    if role not in LOCAL_ROLES:
        raise BrokerConfigError(
            f"{LOCAL_IDENTITY_ENV}={role!r} is not a local ceremony role — the "
            f"catalog is CLOSED (valid roles: {list(LOCAL_ROLES)}): this var "
            "selects which half of the ceremony you are running, it can never "
            "name an identity. Identity is derived (OS user + host), never "
            "asserted — there is no --as, on any arm."
        )
    # The sibling of the dynamo gate, for the same reason (#250 Phase 3): a
    # solo-attested record must never be written where a REAL identity was
    # available and declined. On a cluster the projected token is that real
    # identity — audience-bound, short-lived, and not mintable by the workload —
    # so falling back to two roles one process flips between is a strictly
    # weaker attribution that nothing in the record would reveal as a CHOICE.
    #
    # The escape hatch is deliberate and explicit: a pod with
    # automountServiceAccountToken: false has removed its own identity source on
    # purpose, and there is then nothing better to refuse in favour of.
    if _projected_token() is not None:
        raise BrokerConfigError(
            f"{LOCAL_IDENTITY_ENV}={role!r} is set but a projected "
            f"ServiceAccount token is present at {SA_TOKEN_PATH} — refusing to "
            "run a SOLO-attested ceremony where a real workload identity is "
            "available. Two local roles are a flag one process flips; two "
            "ServiceAccounts are two credentials, neither mintable by the "
            f"other. Set {CEREMONY_IDENTITY_ENV}=serviceaccount and give the "
            "maker and checker legs different ServiceAccounts. (If you really "
            "mean to run solo in a pod, that pod must set "
            "automountServiceAccountToken: false — an explicit act, not a "
            "default.)"
        )
    if is_dynamo_arm():
        raise BrokerConfigError(
            f"{LOCAL_IDENTITY_ENV}={role!r} is set but BROKER_STORE="
            f"{resolve_store_arm()} — refusing to run a solo-attested ceremony "
            "against the real floor. On the DynamoDB arm maker != checker is "
            "backed by IAM (the maker's credentials cannot mint the "
            "checker's); a local role is a flag the same operator flips, and a "
            "record carrying that attestation must never reach the cloud "
            f"grants/registry tables. Unset {LOCAL_IDENTITY_ENV} and run under "
            "MakerRole / CheckerRole, or run the ceremony on the local arm "
            "(BROKER_STORE=sqlite or 'memory')."
        )
    return f"{LOCAL_IDENTITY_PREFIX}{_derive_operator()}#{role}"


def local_release_identity() -> str:
    """The identity that RELEASES a held intent on the local floor (#301).

    ``approve_intent`` documents ``approved_by`` as "the authenticated human
    identity from the approval channel (never sourced from the agent)". On a
    laptop there is no channel to authenticate against, and pretending otherwise
    would be the overclaim the posture ladder forbids. So this derives the same
    ``<osuser>@<shorthost>`` the ceremony arm derives and carries the same
    ``local-solo:`` prefix — the tape then says on its face that a release was
    attested by one operator on one machine, with nothing between them.

    There is no ``--as``, here or anywhere: identity is derived, never asserted.
    What this buys is honest attribution, not authentication — anyone who can run
    the command is that operator, which is the definition of posture 1 and is stated
    rather than papered over.

    Refused on the dynamo arm for the same reason the ceremony arm is: on a cloud
    floor a real authenticated approver exists (the owner channel), so a
    solo-derived ``approvedBy`` must never reach the cloud tape, where nothing in
    the record would reveal it as a downgrade.
    """
    from safe_agents.broker.prototype.boot_config import (  # noqa: PLC0415
        is_dynamo_arm,
        resolve_store_arm,
    )

    if is_dynamo_arm():
        raise BrokerConfigError(
            f"refusing to release an intent under a solo local identity with "
            f"BROKER_STORE={resolve_store_arm()}. On the DynamoDB arm the "
            "approver is authenticated by the owner channel and `approvedBy` "
            "names them; a locally derived OS user is not that, and a record "
            "carrying it must never reach the cloud audit tape. Release through "
            "the owner channel instead."
        )
    return f"{LOCAL_IDENTITY_PREFIX}{_derive_operator()}#{LOCAL_RELEASE_ROLE}"


def _projected_token() -> str | None:
    """The projected ServiceAccount token, or None when there is no such volume.

    Presence of this file is what "a real workload identity is available here"
    means on a cluster. It is read for PRESENCE by the local arm's refusal and
    for CONTENT by the serviceaccount arm; neither ever parses its claims.
    """
    try:
        with open(SA_TOKEN_PATH, encoding="utf-8") as fh:
            token = fh.read().strip()
    except OSError:
        return None
    return token or None


def _post_selfsubjectreview(token: str, url: str, ca_path: str) -> dict:
    """POST a SelfSubjectReview and return the parsed response.

    Split out as the ONE network call so tests can monkeypatch it (the same
    posture as ``issuer_keys._fetch_parameter``). stdlib only: the base must not
    grow a Kubernetes client dependency to learn its own name, and `pip install
    example-wrapper` should not drag one in either.
    """
    import json  # noqa: PLC0415
    import ssl  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    body = json.dumps(
        {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 — https, scheme fixed below
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    # The cluster CA from the same projected volume — never the system trust
    # store: the API server's certificate is cluster-internal and would not
    # validate against public roots, and disabling verification here would make
    # the "derived, never asserted" property meaningless (anything that can
    # intercept the call could choose the identity).
    context = ssl.create_default_context(cafile=ca_path)
    with urllib.request.urlopen(request, timeout=10, context=context) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _serviceaccount_identity() -> str:
    """``system:serviceaccount:<ns>:<name>`` — DERIVED by asking the API server.

    The tempting implementation reads the token's ``sub`` claim, and it is wrong
    for the reason this whole module exists. The STS arm's property is not "the
    credential states who I am" — it is that ``GetCallerIdentity`` is a
    ROUND-TRIP TO THE AUTHORITY. Parsing a JWT this process already holds is an
    assertion dressed as a derivation, and it would happily report an identity
    from an expired, revoked or hand-written token.

    ``SelfSubjectReview`` is the cluster's answer to the same question, and it
    needs no RBAC at all (``system:basic-user`` covers every authenticated
    principal), so this arm adds no standing authority to any ServiceAccount
    [verified 2026-07-27 against a SA with no RoleBinding of any kind].

    Every failure REFUSES. There is no degradation to the solo arm and no
    fallback to a parsed claim: a ceremony that cannot establish who is running
    it must write nothing, which is the #197/#199 shape.
    """
    token = _projected_token()
    if token is None:
        raise BrokerConfigError(
            f"{CEREMONY_IDENTITY_ENV}=serviceaccount but no projected "
            f"ServiceAccount token was found at {SA_TOKEN_PATH} — refusing to "
            "run a ceremony whose identity cannot be established. This arm is "
            "for a process running IN a pod; outside one there is no workload "
            "identity to derive. (A pod with automountServiceAccountToken: "
            "false has deliberately removed its own identity source.)"
        )

    host = os.environ.get("KUBERNETES_SERVICE_HOST", "").strip()
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443").strip() or "443"
    if not host:
        raise BrokerConfigError(
            f"{CEREMONY_IDENTITY_ENV}=serviceaccount but KUBERNETES_SERVICE_HOST "
            "is unset — there is a projected token but no API server to ask who "
            "it belongs to, and this arm derives the identity by asking rather "
            "than by reading the token. Refusing rather than guessing."
        )
    # An IPv6 literal must be bracketed before it can go in a URL authority.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    url = f"https://{host}:{port}/apis/authentication.k8s.io/v1/selfsubjectreviews"
    try:
        payload = _post_selfsubjectreview(token, url, SA_CA_PATH)
    except Exception as exc:  # noqa: BLE001 — every failure is the same refusal
        raise BrokerConfigError(
            f"could not derive the ceremony identity from SelfSubjectReview at "
            f"{url} ({exc!r}) — refusing to run a ceremony without establishing "
            "who is running it."
        ) from exc

    username = ""
    if isinstance(payload, dict):
        status = payload.get("status")
        if isinstance(status, dict):
            user_info = status.get("userInfo")
            if isinstance(user_info, dict):
                username = str(user_info.get("username") or "").strip()
    if not username:
        raise BrokerConfigError(
            "SelfSubjectReview returned no userInfo.username — refusing to "
            "stamp a ceremony record with an empty identity. This usually means "
            "the token was rejected; the API server answers an unauthenticated "
            "request without naming anyone."
        )
    return username


def _sts_identity(session: object = None) -> str:
    """The full STS GetCallerIdentity Arn of the ambient credentials.

    The Arn carries the assumed-role session name, so ceremony records name the
    actual human/pipeline behind the role — derived, never asserted (no --as).

    An AWS-free machine is REFUSED with a pointer at the local arm rather than
    a botocore traceback: this is the wall #226 measured, and the fix is a
    named opt-in, never an automatic fallback.
    """
    try:
        import boto3  # noqa: PLC0415 — lazy, no import-time AWS dependency
        from botocore.exceptions import (  # noqa: PLC0415
            NoCredentialsError,
            NoRegionError,
            PartialCredentialsError,
        )
    except ImportError as exc:
        # `pip install example-wrapper` need not drag in boto3 at all.
        raise BrokerConfigError(_no_aws_guidance(f"boto3 is not installed ({exc})")) from exc

    try:
        client = session.client("sts") if session is not None else boto3.client("sts")
        return client.get_caller_identity()["Arn"]
    except (NoCredentialsError, PartialCredentialsError, NoRegionError) as exc:
        raise BrokerConfigError(_no_aws_guidance(str(exc))) from exc


def _no_aws_guidance(detail: str) -> str:
    return (
        f"cannot derive the ceremony identity from AWS STS ({detail}) and "
        f"{LOCAL_IDENTITY_ENV} is unset — refusing to guess who is running "
        "this ceremony. A record stamps who proposed and who ratified; "
        "substituting that silently is the wrong-authority failure (#197/#199). "
        "Either configure AWS credentials (MakerRole / CheckerRole on the real "
        f"floor), or NAME the local arm: export {LOCAL_IDENTITY_ENV}=maker for "
        "the propose half and =checker for the ratify half, on the local store "
        "arm. The local arm records honestly that one operator held both."
    )


def resolve_ceremony_arm() -> str:
    """Which identity arm is in force — the ONE resolution point.

    Unset keeps the pre-#250 two-way dispatch BYTE-FOR-BYTE, so every existing
    caller (the Mac drills, the container drill, both floors' operator roles) is
    unchanged and no record's attribution moves:

        BROKER_LOCAL_IDENTITY set -> 'local'
        otherwise                 -> 'sts'

    An unrecognized value REFUSES rather than falling through to that default,
    on the #248 reasoning: a typo must not boot the operator into an arm they
    did not name while they believe another is in force.
    """
    named = os.environ.get(CEREMONY_IDENTITY_ENV, "").strip()
    if not named:
        return "local" if os.environ.get(LOCAL_IDENTITY_ENV, "").strip() else "sts"
    if named not in CEREMONY_ARMS:
        raise BrokerConfigError(
            f"{CEREMONY_IDENTITY_ENV}={named!r} is not a recognized ceremony "
            "identity arm — refusing to run: an unrecognized value would fall "
            "through to a DIFFERENT arm than the operator named, and the arm "
            "decides what a signed record's attribution means. Valid values: "
            f"{', '.join(repr(a) for a in CEREMONY_ARMS)}, or unset (the "
            "pre-existing dispatch). This selector names an arm from a CLOSED "
            "catalog; it can never name an identity or a code path."
        )
    return named


def resolve_ceremony_identity(session: object = None) -> str:
    """The identity stamped into proposedBy / ratifiedBy — the ONE derivation.

    Homed here rather than duplicated per command module: the ceremonies must
    not be able to drift apart on who is allowed to run them (extending one copy
    would silently leave the other without an arm).

    All three arms DERIVE. Two of them derive by round-trip to an authority (STS
    GetCallerIdentity; Kubernetes SelfSubjectReview) and the third derives the
    human half from the OS while naming its role from a closed catalog. None of
    them accepts an asserted identity — there is no ``--as`` on any arm.
    """
    arm = resolve_ceremony_arm()
    if arm == "serviceaccount":
        return _serviceaccount_identity()
    if arm == "local":
        return _local_identity(os.environ.get(LOCAL_IDENTITY_ENV, "").strip())
    return _sts_identity(session)


def is_local_identity(identity: str) -> bool:
    """True for an identity minted by the local (solo) arm."""
    return identity.startswith(LOCAL_IDENTITY_PREFIX)


def attestation_for(identity: str) -> str | None:
    """The ledger record's ``attestation`` marker, DERIVED from the identity.

    ``None`` on the STS arm (two IAM-backed credential ARNs — the field is
    absent from every record written before #226, and stays absent for them).
    :data:`SOLO_ATTESTATION` when the identity came from the local arm.

    Deriving it means the marker cannot disagree with the identity it
    describes: there is no separate assertion to get out of step, and a test
    that monkeypatches the identity gets a consistent marker for free.
    """
    return SOLO_ATTESTATION if is_local_identity(identity) else None


def local_role_of(identity: str) -> str | None:
    """The role half of a local identity (``maker`` / ``checker``), else None."""
    if not is_local_identity(identity):
        return None
    _, sep, role = identity.rpartition("#")
    return role if sep else None


def is_same_operator(proposed_by: str, ratifier: str) -> bool:
    """True when these two ceremony identities do NOT form a maker/checker pair.

    Equality is the base case and the only one on the STS arm. The local arm
    adds one: two local identities sharing a ROLE are the same half of the
    ceremony run twice, even when their derived ``user@host`` halves differ —
    which they can, since a hostname is not stable state (a laptop that
    changed networks between propose and ratify would otherwise slip an
    identical role past an equality check and collapse the invariant).

    The role, not the incidental host string, is what carries the meaning on
    the local arm; this makes that explicit instead of hoping.
    """
    if proposed_by == ratifier:
        return True
    maker_role = local_role_of(proposed_by)
    return maker_role is not None and maker_role == local_role_of(ratifier)
