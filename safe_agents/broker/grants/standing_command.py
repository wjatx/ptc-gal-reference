"""The standing ceremony: the only sanctioned way a signing key's state changes.

    python -m safe_agents.broker.grants.standing_command \\
        {init,add,retire,withdraw,reissue} --role {issuer,evaluator} [--zone Z] \\
        [--expect-version N] [--from PATH] [--out PATH]

init      version 1 of a role's standing document, with one active key
          (--key-id, --public-key-file). Refused where the role's configured
          source already holds a document.
add       add an active key (--key-id, --public-key-file). A key id or a public
          key already in the document is refused, whatever its state: a key
          is never reused.
retire    an active key becomes retired (--key-id, --reason superseded |
          cessationOfOperation). Every record it signed keeps standing.
withdraw  an active or retired key becomes withdrawn (--key-id, --reason
          keyCompromise | privilegeWithdrawn). Terminal. No record it signed has
          standing, whatever that record's ts.
reissue   the same keys at the next version with a new issuedAt. A document is
          established for at most its role's maximum age counted from its
          issuedAt, so the standing authority reissues at least that often.

There is no hold state, no reinstate and no command that moves a key backward.
A key that must be trusted again is a new key pair, added under a new key id;
``add`` refuses a public key already in the document under any id.

Every command but ``init`` takes ``--expect-version N``, the version the
operator last issued, from the operator's own record. The command refuses
unless the current document is exactly that version. A verifier refuses a
replayed older document by its version and its withdrawals, but this command
re-signs whatever it builds on with a fresh ``issuedAt``. Without the check,
an older document written back to the source (or a stale ``--from``) would be
signed again as the next version, with a withdrawal it had dropped, and a
process that had not seen the withdrawal would accept it.

Every command runs under the THIRD signing role, the standing authority
(``STANDING_AUTHORITY_SIGNING_KEY_SECRET_ARN`` or ``..._FILE``, ``..._KEY_ID``,
``..._ZONE`` or ``--zone``), and refuses to run without it: an unsigned standing
document is never accepted, so writing one would only break every verifier.
The command reads the current document from the role's configured source
(``<ROLE>_STANDING_PARAM`` or ``<ROLE>_STANDING_FILE``) or ``--from``, verifies
it under ``STANDING_AUTHORITY_VERIFY_KEYS_PARAM`` / ``..._FILE`` before building
on it, signs the next version, verifies its own output as a verifier would, and
writes it to ``--out`` or back to the configured source.

What a successful run buys, and no more: the next version is signed by the
standing authority, follows the version the operator expected, and follows it
under every rule a verifier applies (grants/key_standing.py). It is only as
good as the operator's record of the last version issued. It does not reach any verifier until that
verifier fetches it, and until then the previous version is the one in force.

Exit codes: 0 written; 1 refused (a transition the rules forbid, or a document
that would not verify); 2 configuration error.
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from safe_agents.broker.grants import issuer_keys
from safe_agents.broker.grants.issuer_keys import (
    EVALUATOR_ROLE_ENV,
    ISSUER_ROLE_ENV,
    IssuerSigningConfigError,
    SigningRoleEnv,
    resolve_standing_signer,
)
from safe_agents.broker.grants.key_standing import (
    RETIRED_REASONS,
    WITHDRAWN_REASONS,
    KeyStandingDocument,
    StandingDocumentRefused,
    StandingTransitionError,
    add_key,
    check_authority_not_listed,
    next_document,
    public_key_raw,
    retire_key,
    sign_standing_document,
    verify_standing_envelope,
    withdraw_key,
)
from safe_agents.broker.grants.record_signing import RecordSigner
from safe_agents.broker.grants.standing_keys import AuthorityKeys, resolve_standing_authority_keys

ROLE_ENVS: dict[str, SigningRoleEnv] = {
    ISSUER_ROLE_ENV.role: ISSUER_ROLE_ENV,
    EVALUATOR_ROLE_ENV.role: EVALUATOR_ROLE_ENV,
}

COMMANDS = ("init", "add", "retire", "withdraw", "reissue")


def _put_parameter(name: str, value: str) -> None:
    """Overwrite an SSM String parameter (monkeypatched in tests)."""
    import boto3  # noqa: PLC0415 - lazy, no import-time AWS dependency

    boto3.client("ssm").put_parameter(Name=name, Value=value, Type="String", Overwrite=True)


def _write_file(path: str, value: str) -> None:
    """Replace ``path`` atomically, so a verifier never reads half a document."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _configured_source(role_env: SigningRoleEnv) -> tuple[str, str] | None:
    """("param" | "file", location) for the role's configured source, or None."""
    param = os.environ.get(role_env.standing_param_env or "")
    path = os.environ.get(role_env.standing_file_env or "")
    if param and path:
        raise IssuerSigningConfigError(
            f"both {role_env.standing_param_env} and {role_env.standing_file_env} are set; "
            "set exactly one"
        )
    if param:
        return "param", param
    if path:
        return "file", path
    return None


def _read_current(
    role_env: SigningRoleEnv, from_path: str | None, authority: AuthorityKeys
) -> KeyStandingDocument | None:
    """The current document, verified under the standing authority, or None if absent."""
    source = ("file", from_path) if from_path else _configured_source(role_env)
    if source is None:
        return None
    kind, location = source
    try:
        text = (
            issuer_keys._fetch_parameter(location)
            if kind == "param"
            else issuer_keys._read_verify_keys_file(location)
        )
    except FileNotFoundError:
        return None
    except Exception as exc:
        if type(exc).__name__ == "ParameterNotFound":
            return None  # noqa: BLE001 - surfaced as a refusal with its type
        raise IssuerSigningConfigError(
            f"the current {role_env.role} standing document at {location} could not be read "
            f"({type(exc).__name__})"
        ) from exc
    document, _digest = verify_standing_envelope(
        text, authority=authority.resolver, role=role_env.role
    )
    return document


def _signer_is_an_authority_key(signer: RecordSigner, authority: AuthorityKeys) -> bool:
    """True iff the signing key is published under its own key id as an authority key."""
    published: Ed25519PublicKey | None = authority.resolver(signer.key_id)
    if published is None:
        return False
    raw = published.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw == signer.public_key_raw()


def standing_command(
    args: argparse.Namespace,
    *,
    signer: RecordSigner | None,
    authority: AuthorityKeys | None,
    now: datetime.datetime,
    write: Callable[[str, str, str], None] | None = None,
) -> int:
    """Run one standing transition. Store-free and AWS-free when ``write`` is injected."""
    role_env = ROLE_ENVS[args.role]
    if signer is None:
        print(
            "REFUSED: a standing document is signed by the standing authority; set "
            f"{issuer_keys.STANDING_AUTHORITY_SIGNING_KEY_SECRET_ARN_ENV} (or "
            f"{issuer_keys.STANDING_AUTHORITY_SIGNING_KEY_FILE_ENV} on the local arm), "
            f"{issuer_keys.STANDING_AUTHORITY_SIGNING_KEY_ID_ENV} and a zone"
        )
        return 1
    if authority is None:
        print(
            "REFUSED: no standing-authority verify keys are configured "
            f"({issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_PARAM_ENV} or "
            f"{issuer_keys.STANDING_AUTHORITY_VERIFY_KEYS_FILE_ENV}); a document no "
            "verifier can check is never written"
        )
        return 1
    if not _signer_is_an_authority_key(signer, authority):
        print(
            f"REFUSED: signing key {signer.key_id!r} is not published under that key id "
            "in the standing-authority verify keys, so no verifier would accept its output"
        )
        return 1
    try:
        current = _read_current(role_env, args.from_path, authority)
        _check_expected_version(args, current)
        keys = _apply(args, current, now)
        document = next_document(
            current, role=args.role, keys=keys, issued_at=now, signer=signer
        )
        check_authority_not_listed(document, authority.key_ids, authority.public_keys)
        text = sign_standing_document(document, signer)
        verify_standing_envelope(text, authority=authority.resolver, role=args.role)
    except (StandingTransitionError, StandingDocumentRefused) as exc:
        print(f"REFUSED: {exc}")
        return 1
    destination = _destination(args, role_env)
    (write or _write)(destination[0], destination[1], text)
    entry = document.keys.get(getattr(args, "key_id", None) or "")
    change = f" key={args.key_id} state={entry.state}" if entry is not None else ""
    print(
        f"STANDING: role={args.role} version={document.version} issuedAt={document.issuedAt}"
        f"{change} signedBy={signer.key_id} written to {destination[0]} {destination[1]}"
    )
    if args.command == "withdraw":
        print(
            "NOTE: no record this key signed has standing from the moment a verifier "
            "accepts this version. A verifier still holding the previous version acts "
            "on it until it fetches this one or that version passes its maximum age."
        )
    return 0


def _check_expected_version(
    args: argparse.Namespace, current: KeyStandingDocument | None
) -> None:
    """Refuse to build on any document but the version the operator last issued."""
    expected = getattr(args, "expect_version", None)
    if args.command == "init" or current is None:
        return
    if current.version != expected:
        raise StandingTransitionError(
            f"the current {args.role} standing document is version {current.version}, "
            f"not the expected version {expected}. An older document written back to "
            "the source, or a stale --from, is never built on: it may lack a "
            "withdrawal. Check the source against the last version issued"
        )


def _apply(args: argparse.Namespace, current: KeyStandingDocument | None, now: datetime.datetime):
    if args.command == "init":
        if current is not None:
            raise StandingTransitionError(
                f"a {args.role} standing document already exists (version {current.version}); "
                "use add, retire, withdraw or reissue"
            )
        return add_key({}, args.key_id, _read_pem(args.public_key_file))
    if current is None:
        raise StandingTransitionError(
            f"there is no current {args.role} standing document to change; run init first, "
            "or name it with --from"
        )
    if args.command == "add":
        return add_key(current.keys, args.key_id, _read_pem(args.public_key_file))
    if args.command == "retire":
        return retire_key(current.keys, args.key_id, args.reason, now)
    if args.command == "withdraw":
        return withdraw_key(current.keys, args.key_id, args.reason, now)
    return dict(current.keys)  # reissue


def _read_pem(path: str) -> str:
    pem = Path(path).read_text(encoding="utf-8")
    try:
        public_key_raw(pem)
    except ValueError as exc:
        raise StandingTransitionError(f"{path} is not an Ed25519 public key PEM ({exc})") from exc
    return pem


def _destination(args: argparse.Namespace, role_env: SigningRoleEnv) -> tuple[str, str]:
    if args.out:
        return "file", args.out
    configured = _configured_source(role_env)
    if configured is None:
        raise IssuerSigningConfigError(
            f"nowhere to write: pass --out, or set {role_env.standing_param_env} or "
            f"{role_env.standing_file_env}"
        )
    return configured


def _write(kind: str, location: str, text: str) -> None:
    if kind == "param":
        _put_parameter(location, text)
    else:
        _write_file(location, text)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.grants.standing_command",
        description="Change a signing key's standing (GAL §6.10, GAL-41) under the standing authority.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        cmd = sub.add_parser(name)
        cmd.add_argument("--role", required=True, choices=sorted(ROLE_ENVS))
        cmd.add_argument("--zone", default=None)
        cmd.add_argument("--from", dest="from_path", default=None)
        cmd.add_argument("--out", default=None)
        if name != "init":
            cmd.add_argument(
                "--expect-version",
                type=int,
                required=True,
                help="the version of the current document, as last issued",
            )
        if name in ("init", "add", "retire", "withdraw"):
            cmd.add_argument("--key-id", required=True)
        if name in ("init", "add"):
            cmd.add_argument("--public-key-file", required=True)
        if name == "retire":
            cmd.add_argument("--reason", required=True, choices=RETIRED_REASONS)
        if name == "withdraw":
            cmd.add_argument("--reason", required=True, choices=WITHDRAWN_REASONS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return standing_command(
            args,
            signer=resolve_standing_signer(zone=args.zone),
            authority=resolve_standing_authority_keys(),
            now=datetime.datetime.now(datetime.UTC),
        )
    except IssuerSigningConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
