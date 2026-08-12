"""boot_config.py — the #205 named-config-or-refuse seam for the broker boot.

Doctrine (docs/config-provenance.md; the #197/#199 lesson): authority-shaping
config must be operator-NAMED. On the real-store arm the machine refuses
instead of defaulting or warn-and-continuing, and every refusal fails toward
running nothing / less authority. The local/memory arm keeps every dev
fallback byte-for-byte — the adoption surface stays friendly.

Four refusal seams, all raising :class:`BrokerConfigError` before any store
write or connector call:

  F1  ``resolve_manifest_path`` / ``load_named_manifest`` — BROKER_MANIFEST
      unset on a durable arm (dynamo or sqlite) refuses (the example-manifest
      fallback is memory-arm only).
  F2  ``resolve_hmac_key`` — BROKER_HMAC_KEY unset on a durable arm refuses
      (the fixed dev key is memory-arm only).
  F3  ``require_named_real_backends`` — durable store + memory audit sink or
      fake secrets refuses (was a warn-and-continue).
  F4  ``resolve_counter_cap`` — granted write-effect classes with no
      envelope ``caps.actions_per_utc_day`` refuse the silent platform
      default (message is envelope-source-aware: manifest vs store).
  F5  ``require_sanctioned_grant_load`` — BROKER_GRANT_LOAD=seed on the
      sqlite arm refuses: seed-at-boot blind-upserts manifest-derived grants
      into a DURABLE trust store with no IAM between the broker and the
      table (on the real floor brokerRole is read-only on grants, so
      dynamo+seed is a dev-local-only combination by construction; sqlite
      has no such backstop).

F1–F3 key on ``is_durable_arm`` — dynamo and sqlite alike: a durable store
run under a defaulted manifest, the fixed dev HMAC key, a memory audit sink,
or fake secrets is authority-shaping config the operator never named,
whatever the backend. ``is_dynamo_arm`` remains for the genuinely
Dynamo-specific seams (store construction, table-name resolution).

Plus the arm resolution itself: ``resolve_store_arm`` validates BROKER_STORE
against the CLOSED set {unset, "memory", "dynamo", "sqlite"} — a typo'd value
(``dynamodb``) refuses at boot instead of silently booting the memory arm
with every dev fallback. Since #248 ``resolve_secrets_arm`` gives BROKER_SECRETS
the same treatment against {"file", "dir", "secretsmanager", "fake"}, and is
the ONE point that decides which credential backend is in force — the two sites
that used to test ``== "secretsmanager"`` independently now switch on it.

Split out of broker_server.py (#205 R5) so the refusal seam is one small,
importable module; broker_server re-exports the public names so existing
import surfaces keep working.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from safe_agents.broker.schemas import AgentManifest

if TYPE_CHECKING:
    from safe_agents.broker.manifest import ToolOpTable
    from safe_agents.broker.schemas import Envelope
    from safe_agents.broker.schemas.common import Principal


class BrokerConfigError(ValueError):
    """An authority-shaping config value was defaulted where it must be named (#205).

    Raised at boot / build_runtime, before any store write or connector call — every
    refusal fails toward running nothing, never toward minting authority from a
    fallback (docs/config-provenance.md; the #197/#199 lesson)."""


# The broker builds every agent-specific value from an AgentManifest (principal,
# granted action classes, connectors, per-run cap, envelope) — NOT from module
# constants (de-baking P2, sa#113). This checked-in example is the memory-arm-only
# default; point the broker at a real manifest with BROKER_MANIFEST.
DEFAULT_MANIFEST_PATH = Path(__file__).with_name("example_manifest.yaml")

# Generic platform fallback when a manifest omits envelope.caps.actions_per_utc_day.
# NOT agent-specific — the same ceiling for any agent, the runtime's own default cap
# surfaced as a named constant. A manifest that sets caps.actions_per_utc_day overrides
# it. Since #205 it applies ONLY when no granted class is write-effect: an envelope
# governing granted writes must NAME its cap (resolve_counter_cap refuses the default).
DEFAULT_COUNTER_CAP = 100.0

# Fixed dev HMAC key for grant tamper-evidence on the local/memory arm ONLY.
# Overridable via BROKER_HMAC_KEY; the dynamo arm REQUIRES it (resolve_hmac_key).
DEV_HMAC_KEY = b"safe-agents-dev-hmac-key"

# The CLOSED set of store arms. Unset means "memory" (the AWS-free smoke default);
# anything else must be named exactly — a typo must refuse, not boot the dev arm.
# "sqlite" is the durable LOCAL arm (product-wrapper Phase 1): this session it serves the
# MCP registry + admission-proposal stores (the ceremony CLI); the full broker
# boot on sqlite lands with the counters/intents/envelope/grants slice, and
# build_runtime refuses it loudly until then.
_STORE_ARMS = ("memory", "dynamo", "sqlite")

# The CLOSED set of secrets arms (#248). Config SELECTS from this set; it never
# names an import path (docs/config-provenance.md, #186) — a secrets provider is
# the highest-value possible target for an injected class path.
#
# Before #248 there was no catalog at all: two independent sites tested
# `BROKER_SECRETS == "secretsmanager"` and fell through to BROKER_SECRETS_FILE and
# then to FAKE CREDENTIALS, so a single typo (`secretmanager`) booted green on
# fakes while the operator believed Secrets Manager was in force. That is the
# silent-downgrade shape `resolve_store_arm` already refuses for BROKER_STORE.
_SECRETS_ARMS = ("file", "dir", "secretsmanager", "fake")


def resolve_store_arm() -> str:
    """The store arm from BROKER_STORE: 'memory' (default), 'dynamo', or 'sqlite'.

    An unknown value REFUSES at boot — e.g. a typo'd ``BROKER_STORE=dynamodb``
    must never silently select the memory arm and boot green with every dev
    fallback (fake secrets, dev HMAC key, example manifest)."""
    value = os.environ.get("BROKER_STORE", "memory")
    if value not in _STORE_ARMS:
        raise BrokerConfigError(
            f"BROKER_STORE={value!r} is not a recognized store arm — refusing to "
            "boot: an unrecognized value would silently select the in-memory dev "
            "arm (fake secrets, dev HMAC key, example-manifest fallback) while the "
            "operator believed the real store was in force. Valid values: unset "
            "(= 'memory'), 'memory', 'dynamo', or 'sqlite'."
        )
    return value


def is_dynamo_arm() -> bool:
    """True on the DynamoDB arm (BROKER_STORE=dynamo) — for the genuinely
    Dynamo-specific seams only (store construction, table-name resolution).
    Named-config-or-refuse gates key on :func:`is_durable_arm` instead.
    Refuses (via ``resolve_store_arm``) on an unrecognized BROKER_STORE."""
    return resolve_store_arm() == "dynamo"


def is_durable_arm() -> bool:
    """True on any DURABLE store arm (dynamo or sqlite) — the F1–F3 predicate.

    The local/memory arm (BROKER_STORE unset or 'memory') keeps every dev
    fallback byte-for-byte; a durable arm must NAME its authority-shaping
    config. The sqlite arm joined this predicate with the grants-sqlite slice:
    a durable local store run under the fixed dev HMAC key is tamper-evident
    in name only, and a defaulted manifest on it is the #197/#199
    wrong-authority substitution — the backend being a file instead of a
    table changes none of that."""
    return resolve_store_arm() in ("dynamo", "sqlite")


def load_agent_manifest(path: Path) -> AgentManifest:
    """Read an AgentManifest from a yaml file (broker-side, no pipeline import).

    A minimal ``yaml.safe_load`` + ``model_validate`` — the same
    no-pipeline-dependency posture as ``envelope/seed.py::load_envelope_block`` (the
    broker package must never import ``safe_agents.pipeline``). Raises
    FileNotFoundError if ``path`` is absent, ValueError if it is not a YAML mapping,
    and pydantic.ValidationError if the manifest is malformed (e.g. a missing
    polarity — never silently defaulted).
    """
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(
            f"manifest {path} must be a YAML mapping; got {type(raw).__name__}"
        )
    return AgentManifest.model_validate(raw)


def resolve_manifest_path() -> Path:
    """The manifest path the broker builds from: BROKER_MANIFEST, else (memory arm
    only) the checked-in example. On the dynamo arm an unset BROKER_MANIFEST
    REFUSES — never the example fallback."""
    named = os.environ.get("BROKER_MANIFEST")
    if named:
        return Path(named)
    if is_durable_arm():
        raise BrokerConfigError(
            f"BROKER_STORE={resolve_store_arm()} but BROKER_MANIFEST is unset — "
            "refusing to fall back to the checked-in example manifest "
            "(example_manifest.yaml) on a durable store arm: a defaulted manifest "
            "silently substitutes another agent's principal, grants, and envelope "
            "(#197/#199; docs/config-provenance.md). Export "
            "BROKER_MANIFEST=<path to THIS consumer's manifest>. The "
            "example-manifest fallback stays honored only on the local/memory arm "
            "(BROKER_STORE unset or 'memory')."
        )
    return DEFAULT_MANIFEST_PATH


def load_named_manifest() -> AgentManifest:
    """Load the operator-named (or memory-arm example) manifest, UNCACHED; refuses
    per ``resolve_manifest_path`` on the dynamo arm when none is named. Process-wide
    load-once semantics live in ``broker_server.resolve_manifest``."""
    return load_agent_manifest(resolve_manifest_path())


def resolve_hmac_key() -> bytes:
    """The grant-store HMAC key: BROKER_HMAC_KEY, else (memory arm only) the fixed
    dev key. The dynamo arm must NAME the key the ceremony writes with (#205 — the
    write side, grants/_commands_common.py, already refuses; this is read/write
    symmetry)."""
    hmac_key = os.environ.get("BROKER_HMAC_KEY", "").encode()
    if hmac_key:
        return hmac_key
    if is_durable_arm():
        raise BrokerConfigError(
            f"BROKER_STORE={resolve_store_arm()} but BROKER_HMAC_KEY is unset — "
            "refusing to fall back to the fixed dev HMAC key on a durable store "
            "arm: grants read under the dev key are tamper-evident in name only, "
            "and a key that differs from the one the ceremony wrote with "
            "quarantines every grant. Export BROKER_HMAC_KEY (the same key the "
            "grant ceremony writes with; the Fargate arm injects it from Secrets "
            "Manager). The dev-key fallback stays honored only on the "
            "local/memory arm (BROKER_STORE unset or 'memory')."
        )
    return DEV_HMAC_KEY


def resolve_sqlite_db_path() -> Path:
    """The local store database path on the sqlite arm — NAMED, never defaulted.

    The ONE resolution point for the db path (`example-wrapper migrate` dies a death of a
    thousand env vars otherwise): every sqlite store constructor receives the
    path from here, and no module reads BROKER_SQLITE_PATH itself. Unset
    refuses — a defaulted path would silently open a fresh EMPTY database
    (every admission absent, every call refused) while the operator believed
    their admitted set was in force; loud beats mysteriously-empty."""
    named = os.environ.get("BROKER_SQLITE_PATH")
    if not named:
        raise BrokerConfigError(
            "BROKER_STORE=sqlite but BROKER_SQLITE_PATH is unset — refusing to "
            "default the local store database path: a defaulted path silently "
            "opens a fresh empty database (no admitted tools, no proposals) "
            "while the operator believes their admitted set is in force. Export "
            "BROKER_SQLITE_PATH=<path to this deployment's broker.db>."
        )
    return Path(named)


def resolve_sqlite_grants_db_path() -> Path:
    """Where the CHECKER-WRITABLE key space lives — co-located unless split (#203).

    The grant ceremony's two halves write disjoint key spaces, and the maker's
    half must be structurally unable to write the checker's. On DynamoDB that
    is a `dynamodb:LeadingKeys` condition; a filesystem has no per-identity
    access control on a shared file, so on sqlite the mechanism is **mount
    topology** — ``GRANT#``/``RECORD#``/``TOOLDEF#``/``TOOLREC#`` move to their
    own database file, and the maker mounts that file read-only. The refusal is
    then the kernel's rather than a check of ours, which is the property the
    #250 Phase 3 exit predicate asks for.

    **Unset means co-located, and that is deliberately NOT a #205 violation.**
    The named-or-refuse rule exists because a *defaulted* path silently opens a
    fresh EMPTY database, so the operator believes an admitted set is in force
    when nothing is. That hazard is absent here: the fallback is the path the
    operator ALREADY named through ``BROKER_SQLITE_PATH``, which is the same
    file, with the same contents, that every pre-#203 deployment used. There is
    no empty-database outcome to guess into — an unset value reproduces today's
    behaviour byte for byte, and splitting is an opt-in deployment fact.

    Per the contract-vs-reference lens this stays PACKAGING, not contract: the
    base needs only "these two key spaces may live in different backing
    stores", which the manifests carry. Nothing here lets a caller ask "may I
    write this key?" — that would be the larger, contract-shaped answer and
    nothing has forced it.

    The corresponding risk is a deployment that MEANT to split and typo'd the
    variable: it silently co-locates and the control quietly vanishes. That is
    why the cluster arc ATTEMPTS the forbidden write and asserts the refusal
    rather than trusting the manifest — a split asserted from config is not
    evidence that a split is in force.
    """
    named = os.environ.get("BROKER_SQLITE_GRANTS_PATH")
    if not named:
        return resolve_sqlite_db_path()
    return Path(named)


def resolve_sqlite_grants_readonly() -> bool:
    """Whether the grant-space stores open read-only in THIS process (#203).

    Set in the maker pod, and in the broker pod (which runs
    ``BROKER_GRANT_LOAD=read`` — ``get_grant`` only, never a write). It exists
    because the normal open path writes before it reads anything: it creates
    parent directories, sets a journal-mode pragma, and runs
    ``CREATE TABLE IF NOT EXISTS``. All three fail on a read-only mount, in a
    way that looks like a bug in us rather than the intended refusal.

    **This flag can only ever narrow.** It does not grant write access when
    unset — it selects a read-only open. A process on a read-only mount that
    clears it does not gain the ability to write; it gains a loud open failure.
    So an agent cannot launder authority by flipping it, and the enforcement
    stays entirely in the mount.
    """
    return os.environ.get("BROKER_SQLITE_GRANTS_READONLY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def sqlite_grants_open_options() -> dict:
    """Constructor kwargs for every CHECKER-WRITABLE sqlite store (#203).

    One resolution point, because the journal mode is NOT free to choose:
    journal mode is a persistent property of the database FILE, so when the
    grant space is co-located it must match what every other store opens
    ``broker.db`` with. A second mode on one file would silently flip it under
    the stores already using it. Split ⇒ its own file ⇒ DELETE, which is what
    makes a read-only mount openable at all.
    """
    from safe_agents.broker import sqlite_substrate  # noqa: PLC0415 (cycle-safe)

    path = resolve_sqlite_grants_db_path()
    split = path != resolve_sqlite_db_path()
    return {
        "db_path": path,
        "journal_mode": (
            sqlite_substrate.JOURNAL_DELETE if split else sqlite_substrate.JOURNAL_WAL
        ),
        "read_only": resolve_sqlite_grants_readonly(),
    }


def resolve_secrets_arm() -> str:
    """The secrets arm from BROKER_SECRETS: 'file', 'dir', 'secretsmanager' or 'fake'.

    The ONE place that decides WHICH credential backend is in force (#248). Both
    resolution sites — the broker boot and the MCP operator commands — switch on
    this string; each still composes its own wrappers (the boot overlays dev stubs
    for the stub connectors, an operator invocation deliberately does not), but
    neither re-derives the arm, and neither can reach a provider the catalog does
    not name.

    An unrecognized value REFUSES. Unset keeps the pre-#248 implicit resolution
    byte-for-byte — the path variable selects the arm — so every existing caller
    (run-local.sh, both CDK stacks, the Fargate BROKER_ENV contract) is unchanged:

        BROKER_SECRETS_DIR set   -> 'dir'    (the container arm, #248)
        BROKER_SECRETS_FILE set  -> 'file'   (the 0600 JSON blob, the Mac arm)
        neither                  -> 'fake'   (memory-arm dev default; F3 refuses
                                              this pairing on a durable store)
    """
    value = os.environ.get("BROKER_SECRETS")
    if not value:
        if os.environ.get("BROKER_SECRETS_DIR"):
            return "dir"
        if os.environ.get("BROKER_SECRETS_FILE"):
            return "file"
        return "fake"
    if value not in _SECRETS_ARMS:
        raise BrokerConfigError(
            f"BROKER_SECRETS={value!r} is not a recognized secrets arm — refusing "
            "to boot: an unrecognized value would silently fall through to the "
            "local file provider or, with no file named, to FAKE CREDENTIALS, "
            "while the operator believed the named backend was in force. Valid "
            f"values: {', '.join(repr(a) for a in _SECRETS_ARMS)}, or unset (the "
            "path variable selects the arm: BROKER_SECRETS_DIR -> 'dir', "
            "BROKER_SECRETS_FILE -> 'file', neither -> 'fake')."
        )
    return value


def resolve_secrets_dir() -> Path:
    """The secrets mount directory on the 'dir' arm — NAMED, never defaulted.

    Naming the arm without naming its root is the #205 shape: a defaulted root
    (``/run/secrets``, say) silently resolves every credential against a directory
    the operator never chose — which either misses (a stub credential via the
    overlay fallback) or, worse, hits someone else's mount."""
    named = os.environ.get("BROKER_SECRETS_DIR")
    if not named:
        raise BrokerConfigError(
            "BROKER_SECRETS=dir but BROKER_SECRETS_DIR is unset — refusing to "
            "default the secrets mount directory: every credential would resolve "
            "against a directory the operator never named. Export "
            "BROKER_SECRETS_DIR=<the mount root, one file per secret leaf>."
        )
    return Path(named)


def resolve_secrets_file() -> str:
    """The 0600 JSON credential blob on the 'file' arm — NAMED, never defaulted.

    Symmetric with :func:`resolve_secrets_dir`; reachable only when BROKER_SECRETS
    is explicitly 'file', since the implicit path (unset BROKER_SECRETS) selects
    'file' only when BROKER_SECRETS_FILE is already set."""
    named = os.environ.get("BROKER_SECRETS_FILE")
    if not named:
        raise BrokerConfigError(
            "BROKER_SECRETS=file but BROKER_SECRETS_FILE is unset — refusing to "
            "default the credential file path. Export BROKER_SECRETS_FILE=<path "
            "to the 0600 JSON credential file>, or use BROKER_SECRETS=dir with "
            "BROKER_SECRETS_DIR for a one-file-per-secret mount."
        )
    return named


def require_named_real_backends(audit_label: str, secrets_label: str) -> None:
    """F3 — a DURABLE store (dynamo or sqlite) paired with a non-durable audit
    sink or fake credentials is never a sanctioned combination: it looks like a
    real run but loses the audit tape on restart and/or serves a fake connector
    credential. Was a warn-and-continue; since #205 a refusal at boot (fails
    toward running nothing)."""
    if is_durable_arm() and (audit_label == "memory" or secrets_label == "fake"):
        raise BrokerConfigError(
            f"BROKER_STORE={resolve_store_arm()} with audit={audit_label}, "
            f"secrets={secrets_label} — refusing to boot a durable store with a "
            "non-durable audit sink and/or fake credentials. Set "
            "BROKER_AUDIT_BUCKET (S3 WORM) or BROKER_AUDIT_PATH (local "
            "hash-chained file), and BROKER_SECRETS=secretsmanager or "
            "BROKER_SECRETS_FILE, for a durable arm; or run BROKER_STORE=memory "
            "for an AWS-free smoke."
        )


def require_sanctioned_grant_load(mode: str) -> None:
    """F5 — BROKER_GRANT_LOAD=seed refuses on the sqlite arm.

    Seed mode blind-upserts manifest-derived grants at every boot — a dev
    smoke convenience. On DynamoDB the real floor is protected structurally
    (brokerRole is read-only on the grants table, so dynamo+seed only ever
    works against DynamoDB Local); the sqlite arm has no IAM between the
    broker process and the file, so seed mode there would silently mint
    grants into a durable trust store on every boot — the #197/#199 shape.
    Grants on the sqlite arm come from the ceremony (the #226 solo-identity
    ceremony is the local path); until then ``read`` serves what the ceremony
    wrote (fail-closed: absent ⇒ denied) and ``skip`` is the construction
    smoke."""
    if mode == "seed" and resolve_store_arm() == "sqlite":
        raise BrokerConfigError(
            "BROKER_GRANT_LOAD=seed is not sanctioned on BROKER_STORE=sqlite — "
            "seed mode blind-upserts manifest-derived grants at boot, which on a "
            "durable local trust store is an unceremonied authority mint "
            "(#197/#199; docs/config-provenance.md). Use BROKER_GRANT_LOAD=read "
            "to serve ceremony-written grants (absent grants are denied, "
            "fail-closed) or BROKER_GRANT_LOAD=skip for a construction smoke. "
            "On DynamoDB this combination is confined to DynamoDB Local by IAM "
            "(brokerRole cannot write grants); sqlite has no such backstop, so "
            "the refusal is the backstop."
        )


def resolve_counter_cap(
    envelope: Envelope,
    granted_classes: list[str],
    optable: ToolOpTable,
    principal: Principal,
    envelope_source: str,
) -> float:
    """F4 — the per-op daily counter cap from the in-force envelope.

    The generic platform fallback (``DEFAULT_COUNTER_CAP``) is honored only when
    NO granted class is write-effect — an envelope governing granted writes must
    NAME its daily cap; silently handing writes the default is a defaulted
    authority grant, refused at build. (A granted class with no tool_ops entry is
    inert — the PEP denies it — so it cannot trip this.)

    ``envelope_source`` is the ``BROKER_ENVELOPE_LOAD`` mode in force
    ("manifest" | "store"): the remedy differs — a store-loaded envelope is fixed
    by RE-SEEDING it (seed_envelope), not by editing the manifest the broker
    isn't reading the envelope from.
    """
    caps = envelope.caps
    if caps is not None and caps.actions_per_utc_day is not None:
        return float(caps.actions_per_utc_day)
    write_classes = sorted(
        c
        for c in granted_classes
        if "." in c
        and (entry := optable.entry(*c.split(".", 1))) is not None
        and entry.effect == "write"
    )
    if write_classes:
        if envelope_source == "store":
            remedy = (
                "The envelope in force is STORE-loaded (BROKER_ENVELOPE_LOAD=store), "
                "so re-seed it with caps.actions_per_utc_day set — add the cap to "
                "the envelope manifest and run broker.prototype.seed_envelope "
                "(100 preserves the old default) — or drop the write classes from "
                "grant_classes."
            )
        else:
            remedy = (
                "Set envelope.caps.actions_per_utc_day explicitly in the manifest "
                "(100 preserves the old default), or drop the write classes from "
                "grant_classes."
            )
        raise BrokerConfigError(
            f"the in-force envelope for principal {principal.agentId!r} governs "
            f"granted write-effect action classes {write_classes} but names no "
            "caps.actions_per_utc_day — refusing to fall back to the implicit "
            f"platform default of {DEFAULT_COUNTER_CAP:g}/day for granted writes. "
            f"{remedy}"
        )
    return DEFAULT_COUNTER_CAP


@contextlib.contextmanager
def grant_load_suppressed():
    """Scope BROKER_GRANT_LOAD=skip to a broker_server import (side-effect
    suppression) WITHOUT leaking it into the process env (#210): a bare
    module-level setdefault poisoned later same-process callers — e.g.
    build_runtime resolving grant-load mode to 'skip' and serving an empty
    registry — with test-order-dependent failures as the visible symptom."""
    had = "BROKER_GRANT_LOAD" in os.environ
    os.environ.setdefault("BROKER_GRANT_LOAD", "skip")
    try:
        yield
    finally:
        if not had:
            del os.environ["BROKER_GRANT_LOAD"]
