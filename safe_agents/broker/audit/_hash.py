"""Hashing utilities for audit chain construction.

All functions here produce deterministic, one-way digests. Raw args or PII never
leave the broker as plaintext — only their digest travels to the audit store.
"""

import hashlib
import json

# Sentinel prevHash for the chain's genesis record (seq=0).
# SHA-256 of the empty string, prefixed, so it is clearly a real hash format
# rather than an arbitrary magic value.
GENESIS_PREV_HASH = "sha256:" + hashlib.sha256(b"").hexdigest()


def hash_args(args: object) -> str:
    """Return a deterministic SHA-256 digest of args.

    Never embeds raw args in the result — the audit store must not become a PII store.
    The serialization is canonical (sorted keys, compact separators) so the digest is
    stable across Python versions and object orderings.
    """
    serialized = json.dumps(
        args, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return "sha256:" + hashlib.sha256(serialized).hexdigest()


def hash_stored_call(call) -> str:
    """Digest of a frozen BrokeredCall (#198 storedCallDigest).

    Canonical over model_dump(mode="json") so the digest is stable across the
    intent store's JSON round trip (model_dump_json -> model_validate_json).

    Canonicalization dependency (load-bearing): hold-side and release-side digests
    are recomputed INDEPENDENTLY, so equality relies on every BrokeredCall field
    serializing canonically under mode="json". A future field with non-canonical
    JSON form (a set, a NaN/inf float, a non-normalized datetime) would make the
    two digests diverge SILENTLY — the chain stays intact but executed==approved
    stops being provable. Guarded by
    test_stored_call_digest_stable_across_intent_store_roundtrip.
    """
    return hash_args(call.model_dump(mode="json"))


def hash_record(record_fields: dict) -> str:
    """Return a SHA-256 digest over all record fields (which must include prevHash).

    The caller must NOT include the 'hash' key itself — the hash is computed over
    everything else, then stored as 'hash'. This makes any field mutation detectable.
    """
    serialized = json.dumps(
        record_fields, sort_keys=True, separators=(",", ":"), default=str
    ).encode()
    return "sha256:" + hashlib.sha256(serialized).hexdigest()
