"""grants.standing_source: one role's standing document, as one process holds it.

GAL §6.10 (GAL-41) and §6.15 (GAL-43): a verifier establishes, at the
evaluation instant and from a source it pins, whether the key behind a record
has been withdrawn, and uses no input past a maximum age the deployment declares
for it. ``StandingSource`` is that pinned source for one role.

Where it comes from, and what pins it
-------------------------------------
The source's location, the standing authority's public keys and the maximum age
are bound at deploy (``grants.standing_keys`` reads them from the environment).
None of them is ever read from a store, a grant or a record. ``fetch`` is the
transport: an SSM parameter read or a file read, the same two transports the
flat verify-key map has.

What ``refresh`` accepts
------------------------
A fetched document is accepted only when its signature verifies under a
standing-authority key, it describes this role, it lists no public key twice,
it lists no standing-authority key, it carries every withdrawal this process has
already accepted, its version is greater than the version accepted, no key in
it moves backward or is rebound to a different public key, and no new key id in
it names a key already listed under another id. Anything else is refused and the document
already accepted stays in force until its own age runs out. The same bytes
fetched again change nothing. A refusal is returned as a ``StandingLoad``
verdict; ``refresh`` does not raise for a bad document or a failed fetch.

What these checks buy, and their limit: inside one process, a replayed older
document cannot restore a withdrawn key, and a document rewritten by whoever can
write the parameter but does not hold the standing-authority key is refused.
Across a restart the process remembers nothing. There, a replayed document is
stopped only by its age, because the as-of of a document is never later than
its own ``issuedAt``. That holds while the standing authority does not re-sign
the replay with a fresh ``issuedAt``, which its ceremony refuses to do unless
the operator names the replayed version (``--expect-version``).

How old it is
-------------
The as-of instant is the earlier of the fetch and the document's ``issuedAt``
(``runtime.input_age.InputAsOf``, #176's rule). The document is past its age at
``as_of + max_age`` (``runtime.input_age.end_of``). Fetching the same document
again does not make it younger. The standing authority re-issues the document,
with a higher version and a new ``issuedAt``, at least once per maximum age, or
standing stops being established.

How a caller asks about a key
-----------------------------
``standing_of(key_id, at)`` answers for one key at one instant:

* ``withdrawn``: the key has been seen withdrawn. This holds whatever ``at`` is
  and however old the document is: nothing leaves withdrawn.
* ``not_established``: no document has been accepted, or the accepted one is
  past its maximum age at ``at``. A skew bound moves that end earlier
  (GAL-42), never later, because ``issuedAt`` was stamped by another clock.
* ``unknown_key``: the document is in date and does not list the key.
* ``in_standing``: the document is in date and the key is active or retired.
  A retired key's records keep standing.

``key_state(key_id)`` is the age-free question the record verifier asks: the
state the accepted document records, or None.
"""

from __future__ import annotations

import datetime
import threading
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from safe_agents.broker.grants.key_standing import (
    KEY_WITHDRAWN,
    KeyStandingDocument,
    KeyStandingEntry,
    StandingDocumentRefused,
    check_authority_not_listed,
    check_successor,
    verify_standing_envelope,
)
from safe_agents.broker.runtime.input_age import InputAsOf, end_of, utc_now
from safe_agents.broker.schemas.clock_skew import ZERO_SKEW, end_judged_at
from safe_agents.channels.signing import KeyResolver, load_public_key

Clock = Callable[[], datetime.datetime]

# Load verdicts beyond the refusals in grants.key_standing.
STANDING_ACCEPTED = "accepted"
STANDING_UNCHANGED = "unchanged"
STANDING_UNREADABLE = "unreadable"

# What standing_of answers.
IN_STANDING = "in_standing"
WITHDRAWN = "withdrawn"
NOT_ESTABLISHED = "not_established"
UNKNOWN_KEY = "unknown_key"


@dataclass(frozen=True)
class StandingLoad:
    """The outcome of one ``refresh``: a verdict, the version in force after it, and why."""

    verdict: str
    version: int | None
    detail: str | None = None

    @property
    def accepted(self) -> bool:
        return self.verdict in (STANDING_ACCEPTED, STANDING_UNCHANGED)


@dataclass(frozen=True)
class KeyStanding:
    """One key's standing at one instant, with what the answer rests on."""

    verdict: str
    entry: KeyStandingEntry | None
    version: int | None
    as_of: datetime.datetime | None
    horizon: datetime.datetime | None

    @property
    def in_standing(self) -> bool:
        return self.verdict == IN_STANDING


@dataclass(frozen=True)
class _Accepted:
    """The document in force, swapped whole so a reader never sees half an update."""

    document: KeyStandingDocument
    digest: str
    as_of: InputAsOf
    public_keys: dict[str, Ed25519PublicKey]


class StandingSource:
    """One role's pinned standing source, with this process's accept state.

    Thread-safe: ``refresh`` serializes under a lock, and every reader takes
    one snapshot of the accepted state.
    """

    def __init__(
        self,
        *,
        role: str,
        fetch: Callable[[], str],
        source_label: str,
        authority: KeyResolver,
        authority_key_ids: frozenset[str],
        authority_public_keys: frozenset[bytes],
        max_age: datetime.timedelta,
        clock: Clock = utc_now,
    ) -> None:
        if not isinstance(max_age, datetime.timedelta) or max_age <= datetime.timedelta(0):
            raise ValueError("a standing source needs a positive maximum age")
        self.role = role
        self.source_label = source_label
        self.max_age = max_age
        self._fetch = fetch
        self._authority = authority
        self._authority_key_ids = authority_key_ids
        self._authority_public_keys = authority_public_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._accepted: _Accepted | None = None
        self._seen_withdrawn: dict[str, KeyStandingEntry] = {}

    # -- loading -------------------------------------------------------------

    def refresh(self) -> StandingLoad:
        """Fetch the document and accept it if it may follow the one in force."""
        with self._lock:
            held = self._accepted
            held_version = held.document.version if held else None
            fetched_at = self._clock()
            try:
                text = self._fetch()
            except Exception as exc:  # noqa: BLE001 - a failed fetch is a verdict, never a crash
                return StandingLoad(
                    STANDING_UNREADABLE, held_version, f"{self.source_label}: {type(exc).__name__}"
                )
            try:
                document, digest = verify_standing_envelope(
                    text, authority=self._authority, role=self.role
                )
                if held is not None and digest == held.digest:
                    return StandingLoad(STANDING_UNCHANGED, held_version)
                check_authority_not_listed(
                    document, self._authority_key_ids, self._authority_public_keys
                )
                check_successor(held.document if held else None, document, self._seen_withdrawn)
            except StandingDocumentRefused as exc:
                return StandingLoad(exc.verdict, held_version, exc.detail)
            self._accepted = _Accepted(
                document=document,
                digest=digest,
                as_of=InputAsOf(fetched_at=fetched_at, stated_at=document.issued_at()),
                public_keys={k: load_public_key(e.publicKey) for k, e in document.keys.items()},
            )
            for key_id, entry in document.keys.items():
                if entry.state == KEY_WITHDRAWN:
                    self._seen_withdrawn[key_id] = entry
            return StandingLoad(STANDING_ACCEPTED, document.version)

    # -- reading -------------------------------------------------------------

    @property
    def document(self) -> KeyStandingDocument | None:
        held = self._accepted
        return held.document if held else None

    def as_of(self) -> InputAsOf | None:
        """When the document in force was established (#176's as-of), or None."""
        held = self._accepted
        return held.as_of if held else None

    def horizon(self) -> datetime.datetime | None:
        """The instant the document in force passes its maximum age, or None."""
        held = self._accepted
        return end_of(held.as_of.as_of, self.max_age) if held else None

    def standing_of(
        self,
        key_id: str,
        at: datetime.datetime,
        *,
        skew: datetime.timedelta = ZERO_SKEW,
    ) -> KeyStanding:
        """Is ``key_id`` in standing for this role at ``at``? See the module docstring."""
        if at.tzinfo is None:
            raise ValueError("the evaluation instant must be timezone-aware")
        held = self._accepted
        version = held.document.version if held else None
        as_of = held.as_of.as_of if held else None
        horizon = end_of(as_of, self.max_age) if as_of is not None else None
        seen = self._seen_withdrawn.get(key_id)
        if seen is not None:
            return KeyStanding(WITHDRAWN, seen, version, as_of, horizon)
        if held is None or end_judged_at(at, skew) >= horizon:
            return KeyStanding(NOT_ESTABLISHED, None, version, as_of, horizon)
        entry = held.document.keys.get(key_id)
        if entry is None:
            return KeyStanding(UNKNOWN_KEY, None, version, as_of, horizon)
        return KeyStanding(IN_STANDING, entry, version, as_of, horizon)

    def key_state(self, key_id: str) -> str | None:
        """The state the accepted document records for ``key_id``, age aside."""
        if key_id in self._seen_withdrawn:
            return KEY_WITHDRAWN
        held = self._accepted
        entry = held.document.keys.get(key_id) if held else None
        return entry.state if entry else None

    def known_key_ids(self) -> frozenset[str]:
        held = self._accepted
        return frozenset(held.document.keys) if held else frozenset()

    def key_resolver(self) -> KeyResolver:
        """A resolver over every key the document in force lists, in any state.

        Signatures by retired and withdrawn keys still verify: validity when
        signed is a separate question from standing, which ``key_state`` and
        ``standing_of`` answer.
        """

        def _resolve(key_id: str) -> Ed25519PublicKey | None:
            held = self._accepted
            return held.public_keys.get(key_id) if held else None

        return _resolve
