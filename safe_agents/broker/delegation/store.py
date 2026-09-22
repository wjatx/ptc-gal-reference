"""broker.delegation.store — persistence interface for sub-grants.

Sub-grants are stored in the broker's store (not in the agent's working memory)
so the agent cannot tamper with them. The broker looks up the sub-grant by ID
when the sub-agent presents it on a BrokeredCall.

Two implementations:
  InMemorySubGrantStore  — no AWS, no creds; for tests and local development
  (DynamoDB production implementation is a future concern — tracked by #56)
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .types import AmbiguousSubGrantError, SubGrant

if TYPE_CHECKING:
    from safe_agents.broker.schemas.common import Principal


@runtime_checkable
class SubGrantStore(Protocol):
    """Persistence interface for sub-grant records.

    Sub-grants are written by the broker at issuance and read by the broker
    when a sub-agent makes a BrokeredCall. The agent never reads or writes
    this store directly.
    """

    def save(self, sub_grant: SubGrant) -> None:
        """Persist a newly issued sub-grant.

        Must be durable before the sub-agent is allowed to use it.
        """
        ...

    def get(self, sub_grant_id: str) -> SubGrant | None:
        """Return the sub-grant for this ID, or None if not found."""
        ...

    def get_by_parent(self, parent_grant_id: str) -> list[SubGrant]:
        """Return all sub-grants derived from the given parent grant ID."""
        ...

    def get_by_principal(self, principal: "Principal") -> SubGrant | None:
        """Return the sub-grant held by this principal, or None for a root.

        This is the lookup the ENFORCEMENT path uses, and it is the reason a
        sub-agent never presents anything. A child zone's principal is
        image-baked into its manifest and its sub-grant row is broker-written, so
        the broker resolves the child's derived authority from its own store by
        the principal it already authenticated -- exactly as it resolves a Grant.
        Nothing is read from the call, so there is nothing for a compromised
        child to assert.

        At most ONE sub-grant per principal. A zone is one principal with one
        derived authority, and a sub-grant already carries a LIST of
        actionClasses, so a second row for the same principal is an ambiguity
        about which pool to charge rather than a wider grant. Implementations
        MUST refuse loudly instead of choosing one.
        """
        ...


# ---------------------------------------------------------------------------
# InMemorySubGrantStore — thread-safe fake for tests
# ---------------------------------------------------------------------------


class InMemorySubGrantStore:
    """Thread-safe in-memory implementation for tests and local development.

    No AWS credentials, no network. The locking semantics match what a production
    DynamoDB store would provide.
    """

    def __init__(self) -> None:
        self._store: dict[str, SubGrant] = {}
        self._lock = threading.Lock()

    def save(self, sub_grant: SubGrant) -> None:
        with self._lock:
            self._store[sub_grant.id] = sub_grant

    def get(self, sub_grant_id: str) -> SubGrant | None:
        with self._lock:
            return self._store.get(sub_grant_id)

    def get_by_parent(self, parent_grant_id: str) -> list[SubGrant]:
        with self._lock:
            return [
                sg for sg in self._store.values() if sg.parentGrantId == parent_grant_id
            ]

    def get_by_principal(self, principal: "Principal") -> SubGrant | None:
        """Return this principal's sub-grant, refusing an ambiguous pair."""
        with self._lock:
            matches = [
                sg for sg in self._store.values() if sg.principal == principal
            ]
        if not matches:
            return None
        if len(matches) > 1:
            raise AmbiguousSubGrantError(
                f"principal {principal.agentId}#{principal.skill}#"
                f"{principal.user}#{principal.tier} holds {len(matches)} "
                f"sub-grants ({', '.join(sorted(sg.id for sg in matches))}); "
                "a zone has one derived authority, so which ancestor pool to "
                "charge is undefined"
            )
        return matches[0]

    def all(self) -> list[SubGrant]:
        """Test helper — return all stored sub-grants."""
        with self._lock:
            return list(self._store.values())
