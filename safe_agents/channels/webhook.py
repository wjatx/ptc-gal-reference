"""channels.webhook — the signed-webhook inbound adapter (reference-tier).

The first concrete `InboundAdapter` (channels/adapters.py), shaped for the
A2A wire: a peer zone POSTs an `EventTrigger` envelope as a JSON body, proving
transport authenticity with a secret-token header. Each peer holds its own
token, and the token names the peer: the airlock's webhook secret is a map from
channel identity to token (`parse_token_map`). Reference-tier per
docs/contract-vs-reference.md — it binds the contract-tier interfaces to the
webhook transport and is exercised by the same conformance idiom the ABCs are.

No transport client, no consumer identity, and no channel-specific literal
beyond the webhook shape lives here — the airlock stays channel-agnostic
(channels/ADAPTERS.md §"What an adapter is").
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from safe_agents.channels.adapters import InboundAdapter
from safe_agents.channels.schemas import EventTrigger

if TYPE_CHECKING:  # config lives in manifest.py; type-only import avoids an import cycle
    from safe_agents.channels.manifest import WebhookAdapterConfig

# The shape every refusal below names. No refusal message carries a token, an
# identity, or any other part of the document: the document is the secret, and
# a map written the wrong way round would put a token where an identity goes.
TOKEN_MAP_SHAPE = '{"<channel_identity>": "<token>", ...}'


class WebhookTokenMapError(ValueError):
    """The webhook secret is not a usable identity-to-token map.

    Raised at load, which fails the airlock's cold start: with no usable map
    there is no way to authenticate anyone. The message names the fault and
    the expected shape, never a value from the secret.
    """


# What a parsed non-object is called in the refusal, in JSON's own words.
_JSON_TYPE_NAMES = {list: "array", int: "number", float: "number", bool: "boolean", type(None): "null"}


def _refuse(fault: str) -> WebhookTokenMapError:
    return WebhookTokenMapError(
        f"webhook token secret {fault}; it must be a JSON object of the form {TOKEN_MAP_SHAPE}, "
        f"one entry per peer, keyed by the trust map's channel_identity"
    )


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # The default parser keeps the last of two equal keys silently, so a second
    # entry for one identity would replace the first with nothing said.
    seen: dict[str, object] = {}
    for name, value in pairs:
        if name in seen:
            raise _refuse("names one identity more than once")
        seen[name] = value
    return seen


def parse_token_map(secret: str) -> dict[str, str]:
    """Parse the webhook secret's `SecretString` into a canonical identity → token map.

    Refused, by name: a bare string (the shared single-token form this airlock
    no longer accepts), anything that is not a JSON object, an empty object,
    and every fault `canonical_token_map` refuses.
    """
    try:
        document = json.loads(secret, object_pairs_hook=_no_duplicate_keys)
    except WebhookTokenMapError:
        raise
    except Exception as exc:
        # `from None`: a JSON decode error carries the document it was parsing,
        # and that document is the secret. A bare token is not JSON, so the old
        # shared form lands here.
        raise _refuse(
            f"is not a JSON object ({type(exc).__name__}); a bare token string, the shared "
            f"single-token form, is no longer accepted"
        ) from None
    if isinstance(document, str):
        raise _refuse(
            "is a bare string; the shared single-token form is no longer accepted"
        )
    if not isinstance(document, dict):
        raise _refuse(f"is a JSON {_JSON_TYPE_NAMES.get(type(document), 'value')}, not an object")
    return canonical_token_map(document)


def canonical_token_map(tokens: Mapping[str, object]) -> dict[str, str]:
    """Validate an identity → token map and canonicalize its identities.

    Each identity is canonicalized with the adapter's one rule, the rule gate 2
    and the trust map see. Refused: an empty map, an empty identity, two
    identities that canonicalize to one, a token that is not a non-empty
    string, a token or identity that is not encodable as UTF-8 (a lone
    surrogate, which a JSON `\\u` escape can carry), and one token under two
    identities (a token must name exactly one sender, or gate 2 could not say
    which it is).
    """
    if not tokens:
        raise _refuse("is an empty object, which authenticates no one")
    canonical: dict[str, str] = {}
    for raw_identity, token in tokens.items():
        if not isinstance(token, str) or not token:
            raise _refuse("holds a token that is not a non-empty string")
        if not _encodable(token):
            raise _refuse("holds a token that is not encodable as UTF-8")
        identity = _canonical_identity(raw_identity) if isinstance(raw_identity, str) else ""
        if not identity:
            raise _refuse("holds an empty identity")
        if not _encodable(identity):
            raise _refuse("holds an identity that is not encodable as UTF-8")
        if identity in canonical:
            raise _refuse("names one identity twice once identities are canonicalized")
        canonical[identity] = token
    if len(set(canonical.values())) != len(canonical):
        raise _refuse("gives one token to more than one identity")
    return canonical


def _encodable(text: str) -> bool:
    # Checked here so the refusal is by name: Python's own UnicodeEncodeError
    # names the offending character and its position, which is part of the secret.
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


@dataclass(frozen=True)
class WebhookRequest:
    """The transport-neutral request the Lambda handler and tests both build.

    `headers` is lowercase-keyed (the handler lowercases API Gateway's headers
    before constructing this); `body` is the decoded request body as text.
    """

    headers: dict[str, str]
    body: str


class SignedWebhookAdapter(InboundAdapter):
    """Secret-token webhook adapter: the peer POSTs an EventTrigger as JSON.

    Each peer holds its own token. `verify_token` (gate 1) compares the
    configured header against every peer's token in constant time, and
    `extract_identity` (gate 2) returns the identity the presented token is
    bound to. Neither reads the body. `normalize` (gate 3) parses the JSON body
    and rejects a body whose `sender.channel_type` disagrees with this
    adapter's own type, so a peer cannot pose as a different channel. The
    body's `sender.channel_identity` is bound to the token by the dispatcher's
    gate-3 check against the gate-2 identity, so a peer cannot pose as another
    peer either.
    """

    # The gate-1 credential is one sender's own token, so a sender that passes
    # gate 1 is authenticated as the identity gate 2 returns.
    credential_per_sender = True

    def __init__(self, config: "WebhookAdapterConfig", tokens: Mapping[str, str]) -> None:
        # channel_type is instance state (from config), satisfying the ABC's
        # `channel_type: str` — the airlock resolves the trust map against it.
        self.channel_type = config.channel_type
        self._token_header = config.token_header
        # Compared as bytes: `hmac.compare_digest` refuses a non-ASCII str, and
        # a header is whatever the caller sent.
        self._tokens = tuple(
            (identity, token.encode("utf-8"))
            for identity, token in canonical_token_map(tokens).items()
        )

    def _matching_identities(self, request: Any) -> list[str]:
        """Every identity whose token equals the presented header.

        Reads the header only. Every entry is compared, whatever an earlier
        comparison found, so the time taken does not say which entry matched.
        """
        provided = request.headers.get(self._token_header)
        if not isinstance(provided, str):
            return []
        try:
            presented = provided.encode("utf-8")
        except UnicodeEncodeError:  # a lone surrogate matches no token: fail gate 1, never raise
            return []
        flags = [hmac.compare_digest(presented, token) for _, token in self._tokens]
        return [identity for (identity, _), matched in zip(self._tokens, flags) if matched]

    def verify_token(self, request: Any) -> bool:
        return len(self._matching_identities(request)) == 1

    def extract_identity(self, request: Any) -> str:
        # The identity is the one the presented token names, never one the
        # body claims. Tokens are unique per identity (canonical_token_map), so
        # a request that passed gate 1 matches exactly one entry and this
        # cannot raise after gate 1; if it did, dispatch's gate 2 drops
        # `malformed`.
        matched = self._matching_identities(request)
        if len(matched) != 1:
            raise ValueError("the presented token names no single identity")
        return matched[0]

    def normalize(self, request: Any) -> EventTrigger:
        # This call IS the schema gate (channels/ADAPTERS.md §InboundAdapter);
        # pydantic ValidationErrors propagate → dispatch's gate 3 drops `malformed`.
        envelope = EventTrigger.model_validate(json.loads(request.body))
        if envelope.sender.channel_type != self.channel_type:
            raise ValueError(
                f"sender.channel_type {envelope.sender.channel_type!r} does not match "
                f"adapter channel_type {self.channel_type!r}"
            )
        # The emitted envelope must carry the SAME identity the trust map matched:
        # dedupe_key() keys on sender.channel_identity, so a casing/whitespace wire
        # variant would otherwise give a mapped sender a fresh dedupe key per spelling
        # (unlimited replays of one event_id past gate 6). The dispatcher then
        # refuses a body whose canonical identity is not the token's
        # (`sender_identity_mismatch`).
        canonical = _canonical_identity(envelope.sender.channel_identity)
        if canonical != envelope.sender.channel_identity:
            envelope = envelope.model_copy(
                update={
                    "sender": envelope.sender.model_copy(
                        update={"channel_identity": canonical}
                    )
                }
            )
        return envelope


def _canonical_identity(raw: str) -> str:
    """The adapter's one normalization rule; gates 5 and 6 must see the same value."""
    return raw.strip().casefold()
