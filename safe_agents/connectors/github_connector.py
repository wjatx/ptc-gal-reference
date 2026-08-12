"""GitHubConnector — a real, read-only connector for the local-arm prototype.

This is the first *real* connector wired into the prototype broker: it makes a live,
read-only call to the GitHub REST API so the local arm exercises the full broker path
end to end (decide → enforce → doer → connector → audit) against an actual external
service, not a stub.

The broker injects the credential — the connector never sources it. The Doer fetches
the GitHub token from the SecretsProvider (secret name "github") and passes it here as
``credential``; the agent never sees it.

Read-only by construction: the only supported op is "whoami" (GET /user). No write op
exists on this connector, so even a fully compromised agent that reaches it can only
ask "who am I". stdlib urllib only — no new dependencies.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

_GITHUB_USER_URL = "https://api.github.com/user"
_TIMEOUT_SECONDS = 15


class GitHubConnector:
    """Real read-only GitHub connector. Only the Doer holds an instance of this."""

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        """Execute a read-only GitHub op with the broker-injected token.

        Supported op:
            "whoami" -> GET /user, returns {"login": <login>}.

        Raises ValueError for any other op — the connector exposes no write path.
        """
        if op != "whoami":
            raise ValueError(
                f"GitHubConnector supports only the read-only 'whoami' op, got {op!r}"
            )
        request = urllib.request.Request(  # noqa: S310 — fixed https URL, not user input
            _GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {credential}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "safe-agents-broker",
            },
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
            data = json.load(response)
        return {"login": data.get("login")}
