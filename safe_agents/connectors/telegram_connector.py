"""TelegramConnector — a real connector for a consumer agent's notify.send grant.

The third real connector on the platform (after github.whoami, example.read), and the
first *write* one: proves a brokered `notify.send` reaches an external API with a
broker-injected credential, not a stub.

The broker injects the credential — the connector never sources it. Telegram needs a
bot token AND a destination chat id; both are bundled into the credential as a JSON
string ('{"bot_token": ..., "chat_id": ...}'), fetched from the SecretsProvider
(secret name resolves to "example-agent/connectors/telegram"). The chat id is
deliberately NOT a caller-supplied arg — only "text" is — so a compromised agent can
ask to send a message but can never choose who receives it. This is the same
"security-relevant facts come from code/config, never the model" principle the static
manifest already applies to effect/external/reversible.

Supported op: "send" — POST to Telegram's sendMessage API with args["text"] and an
optional args["parse_mode"] ("Markdown" default, or "none" for plain text — Telegram
rejects free-form LLM text with unbalanced Markdown, so callers whose text isn't
Markdown-safe pass "none"). parse_mode only affects rendering, never the destination,
so it's safe as a caller-supplied arg unlike chat_id. No other op exists on this
connector.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

_TIMEOUT_SECONDS = 15
_MAX_MESSAGE_LENGTH = 4096  # Telegram's hard per-message cap


class TelegramConnector:
    """Real Telegram connector. Only the Doer holds an instance of this."""

    def execute(self, tool: str, op: str, args: Any, credential: str) -> Any:
        """Send a Telegram message with the broker-injected bot token + chat id.

        Supported op:
            "send" -> POST sendMessage with args["text"] (+ optional args["parse_mode"]).
                      Returns {"message_id": int}.

        Raises ValueError for any other op, missing/oversized text, or a non-ok
        Telegram response.
        """
        if op != "send":
            raise ValueError(
                f"TelegramConnector supports only the 'send' op, got {op!r}"
            )
        text = args.get("text") if isinstance(args, dict) else None
        if not text:
            raise ValueError("TelegramConnector 'send' requires args={'text': ...}")
        if len(text) > _MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"TelegramConnector 'send' text exceeds Telegram's "
                f"{_MAX_MESSAGE_LENGTH}-char limit ({len(text)} chars)"
            )

        creds = json.loads(credential)
        bot_token = creds["bot_token"]
        chat_id = creds["chat_id"]  # the owner's chat — never a model-suppliable arg

        params = {"chat_id": chat_id, "text": text}
        parse_mode = args.get("parse_mode", "Markdown")
        if parse_mode != "none":
            params["parse_mode"] = parse_mode
        data = urllib.parse.urlencode(params).encode()
        request = urllib.request.Request(  # noqa: S310 — fixed https URL, not user input
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data=data,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
            result = json.load(response)
        if not result.get("ok"):
            raise RuntimeError(f"Telegram sendMessage failed: {result}")
        return {"message_id": result["result"]["message_id"]}
