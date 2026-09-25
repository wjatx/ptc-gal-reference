"""Store your own Tavily API key where the broker's 'dir' secrets arm reads it.

    python -m safe_agents.broker.gateway.set_search_key [--dir PATH]

No real key ships in this repository. The default secrets arm holds a placeholder
that Tavily rejects, which is enough to watch the broker decide but not enough to see
a search succeed. This writes your key as the `search` secret leaf, in the JSON shape
the search connector reads (`{"provider": "tavily", "api_key": ...}`), and prints the
one line that points the broker at it.

The key is read with `getpass`, so it is not echoed, and it is deliberately not
accepted as an argument, which would leave it in your shell history. The default
directory is outside the repository (`~/.ptc-gal/secrets`), and a directory inside
it is refused, so the key cannot be committed by accident. The file is written
atomically and, on macOS and Linux, owner-read-only; on Windows it inherits the ACL
of your user profile.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path, PurePath

from safe_agents.broker.runtime.secrets import DirSecretsProvider

SEARCH_SECRET_LEAF = "search"
SEARCH_PROVIDER = "tavily"
DEFAULT_SECRETS_DIR = Path("~") / ".ptc-gal" / "secrets"
TAVILY_KEY_PREFIX = "tvly-"

# The checkout this module was imported from. Editable installs import from the
# working tree, which is exactly the tree a key must stay out of.
_REPO_ROOT = Path(__file__).resolve().parents[3]


class KeyRefused(ValueError):
    """The key or the directory was refused; the message says why."""


def validate_key(key: str) -> str:
    """Light shape check. The authority on whether a key is valid is Tavily."""
    if not key:
        raise KeyRefused("no key entered")
    if any(ch.isspace() for ch in key):
        raise KeyRefused(
            "the key contains whitespace; paste it again without spaces or line breaks"
        )
    return key


def resolve_secrets_dir(raw: str | os.PathLike[str] | None, repo_root: Path = _REPO_ROOT) -> Path:
    """The absolute secrets directory, refusing one inside this checkout."""
    target = Path(raw if raw is not None else DEFAULT_SECRETS_DIR).expanduser().resolve()
    if target == repo_root or repo_root in target.parents:
        raise KeyRefused(
            f"{target} is inside this checkout ({repo_root}), where a key can be "
            f"committed by accident. Use a directory outside it, such as the default "
            f"{DEFAULT_SECRETS_DIR}."
        )
    return target


def write_search_key(secrets_dir: Path, key: str) -> Path:
    """Write the `search` leaf under `secrets_dir`, creating the directory owner-only."""
    secrets_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(secrets_dir, 0o700)
    credential = json.dumps({"provider": SEARCH_PROVIDER, "api_key": key})
    DirSecretsProvider(str(secrets_dir)).store_secret(SEARCH_SECRET_LEAF, credential)
    return secrets_dir / SEARCH_SECRET_LEAF


def export_lines(secrets_dir: PurePath) -> str:
    """The line to paste for each shell, quoted for that shell."""
    posix = str(secrets_dir).replace("'", "'\\''")
    powershell = str(secrets_dir).replace("'", "''")
    return (
        f"  macOS or Linux (bash, zsh):  export BROKER_SECRETS_DIR='{posix}'\n"
        f"  Windows (PowerShell):        $env:BROKER_SECRETS_DIR = '{powershell}'"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safe_agents.broker.gateway.set_search_key",
        description=(
            "Prompt for a Tavily API key (input hidden) and store it as the broker's "
            "'search' secret, outside this repository."
        ),
    )
    parser.add_argument(
        "--dir",
        default=None,
        help=f"secrets directory to write into (default: {DEFAULT_SECRETS_DIR})",
    )
    args = parser.parse_args(argv)

    try:
        secrets_dir = resolve_secrets_dir(args.dir)
        try:
            key = getpass.getpass("Tavily API key (input hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            raise KeyRefused("no key entered") from None
        validate_key(key)
        written = write_search_key(secrets_dir, key)
    except KeyRefused as exc:
        print(f"set_search_key: {exc}. Nothing was written.", file=sys.stderr)
        return 2

    if not key.startswith(TAVILY_KEY_PREFIX):
        print(
            f"Note: Tavily keys usually start with {TAVILY_KEY_PREFIX!r}. Stored anyway; "
            "a wrong key shows up as a failed search, not as an error here."
        )
    print(f"Stored the search credential in {written}")
    print("Point the broker at it in each shell you run it from:")
    print(export_lines(secrets_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
