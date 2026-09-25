"""The Tavily key helper (`python -m safe_agents.broker.gateway.set_search_key`).

The property that matters most is where the key does NOT go: not onto the command
line, not into the checkout, not onto the screen. Then that what it writes is what
the broker's 'dir' arm and the search connector read back.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path, PurePosixPath

import pytest

from safe_agents.broker.gateway import set_search_key as helper
from safe_agents.broker.runtime.secrets import DirSecretsProvider

_KEY = "tvly-dev-0123456789abcdef"


@pytest.fixture
def prompt(monkeypatch: pytest.MonkeyPatch):
    """Answer getpass with `answer`, recording the prompt it was asked with."""
    asked: list[str] = []

    def install(answer: str | BaseException) -> list[str]:
        def fake_getpass(prompt: str = "") -> str:
            asked.append(prompt)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        monkeypatch.setattr(helper.getpass, "getpass", fake_getpass)
        return asked

    return install


def test_writes_the_credential_the_dir_arm_and_connector_read(
    tmp_path: Path, prompt, capsys: pytest.CaptureFixture[str]
) -> None:
    asked = prompt(_KEY + "\n")
    target = tmp_path / "secrets"

    assert helper.main(["--dir", str(target)]) == 0

    assert asked == ["Tavily API key (input hidden): "]
    stored = DirSecretsProvider(str(target)).fetch_secret("search")
    assert json.loads(stored) == {"provider": "tavily", "api_key": _KEY}
    out = capsys.readouterr().out
    assert _KEY not in out, "the key was echoed to the terminal"
    assert f"export BROKER_SECRETS_DIR='{target.resolve()}'" in out
    assert f"$env:BROKER_SECRETS_DIR = '{target.resolve()}'" in out


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits; Windows uses the profile ACL")
def test_directory_and_file_are_owner_only(tmp_path: Path, prompt) -> None:
    prompt(_KEY)
    target = tmp_path / "secrets"
    assert helper.main(["--dir", str(target)]) == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE((target / "search").stat().st_mode) == 0o600


def test_the_key_is_never_accepted_as_an_argument(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        helper.main(["--dir", str(tmp_path), _KEY])


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        ("", "no key entered"),
        ("   ", "no key entered"),
        ("tvly-abc def", "contains whitespace"),
        (EOFError(), "no key entered"),
        (KeyboardInterrupt(), "no key entered"),
    ],
)
def test_refused_keys_write_nothing(
    tmp_path: Path, prompt, capsys: pytest.CaptureFixture[str], answer, reason: str
) -> None:
    prompt(answer)
    target = tmp_path / "secrets"
    assert helper.main(["--dir", str(target)]) == 2
    err = capsys.readouterr().err
    assert reason in err and "Nothing was written." in err
    assert not (target / "search").exists()


def test_a_directory_inside_the_checkout_is_refused(prompt, capsys: pytest.CaptureFixture[str]) -> None:
    asked = prompt(_KEY)
    inside = helper._REPO_ROOT / "spec" / "secrets"
    assert helper.main(["--dir", str(inside)]) == 2
    assert asked == [], "prompted for a key it was always going to refuse to store"
    assert "inside this checkout" in capsys.readouterr().err
    assert not inside.exists()


def test_the_default_directory_is_in_the_home_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert helper.resolve_secrets_dir(None) == (tmp_path / ".ptc-gal" / "secrets").resolve()


def test_a_key_without_the_usual_prefix_is_stored_with_a_note(
    tmp_path: Path, prompt, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt("0123456789abcdef")
    assert helper.main(["--dir", str(tmp_path / "s")]) == 0
    assert "usually start with 'tvly-'" in capsys.readouterr().out


def test_export_lines_quote_for_each_shell() -> None:
    lines = helper.export_lines(PurePosixPath("/tmp/it's here"))
    assert "export BROKER_SECRETS_DIR='/tmp/it'\\''s here'" in lines
    assert "$env:BROKER_SECRETS_DIR = '/tmp/it''s here'" in lines
