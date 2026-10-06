"""The network MCP mouth's authenticator catalog and refusal ledger — SDK-free.

No `mcp` SDK, no socket and no ASGI here, by design: who may speak on the mouth is
decided by `gateway/authn.py`, which imports only the standard library, so it is
tested the same way. `test_gateway_network.py` proves the check sits in front of a
request; `test_gateway_network_e2e.py` proves it over a real socket.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from safe_agents.broker.gateway.authn import (
    ADMITTED,
    AUTH_ENV,
    MIN_TOKEN_CHARS,
    TOKEN_FILE_ENV,
    ConnectionFacts,
    GatewayAuthConfigError,
    LaunchToken,
    MouthAuthenticator,
    RefusalCause,
    RefusalLedger,
    read_launch_token,
    resolve_authenticator,
)

TOKEN = "t0ken-" + "a" * 40
OTHER = "t0ken-" + "b" * 40


def _bearer(token: str = TOKEN) -> tuple[bytes, ...]:
    return (f"Bearer {token}".encode(),)


def write_token(path: Path, content: str | bytes = TOKEN, mode: int = 0o600) -> Path:
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    os.chmod(path, mode)
    return path


class TestCatalog:
    def test_the_catalog_is_exactly_one_built_arm_and_two_reserved_names(self) -> None:
        assert {member.value for member in MouthAuthenticator} == {
            "launch_token",
            "oauth_bearer",
            "mtls_workload_identity",
        }

    @pytest.mark.parametrize(
        ("env", "words"),
        [
            pytest.param({}, "is unset", id="unnamed"),
            pytest.param({AUTH_ENV: ""}, "is unset", id="empty name"),
            pytest.param({AUTH_ENV: "none"}, "not a recognized authenticator", id="none"),
            pytest.param({AUTH_ENV: "LAUNCH_TOKEN"}, "not a recognized authenticator", id="wrong case"),
            pytest.param(
                {AUTH_ENV: "my.module:Authenticator"},
                "not a recognized authenticator",
                id="an import path selects nothing",
            ),
            pytest.param({AUTH_ENV: "oauth_bearer"}, "NOT YET IMPLEMENTED", id="reserved oauth"),
            pytest.param(
                {AUTH_ENV: "mtls_workload_identity"}, "NOT YET IMPLEMENTED", id="reserved mtls"
            ),
            pytest.param({AUTH_ENV: "launch_token"}, f"{TOKEN_FILE_ENV} is unset", id="no token file"),
            pytest.param(
                {AUTH_ENV: "launch_token", TOKEN_FILE_ENV: ""},
                f"{TOKEN_FILE_ENV} is unset",
                id="empty token file name",
            ),
        ],
    )
    def test_startup_refuses_in_words(self, env: dict[str, str], words: str) -> None:
        with pytest.raises(GatewayAuthConfigError) as refusal:
            resolve_authenticator(env)
        assert words in str(refusal.value)
        assert "refusing to start" in str(refusal.value)

    def test_a_token_value_in_the_environment_is_never_read(self, tmp_path: Path) -> None:
        """The token arrives as a file its launcher wrote. A value in an
        environment variable, under any plausible name, authenticates nothing."""
        env = {
            AUTH_ENV: "launch_token",
            "BROKER_GATEWAY_TOKEN": TOKEN,
            "BROKER_GATEWAY_LAUNCH_TOKEN": TOKEN,
        }
        with pytest.raises(GatewayAuthConfigError):
            resolve_authenticator(env)

    def test_the_named_arm_is_built_from_its_file(self, tmp_path: Path) -> None:
        env = {AUTH_ENV: "launch_token", TOKEN_FILE_ENV: str(write_token(tmp_path / "t"))}
        authenticator = resolve_authenticator(env)
        assert authenticator.name is MouthAuthenticator.LAUNCH_TOKEN
        assert authenticator.check(ConnectionFacts(authorization=_bearer())) is ADMITTED


class TestTokenFile:
    @pytest.mark.parametrize(
        ("content", "words"),
        [
            pytest.param(b"", "is empty", id="empty file"),
            pytest.param(b"\n", "is empty", id="only a newline"),
            pytest.param(b"short", "at least", id="too short"),
            pytest.param(("a" * (MIN_TOKEN_CHARS - 1)).encode(), "at least", id="one under the floor"),
            pytest.param(("a" * 40 + " b").encode(), "cannot carry", id="a space"),
            pytest.param(("a" * 40 + "\n\n").encode(), "cannot carry", id="two newlines"),
            pytest.param(("é" * 40).encode(), "ASCII", id="not ascii"),
            pytest.param(b"a" * 5000, "larger than", id="oversized"),
        ],
    )
    def test_an_unusable_token_refuses(self, tmp_path: Path, content: bytes, words: str) -> None:
        path = write_token(tmp_path / "token", content)
        with pytest.raises(GatewayAuthConfigError) as refusal:
            read_launch_token(str(path))
        assert words in str(refusal.value)
        assert TOKEN_FILE_ENV in str(refusal.value)

    def test_the_floor_is_thirty_two_characters(self, tmp_path: Path) -> None:
        """G14 states the number, so the number is pinned here as a number and
        not as whatever the constant currently says."""
        assert MIN_TOKEN_CHARS == 32
        with pytest.raises(GatewayAuthConfigError, match="at least"):
            read_launch_token(str(write_token(tmp_path / "under", b"a" * 31)))
        assert read_launch_token(str(write_token(tmp_path / "at", b"a" * 32))) == "a" * 32

    @pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"], ids=["bare", "lf", "crlf"])
    def test_one_trailing_newline_is_dropped(self, tmp_path: Path, ending: bytes) -> None:
        path = write_token(tmp_path / "token", TOKEN.encode() + ending)
        assert read_launch_token(str(path)) == TOKEN

    def test_a_missing_file_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(GatewayAuthConfigError, match="could not be read"):
            read_launch_token(str(tmp_path / "absent"))

    def test_a_directory_refuses(self, tmp_path: Path) -> None:
        os.chmod(tmp_path, 0o700)
        with pytest.raises(GatewayAuthConfigError, match="not a regular file"):
            read_launch_token(str(tmp_path))

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    @pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660], ids=oct)
    def test_a_token_readable_beyond_its_owner_refuses(self, tmp_path: Path, mode: int) -> None:
        path = write_token(tmp_path / "token", mode=mode)
        with pytest.raises(GatewayAuthConfigError, match="readable beyond its owner"):
            read_launch_token(str(path))

    def test_a_refusal_never_quotes_the_token(self, tmp_path: Path) -> None:
        secret = "s3cret-but-too-short"
        path = write_token(tmp_path / "token", secret)
        with pytest.raises(GatewayAuthConfigError) as refusal:
            read_launch_token(str(path))
        assert secret not in str(refusal.value)


class TestLaunchTokenCheck:
    @pytest.mark.parametrize(
        ("facts", "expected"),
        [
            pytest.param(ConnectionFacts(), RefusalCause.MISSING_CREDENTIAL, id="no header"),
            pytest.param(
                ConnectionFacts(authorization=_bearer(OTHER)),
                RefusalCause.WRONG_TOKEN,
                id="wrong token",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(TOKEN[:-1])),
                RefusalCause.WRONG_TOKEN,
                id="a prefix of the token",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(TOKEN + "x")),
                RefusalCause.WRONG_TOKEN,
                id="the token and more",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer("x")),
                RefusalCause.WRONG_TOKEN,
                id="one character",
            ),
            pytest.param(
                ConnectionFacts(authorization=(f"Basic {TOKEN}".encode(),)),
                RefusalCause.WRONG_SCHEME,
                id="basic scheme",
            ),
            pytest.param(
                ConnectionFacts(authorization=(TOKEN.encode(),)),
                RefusalCause.WRONG_SCHEME,
                id="no scheme at all",
            ),
            pytest.param(
                ConnectionFacts(authorization=(b"Bearer",)),
                RefusalCause.MALFORMED_CREDENTIAL,
                id="scheme and nothing else",
            ),
            pytest.param(
                ConnectionFacts(authorization=(b"Bearer   ",)),
                RefusalCause.MALFORMED_CREDENTIAL,
                id="scheme and spaces",
            ),
            pytest.param(
                ConnectionFacts(authorization=(f"Bearer {TOKEN} extra".encode(),)),
                RefusalCause.MALFORMED_CREDENTIAL,
                id="two words after the scheme",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer() + _bearer()),
                RefusalCause.MALFORMED_CREDENTIAL,
                id="two authorization headers, both right",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(OTHER) + _bearer()),
                RefusalCause.MALFORMED_CREDENTIAL,
                id="two authorization headers, one right",
            ),
            pytest.param(
                ConnectionFacts(query_string=f"access_token={TOKEN}".encode()),
                RefusalCause.CREDENTIAL_IN_QUERY,
                id="token only in the query",
            ),
            pytest.param(
                ConnectionFacts(query_string=f"token={TOKEN}".encode()),
                RefusalCause.CREDENTIAL_IN_QUERY,
                id="token under the short name",
            ),
            pytest.param(
                ConnectionFacts(query_string=f"x=1&ACCESS_TOKEN={TOKEN}".encode()),
                RefusalCause.CREDENTIAL_IN_QUERY,
                id="token in the query, upper case, not first",
            ),
            pytest.param(
                ConnectionFacts(
                    authorization=_bearer(), query_string=f"access_token={TOKEN}".encode()
                ),
                RefusalCause.CREDENTIAL_IN_QUERY,
                id="right header AND a token in the query",
            ),
            # The token is compared as the exact bytes presented. Each of these is a
            # way a comparison gets loosened by someone being helpful, and each would
            # shrink the space a guesser has to search or admit a credential that
            # was never issued.
            pytest.param(
                ConnectionFacts(authorization=_bearer(TOKEN.upper())),
                RefusalCause.WRONG_TOKEN,
                id="the token in another case",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(TOKEN + "=")),
                RefusalCause.WRONG_TOKEN,
                id="the token with padding added",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(f'"{TOKEN}"')),
                RefusalCause.WRONG_TOKEN,
                id="the token in quotes",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(TOKEN.replace("-", "%2D"))),
                RefusalCause.WRONG_TOKEN,
                id="the token percent-encoded",
            ),
            pytest.param(
                ConnectionFacts(authorization=(f"BearerX {TOKEN}".encode(),)),
                RefusalCause.WRONG_SCHEME,
                id="a scheme that only starts with Bearer",
            ),
            pytest.param(ConnectionFacts(authorization=_bearer()), ADMITTED, id="right token"),
            pytest.param(
                ConnectionFacts(authorization=(f"bearer {TOKEN}".encode(),)),
                ADMITTED,
                id="scheme is case-insensitive",
            ),
            pytest.param(
                ConnectionFacts(authorization=_bearer(), query_string=b"cursor=3"),
                ADMITTED,
                id="an unrelated query parameter",
            ),
        ],
    )
    def test_verdict(self, facts: ConnectionFacts, expected: object) -> None:
        assert LaunchToken(TOKEN).check(facts) is expected

    def test_the_comparison_is_constant_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pinned structurally: the verdict comes from `hmac.compare_digest` over
        two equal-length digests, never from `==` on the presented bytes."""
        from safe_agents.broker.gateway import authn

        seen: list[tuple[int, int]] = []
        real = authn.hmac.compare_digest

        def spy(a: bytes, b: bytes) -> bool:
            seen.append((len(a), len(b)))
            return real(a, b)

        monkeypatch.setattr(authn.hmac, "compare_digest", spy)
        token = LaunchToken(TOKEN)
        for presented in (TOKEN, OTHER, "x", TOKEN * 3):
            token.check(ConnectionFacts(authorization=_bearer(presented)))
        assert seen == [(32, 32)] * 4

    def test_the_authenticator_does_not_keep_or_show_the_token(self) -> None:
        token = LaunchToken(TOKEN)
        assert TOKEN not in repr(token)
        assert TOKEN not in repr(vars(token))
        assert TOKEN.encode() not in vars(token).values()


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class TestRefusalLedger:
    def _ledger(self, **kwargs):
        written: list[dict[str, int]] = []
        clock = _Clock()
        ledger = RefusalLedger(lambda counts: written.append(dict(counts)), clock=clock, **kwargs)
        return ledger, written, clock

    def test_the_first_refusal_is_recorded_at_once(self) -> None:
        ledger, written, _ = self._ledger()
        ledger.refuse(RefusalCause.WRONG_TOKEN)
        assert written == [{"wrong_token": 1}]
        assert ledger.pending == {}

    def test_a_flood_inside_one_window_writes_one_record_and_loses_no_count(self) -> None:
        """The property the ledger exists for: an unauthenticated party cannot
        grow the tape one record per attempt, and no attempt goes uncounted."""
        ledger, written, clock = self._ledger(window_s=60.0)
        for _ in range(10_000):
            ledger.refuse(RefusalCause.WRONG_TOKEN)
            clock.now += 0.001
        assert written == [{"wrong_token": 1}]
        assert ledger.pending == {"wrong_token": 9_999}

        clock.now += 60.0
        ledger.refuse(RefusalCause.MISSING_CREDENTIAL)
        assert written[1] == {"missing_credential": 1, "wrong_token": 9_999}
        assert len(written) == 2
        assert sum(sum(record.values()) for record in written) == 10_001

    def test_records_are_bounded_by_windows_not_by_attempts(self) -> None:
        ledger, written, clock = self._ledger(window_s=60.0)
        for _ in range(600):  # ten minutes, one refusal a second
            ledger.refuse(RefusalCause.WRONG_TOKEN)
            clock.now += 1.0
        assert len(written) == 10
        ledger.close()
        assert sum(sum(record.values()) for record in written) == 600

    def test_an_authenticated_request_flushes_what_is_due_and_only_then(self) -> None:
        ledger, written, clock = self._ledger(window_s=60.0)
        ledger.refuse(RefusalCause.WRONG_TOKEN)
        ledger.refuse(RefusalCause.WRONG_TOKEN)
        ledger.flush_if_due()
        assert len(written) == 1
        clock.now += 61.0
        ledger.flush_if_due()
        assert written[1] == {"wrong_token": 1}

    def test_close_records_the_tail_and_is_quiet_when_there_is_none(self) -> None:
        ledger, written, _ = self._ledger()
        ledger.close()
        assert written == []
        ledger.refuse(RefusalCause.WRONG_SCHEME)
        ledger.refuse(RefusalCause.WRONG_SCHEME)
        ledger.close()
        assert written == [{"wrong_scheme": 1}, {"wrong_scheme": 1}]

    def test_a_failed_record_keeps_the_counts_and_retries_at_the_window(self) -> None:
        clock = _Clock()
        attempts: list[dict[str, int]] = []
        healthy = False

        def record(counts) -> None:
            attempts.append(dict(counts))
            if not healthy:
                raise OSError("tape unavailable")

        ledger = RefusalLedger(record, window_s=60.0, clock=clock)
        ledger.refuse(RefusalCause.WRONG_TOKEN)  # raises inside, must not propagate
        ledger.refuse(RefusalCause.WRONG_TOKEN)
        assert len(attempts) == 1, "a broken tape is retried once a window, not per refusal"
        assert ledger.pending == {"wrong_token": 2}

        healthy = True
        clock.now += 60.0
        ledger.refuse(RefusalCause.WRONG_TOKEN)
        assert attempts[-1] == {"wrong_token": 3}
        assert ledger.pending == {}

    def test_what_is_recorded_is_only_cause_codes_and_counts(self) -> None:
        ledger, written, _ = self._ledger()
        for cause in RefusalCause:
            ledger.refuse(cause)
        ledger.close()
        vocabulary = {cause.value for cause in RefusalCause}
        for record in written:
            assert set(record) <= vocabulary
            assert all(isinstance(count, int) for count in record.values())
