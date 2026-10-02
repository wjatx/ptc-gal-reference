"""No unpinned third-party fetch in anything the arms bake, build or boot.

Every external download in this project is exact-version pinned and hash verified.
The thing prevented is a convenience that lets a maintainer bake in something
dangerous without knowing it: an installer piped to a shell, a `latest` URL, an
`npm install` that resolves afresh on every bake.

Scanned: tracked files under `safe_agents/` and `examples/` that are `*.sh`,
`*.tmpl`, `Containerfile*` or Image Builder `component-*.yaml`, plus files of those
kinds not yet added that git does not ignore. Comment lines are ignored. The sanctioned ways to download are a literal
`fetch_verified URL SHA256 DEST` call (toolchain/fetch-verified.sh) and the
canonical inline form (toolchain/README.md); every pair they carry must be a line
of toolchain/artifacts.lock.

The rules, by id:

  unverified-fetch    a curl or wget whose response body is KEPT, in any way but the
                      two sanctioned ones; also a Containerfile `ADD <url>` and an
                      Image Builder `WebDownload` action
  pipe-to-shell       a curl or wget whose response body is RUN
  fetch-not-literal   a `fetch_verified` call whose url or hash is not a literal,
                      so it cannot be checked against the lock
  npm-install         `npm install` / `i` / `add` / `update` (only `npm ci` installs)
  pip-install         `pip install` / `pip3 install` / `python -m pip install` /
                      `uv pip install` without `--require-hashes` or `--no-index`
  tool-install        `uv tool install|run`, `uvx`, `pipx`, `npx`, `npm exec`
  repo-or-rpm-by-url  `dnf` / `yum` / `rpm` / `zypper` given an http(s) URL,
                      `--add-repo`, `add-apt-repository`
  image-unpinned      a `FROM` or `COPY --from=` image, or any image named on a
                      public registry, without `@sha256:<digest>`
  latest-lookup       an http(s) URL with a `latest` path or file-name segment

The line between a fetch and a probe is WHERE THE RESPONSE BODY GOES, never which
host is called. A body is KEPT when curl writes it to a path other than /dev/null
(`-o`, `-O`, `> file`, wget's default) or pipes it to an unpacker or writer (`tar`,
`unzip`, `gunzip`, `tee`, ...). It is RUN when it reaches a shell or interpreter:
`| sh`, `| sudo bash -`, `sh -c "$(curl ...)"`, `eval "$(curl ...)"`,
`bash <(curl ...)`. A body that is discarded (`-o /dev/null`, `> /dev/null`),
captured into a shell variable, or read by a filter (`grep`, `jq`, `python3 -c`) is
a probe or an API call and is left alone: nothing it returned is installed. That is
what keeps run-brokered.sh, smoke-egress.sh and drain.sh out of scope.

Deliberately not flagged:

  * `dnf` / `apt-get install` of named distribution packages. The distribution
    signs them and the baked image is the pin. Adding a third-party repository or
    installing an RPM by URL is flagged.
  * `aws s3 cp`. Those are first-party bundles this project builds and uploads.
  * `FROM ${VAR}`. A build-arg base is the caller's choice of first-party image.
  * `latest` on the instance metadata address or loopback: `/latest/` there is the
    metadata API's own version segment, and nothing third-party answers.

What the scan cannot see: a command reached through a variable (`"$PIP" install`,
`$CURL -o`, `eval "$cmd"`), a wrapper it does not know followed by a shell, a
command substitution that spans physical lines without a backslash, a download
made by anything but curl or wget (`git clone`, `go install`, `helm repo add`, a
`python3 -c` that opens a URL), and any file kind not listed above (JSON recipes,
agent manifests, Kubernetes manifests, workflow files).

The rules are implemented in fetch_rules.py, beside this module. This module holds
their statement, the allow-list of today's violations, and the tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest
import yaml

from safe_agents.arms.tests.fetch_rules import HELPER_RELPATH, REPO_ROOT, RULES, is_scanned_kind, pins, scan, scanned_files

TOOLCHAIN = REPO_ROOT / "safe_agents" / "arms" / "toolchain"

# ALLOWED: the unpinned fetches that exist TODAY, as a count per rule per file.
#
# Every entry is debt. The install scripts have not been converted to verified
# fetches yet, and this list is what keeps the suite green until they are. It may
# only shrink: the test fails when a file has a violation not counted here, and
# equally when a count here is no longer reached, so converting a file forces its
# entry down or out in the same change. One file per line, so conversions that land
# separately merge without conflict. Never add to it to make a new fetch pass.
ALLOWED: dict[str, dict[str, int]] = {
    "safe_agents/arms/ec2/ami/image-builder/component-base.yaml": {"npm-install": 1, "pip-install": 1, "unverified-fetch": 1},
    "safe_agents/arms/fargate/Containerfile.agent": {"image-unpinned": 1, "npm-install": 1, "unverified-fetch": 1},
    "safe_agents/arms/local/Containerfile": {"image-unpinned": 1, "npm-install": 1},
    "safe_agents/arms/rhel_openshell/ami/image-builder/component-base.yaml": {"latest-lookup": 2, "npm-install": 1, "pip-install": 2, "pipe-to-shell": 2, "repo-or-rpm-by-url": 3, "tool-install": 1, "unverified-fetch": 1},
    "safe_agents/arms/rhel_openshell/bootstrap/scripts/install-k8s-tools.sh": {"latest-lookup": 3, "unverified-fetch": 7},
    "safe_agents/arms/rhel_openshell/bootstrap/scripts/install-languages.sh": {"pipe-to-shell": 1, "unverified-fetch": 1},
    "safe_agents/arms/rhel_openshell/bootstrap/scripts/install-openshell.sh": {"pipe-to-shell": 1},
    "safe_agents/arms/rhel_openshell/bootstrap/scripts/install-python-env.sh": {"pip-install": 3, "pipe-to-shell": 1, "tool-install": 1},
    "safe_agents/arms/rhel_openshell/bootstrap/scripts/install-tools.sh": {"latest-lookup": 1, "pipe-to-shell": 1, "repo-or-rpm-by-url": 2, "unverified-fetch": 2},
    "safe_agents/arms/rhel_openshell/bootstrap/scripts/setup-claude.sh": {"npm-install": 1},
    "safe_agents/arms/rhel_openshell/user-data.sh.tmpl": {"latest-lookup": 1, "repo-or-rpm-by-url": 1, "unverified-fetch": 1},
}


def audit(root: Path = REPO_ROOT, allowed: dict[str, dict[str, int]] | None = None) -> list[str]:
    """Compare what the scan finds with the allow-list. Returns the failures, each
    naming a file, a line and a rule."""
    allowed = ALLOWED if allowed is None else allowed
    files = scanned_files(root)
    failures: list[str] = []
    for relpath in sorted(set(files) | set(allowed)):
        violations = scan(relpath, (root / relpath).read_text(encoding="utf-8")) if relpath in files else []
        counts = Counter(violation.rule for violation in violations)
        debt = allowed.get(relpath, {})
        for rule in sorted(set(counts) | set(debt)):
            have, may = counts[rule], debt.get(rule, 0)
            if have > may:
                failures.append(f"{relpath}: {have} `{rule}` found, {may} allowed. Pin the fetch; do not raise the count.")
                failures += [f"  {relpath}:{v.line}: {rule}: {v.text[:160]}" for v in violations if v.rule == rule]
            elif have < may:
                failures.append(
                    f"{relpath}: ALLOWED counts {may} `{rule}` but only {have} remain. "
                    f"Lower the entry to {have}" + (" (delete it)." if not have else ".")
                )
    return failures


# --- the tests ---------------------------------------------------------------------


def test_no_unpinned_third_party_fetch():
    assert scanned_files(), "the scan found no files to look at"
    failures = audit()
    assert not failures, "unpinned third-party fetches (see this module's docstring):\n" + "\n".join(failures)


def test_every_fetched_pair_is_a_line_in_the_lock():
    """`update-artifact-pin.py --check`: every (url, sha256) a tracked file fetches is
    in artifacts.lock, the lock is well formed, and each line is used or listed unused."""
    errors = pins.check(REPO_ROOT)
    assert not errors, "\n".join(errors)


def test_the_lock_is_in_the_form_the_updater_writes():
    text = (TOOLCHAIN / "artifacts.lock").read_text(encoding="utf-8")
    assert pins.parse_lock(text).render() == text


def test_allow_list_names_only_known_rules_and_is_sorted():
    assert list(ALLOWED) == sorted(ALLOWED)
    assert {rule for debt in ALLOWED.values() for rule in debt} <= set(RULES)


@pytest.mark.parametrize(
    "relpath",
    [
        "safe_agents/arms/rhel_openshell/bootstrap/scripts/install-tools.sh",
        "safe_agents/arms/rhel_openshell/user-data.sh.tmpl",
        "safe_agents/arms/rhel_openshell/ami/image-builder/component-base.yaml",
        "safe_agents/arms/ec2/ami/image-builder/component-base.yaml",
        "safe_agents/arms/fargate/Containerfile.agent",
        "safe_agents/arms/local/Containerfile",
        "examples/restricted_mcp_server/Containerfile.broker",
    ],
)
def test_the_scan_reaches_each_kind_of_file(relpath):
    """Once ALLOWED is empty, a scan that quietly stopped looking at a file kind would
    pass. This names one real file of each kind and fails if the scan skips it."""
    assert relpath in scanned_files()


def test_the_helper_is_the_only_file_exempt_from_the_scan():
    of_scanned_kinds = {name for name in pins.tracked_files(REPO_ROOT) if is_scanned_kind(name)}
    assert of_scanned_kinds - set(scanned_files()) == {HELPER_RELPATH}


def _pin() -> tuple[str, str]:
    pin = pins.parse_lock((TOOLCHAIN / "artifacts.lock").read_text(encoding="utf-8")).pins[0]
    return pin.url, pin.sha256


def _inline(dest: str = "/tmp/a.bin") -> str:
    url, sha256 = _pin()
    return pins.INLINE_TEMPLATE.format(url=url, sha256=sha256, dest=dest)


def _call(dest: str = "/tmp/a.bin") -> str:
    return "fetch_verified {} {} {}".format(*_pin(), dest)


# One new violation of each rule, as it would be written in a shell script.
SHELL_VIOLATIONS = [
    ("unverified-fetch", "curl -fsSL https://example.com/tool-1.2.3.tar.gz -o /tmp/tool.tar.gz"),
    ("unverified-fetch", 'curl -LO "https://example.com/v${VERSION}/tool.tar.gz"'),
    ("unverified-fetch", "curl -fsSL https://example.com/tool-1.2.3.tar.gz | tar -xz -C /usr/local"),
    ("unverified-fetch", "curl -fsSL https://example.com/gpg.key > /etc/pki/rpm-gpg/KEY"),
    ("unverified-fetch", "wget -q https://example.com/tool-1.2.3.tar.gz"),
    ("unverified-fetch", "in_ns curl -sS https://example.com/x | jq -r .body > /opt/x.json"),
    ("pipe-to-shell", "curl -fsSL https://example.com/install.sh | sh"),
    ("pipe-to-shell", "curl -LsSf https://example.com/install.sh | env INSTALL_DIR=/usr/local/bin sh"),
    ("pipe-to-shell", "curl -fsSL https://example.com/setup | $SUDO bash -"),
    ("pipe-to-shell", "wget -qO- https://example.com/install.sh | sudo -E bash"),
    ("pipe-to-shell", 'sh -c "$(curl -fsSL https://example.com/install.sh)"'),
    ("pipe-to-shell", "bash <(curl -fsSL https://example.com/install.sh)"),
    ("pipe-to-shell", 'eval "$(curl -fsSL https://example.com/env)"'),
    ("pipe-to-shell", "curl -fsSL https://example.com/get.py | python3 -"),
    ("pipe-to-shell", "(curl -fsSL https://example.com/install.sh; echo) | sh"),
    ("pipe-to-shell", "{ curl -fsSL https://example.com/install.sh; } | sudo bash"),
    ("pipe-to-shell", 'echo "$(curl -fsSL https://example.com/install.sh)" | sh'),
    ("fetch-not-literal", 'fetch_verified "$URL" "$SHA" /tmp/x'),
    ("npm-install", "npm install -g some-package"),
    ("npm-install", "$SUDO npm i --global some-package"),
    ("pip-install", "pip install --user ruff"),
    ("pip-install", "/opt/venv/bin/pip install --quiet boto3"),
    ("pip-install", "python3 -m pip install --upgrade pip"),
    ("pip-install", "uv pip install ruff"),
    ("tool-install", "uv tool install ruff"),
    ("tool-install", "uvx ruff check ."),
    ("tool-install", "pipx install ruff"),
    ("tool-install", "npx some-package"),
    ("repo-or-rpm-by-url", "dnf install -y https://example.com/pkg-1.0.rpm"),
    ("repo-or-rpm-by-url", "$SUDO dnf config-manager --add-repo https://example.com/tool.repo"),
    ("repo-or-rpm-by-url", "rpm --import https://example.com/RPM-GPG-KEY"),
    ("image-unpinned", "podman run --rm docker.io/library/alpine:3.20 true"),
    ("image-unpinned", "IMG=registry.access.redhat.com/ubi9/ubi-minimal"),
    ("latest-lookup", "V=$(curl -fsSL https://api.github.com/repos/o/r/releases/latest | jq -r .tag_name)"),
    ("latest-lookup", 'echo "see https://example.com/dist/latest/notes"'),
]

CONTAINERFILE_VIOLATIONS = [
    ("image-unpinned", "FROM node:22-slim"),
    ("image-unpinned", "FROM --platform=linux/amd64 docker.io/library/python:3.12-slim AS build"),
    ("image-unpinned", "COPY --from=ghcr.io/astral-sh/uv:0.12.22 /uv /usr/local/bin/uv"),
    ("unverified-fetch", "ADD https://example.com/tool-1.2.3.tar.gz /opt/"),
    ("unverified-fetch", "RUN set -eux; \\\n    curl -fsSL https://example.com/t-1.zip -o /tmp/t.zip; \\\n    unzip -q /tmp/t.zip"),
    ("pipe-to-shell", "RUN curl -fsSL https://example.com/install.sh | sh"),
    ("npm-install", "RUN npm install -g some-package"),
    ("pip-install", 'RUN pip install --no-cache-dir ".[aws]"'),
]

# Things that look like fetches and are not, or are fetches done the sanctioned way.
CLEAN_SHELL = [
    "dnf install -y --allowerasing git jq unzip tar curl wget python3-pip npm pipx",
    "apt-get install -y --no-install-recommends curl ca-certificates unzip",
    "$SUDO dnf install -y htop bat ripgrep 2>/dev/null || true",
    "dnf config-manager --set-enabled crb",
    'if curl -sS -m5 https://api.telegram.org >/dev/null 2>&1; then echo "FAIL: reachable"; fi',
    "smoke_code=\"$(curl -sS -m8 -o /dev/null -w '%{http_code}' \"https://api.anthropic.com/\" 2>/dev/null)\"",
    "curl -sS -m8 -o /dev/null -w '%{http_code}' https://api.anthropic.com/ 2>/dev/null | grep -qE '^[0-9]{3}$'",
    'toolcall_out="$(curl -sS -m20 -X POST "http://${BROKER}:${TOOL_PORT}/call" -H "Content-Type: application/json" -d "$body")"',
    'runuser -u agent -- curl -sS -m20 -X POST "http://${BROKER}:${TOOL_PORT}/call" -d "$body"',
    'token="$(curl -sS -m5 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)"',
    'IMDS="http://169.254.169.254/latest"',
    'aws s3 cp "s3://${S3_BUCKET}/${S3_KEY}" /tmp/agent-bundle.tar.gz',
    "command -v curl >/dev/null 2>&1 || exit 1",
    "npm ci --omit=dev",
    "python -m pip install --require-hashes -r requirements/dev.txt",
    'python -m pip install --no-index --no-build-isolation -e ".[dev]"',
    'podman run -d --name sa-broker --network "$NET" "$BROKER_IMG"',
    'log "Installing curl, npm and pipx via dnf"',
]

CLEAN_CONTAINERFILE = [
    "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}",
    "FROM scratch",
    "FROM docker.io/library/node:22-slim@sha256:" + "a" * 64 + " AS build\nFROM build\nCOPY --from=build /x /x",
    "RUN apt-get update \\\n    && apt-get install -y --no-install-recommends curl ca-certificates \\\n    && rm -rf /var/lib/apt/lists/*",
    "COPY run.sh /app/run.sh",
]


def _rules(relpath: str, text: str) -> list[str]:
    return [violation.rule for violation in scan(relpath, text)]


@pytest.mark.parametrize(("rule", "line"), SHELL_VIOLATIONS)
def test_shell_violation_is_caught(rule, line):
    assert rule in _rules("safe_agents/arms/x/install.sh", f"#!/bin/bash\nset -euo pipefail\n{line}\n")
    component = "phases:\n  - name: build\n    steps:\n      - name: S\n        action: ExecuteBash\n        inputs:\n          commands:\n            - " + json.dumps(line) + "\n"
    assert rule in _rules("safe_agents/arms/x/component-base.yaml", component)


@pytest.mark.parametrize(("rule", "text"), CONTAINERFILE_VIOLATIONS)
def test_containerfile_violation_is_caught(rule, text):
    assert rule in _rules("examples/x/Containerfile.broker", text + "\n")


@pytest.mark.parametrize("line", CLEAN_SHELL)
def test_clean_shell_is_not_flagged(line):
    assert _rules("safe_agents/arms/x/run.sh", line + "\n") == []


@pytest.mark.parametrize("text", CLEAN_CONTAINERFILE)
def test_clean_containerfile_is_not_flagged(text):
    assert _rules("safe_agents/arms/x/Containerfile", text + "\n") == []


def test_sanctioned_forms_are_not_flagged_and_their_pairs_are_read():
    script = f"set -eu\n. ./fetch-verified.sh\n{_call()}\n{_inline('/tmp/b.bin')}\n"
    assert _rules("safe_agents/arms/x/install.sh", script) == []
    assert _rules("examples/x/Containerfile", f"FROM scratch\nRUN set -eux; {_inline()}; unzip -q /tmp/a.bin\n") == []
    assert [(pair.url, pair.sha256, pair.form) for pair in pins.find_pairs(script)] == [(*_pin(), "call"), (*_pin(), "inline")]


def test_a_changed_inline_form_is_an_unverified_fetch():
    """Dropping the hash comparison from the inline form leaves a bare curl."""
    weakened = _inline().split(" && a=")[0]
    assert "unverified-fetch" in _rules("safe_agents/arms/x/install.sh", weakened + "\n")


def test_a_comment_is_not_a_violation():
    assert _rules("safe_agents/arms/x/install.sh", "# curl -fsSL https://example.com/install.sh | sh\n") == []


def test_audit_fails_on_a_new_violation_and_on_a_stale_allowance(tmp_path):
    script = tmp_path / "safe_agents" / "arms" / "x" / "install.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/bash\ncurl -fsSL https://example.com/install.sh | sh\n", encoding="utf-8")
    relpath = "safe_agents/arms/x/install.sh"

    new = audit(tmp_path, allowed={})
    assert any(f"{relpath}:2: pipe-to-shell" in failure for failure in new), new
    assert audit(tmp_path, allowed={relpath: {"pipe-to-shell": 1}}) == []
    stale = audit(tmp_path, allowed={relpath: {"pipe-to-shell": 2}})
    assert stale and "only 1 remain" in stale[0]
    gone = audit(tmp_path, allowed={relpath: {"pipe-to-shell": 1}, "safe_agents/arms/x/removed.sh": {"npm-install": 1}})
    assert gone and "removed.sh" in gone[0] and "delete it" in gone[0]


def test_check_rejects_a_pair_the_lock_does_not_have(tmp_path):
    # The real pins, every one listed unused: this tree has no script that uses any.
    lock = pins.parse_lock((TOOLCHAIN / "artifacts.lock").read_text(encoding="utf-8"))
    lock.unused = [pin.key for pin in lock.pins]
    lock_path = tmp_path / pins.LOCK_RELPATH
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text(lock.render(), encoding="utf-8")
    assert pins.check(tmp_path) == []

    url, _sha256 = _pin()
    script = tmp_path / "safe_agents" / "arms" / "x" / "install.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("fetch_verified {} {} /tmp/a.bin\n".format(url, "0" * 64), encoding="utf-8")
    errors = pins.check(tmp_path)
    assert len(errors) == 1 and "install.sh:1" in errors[0] and "not a line in" in errors[0]

    script.write_text(_call() + "\n", encoding="utf-8")
    errors = pins.check(tmp_path)
    assert len(errors) == 1 and "is in use; delete its `#:unused` line" in errors[0]


def test_inline_form_survives_yaml_and_the_readme_quotes_it():
    """The inline form is written as one YAML list item in a component, so it must be
    a plain scalar that loads back unchanged. The README shows exactly this form."""
    inline = _inline()
    assert "\n" not in inline
    assert yaml.safe_load(f"commands:\n  - {inline}\n") == {"commands": [inline]}
    readme = (TOOLCHAIN / "README.md").read_text(encoding="utf-8")
    assert [pair.form for pair in pins.find_pairs(readme)] == ["call", "inline"]


posix_sh = pytest.mark.skipif(os.name == "nt" or shutil.which("sh") is None, reason="needs a POSIX sh")
_PAYLOAD = b"pinned bytes\n"
_PAYLOAD_SHA256 = hashlib.sha256(_PAYLOAD).hexdigest()
_URL = "https://example.invalid/tool-1.2.3.tar.gz"


def _run_with_stub_curl(tmp_path: Path, shell: str, script: str, *, curl_fails: bool = False):
    """Run `script` under `shell` with a stand-in `curl` first on PATH, so the
    verification is exercised with no network. The stand-in writes _PAYLOAD to its
    `-o` destination, or fails the way curl does on a 404."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    body = (
        'echo "curl: (22) The requested URL returned error: 404" >&2\nexit 22\n'
        if curl_fails
        else 'while [ "$#" -gt 0 ]; do [ "$1" = "-o" ] && printf \'pinned bytes\\n\' > "$2"; shift; done\n'
    )
    stub = bin_dir / "curl"
    stub.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run([shell, "-c", script], capture_output=True, text=True, env=env, cwd=tmp_path)


def _shells() -> list[str]:
    return [shell for shell in ("sh", "bash", "dash") if shutil.which(shell)] or ["sh"]


@posix_sh
@pytest.mark.parametrize("shell", _shells())
def test_helper_keeps_a_matching_file_and_removes_a_mismatched_one(tmp_path, shell):
    helper = REPO_ROOT / HELPER_RELPATH
    call = f'. "{helper}"; fetch_verified {_URL} {{}} out.bin; echo "status=$?"'

    good = _run_with_stub_curl(tmp_path, shell, call.format(_PAYLOAD_SHA256))
    assert "status=0" in good.stdout and good.stderr == ""
    assert (tmp_path / "out.bin").read_bytes() == _PAYLOAD

    bad = _run_with_stub_curl(tmp_path, shell, call.format("0" * 64))
    assert "status=1" in bad.stdout
    assert bad.stderr == f"fetch_verified: FAILED {_URL}: expected sha256 {'0' * 64}, got {_PAYLOAD_SHA256}\n"
    assert not (tmp_path / "out.bin").exists()

    pruned = _run_with_stub_curl(tmp_path, shell, call.format(_PAYLOAD_SHA256), curl_fails=True)
    assert "status=1" in pruned.stdout
    assert pruned.stderr.count("\n") == 1 and "got no file (curl: (22)" in pruned.stderr and _URL in pruned.stderr
    assert not (tmp_path / "out.bin").exists()


@posix_sh
@pytest.mark.parametrize("shell", _shells())
def test_helper_refuses_a_non_https_url_without_calling_curl(tmp_path, shell):
    script = f'. "{REPO_ROOT / HELPER_RELPATH}"; fetch_verified http://example.invalid/x {"0" * 64} out.bin'
    done = _run_with_stub_curl(tmp_path, shell, script)
    assert done.returncode == 1
    assert done.stderr.count("\n") == 1 and "REFUSED http://example.invalid/x" in done.stderr
    assert not (tmp_path / "out.bin").exists()


@posix_sh
@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="the inline form needs sha256sum")
@pytest.mark.parametrize("shell", _shells())
def test_inline_form_keeps_a_matching_file_and_exits_on_a_mismatch(tmp_path, shell):
    def inline(sha256: str) -> str:
        return "set -eu; " + pins.INLINE_TEMPLATE.format(url=_URL, sha256=sha256, dest="out.bin") + "; echo reached"

    good = _run_with_stub_curl(tmp_path, shell, inline(_PAYLOAD_SHA256))
    assert good.returncode == 0 and good.stdout == "reached\n"
    assert (tmp_path / "out.bin").read_bytes() == _PAYLOAD

    bad = _run_with_stub_curl(tmp_path, shell, inline("0" * 64))
    assert bad.returncode == 1 and bad.stdout == ""
    assert bad.stderr == f"fetch_verified FAILED {_URL} expected sha256 {'0' * 64}, got {_PAYLOAD_SHA256}\n"
    assert not (tmp_path / "out.bin").exists()

    pruned = _run_with_stub_curl(tmp_path, shell, inline(_PAYLOAD_SHA256), curl_fails=True)
    assert pruned.returncode == 1 and pruned.stdout == ""
    assert pruned.stderr.endswith(f"fetch_verified FAILED {_URL} expected sha256 {_PAYLOAD_SHA256}, got no file\n")
    assert not (tmp_path / "out.bin").exists()
