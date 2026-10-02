"""The two confined-agent images: the Fargate arm's and the local arm's.

Both install the pinned Claude Code native binary and no Node.js, from the base
image the broker image already pins, and both may build for arm64 or amd64. These
tests hold that shape. test_pinned_fetches.py holds the rules about downloads.

No image is built here. CI builds both (the container job in
.github/workflows/ci.yml), and that build is the only place the binary is run.
"""

from __future__ import annotations

import re
import subprocess

import pytest

from safe_agents.arms.tests.fetch_rules import REPO_ROOT, pins
from safe_agents.broker.tests.platform_marks import requires_posix_bash

BROKER_CONTAINERFILE = "safe_agents/arms/local/Containerfile.broker"
#: Containerfile -> build context, both repo-relative, as CI and run-local.sh build them.
AGENT_IMAGES = {
    "safe_agents/arms/fargate/Containerfile.agent": "safe_agents/arms/fargate/",
    "safe_agents/arms/local/Containerfile": "safe_agents/arms/local/",
}
PER_ARCH = {"linux-aarch64", "linux-x86_64"}

images = pytest.mark.parametrize("relpath", sorted(AGENT_IMAGES))


def _text(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8")


def _instructions(relpath: str) -> list[str]:
    """Each instruction as one line: comments dropped, continuations joined."""
    body = "\n".join(line for line in _text(relpath).splitlines() if not line.lstrip().startswith("#"))
    return [line.strip() for line in body.replace("\\\n", " ").splitlines() if line.strip()]


def _from_lines(relpath: str) -> list[str]:
    return [line for line in _instructions(relpath) if line.startswith("FROM ")]


@images
def test_base_is_the_digest_the_broker_image_pins(relpath):
    """One third-party base for the Debian images, pinned once. Moving the broker
    image's digest moves these with it or fails here."""
    broker = _from_lines(BROKER_CONTAINERFILE)
    assert len(broker) == 1 and re.search(r"@sha256:[0-9a-f]{64}$", broker[0])
    assert _from_lines(relpath) == broker


@images
def test_claude_code_is_the_pinned_binary_for_both_architectures(relpath):
    """The image may build for arm64 or amd64, so it carries the lock line for each,
    and for nothing else."""
    lock = pins.parse_lock((REPO_ROOT / pins.LOCK_RELPATH).read_text(encoding="utf-8"))
    by_pair = {(pin.url, pin.sha256): pin for pin in lock.pins}
    used = [by_pair[(pair.url, pair.sha256)] for pair in pins.find_pairs(_text(relpath))]

    names = {pin.name for pin in used}
    assert "claude-code" in names
    assert {(pin.name, pin.platform) for pin in used} == {(name, platform) for name in names for platform in PER_ARCH}
    assert 'case "$(dpkg --print-architecture)" in' in _text(relpath)


@images
def test_no_node_and_no_npm(relpath):
    found = re.findall(r"\b(?:node(?:js)?|npm|npx)\b|@anthropic-ai/claude-code", "\n".join(_instructions(relpath)), re.IGNORECASE)
    assert not found, f"{relpath} must not carry Node.js or use npm: found {found}"


@images
def test_updates_are_disabled_in_settings_and_in_the_environment(relpath):
    instructions = _instructions(relpath)
    assert "ENV DISABLE_UPDATES=1" in instructions
    assert any(
        '{"env": {"DISABLE_UPDATES": "1"}}' in line and "> /etc/claude-code/managed-settings.json" in line
        for line in instructions
    )


@images
def test_the_build_runs_the_binary_as_the_agent_user(relpath):
    """`RUN claude --version` after `USER agent`: a binary that cannot execute on the
    build's architecture fails the build."""
    instructions = _instructions(relpath)
    assert instructions.index("USER agent") < instructions.index("RUN claude --version")


@requires_posix_bash
@images
def test_every_run_instruction_is_shell_that_parses(relpath):
    runs = [line[len("RUN "):] for line in _instructions(relpath) if line.startswith("RUN ")]
    assert runs
    for command in runs:
        done = subprocess.run(["bash", "--posix", "-n"], input=command, capture_output=True, text=True)
        assert done.returncode == 0, f"sh -n failed: {done.stderr}\n{command}"


@images
def test_ci_builds_the_image(relpath):
    """These images are built nowhere else before they are used, so CI must build each."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert f"-f {relpath} {AGENT_IMAGES[relpath]}" in workflow
