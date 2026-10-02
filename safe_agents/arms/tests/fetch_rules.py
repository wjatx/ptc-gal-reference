"""The rules behind test_pinned_fetches.py: one file's text in, violations out.

The rules are stated, with the reasoning for each boundary, in the docstring of
test_pinned_fetches.py. This module is their implementation and nothing else. It
reads shell through shell_stages.py, and takes the two sanctioned fetch forms and
the lock from scripts/update-artifact-pin.py so there is one definition of each.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

from safe_agents.arms.tests.shell_stages import Pipeline, Stage, argv, basename, parse, walk

REPO_ROOT = Path(__file__).resolve().parents[3]
HELPER_RELPATH = "safe_agents/arms/toolchain/fetch-verified.sh"
SCAN_ROOTS = ("safe_agents/", "examples/")


def _load_pins():
    """scripts/update-artifact-pin.py as a module: it owns the lock, the two
    sanctioned forms and the `--check` logic, and its file name is not importable."""
    spec = importlib.util.spec_from_file_location("update_artifact_pin", REPO_ROOT / "scripts" / "update-artifact-pin.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pins = _load_pins()

RULES = (
    "unverified-fetch",
    "pipe-to-shell",
    "fetch-not-literal",
    "npm-install",
    "pip-install",
    "tool-install",
    "repo-or-rpm-by-url",
    "image-unpinned",
    "latest-lookup",
)

SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "source", ".", "eval"})
INTERPRETERS = frozenset({"python", "python3", "perl", "ruby", "node"})
#: Commands that keep what they read: they unpack it, install it or write it out.
KEEPERS = frozenset(
    {"tar", "bsdtar", "unzip", "funzip", "gunzip", "gzip", "zcat", "xz", "unxz", "bunzip2", "zstd", "cpio", "tee", "dd", "rpm", "dpkg", "gpg", "apt-key"}
)
#: When one of these is the command, a later word such as `curl` or `pipx` is a
#: package name or a name being looked up, never an invocation.
PACKAGE_MANAGERS = frozenset({"dnf", "yum", "microdnf", "zypper", "apt-get", "apt", "apk"})
NOT_INVOKING = PACKAGE_MANAGERS | {"which", "type", "hash"}
RPM_TOOLS = frozenset({"dnf", "yum", "microdnf", "zypper", "rpm", "rpmkeys", "yum-config-manager"})

#: curl short options that take a value, other than `-o`.
_CURL_VALUED = frozenset("AbcCdDeEFhHKmPQrTuUwxXyYz")
_NPM_INSTALLS = frozenset({"install", "i", "add", "update", "up", "upgrade", "install-test", "it"})
_PIP = re.compile(r"pip(3(\.\d+)?)?\Z")
_PYTHON = re.compile(r"python(\d(\.\d+)?)?\Z")
_URL = re.compile(r"https?://[^\s\"'<>|;)]+")
#: The instance metadata service and loopback. See the module docstring.
_LOCAL_HOSTS = ("169.254.169.254", "169.254.170.2", "[fd00:ec2::254]", "localhost", "127.0.0.1", "[::1]")
_PUBLIC_REGISTRIES = (
    "docker.io", "quay.io", "ghcr.io", "gcr.io", "registry.k8s.io", "registry.access.redhat.com",
    "registry.redhat.io", "public.ecr.aws", "mcr.microsoft.com", "nvcr.io",
)  # fmt: skip
_REGISTRY_IMAGE = re.compile(
    r"(?<![\w./])(?:" + "|".join(map(re.escape, _PUBLIC_REGISTRIES)) + r")/[\w./${}-]+(?::[\w.${}-]+)?(@sha256:[0-9a-f]{64})?"
)
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\Z")
_DOCKER_INSTRUCTIONS = frozenset(
    "FROM RUN CMD LABEL MAINTAINER EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD STOPSIGNAL HEALTHCHECK SHELL".split()
)


@dataclass(frozen=True)
class Violation:
    line: int
    rule: str
    text: str


# --- where a response body goes ---------------------------------------------------


def _curl_body(tool: str, args: list[str]) -> str:
    """'kept', 'discarded' or 'stdout' for one curl or wget invocation."""
    dest: str | None = None
    remote_name = False
    i = 0
    while i < len(args):
        arg, following = args[i], (args[i + 1] if i + 1 < len(args) else "")
        i += 1
        if arg in ("--output", "--output-document"):
            dest, i = following, i + 1
        elif arg.startswith(("--output=", "--output-document=")):
            dest = arg.split("=", 1)[1]
        elif arg in ("--remote-name", "--remote-name-all"):
            remote_name = True
        elif arg == "--spider":
            return "discarded"
        elif arg.startswith("-") and not arg.startswith("--"):
            letters = arg[1:]
            for j, letter in enumerate(letters):
                rest = letters[j + 1:]
                if letter == "O" and tool == "curl":
                    remote_name = True
                elif letter == ("o" if tool == "curl" else "O"):
                    dest = rest or following
                    i += 0 if rest else 1
                    break
                elif tool == "curl" and letter in _CURL_VALUED:
                    i += 0 if rest else 1
                    break
    if remote_name or (tool == "wget" and dest is None):
        return "kept"
    if dest is None or dest == "-":
        return "stdout"
    return "discarded" if dest == "/dev/null" else "kept"


def _runs_stdin(command: list[str]) -> bool:
    """Does this command execute what it reads on stdin?"""
    name = basename(command[0])
    if name in SHELLS:
        return True
    operands = [word for word in command[1:] if not word.startswith("-") or word == "-"]
    return name in INTERPRETERS and not {"-c", "-e", "-m"} & set(command[1:]) and operands in ([], ["-"])


def _curl_at(command: list[str]) -> int | None:
    """Index of the curl or wget this command invokes, through any wrapper, or None."""
    if not command or basename(command[0]) in NOT_INVOKING:
        return None
    return next((n for n, word in enumerate(command) if basename(word) in ("curl", "wget")), None)


def _fetch_violations(pipelines: list[Pipeline], context: list[str] | None, kind: str = "") -> list[str]:
    """Rule ids for every curl/wget in `pipelines` whose body is kept or run. `context`
    is the command that receives this script's output when it is a substitution."""
    found: list[str] = []
    for pipeline in pipelines:
        for k, stage in enumerate(pipeline):
            command = argv(stage)
            for sub_kind, inner in stage.subs:
                found += _fetch_violations(inner, command, sub_kind)
            at = _curl_at(command)
            if at is None:
                continue
            fate = _curl_body(basename(command[at]), command[at + 1:])
            if fate == "stdout" and stage.stdout_to is not None:
                fate = "discarded" if stage.stdout_to == "/dev/null" else "kept"
            for later in pipeline[k + 1:] if fate == "stdout" else ():
                consumer = argv(later)
                if consumer and _runs_stdin(consumer):
                    fate = "run"
                elif (consumer and basename(consumer[0]) in KEEPERS) or later.stdout_to not in (None, "/dev/null"):
                    fate = "kept"
                elif later.stdout_to == "/dev/null":
                    fate = "discarded"
                if fate != "stdout":
                    break
            if fate == "stdout" and context:
                # The body left this substitution: what did the enclosing command do with it?
                name = basename(context[0])
                if name == "eval" or (name in SHELLS and (kind == "proc" or "-c" in context)):
                    fate = "run"
                elif kind == "proc" and name in INTERPRETERS:
                    fate = "run"
                elif kind == "proc" and name in KEEPERS:
                    fate = "kept"
            if fate == "run":
                found.append("pipe-to-shell")
            elif fate == "kept":
                found.append("unverified-fetch")
    return found


# --- installers that resolve at run time ------------------------------------------


def _subcommand(words: list[str]) -> str:
    return next((word for word in words if not word.startswith("-")), "")


def _installer_violations(stage: Stage) -> list[str]:
    command = argv(stage)
    if not command:
        return []
    rpm_tool = next((n for n, word in enumerate(command) if basename(word) in RPM_TOOLS), None)
    if "add-apt-repository" in map(basename, command) or (
        rpm_tool is not None
        and any("http://" in w or "https://" in w or w.startswith("--add-repo") for w in command[rpm_tool + 1:])
    ):
        return ["repo-or-rpm-by-url"]
    if basename(command[0]) in NOT_INVOKING:
        return []
    if command[0] == "fetch_verified":
        return ["fetch-not-literal"]
    found: list[str] = []
    hashed = bool({"--require-hashes", "--no-index"} & set(command))
    for n, word in enumerate(command):
        name, rest = basename(word), command[n + 1:]
        sub = _subcommand(rest)
        if name == "npm" and sub in _NPM_INSTALLS:
            found.append("npm-install")
        elif name in ("uvx", "pipx", "npx") or (name == "npm" and sub in ("exec", "x")):
            found.append("tool-install")
        elif name == "uv" and rest[:1] == ["tool"] and _subcommand(rest[1:]) in ("install", "run", "upgrade"):
            found.append("tool-install")
        elif not hashed and (
            (_PIP.match(name) and sub in ("install", "download", "wheel"))
            or (_PYTHON.match(name) and rest[:2] == ["-m", "pip"] and _subcommand(rest[2:]) == "install")
            or (name == "uv" and rest[:1] == ["pip"] and _subcommand(rest[1:]) in ("install", "sync"))
        ):
            found.append("pip-install")
            break  # `python -m pip install` and `uv pip install` name pip twice
    return found


def _text_violations(text: str, *, images: bool = True) -> list[str]:
    found: list[str] = []
    for url in _URL.findall(text):
        host, _, path = url.split("://", 1)[1].partition("/")
        if not host.startswith(_LOCAL_HOSTS) and pins.LATEST_IN_URL_RE.search(path):
            found.append("latest-lookup")
    if images:
        found += ["image-unpinned" for match in _REGISTRY_IMAGE.finditer(text) if not match.group(1)]
    return found


#: A group or substitution piped to a shell: `( ...; ) | sh`, `{ ...; } | bash`,
#: `echo "$(...)" | sh`. The reader does not track what a group's output is, so a
#: line that does this AND calls curl or wget is reported as a whole.
_GROUP_TO_SHELL = re.compile(r"[)}][\"']?\s*\|\s*(?:sudo\s+(?:-\S+\s+)*|\$\{?SUDO\}?\s+)?(?:ba|da|z|k)?sh\b")


def _shell_violations(text: str) -> list[str]:
    """Rule ids for one logical line of shell, with the sanctioned forms taken out first."""
    text = pins.CALL_RE.sub("true", pins.INLINE_RE.sub("true", text))
    pipelines = parse(text)
    found = _fetch_violations(pipelines, context=None)
    stages = list(walk(pipelines))
    if "pipe-to-shell" not in found and _GROUP_TO_SHELL.search(text):
        if any(_curl_at(argv(stage)) is not None for stage in stages):
            found.append("pipe-to-shell")
    for stage in stages:
        found += _installer_violations(stage)
    return found + _text_violations(text)


# --- file kinds --------------------------------------------------------------------


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """(first line number, text) per command: comment lines dropped, and a line joined
    to the next when it ends in a backslash, a pipe or `&&`."""
    lines: list[tuple[int, str]] = []
    parts: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        start = start or number
        stripped = raw.rstrip()
        if stripped.endswith("\\") and not stripped.endswith("\\\\"):
            parts.append(stripped[:-1])
        elif stripped.endswith(("|", "&&")):
            parts.append(stripped)
        else:
            lines.append((start, " ".join([*parts, raw])))
            parts, start = [], 0
    if parts:
        lines.append((start, " ".join(parts)))
    return lines


def _scan_shell(text: str, offset: int = 0) -> list[Violation]:
    return [
        Violation(number + offset, rule, line.strip())
        for number, line in _logical_lines(text)
        for rule in _shell_violations(line)
    ]


def _image_unpinned(image: str, stages: set[str]) -> bool:
    if "$" in image or image == "scratch" or image in stages or image.isdigit():
        return False
    return not _DIGEST.search(image)


def _scan_containerfile(text: str) -> list[Violation]:
    found: list[Violation] = []
    stages: set[str] = set()
    for number, line in _logical_lines(text):
        instruction, _, rest = line.strip().partition(" ")
        keyword, rest = instruction.upper(), rest.strip()
        rules: list[str] = []
        if keyword == "FROM":
            operands = [word for word in rest.split() if not word.startswith("--")]
            if operands and _image_unpinned(operands[0], stages):
                rules.append("image-unpinned")
            if len(operands) >= 3 and operands[1].upper() == "AS":
                stages.add(operands[2])
            rules += _text_violations(rest, images=False)
        elif keyword == "RUN":
            while rest.startswith("--"):
                rest = rest.partition(" ")[2].strip()
            if rest.startswith("["):
                try:
                    exec_form = json.loads(rest)
                    rest = exec_form[2] if exec_form[1:2] == ["-c"] else " ".join(exec_form)
                except (ValueError, IndexError, TypeError):
                    pass
            rules += _shell_violations(rest)
        elif keyword in ("COPY", "ADD"):
            source = re.search(r"--from=(\S+)", rest)
            if source and _image_unpinned(source.group(1), stages):
                rules.append("image-unpinned")
            if keyword == "ADD" and _URL.search(rest):
                rules.append("unverified-fetch")
            rules += _text_violations(rest, images=False)
        elif keyword in _DOCKER_INSTRUCTIONS:
            rules += _text_violations(rest)
        else:  # a here-document body under RUN, or anything else: read it as shell
            rules += _shell_violations(line)
        found += [Violation(number, rule, line.strip()) for rule in rules]
    return found


def _scan_component(text: str) -> list[Violation]:
    """An Image Builder component: every `commands:` entry is shell, and a
    `WebDownload` action is a download with no hash this project controls."""
    found: list[Violation] = []

    def visit(node: yaml.Node) -> None:
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if key.value == "action" and getattr(value, "value", None) == "WebDownload":
                    found.append(Violation(value.start_mark.line + 1, "unverified-fetch", "action: WebDownload"))
                if key.value == "commands" and isinstance(value, yaml.SequenceNode):
                    for item in value.value:
                        if isinstance(item, yaml.ScalarNode):
                            # A block scalar's text starts on the line after its indicator.
                            found.extend(_scan_shell(item.value, item.start_mark.line + (1 if item.style in ("|", ">") else 0)))
                visit(value)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                visit(item)

    root = yaml.compose(text)
    if root is not None:
        visit(root)
    return found


def scan(relpath: str, text: str) -> list[Violation]:
    """Every violation in one file, chosen by the file's kind."""
    name = PurePosixPath(relpath).name
    if name.startswith("Containerfile"):
        return _scan_containerfile(text)
    if name.startswith("component-") and name.endswith(".yaml"):
        return _scan_component(text)
    return _scan_shell(text)


def is_scanned_kind(relpath: str) -> bool:
    name = PurePosixPath(relpath).name
    return relpath.startswith(SCAN_ROOTS) and (
        name.endswith((".sh", ".tmpl")) or name.startswith("Containerfile") or (name.startswith("component-") and name.endswith(".yaml"))
    )


def scanned_files(root: Path = REPO_ROOT) -> list[str]:
    # fetch-verified.sh is the one place a bare curl is the point; it is the helper.
    return [name for name in pins.tracked_files(root) if is_scanned_kind(name) and name != HELPER_RELPATH]
