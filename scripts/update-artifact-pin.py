#!/usr/bin/env python3
"""Move one pinned download, or check every pin, against artifacts.lock.

`safe_agents/arms/toolchain/artifacts.lock` is the single authority for every
third-party file the substrate arms download. Install scripts do not read it at run
time: they carry one line's url and sha256 as literals, in a `fetch_verified` call
or in the canonical inline form. This script is what keeps the two in step.

Move a pin (network):

    python3 scripts/update-artifact-pin.py NAME PLATFORM VERSION URL

downloads URL, computes its SHA-256, rewrites that line of the lock, and replaces
the old url and the old sha256 with the new ones in every tracked file that carries
them, printing each file it changed. Pass `--expect-sha256` with the value upstream
publishes and the move is refused unless the download matches it. A NAME/PLATFORM
the lock does not have yet is added and listed as not yet used.

Check (no network):

    python3 scripts/update-artifact-pin.py --check

fails unless the lock is well formed, every (url, sha256) pair a tracked file uses
is a line in the lock, and every lock line is used or is listed `#:unused`. Markdown
may cite a pin, and the pair is checked, but only a non-markdown file counts as a
use. `safe_agents/arms/tests/test_pinned_fetches.py` runs this check in the suite.

Print the two call forms for a pin, ready to paste:

    python3 scripts/update-artifact-pin.py --show NAME PLATFORM

Standard library only, so it runs before any environment exists.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK_RELPATH = "safe_agents/arms/toolchain/artifacts.lock"

PLATFORMS = ("linux-x86_64", "linux-aarch64", "any")
UNUSED_MARK = "#:unused"

#: A pinned url is written unquoted in shell, YAML and Containerfiles, so it may
#: hold nothing a shell or a YAML plain scalar would interpret.
URL_RE = r"https://[A-Za-z0-9._~%+/:=@-]+"
SHA_RE = r"[0-9a-f]{64}"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

#: A url that names "the newest" is not a pin, whatever hash sits beside it.
LATEST_IN_URL_RE = re.compile(r"(?:^|[/._-])latest(?:$|[/._-])", re.IGNORECASE)

#: The canonical ONE-LINE inline form, for places that cannot source
#: fetch-verified.sh (an Image Builder component step, a Containerfile RUN). It is
#: defined here once; the README quotes it and the test recognises exactly it.
#: Only the three assignments at the front vary.
INLINE_TEMPLATE = (
    "u={url}; h={sha256}; d={dest}; a=; "
    "curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o \"$d\" \"$u\" "
    "&& a=$(sha256sum \"$d\" | cut -d' ' -f1); "
    "[ \"$a\" = \"$h\" ] || {{ echo \"fetch_verified FAILED $u expected sha256 $h, got ${{a:-no file}}\" >&2; "
    "rm -f \"$d\"; exit 1; }}"
)


def _inline_regex() -> re.Pattern[str]:
    marks = {"url": "\0U\0", "sha256": "\0H\0", "dest": "\0D\0"}
    pattern = re.escape(INLINE_TEMPLATE.format(**marks))
    pattern = pattern.replace(re.escape(marks["url"]), f"(?P<url>{URL_RE})")
    pattern = pattern.replace(re.escape(marks["sha256"]), f"(?P<sha256>{SHA_RE})")
    pattern = pattern.replace(re.escape(marks["dest"]), r"(?P<dest>[A-Za-z0-9._/-]+)")
    return re.compile(pattern)


#: Matches one whole canonical inline fetch.
INLINE_RE = _inline_regex()

_GAP = r"(?:[ \t]|\\\n)+"
#: Matches a literal `fetch_verified URL SHA256 DEST` call. A call whose url or hash
#: is a variable does not match, and the test reports it as its own violation.
CALL_RE = re.compile(
    rf"(?<![\w-])fetch_verified{_GAP}(?P<uq>['\"]?)(?P<url>{URL_RE})(?P=uq)"
    rf"{_GAP}(?P<hq>['\"]?)(?P<sha256>{SHA_RE})(?P=hq)"
    rf"{_GAP}(?P<dest>(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s;&|<>()]+))"
)

#: Files in which a pair is checked against the lock but does not count as a use.
DOC_SUFFIXES = (".md",)

#: Directories never walked when the tree is not a git checkout.
_WALK_SKIP = {".git", ".venv", "venv", "node_modules", "spec", "build", "dist", "cdk.out", "__pycache__"}


@dataclass(frozen=True, order=True)
class Pin:
    name: str
    platform: str
    version: str
    sha256: str
    url: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.platform)

    def line(self) -> str:
        return f"{self.name} {self.platform} {self.version} {self.sha256} {self.url}"


@dataclass(frozen=True)
class Pair:
    """One (url, sha256) a file carries, in either sanctioned form."""

    line: int
    url: str
    sha256: str
    dest: str
    form: str  # "call" or "inline"


@dataclass
class Lock:
    """The lock as parsed: comment lines before and after the pins are kept verbatim."""

    head: list[str]
    pins: list[Pin]
    tail: list[str]
    unused: list[tuple[str, str]]
    errors: list[str]

    def render(self) -> str:
        lines = [*self.head, *(pin.line() for pin in sorted(self.pins)), *self.tail]
        lines += [f"{UNUSED_MARK} {name} {platform}" for name, platform in sorted(self.unused)]
        return "\n".join(lines) + "\n"

    def by_key(self) -> dict[tuple[str, str], Pin]:
        return {pin.key: pin for pin in self.pins}


def parse_lock(text: str) -> Lock:
    """Parse the lock. Problems are collected in `errors`, never raised, so `--check`
    can report all of them at once."""
    lock = Lock(head=[], pins=[], tail=[], unused=[], errors=[])
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith(UNUSED_MARK):
            fields = line.split()
            if len(fields) != 3:
                lock.errors.append(f"lock line {number}: expected `{UNUSED_MARK} name platform`, got {raw!r}")
            else:
                lock.unused.append((fields[1], fields[2]))
            continue
        if not line or line.startswith("#"):
            (lock.tail if lock.pins else lock.head).append(raw)
            continue
        fields = line.split()
        if len(fields) != 5:
            lock.errors.append(
                f"lock line {number}: expected 5 columns (name platform version sha256 url), got {len(fields)}"
            )
            continue
        pin = Pin(*fields)
        lock.errors.extend(f"lock line {number}: {problem}" for problem in _pin_problems(pin))
        lock.pins.append(pin)

    keys = [pin.key for pin in lock.pins]
    if keys != sorted(keys):
        lock.errors.append("lock: lines are not sorted by name, then platform")
    for key in sorted({key for key in keys if keys.count(key) > 1}):
        lock.errors.append(f"lock: {key[0]} {key[1]} appears more than once")
    if lock.unused != sorted(set(lock.unused)):
        lock.errors.append(f"lock: `{UNUSED_MARK}` lines are not sorted and unique")
    return lock


def _pin_problems(pin: Pin) -> list[str]:
    problems = []
    if not NAME_RE.match(pin.name):
        problems.append(f"name {pin.name!r} is not lowercase letters, digits and hyphens")
    if pin.platform not in PLATFORMS:
        problems.append(f"platform {pin.platform!r} is not one of {', '.join(PLATFORMS)}")
    if not re.fullmatch(SHA_RE, pin.sha256):
        problems.append(f"sha256 for {pin.name} is not 64 lowercase hex characters")
    if not re.fullmatch(URL_RE, pin.url):
        problems.append(f"url for {pin.name} is not a plain https:// url: {pin.url}")
    if LATEST_IN_URL_RE.search(pin.url.split("://", 1)[-1]):
        problems.append(f"url for {pin.name} names `latest`, which is not a pin: {pin.url}")
    if pin.version not in pin.url:
        problems.append(f"version {pin.version} of {pin.name} does not appear in its url, so the url is not versioned")
    return problems


def find_pairs(text: str) -> list[Pair]:
    """Every literal (url, sha256) pair `text` carries, in file order."""
    pairs = []
    for form, regex in (("inline", INLINE_RE), ("call", CALL_RE)):
        for match in regex.finditer(text):
            pairs.append(
                Pair(
                    line=text.count("\n", 0, match.start()) + 1,
                    url=match["url"],
                    sha256=match["sha256"],
                    dest=match["dest"],
                    form=form,
                )
            )
    return sorted(pairs, key=lambda pair: pair.line)


def tracked_files(root: Path) -> list[str]:
    """Repo-relative POSIX paths of every tracked file that still exists, plus files
    not yet added that git does not ignore, so a new script is checked before its
    first `git add` and not only in CI. Where git lists nothing (no git, not a
    checkout, an unpacked archive) this walks the tree instead, so the check never
    passes by finding nothing to look at."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            check=True,
        ).stdout.decode("utf-8", "surrogateescape")
        names = [name for name in out.split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        names = []
    if not names:
        for directory, subdirs, files in os.walk(root):
            subdirs[:] = [d for d in subdirs if d not in _WALK_SKIP and not d.endswith(".egg-info")]
            names += [(Path(directory) / f).relative_to(root).as_posix() for f in files]
    return sorted(name for name in names if (root / name).is_file())


def read_text(path: Path) -> str | None:
    """A file's text, or None when it is not UTF-8 text."""
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def write_text(path: Path, text: str) -> None:
    """Write LF-terminated UTF-8 on every platform (.gitattributes: `eol=lf`)."""
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def check(root: Path = ROOT) -> list[str]:
    """Every problem with the lock and its uses. An empty list is a pass."""
    lock_path = root / LOCK_RELPATH
    text = read_text(lock_path)
    if text is None:
        return [f"{LOCK_RELPATH}: missing or unreadable"]
    lock = parse_lock(text)
    errors = list(lock.errors)

    locked = {(pin.url, pin.sha256): pin for pin in lock.pins}
    sha_for_url = {pin.url: pin.sha256 for pin in lock.pins}
    used: set[tuple[str, str]] = set()
    for name in tracked_files(root):
        if name == LOCK_RELPATH:
            continue
        body = read_text(root / name)
        if body is None or "fetch_verified" not in body:
            continue
        for pair in find_pairs(body):
            pin = locked.get((pair.url, pair.sha256))
            if pin is None:
                known = sha_for_url.get(pair.url)
                why = (
                    f"the lock pins this url to sha256 {known}"
                    if known
                    else "the lock has no line with this url"
                )
                errors.append(
                    f"{name}:{pair.line}: fetches {pair.url} with sha256 {pair.sha256}, "
                    f"which is not a line in {LOCK_RELPATH} ({why})"
                )
            elif not name.endswith(DOC_SUFFIXES):
                used.add(pin.key)

    keys = set(lock.by_key())
    listed = set(lock.unused)
    for name, platform in sorted(listed - keys):
        errors.append(f"lock: `{UNUSED_MARK} {name} {platform}` names a pin the lock does not have")
    for name, platform in sorted(keys - used - listed):
        errors.append(
            f"lock: {name} {platform} is used by no tracked file and is not listed `{UNUSED_MARK}`; "
            "use it, list it, or delete the line"
        )
    for name, platform in sorted(used & listed):
        errors.append(f"lock: {name} {platform} is in use; delete its `{UNUSED_MARK}` line")
    return errors


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.URLError(f"redirect to a non-https url refused: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


DOWNLOAD_ATTEMPTS = 3
_CHUNK = 1 << 20


def download_sha256(url: str) -> str:
    """SHA-256 of the bytes at `url`, fetched over HTTPS only. Nothing is kept."""
    # Installed process-wide so the call below is `urlopen`: this script fetches nothing else.
    urllib.request.install_opener(urllib.request.build_opener(_HttpsOnly))
    request = urllib.request.Request(url, headers={"User-Agent": "update-artifact-pin"})
    failure: Exception | None = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            digest = hashlib.sha256()
            with urllib.request.urlopen(request, timeout=60) as response:
                expected = response.headers.get("Content-Length")
                received = 0
                while chunk := response.read(_CHUNK):
                    digest.update(chunk)
                    received += len(chunk)
            if expected is not None and received != int(expected):
                raise OSError(f"short read: {received} of {expected} bytes")
            return digest.hexdigest()
        except urllib.error.HTTPError as exc:
            # A status the server chose is an answer, not a blip. A pruned url is a 404
            # and must fail here, loudly, not on the fourth try.
            if exc.code < 500:
                raise SystemExit(f"error: {url} returned HTTP {exc.code}; nothing was changed") from exc
            failure = exc
        except (OSError, urllib.error.URLError) as exc:
            failure = exc
        if attempt < DOWNLOAD_ATTEMPTS:
            time.sleep(2 * attempt)
    raise SystemExit(f"error: could not download {url} after {DOWNLOAD_ATTEMPTS} attempts: {failure}")


def move(root: Path, name: str, platform: str, version: str, url: str, expect: str | None) -> int:
    lock_path = root / LOCK_RELPATH
    lock = parse_lock(lock_path.read_text(encoding="utf-8"))
    if lock.errors:
        print("error: the lock is malformed; fix it before moving a pin:", file=sys.stderr)
        for error in lock.errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    candidate = Pin(name, platform, version, "0" * 64, url)
    problems = _pin_problems(candidate)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    print(f"downloading {url}")
    sha256 = download_sha256(url)
    print(f"sha256 {sha256}")
    if expect is not None and sha256 != expect.lower():
        print(f"error: --expect-sha256 was {expect}, the download is {sha256}; nothing was changed", file=sys.stderr)
        return 1
    new = Pin(name, platform, version, sha256, url)

    old = lock.by_key().get(new.key)
    if old == new:
        print(f"{name} {platform} is already pinned to exactly this; nothing to change")
        return 0
    if old is None:
        lock.pins.append(new)
        lock.unused.append(new.key)
        print(f"added {name} {platform} {version} (listed `{UNUSED_MARK}` until a script uses it)")
    else:
        lock.pins[lock.pins.index(old)] = new
        print(f"moved {name} {platform} {old.version} -> {version}")
    write_text(lock_path, lock.render())
    print(f"changed {LOCK_RELPATH}")

    if old is not None:
        for tracked in tracked_files(root):
            if tracked == LOCK_RELPATH:
                continue
            path = root / tracked
            body = read_text(path)
            if body is None or (old.url not in body and old.sha256 not in body):
                continue
            write_text(path, body.replace(old.url, new.url).replace(old.sha256, new.sha256))
            print(f"changed {tracked}")

    errors = check(root)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


def show(root: Path, name: str, platform: str) -> int:
    lock = parse_lock((root / LOCK_RELPATH).read_text(encoding="utf-8"))
    pin = lock.by_key().get((name, platform))
    if pin is None:
        print(f"error: the lock has no line for {name} {platform}", file=sys.stderr)
        return 1
    dest = "/tmp/" + pin.url.rsplit("/", 1)[-1]
    print(f"# {pin.name} {pin.platform} {pin.version}")
    print(f"fetch_verified {pin.url} {pin.sha256} {dest}")
    print(INLINE_TEMPLATE.format(url=pin.url, sha256=pin.sha256, dest=dest))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Move one pinned download in artifacts.lock, or check every pin.",
        epilog="See safe_agents/arms/toolchain/README.md.",
    )
    parser.add_argument("pin", nargs="*", metavar="NAME PLATFORM VERSION URL")
    parser.add_argument("--check", action="store_true", help="verify the lock and every use of it; no network")
    parser.add_argument("--show", action="store_true", help="print the two call forms for NAME PLATFORM")
    parser.add_argument("--expect-sha256", metavar="HEX", help="refuse the move unless the download has this hash")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.check:
        if args.pin or args.show:
            parser.error("--check takes no other arguments")
        errors = check(root)
        for error in errors:
            print(error, file=sys.stderr)
        if errors:
            print(f"{len(errors)} problem(s) with {LOCK_RELPATH}", file=sys.stderr)
            return 1
        lock = parse_lock((root / LOCK_RELPATH).read_text(encoding="utf-8"))
        print(f"ok: {len(lock.pins)} pins, {len(lock.pins) - len(lock.unused)} in use, {len(lock.unused)} not yet used")
        return 0
    if args.show:
        if len(args.pin) != 2:
            parser.error("--show takes NAME PLATFORM")
        return show(root, *args.pin)
    if len(args.pin) != 4:
        parser.error("expected NAME PLATFORM VERSION URL, or --check, or --show NAME PLATFORM")
    return move(root, *args.pin, expect=args.expect_sha256)


if __name__ == "__main__":
    sys.exit(main())
