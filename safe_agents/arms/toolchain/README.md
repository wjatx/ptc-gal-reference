# Pinned downloads for the arms

The arms bake machine images and build containers, and those builds download
third-party files. Every such file is pinned to an exact version and verified
against a SHA-256 before anything uses it. A pinned URL that upstream has removed
fails the build. There is no fallback to a newer file.

## The lock

`artifacts.lock` lists every pinned file, one per line:

```
name  platform  version  sha256  url
```

`platform` is `linux-x86_64`, `linux-aarch64` or `any`. Lines are sorted by name,
then platform. The version appears in the URL, so a URL that means "the newest" is
rejected.

Install scripts do not read the lock when they run. Each one carries the URL and
hash of a lock line as literals, so a reader sees exactly what is fetched and the
script needs no parser. The test described below fails if a script carries a pair
that is not a line in the lock.

## Fetching a pinned file

Where a script can source a file, use the function in `fetch-verified.sh`:

```sh
. /path/to/fetch-verified.sh
fetch_verified https://github.com/astral-sh/uv/releases/download/0.12.22/uv-x86_64-unknown-linux-gnu.tar.gz b9980552309f09c15172b8be828555e375097f16deb459795ce7bfd200380f0b /tmp/uv.tar.gz
```

Where it cannot, such as an Image Builder component step or a Containerfile `RUN`,
use the inline form. It is one line, and only the three assignments at the front
change:

```sh
u=https://github.com/astral-sh/uv/releases/download/0.12.22/uv-x86_64-unknown-linux-gnu.tar.gz; h=b9980552309f09c15172b8be828555e375097f16deb459795ce7bfd200380f0b; d=/tmp/uv.tar.gz; a=; curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$d" "$u" && a=$(sha256sum "$d" | cut -d' ' -f1); [ "$a" = "$h" ] || { echo "fetch_verified FAILED $u expected sha256 $h, got ${a:-no file}" >&2; rm -f "$d"; exit 1; }
```

Both forms download over HTTPS only, retry a transient failure three times, and
compare the SHA-256. On any failure they remove the partial file and print a line
to stderr naming the URL and the expected and actual hash. The function then
returns non-zero. The inline form exits the shell with status 1. Both need `curl`
and `sha256sum` on the machine that runs them.

`python3 scripts/update-artifact-pin.py --show NAME PLATFORM` prints both forms for
a lock line, ready to paste.

## Moving a pin

```sh
python3 scripts/update-artifact-pin.py NAME PLATFORM VERSION URL
```

This downloads the new file, computes its hash, rewrites the lock line, and
replaces the old URL and hash in every tracked file that carries them. It prints
each file it changed. Add `--expect-sha256 HEX` with the checksum the upstream
project publishes, and the move is refused unless the download matches. A name the
lock does not have yet is added and marked `#:unused` until a script fetches it.

`python3 scripts/update-artifact-pin.py --check` verifies, without network access,
that every pair in a tracked file is a lock line and that every lock line is used
or marked `#:unused`. Do not edit a URL or hash by hand.

## Claude Code

`claude-code` is the native executable Anthropic publishes for each platform. It
is a single self-contained binary: it needs glibc and nothing else, so the arms
install no Node.js and no npm for it. The npm package of the same name is a
launcher that links this same file into place.

Its hashes come from the release manifest, which is GPG-signed. Check the
signature before moving the pin:

```sh
v=2.1.285
curl -fsSLO "https://downloads.claude.ai/claude-code-releases/$v/manifest.json"
curl -fsSLO "https://downloads.claude.ai/claude-code-releases/$v/manifest.json.sig"
curl -fsSL -o claude-code.asc https://downloads.claude.ai/keys/claude-code.asc
gpg --import claude-code.asc
gpg --verify manifest.json.sig manifest.json
```

The signing key's fingerprint is `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE`.
Then run `update-artifact-pin.py` with `--expect-sha256` set to the manifest's
`platforms.<platform>.checksum` for each platform. The pin follows the `stable`
release channel and not `latest`.

A pinned install must not update itself. Every arm sets `DISABLE_UPDATES=1` for
the CLI, in `/etc/claude-code/managed-settings.json` and in the environment it
runs under.

## Out of scope

Two kinds of download are left as they are.

The first is a package that `dnf` or `apt-get` installs by name from the
distribution's own repositories. The package manager checks the distribution's
signature on each one, and the baked image fixes the versions. Adding a
third-party repository or installing an RPM from a URL is in scope and is flagged.

The second is a bundle fetched with `aws s3 cp`. This project builds and uploads
those bundles, so they are first-party.

## What the test enforces

`safe_agents/arms/tests/test_pinned_fetches.py` scans tracked shell scripts,
templates, Containerfiles and Image Builder components under `safe_agents/`
and `examples/`. It fails on a download that keeps or runs its response without
verifying it, on a `curl` piped to a shell, on `npm install`, on `pip install`
without `--require-hashes` or `--no-index`, on `uv tool install`, `uvx` and
`pipx`, on an RPM or repository added by URL, on a base image without a digest,
and on a `latest` URL. Its docstring states each rule and the distinction between
a download and a run-time probe.

The test carries a list of the violations that existed when it was written. The
list can only shrink. Converting a script to verified fetches means deleting its
entry in the same change.
