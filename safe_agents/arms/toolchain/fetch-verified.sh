# shellcheck shell=sh
# fetch-verified.sh: download one pinned third-party file and verify its SHA-256.
#
# A library, not a program: source it, then call
#
#     fetch_verified URL SHA256 DEST
#
# URL and SHA256 are written as LITERALS at the call site, copied from one line of
# artifacts.lock in this directory. That is deliberate. A reader of an install script
# sees exactly what is fetched without opening a second file, the script needs no lock
# parser at run time, and safe_agents/arms/tests/test_pinned_fetches.py can check every
# pair against the lock. Move a pin with scripts/update-artifact-pin.py, never by hand.
#
# Contract:
#   - HTTPS only, on the first request and on every redirect (curl --proto '=https'
#     denies every other protocol, and a protocol denied there stays denied on redirect).
#   - curl retries transient failures three times. A 404 is not transient: a pinned URL
#     that upstream has pruned fails here, and that is the wanted outcome.
#   - On any failure the partial DEST is removed, ONE line goes to stderr naming the URL
#     and the expected and actual hash, and the function returns non-zero.
#   - No fallback and no "continue anyway". Callers run under `set -e` or test the status.
#
# POSIX sh: no `local`, no arrays, no `[[`. Runs under bash (RHEL 9, Amazon Linux 2023)
# and dash (Debian slim images). Needs curl and sha256sum (coreutils); `shasum -a 256`
# is accepted so the helper can be exercised on a macOS workstation.
#
# Where a file cannot be sourced (an Image Builder component step, a Containerfile RUN)
# use the canonical inline form, which toolchain/README.md gives and the test recognises.

fetch_verified() {
    if [ "$#" -ne 3 ]; then
        echo "fetch_verified: usage: fetch_verified URL SHA256 DEST (got $# arguments)" >&2
        return 2
    fi
    _fv_url=$1
    _fv_want=$2
    _fv_dest=$3
    _fv_got=

    case $_fv_url in
        https://*) ;;
        *)
            echo "fetch_verified: REFUSED $_fv_url: not an https:// URL (expected sha256 $_fv_want, nothing fetched)" >&2
            return 1
            ;;
    esac

    # curl's own diagnostic is captured so a failure is reported on ONE line.
    if _fv_err=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$_fv_dest" "$_fv_url" 2>&1); then
        if command -v sha256sum >/dev/null 2>&1; then
            _fv_got=$(sha256sum "$_fv_dest" | cut -d' ' -f1)
        elif command -v shasum >/dev/null 2>&1; then
            _fv_got=$(shasum -a 256 "$_fv_dest" | cut -d' ' -f1)
        else
            _fv_got="nothing (no sha256sum or shasum on PATH)"
        fi
    else
        _fv_got="no file ($(printf '%s' "$_fv_err" | tr '\n' ' '))"
    fi

    if [ "$_fv_got" = "$_fv_want" ]; then
        return 0
    fi

    rm -f "$_fv_dest"
    echo "fetch_verified: FAILED $_fv_url: expected sha256 $_fv_want, got $_fv_got" >&2
    return 1
}
