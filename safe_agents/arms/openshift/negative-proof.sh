# negative-proof.sh — assert the SPECIFIC mechanism refused (#312). Sourced, never run.
#
#   source "$(dirname "$0")/negative-proof.sh"
#
# WHY THIS EXISTS. A negative proof asserts that nothing happened, and "nothing
# happened" has many causes: the control fired, a DIFFERENT control fired, the setup
# was wrong, the binary was stale, the command name was misspelled. A bare non-zero
# exit cannot tell them apart, so it passes for the wrong reason -- silently, and
# green. The cost is not a flaky drill; it is that the mislabelled proof gets cited
# later as evidence for a control that never ran.
#
# It has already happened here three times, which is why this is a file rather than
# advice:
#
#   * Phase 3 signing half: a check grepped for "REFUSED" and labelled the M8
#     refusal as M7 -- the wrong control, reported as the right one.
#   * #310 tamper leg: four attempts asserted rc != 0 and never checked that the
#     kernel said "Read-only file system", so a read-only ROOT filesystem, a bad SCC
#     or a mistyped volume would each have printed PASS four times.
#   * Phase 4 agent leg: a 500 from a broker that ANSWERED was reported as "could not
#     reach the broker at all", because HTTPError is a subclass of URLError and the
#     parent was caught first.
#
# WHAT IT DELIBERATELY IS NOT: a test framework. Four functions, no runner, no
# discovery, no assertions library. The drill scripts stay readable top-to-bottom,
# because a reviewer from the audience this epic is aimed at will read them.
#
# SCOPE. Reference-tier drill machinery, not broker mechanism -- per
# docs/contract-vs-reference.md it ships as the reference implementation of a habit,
# and nothing in safe_agents/broker imports it.
#
# The Python half is NOT built yet, on purpose. The refusals inside the `python3 -
# <<PY` heredocs already assert their mechanisms (errno, HTTP status, message
# contents); the demonstrated defect is in the SHELL sites, which is where this
# starts. When a python site is found asserting only "it raised", extract the twin
# then -- from its own consumers, not from this file's shape.
#
# LIVES HERE, not in a shared arms/ directory, for a mechanical reason worth knowing:
# kustomize's configMapGenerator cannot reach outside its own root without disabling
# the load restrictor, and these scripts ride to the cluster in that ConfigMap. When
# arms/local/container-arc.sh adopts this (#312 asks it to), decide placement then --
# with two real consumers, rather than guessing now with one.

# --- state -------------------------------------------------------------------
# Deliberately module-level counters rather than a return-code protocol: a refusal
# that aborts on first failure hides the other three, and seeing all four verdicts is
# most of the diagnostic value when a mount goes wrong.
_NP_REFUSALS=0
_NP_CONTROLS=0
_NP_FAILURES=0

np_say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
np_ok()  { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
np_die() { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# _np_bad counts a failure; _np_note continues one. Split because the first version
# counted every printed LINE, so two real problems reported as "6 check(s) failed" —
# a diagnostic that overstates its own findings is the same genre of error this file
# exists to prevent, just pointed at the reader instead of the control.
_np_bad()  { printf '   \033[31m%s\033[0m\n' "$*" >&2; _NP_FAILURES=$((_NP_FAILURES + 1)); }
_np_note() { printf '   \033[31m%s\033[0m\n' "$*" >&2; }

# --- np_control <label> -- <cmd...> ------------------------------------------
# The adjacent thing that MUST still succeed. This is the argument that keeps being
# re-derived from scratch in each script, so it is a first-class call here.
#
# Without it every refusal below is ambiguous: a pod with no network refuses every
# connection, a read-only root filesystem refuses every write, and a pod that failed
# to start refuses everything. All three produce a flawless-looking negative proof.
# #203's maker-mount leg carries "evidence reads still succeed" for exactly this
# reason -- read-denied is not a stricter write-denied, and a proof that checks only
# the denial cannot tell a working control from a broken mount.
np_control() {
  local label="$1"; shift
  [ "${1:-}" = "--" ] && shift
  local out rc
  set +e; out=$("$@" 2>&1); rc=$?; set -e
  if [ "$rc" -ne 0 ]; then
    _np_bad "CONTROL FAILED: $label (rc=$rc) ${out:+— $(printf '%s' "$out" | tail -1 | cut -c1-100)}"
    _np_note "  every refusal in this section is now UNINTERPRETABLE, not passing"
  else
    printf '   control: %s -> ok\n' "$label"
  fi
  _NP_CONTROLS=$((_NP_CONTROLS + 1))
}

# --- np_precondition <label> -- <cmd...> -------------------------------------
# The STATE the attempt runs against, asserted rather than assumed.
#
# From the #310 retro: placing the tamper attempt in the maker's existing leg would
# have passed against an EMPTY directory while the heading claimed "cannot erase
# another leg's records". The verb was right and the target was vacuous. So the
# precondition ("the tape holds N records", "the file exists and is non-empty") is
# part of the proof, not setup that happens to run first.
np_precondition() {
  local label="$1"; shift
  [ "${1:-}" = "--" ] && shift
  local out rc
  set +e; out=$("$@" 2>&1); rc=$?; set -e
  if [ "$rc" -ne 0 ]; then
    _np_bad "PRECONDITION FAILED: $label (rc=$rc) ${out:+— $(printf '%s' "$out" | tail -1 | cut -c1-100)}"
    _np_note "  the attempt would run against the wrong state; its refusal would prove nothing"
  else
    printf '   given: %s\n' "$label"
  fi
}

# --- np_refuse <label> <mechanism> -- <cmd...> -------------------------------
# The attempt itself. Runs for real, and demands THREE things rather than one:
#
#   1. it did not succeed                       (the forbidden success)
#   2. it failed                                (rc != 0)
#   3. it failed FOR THE STATED REASON          (the mechanism, matched in the output)
#
# (3) is the whole point and is this helper's default behaviour, not something each
# script remembers: a refusal whose output does not contain <mechanism> is recorded
# as a FAILURE even though the attempt failed. That is the M7/M8 bug, refused by
# construction.
#
# <mechanism> is a fixed string (grep -F), not a regex: these are kernel and API
# messages being matched, and a regex metacharacter arriving in one by accident would
# silently widen the match, which is the opposite of what this function is for.
np_refuse() {
  local label="$1" mechanism="$2"; shift 2
  [ "${1:-}" = "--" ] && shift
  local out rc last
  set +e; out=$("$@" 2>&1); rc=$?; set -e
  last=$(printf '%s' "$out" | tail -1 | cut -c1-96)
  _NP_REFUSALS=$((_NP_REFUSALS + 1))

  if [ "$rc" -eq 0 ]; then
    printf '   \033[31m%-34s -> SUCCEEDED\033[0m %s\n' "$label" "$last"
    _np_bad "  '$label' was NOT refused — the control this asserts is not in force"
    return
  fi
  if ! printf '%s' "$out" | grep -qF -- "$mechanism"; then
    printf '   \033[31m%-34s -> rc=%s WRONG MECHANISM\033[0m %s\n' "$label" "$rc" "$last"
    _np_bad "  expected to be refused by: $mechanism"
    _np_note "  it failed, but something else refused it. A proof that cannot name which"
    _np_note "  control fired is worse than none — it gets cited as evidence for this one."
    return
  fi
  printf '   %-34s -> rc=%s %s\n' "$label" "$rc" "$last"
}

# --- np_summary <passing message> --------------------------------------------
# Ends a section. Fails the script if anything above failed, AND -- the teeth --
# fails it if refusals were recorded with no positive control anywhere in the run.
#
# That second rule is the one worth having a machine enforce. A missing mechanism
# check is at least visible in the diff; a missing control looks exactly like a
# script that simply did not need one, and is the omission that recurs.
np_summary() {
  if [ "$_NP_REFUSALS" -gt 0 ] && [ "$_NP_CONTROLS" -eq 0 ]; then
    _np_bad "$_NP_REFUSALS refusal(s) recorded and NO positive control was declared."
    _np_note "  A pod that can do nothing at all refuses everything and proves nothing."
    _np_note "  Add np_control for the adjacent thing that must still work."
  fi
  [ "$_NP_FAILURES" -eq 0 ] || np_die "${1:-negative proof} — $_NP_FAILURES check(s) failed"
  np_ok "${1:-negative proof}"
}
