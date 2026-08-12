#!/usr/bin/env bash
# negative-proof-selftest.sh — does the helper actually FAIL when it should? (#312)
#
#   ./safe_agents/arms/openshift/negative-proof-selftest.sh
#
# No cluster, no image, no credentials: it runs on a laptop in about a second, which
# is the point — the thing it guards is cheap to break and expensive to notice.
#
# WHY THIS EXISTS AT ALL. `negative-proof.sh` is itself a control, and this epic's
# standing complaint is about controls nobody has watched fire. A helper whose
# failure paths are never exercised is the same fixture-that-never-pops as a cap that
# never trips: every drill goes green, and green is also what a helper that silently
# passes everything produces.
#
# That is not hypothetical. Refactoring the helper's failure-counting split the print
# helpers into "counts" and "continues", and the first version made ALL THREE lines of
# the wrong-mechanism branch non-counting -- so `np_refuse` would have accepted a
# refusal by the wrong control while printing WRONG MECHANISM on screen. Every cluster
# drill still passed. Case A below is what caught it, in the same minute it was
# introduced.
#
# Deliberately NOT pytest: this file has no Python in it, and a bash helper whose only
# test needs a Python test runner installed is a helper the drill environment cannot
# check. Five cases, each a subshell, each asserting an exit code.
set -uo pipefail
cd "$(dirname "$0")"

PASS=0
FAIL=0

# Each case runs in a subshell so the helper's module-level counters start clean --
# they are global by design (see negative-proof.sh), which makes process isolation the
# honest way to test them rather than resetting the internals from outside.
expect() {
  local want="$1" name="$2" body="$3"
  local out rc
  out=$(bash -c "set -e; source ./negative-proof.sh; $body" 2>&1); rc=$?
  if [ "$rc" -eq "$want" ]; then
    printf '  \033[32mok\033[0m   %-52s (exit %s)\n' "$name" "$rc"
    PASS=$((PASS + 1))
  else
    printf '  \033[31mFAIL\033[0m %-52s (exit %s, wanted %s)\n' "$name" "$rc" "$want"
    printf '%s\n' "$out" | sed 's/^/         /'
    FAIL=$((FAIL + 1))
  fi
}

printf '\n\033[1m== negative-proof.sh self-test\033[0m\n'

# The M7/M8 bug, which is the whole reason the helper exists: the attempt DID fail,
# just not for the stated reason. Must not pass.
expect 1 "refused by the WRONG mechanism is a failure" '
  np_control "c" -- true
  np_refuse "cat a missing file" "Read-only file system" -- cat /nope/nothing
  np_summary "A"'

# The forbidden success.
expect 1 "an attempt that SUCCEEDS is a failure" '
  np_control "c" -- true
  np_refuse "echo" "Read-only file system" -- echo hi
  np_summary "B"'

# The omission that recurs, per #312's own comment: refusals with nothing proving the
# subject was capable of anything.
expect 1 "refusals with NO positive control is a failure" '
  np_refuse "cat a missing file" "No such file" -- cat /nope/nothing
  np_summary "C"'

# A control that does not hold makes every refusal beside it uninterpretable.
expect 1 "a FAILING positive control is a failure" '
  np_control "a broken control" -- cat /nope/nothing
  np_refuse "cat a missing file" "No such file" -- cat /nope/nothing
  np_summary "E"'

# A precondition asserts the state the attempt runs against — the #310 lesson that a
# tamper attempt against an EMPTY target refuses identically and claims far more.
expect 1 "a FAILING precondition is a failure" '
  np_control "c" -- true
  np_precondition "the target is non-empty" -- test -s /nope/nothing
  np_refuse "cat a missing file" "No such file" -- cat /nope/nothing
  np_summary "F"'

# And the shape every drill leg actually uses must still pass, or the helper is just
# a machine for failing.
expect 0 "correct mechanism + control + precondition PASSES" '
  np_control "echo works" -- echo hi
  np_precondition "this file exists" -- test -f ./negative-proof.sh
  np_refuse "cat a missing file" "No such file" -- cat /nope/nothing
  np_summary "D"'

printf '\n'
if [ "$FAIL" -ne 0 ]; then
  printf '\033[31mSELF-TEST FAILED\033[0m — %s of %s cases wrong.\n' "$FAIL" "$((PASS + FAIL))"
  printf 'The helper is not enforcing what the drill legs rely on it to enforce.\n'
  exit 1
fi
printf '\033[32mSELF-TEST PASS\033[0m — %s cases; the helper fails when it should.\n' "$PASS"
