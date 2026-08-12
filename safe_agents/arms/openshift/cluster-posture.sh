#!/usr/bin/env bash
# cluster-posture.sh — a posture report from INSIDE a pod (#250 Phase 6.1).
#
# Every other leg in this arm demonstrates a property. This one demonstrates that
# the surface a reader will actually consult DESCRIBES those properties in this
# platform's vocabulary — ServiceAccount, SCC, RBAC, NetworkPolicy — and names
# the limit of each.
#
# It runs in a pod rather than on a laptop, and that is the whole point: a posture
# report generated where the containment is not is a report about somewhere else.
# The wrapper's cluster probe observes /proc, the filesystem and the projected
# token; on a laptop those observations are absent and the section is empty.
#
# WHAT THIS LEG ASSERTS, and why each one is here rather than left to the eye:
#
#   1. the CLUSTER section EXISTS — otherwise the module silently degraded to the
#      laptop path and the report would look fine while claiming nothing
#   2. this pod is seen as its own ServiceAccount
#   3. the two REFUSALS are reported `unknown` and NOT `yes`. This is the
#      assertion that matters. Egress denial and the Secret refusal are both TRUE
#      here -- the drill proves them a few steps earlier -- which is exactly why
#      a future edit is tempted to have posture assert them from the manifest.
#      It must not: posture makes no network calls, so it cannot have attempted
#      either, and a report claiming a refusal it never attempted is the
#      overclaim this epic's audience is best equipped to find.
#   4. no gap is written in the future tense, which reads to a user as handled
#
# NOTE what this leg does NOT do: it does not check that the claims are TRUE.
# Nothing in a test can settle whether "admission is two-key" is semantically
# true of the code it cites. The wrapper's own citation test
# checks that every citation still resolves and that no cited gap's issue has
# been closed (#280); the rest is a review cadence's job, and saying so is
# cheaper than implying a coverage that does not exist.
set -euo pipefail

HOME_DIR="${POSTURE_HOME:-/var/lib/broker}"
PROJECT_DIR="${POSTURE_PROJECT:-/tmp}"
# The wrapper CLI, overridable. The default names OUR wrapper deliberately, and it is the one
# product name left in this tree on purpose. The alternative — no default — would make this leg
# skip silently in our own runs unless an operator remembered a variable, and a coverage leg that
# quietly stops running is the exact failure this arm exists to catch. A reader without that
# wrapper installed gets the skip message below, which says what the leg needs and why.
POSTURE_CLI="${POSTURE_CLI:-tegh}"

# This leg reports posture through a PRODUCT WRAPPER, not through the platform. The wrapper
# is deliberately absent from the public reference implementation, so skip rather than fail:
# the arm predates this leg by twelve minor versions and is complete without it.
if ! command -v "$POSTURE_CLI" >/dev/null 2>&1; then
  printf '   posture leg SKIPPED: no `%s` on PATH.\n' "$POSTURE_CLI"
  printf '   This leg reports through a product wrapper that is not part of the platform.\n'
  exit 0
fi

# shellcheck source=negative-proof.sh
source "$(dirname "$0")/negative-proof.sh"
say() { np_say "$@"; }
ok()  { np_ok "$@"; }
die() { np_die "$@"; }

say "0. where this report is being generated"
printf '   pod=%s  uid=%s  sa=%s  ns=%s\n' \
  "$(hostname | cut -d. -f1)" "$(id -u)" \
  "${POD_SERVICE_ACCOUNT:-<not injected>}" \
  "$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo '<none>')"

# The store may or may not be mounted here, and BOTH are legitimate: the agent
# pod holds nothing by design, the broker pod holds the store. posture reports
# whichever it finds, so this leg must not require one.
say "1. the report, as JSON, asserted"
"$POSTURE_CLI" posture --home "$HOME_DIR" --project "$PROJECT_DIR" --json > /tmp/posture.json \
  || die "posture exited non-zero — a report it could produce always exits 0"

python3 - /tmp/posture.json <<'PY' || die "the posture report did not satisfy the Phase 6.1 predicate"
import json
import sys

report = json.loads(open(sys.argv[1], encoding="utf-8").read())
cluster = report.get("cluster") or []
failures = []

# 1. the section exists at all.
if not cluster:
    print("   the CLUSTER section is EMPTY inside a pod — cluster.observe() found no\n"
          "   ServiceAccount namespace file, so the report silently fell back to the\n"
          "   laptop path and claims nothing about this containment", file=sys.stderr)
    sys.exit(1)
print(f"   CLUSTER section: {len(cluster)} line(s)")

# 2. this pod is seen as a distinct principal.
identity = [x for x in cluster if "ServiceAccount" in x["claim"]]
if not identity:
    failures.append("no line names this pod's ServiceAccount")
else:
    print(f"   identity: {identity[0]['claim'][:96]}...  [{identity[0]['holds']}]")
    if identity[0]["holds"] not in ("yes", "unknown"):
        failures.append(f"identity line holds={identity[0]['holds']}")
    if "UNVERIFIED" not in identity[0]["source"]:
        failures.append("the identity line does not mark the token payload unverified — "
                        "posture cannot ask the API server, and must say so")

# 3. THE ONE THAT MATTERS. Both refusals are true here and neither was attempted
#    by this process, so neither may be reported as holding.
for subject in ("egress", "RBAC"):
    matched = [x for x in cluster if subject in x["claim"]]
    if not matched:
        failures.append(f"no line addresses {subject}")
        continue
    line = matched[0]
    print(f"   {subject}: [{line['holds']}] {line['claim'][:80]}")
    if line["holds"] != "unknown":
        failures.append(
            f"the {subject} line reports holds={line['holds']!r}. posture makes no "
            f"network calls, so it cannot have attempted this refusal — reporting it "
            f"as anything but 'unknown' is a claim read off the manifest")
    if "cluster-agent.sh" not in line["source"]:
        failures.append(f"the {subject} line does not name what DOES attempt it")

# 4. no gap in the future tense, across the whole report.
blob = json.dumps(report).lower()
for weasel in ("will be", "coming soon", "pending implementation"):
    if weasel in blob:
        failures.append(f"future tense in a posture report: {weasel!r}")

for f in failures:
    print(f"   {f}", file=sys.stderr)
sys.exit(1 if failures else 0)
PY
ok "the report names this pod's identity, and reports both refusals as UNKNOWN rather than claiming them"

say "2. the report, as a human reads it"
"$POSTURE_CLI" posture --home "$HOME_DIR" --project "$PROJECT_DIR" | sed 's/^/   /'

printf '\n\033[32mPHASE 6.1 PREDICATE: PASS\033[0m — posture speaks cluster vocabulary, from inside a pod.\n'
printf '\n\033[1mWhat this leg does NOT establish:\033[0m\n'
printf '  * That the claims are TRUE. It checks the report is honest about what it\n'
printf '    did not attempt; whether "admission is two-key" describes the code is a\n'
printf '    reviewer'"'"'s judgement, and #280 checks only that the citations resolve.\n'
printf '  * Rung 2. The containment half is observed here and the gating half is not,\n'
printf '    because this pod drives the broker over HTTP rather than through a wrapped\n'
printf '    harness. A boundary around something that gates nothing is not a rung.\n'
