#!/usr/bin/env bash
# retag-v2-6-1.sh: P41-03 — full-closure retag of v2.6 → v2.6.1.
# Pre-flight checks all 9 carry-over REQs flipped + audit addendum landed
# + ROADMAP marker upgraded + tag does not already exist. Halts if any check fails.
#
# autonomous: false at the plan level — script lives in repo so contributors
# can invoke it after reviewing the CI run output. Does NOT auto-push the tag
# (CLAUDE.md "no push without explicit user request").
set -euo pipefail

ARCHIVE_REQS=".planning/milestones/v2.6-REQUIREMENTS.md"
AUDIT_FILE=".planning/v2.6-AUDIT.md"
ROADMAP_FILE=".planning/ROADMAP.md"

# Pre-flight 1: all 9 carry-over REQs closed
fail=0
for req in CAPE-02 CAPE-03 CAPE-04 CAPE-05 CAPE-06 COVR-01 COVR-02 COVR-03 COVR-04; do
    if ! grep -qE "^- \[x\] \*\*${req}\*\*" "$ARCHIVE_REQS"; then
        echo "[fail] ${req} not closed in $ARCHIVE_REQS"
        fail=1
    fi
done
if [[ $fail -ne 0 ]]; then
    echo "[halt] one or more v2.6 carry-over REQs not closed; run CI chain first"
    exit 1
fi

# Pre-flight 2: audit addendum landed
if ! grep -q "## Closure Addendum" "$AUDIT_FILE"; then
    echo "[halt] $AUDIT_FILE missing closure addendum"
    exit 1
fi
if ! grep -q "Status upgraded: partial → passed" "$AUDIT_FILE"; then
    echo "[halt] $AUDIT_FILE missing status upgrade line"
    exit 1
fi

# Pre-flight 3: ROADMAP marker upgraded (no 🟡 v2.6 marker remains)
if grep -qE "🟡 \*\*v2\.6 " "$ROADMAP_FILE"; then
    echo "[halt] $ROADMAP_FILE still shows 🟡 v2.6 marker; flip-v2-6-reqs.sh did not run"
    exit 1
fi

# Pre-flight 4: tag does not already exist
if git tag -l v2.6.1 | grep -q v2.6.1; then
    echo "[halt] tag v2.6.1 already exists; retag would amend (CLAUDE.md forbids)"
    exit 1
fi

SHA=$(git rev-parse --short HEAD)
MSG="v2.6.1 full-closure: closes CAPE-02..06 + COVR-01..04 via CI run on ${SHA}; backlog 999.4 retired."

git tag -a v2.6.1 -m "$MSG"
echo "[tagged] v2.6.1 at ${SHA}"

# STATE.md update — atomic with tag creation (set -e ensures we don't get here on tag failure).
{
    echo ""
    echo "## v2.6 Full-Closure Event $(date -u +%Y-%m-%d)"
    echo ""
    echo "v2.6 retagged as v2.6.1 at ${SHA}. CI carry-over chain closed all 9 REQs"
    echo "(CAPE-02..06 + COVR-01..04). Backlog 999.4 retired. v2.7 active milestone unchanged."
} >> .planning/STATE.md

echo "[done] v2.6.1 retag complete; STATE.md appended"
echo "[note] tag is local; push manually if/when ready: git push origin v2.6.1"
