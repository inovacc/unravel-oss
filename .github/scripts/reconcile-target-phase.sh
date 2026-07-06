#!/usr/bin/env bash
# reconcile-target-phase.sh: P41-02 — implements P37-04 / P38-04 reconciliation
# in bash + jq for CI integration. Routes target_phase: <N> defects to closures.
#
# Default policy: every defect for the given target_phase routes to
# CLOSED-by-{TARGET_PHASE} citing the v2.6 plan SUMMARY commits. Human reviewers
# can amend post-hoc to CLOSED-by-new-fix or DEFERRED with rationale (per
# P37-04 / P38-04 plan-level autonomous: false on the new-fix bucket).
set -euo pipefail

TARGET_PHASE="${1:?usage: $0 <target_phase> <output_md>}"
OUTPUT_MD="${2:?usage: $0 <target_phase> <output_md>}"
FINDINGS_JSON=".planning/phases/36-kb-capture-e2e-uat/36-UAT-FINDINGS.json"

if [[ ! -f "$FINDINGS_JSON" ]]; then
    echo "[skip] $FINDINGS_JSON missing"
    exit 0
fi

DEFECT_COUNT=$(jq "[.defects[] | select(.target_phase == ${TARGET_PHASE})] | length" "$FINDINGS_JSON")
echo "[reconcile] phase=${TARGET_PHASE} defects=${DEFECT_COUNT}"

mkdir -p "$(dirname "$OUTPUT_MD")"

cat > "$OUTPUT_MD" <<EOF
# Phase ${TARGET_PHASE} — P36 Findings Reconciliation

**Source:** \`$FINDINGS_JSON\`
**Run date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Total target_phase: ${TARGET_PHASE} defects:** ${DEFECT_COUNT}

EOF

if [[ "$DEFECT_COUNT" == "0" ]]; then
    echo "_No defects observed for fixtures present at CI run._" >> "$OUTPUT_MD"
    echo "[done] wrote $OUTPUT_MD (no defects)"
    exit 0
fi

cat >> "$OUTPUT_MD" <<EOF

## Defect → Closure Map

| F-36-NN | platform | severity | kb_field | observed | closure | reference |
|---------|----------|----------|----------|----------|---------|-----------|
EOF

jq -r ".defects[] | select(.target_phase == ${TARGET_PHASE}) | \"| \(.id) | \(.platform) | \(.severity) | \(.kb_field) | \(.observed) | CLOSED-by-${TARGET_PHASE} | v2.6 P${TARGET_PHASE} SUMMARY |\"" "$FINDINGS_JSON" >> "$OUTPUT_MD"

cat >> "$OUTPUT_MD" <<EOF

## Methodology

CI auto-classified all \`target_phase: ${TARGET_PHASE}\` defects to CLOSED-by-${TARGET_PHASE}.
Human reviewer can amend post-hoc to CLOSED-by-new-fix or DEFERRED with rationale.
EOF

echo "[done] wrote $OUTPUT_MD"
