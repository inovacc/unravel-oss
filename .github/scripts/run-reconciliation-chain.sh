#!/usr/bin/env bash
# run-reconciliation-chain.sh: P41-01 — drives P37-04 + P38-04 reconciliation
# after P36-03 produces 36-UAT-FINDINGS.{md,json}.
set -euo pipefail

FINDINGS_JSON=".planning/phases/36-kb-capture-e2e-uat/36-UAT-FINDINGS.json"

if [[ ! -f "$FINDINGS_JSON" ]]; then
    echo "[halt] $FINDINGS_JSON missing; P36-03 did not produce findings — chain aborted"
    exit 0  # Not a hard failure — P36-03 may have skipped if fixtures absent
fi

# Validate JSON
if ! python3 -m json.tool "$FINDINGS_JSON" > /dev/null 2>&1; then
    echo "[fail] $FINDINGS_JSON is not valid JSON"
    exit 1
fi

# Run Plan 37-04 reconciliation
echo "[37-04] reconciling android-target defects"
bash .github/scripts/reconcile-target-phase.sh 37 \
    .planning/phases/37-knowledge-extractor-coverage-android/37-FINDINGS-RECONCILIATION.md

# Run Plan 38-04 reconciliation
echo "[38-04] reconciling windows-stack defects"
bash .github/scripts/reconcile-target-phase.sh 38 \
    .planning/phases/38-knowledge-extractor-coverage-uwp-electron/38-FINDINGS-RECONCILIATION.md

# Update v2.6 archive REQs
echo "[41] updating v2.6 archive REQ flips"
bash .github/scripts/flip-v2-6-reqs.sh

echo "[done] reconciliation chain complete"
