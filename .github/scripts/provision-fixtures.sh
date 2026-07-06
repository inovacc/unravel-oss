#!/usr/bin/env bash
# provision-fixtures.sh: P41-01 — fetch v2.6 CI fixtures from secret URLs.
# Per D-36-FIXTURE-ENV-VARS: skip-when-fixture-absent honored.
set -euo pipefail

FIXTURE_DIR="${RUNNER_TEMP:-/tmp}/fixtures"
mkdir -p "$FIXTURE_DIR"

provision() {
    local var_url="$1"
    local var_path="$2"
    local fname="$3"
    local url="${!var_url:-}"
    if [[ -z "$url" ]]; then
        echo "[skip] $var_url unset; subtest will skip"
        return 0
    fi
    local target="$FIXTURE_DIR/$fname"
    echo "[fetch] $fname (URL redacted by GHA secret masking)"
    curl -fsSL --max-time 300 "$url" -o "$target"
    local size
    size=$(stat -c%s "$target")
    if [[ "$size" -lt 1024 ]]; then
        echo "[fail] $fname is $size bytes; expected >1K"
        exit 1
    fi
    echo "[ok] $fname ($size bytes)"
    echo "$var_path=$target" >> "${GITHUB_ENV:-/dev/null}"
}

provision UNRAVEL_FIXTURE_URL_WHATSAPP_MSIX UNRAVEL_TEST_WHATSAPP_MSIX whatsapp.msix
provision UNRAVEL_FIXTURE_URL_TEAMS_MSIX    UNRAVEL_TEST_TEAMS_MSIX    teams.msix
provision UNRAVEL_FIXTURE_URL_DOTNET_EXE    UNRAVEL_TEST_DOTNET_EXE    dotnet-console.exe
provision UNRAVEL_FIXTURE_URL_IOS_IPA       UNRAVEL_TEST_IOS_IPA       sample.ipa

echo "[done] fixture provisioning complete"
