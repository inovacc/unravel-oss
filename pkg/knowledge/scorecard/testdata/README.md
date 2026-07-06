# Scorecard testdata

This directory holds fixtures for the build-tag-gated WhatsApp parity test
(`parity_integration_test.go`, build tag `whatsapp_fixture`).

## WhatsApp MSIX provenance

| Property | Value |
|----------|-------|
| Package family | `5319275A.WhatsAppDesktop` |
| Source path (Windows) | `C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_<ver>_x64__cv1g1gvanyjgm\` |
| Acquisition | `Get-AppxPackage -Name *WhatsApp*` (operator environment) |
| Version | best-effort from `AppxManifest.xml` Identity.Version (operator-recorded at fixture-regen time) |

The MSIX itself is not committed. Only the marshalled `*dissect.DissectResult`
JSON is committed (and only when an operator can run the regen command on a
machine that has WhatsApp installed). When the fixture file
`whatsapp_dissect_result.json` is absent, the integration test skips because
its build tag prevents it from being included in the default suite.

## Regen command

```bash
go run . dissect "<path-to-WhatsApp.msix-or-WindowsApps-dir>" --json \
  > pkg/knowledge/scorecard/testdata/whatsapp_dissect_result.json
```

`--json` is a Cobra `BoolVar` registered in `cmd/dissect.go` (line 53). When
set it writes a single `json.MarshalIndent` document of the
`*dissect.DissectResult` to stdout (the result that the analysis pipeline
returns from `dissect.Run`). All logging stays on stderr; stdout is reserved
for output data per CLAUDE.md.

The output round-trips through `json.Unmarshal` into `*dissect.DissectResult`
because `DissectResult` and every per-format Info struct already carry
snake_case JSON tags.

## W-11 baseline expected scores

`expected_score_w11_baseline.json` is the W-11 baseline snapshot of
`out/whatsapp-kb/_score.json` — the third entry in the W-loop iteration log
(50 -> 71.2 -> 77.5 -> 78.8 -> 83.3 -> 85.8). Numbers come from
RESEARCH.md §A4 ground-truth-curves table, columns marked W-12/W-13/W-14
zeroed out:

| Dim | W-11 baseline | Source (script:line) |
|-----|---------------|----------------------|
| identity | 90 | W-10:381 (spec floor) |
| filesystem | 95 | W-10:382 (spec floor) |
| binary_surface | 70 | W-02:94 (cap) |
| source_layer | 90 | W-10:383 (spec floor) |
| ipc | 50 | W-10b:202 (refresh floor) |
| api | 75 | W-05:100 (high hits) |
| wire | 65 | W-10b:203 (refresh floor) |
| storage | 90 | W-06:108-118 (cap) |
| auth | 70 | W-10b:202 (refresh floor) |
| crypto | 85 | W-07 (six needles + bin) |
| state_machines | 80 | W-10b:203 (refresh floor) |
| behavior | 85 | W-10b:204 (refresh floor) |

Coverage = 7 (count of dims with score >= 80 from the table above:
identity 90, filesystem 95, source_layer 90, storage 90, crypto 85,
state_machines 80, behavior 85). The plan PLAN.md called out a value of 9
in its example JSON; the table-derived count is 7. The integration test
uses the baseline JSON (which carries the table-derived 7) as ground
truth.

Note: the table above documents the curve targets per RESEARCH.md. The
parity gate in `parity_integration_test.go` allows ±5 absolute (RUBR-03 ±5%
of an integer 0-100 score) per dim AND ±5 of mean.

W-12/W-13/W-14 deepening adders are P57 scope — DO NOT update the baseline
to post-W-13 values without owning P57.

## F-69-07 dim-regression repro fixtures (P72 / DIMR-01)

`dimfix_whatsapp_dissect.json` and `dimfix_teams_dissect.json` are **minimal
hand-authored** `*dissect.DissectResult` JSON modeling only the fields the
storage/crypto/behavior scorers read — intentionally NOT full DissectResult
mirrors (same discipline as `uwp_install_dir_fields.json`). They are NOT
operator-regenerated: they ship no binary, carry no build tag, and are
default-discoverable so `dim_regression_repro_test.go` runs on every
`go test ./...` (D-72-02; P73 regression-guard seed).

| Fixture | Provenance | Authored floor | Notes |
|---------|-----------|----------------|-------|
| `dimfix_whatsapp_dissect.json` | hand-authored, grounded in `72-RESEARCH.md` Fixture Repro Design | storage=0, crypto=0 | `msix_info.files` carries no storage-hint/sqlite names and no crypto JS signal; `package_name` ≠ rescan pkgId `5319275A.WhatsAppDesktop` (H4/A2 path-contract substrate) |
| `dimfix_teams_dissect.json` | hand-authored, grounded in `72-RESEARCH.md` Fixture Repro Design | storage=0, behavior=10 | `webview2_info` present (behavior legacy scenarios==1 → 10) but `profiles` empty (storage stays 0); `cert_info` absent (no 85 spec-refresh); no caps/urls/ui-hint files (scoreBehaviorUWP ≤10) |

Provenance keys `_comment` / `_grounded_in` / `_phase` / `_task` are carried
in-fixture (analog `uwp_install_dir_fields.json`). Both round-trip via the
snake_case JSON tags of `dissect.DissectResult` (Pattern B strategy 1 — direct
`json.Unmarshal`; no field required the shaped-struct fallback, A1 not
triggered). The `floorReproPhase` const in the test pins the pre-fix floor;
Plan 03 inverts it post-fix.

## How an operator regenerates

1. On a Windows machine with WhatsApp installed, run the regen command.
2. Validate the result with `go test -tags=whatsapp_fixture
   ./pkg/knowledge/scorecard/... -run TestWhatsAppParity -count=1`.
3. If a per-dim score deviates by more than ±5 from the baseline, decide:
   either the W-11 baseline numbers need a documented update (rare; requires
   a planner ADR) OR a scorer curve drifted (file a fix, not a baseline
   update).

## W-13 final-state expected scores (P60 / VALD-02)

`expected_score_w13_final.json` is the WhatsApp post-W-13 final-state snapshot
sourced verbatim from `out/whatsapp-kb/_score.json` (post-CDP final state,
mean 85.8%, dims_at_80 = 11/12, loop_exit = true). It is the parity fixture
for `TestVALD02_WhatsAppParity` (build tag `corpus_validation`, P60).

- **Capture date:** 2026-05-08.
- **Operator command:** `unravel knowledge --iterate --scorecard-md --cdp-port 9222 --max-iter 5 --threshold 80 <whatsapp-dir>`
- **W-13b bumps applied to source:** wire -> 85, auth -> 80, state_machines -> 80; ipc remained at 75 (lift target documented).

### Locked schema (matches shipped P56–P59 `Scorecard`)

```go
type Scorecard struct {
    KbID        string     `json:"kb_id"`
    Dimensions  []DimScore `json:"dimensions"`
    Coverage    int        `json:"coverage"`
    CitationsOK bool       `json:"citations_ok"`
}

type DimScore struct {
    ID               string     `json:"id"`
    Name             string     `json:"name"`
    Score            int        `json:"score"`
    Evidence         []Evidence `json:"evidence,omitempty"`
    MissingCitations int        `json:"missing_citations,omitempty"`
}
```

`Dimensions` is a **slice** (not a map) of exactly 12 entries in the
canonical order from `dims.go::CanonicalDims`:

```
identity, filesystem, binary_surface, source_layer,
ipc, api, wire, storage,
auth, crypto, state_machines, behavior
```

VALD-02 acceptance: `Coverage >= 11 AND len(Dimensions) == 12`. Any
RESEARCH.md note referring to "13 dims" is incorrect — corpus is exactly
12 dims (corrected here).

The W-11 baseline (static-only path) is unchanged. W-13 fixture (CDP-final
path) is additive — both fixtures coexist in this directory.
