/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// kbScorecardHeatmapFlags backs the `unravel kb scorecard-heatmap`
// subcommand (P60 / VALD-03). Two modes:
//   - --in <dir> (offline): read every *-SCORECARD.md / *_score.json sidecar
//     from a directory and render the cross-app heatmap.
//   - default DB mode (no --in): read kb_scorecards table; not exercised
//     by P60 default tests.
//
// The output markdown matches the v2.9 P52/P53 CORPUS-MATURITY.md shape:
// LINE 1 of expected.md is the verbatim v2.9 header so any drift is caught
// fast by the byte-equal golden test.
var kbScorecardHeatmapFlags struct {
	in  string
	out string
	dsn string
}

var kbScorecardHeatmapCmd = &cobra.Command{
	Use:   "scorecard-heatmap",
	Short: "Aggregate per-app scorecards into a corpus-maturity heatmap (P60 / VALD-03)",
	Long: `Aggregate per-app scorecard sidecars into a single cross-app heatmap.

Two modes:

  --in <dir>      Offline mode. Reads every *-SCORECARD.md or *_score.json
                  in <dir>; emits a markdown heatmap row per app.
  (default)       DB mode. Reads kb_scorecards table via --dsn (P59 surface).

Output is byte-comparable to v2.9 out/reports/CORPUS-MATURITY.md (line 1
header verbatim) so heatmap-shape drift is caught by the golden test.`,
	RunE: runKbScorecardHeatmap,
}

func init() {
	kbScorecardHeatmapCmd.Flags().StringVar(&kbScorecardHeatmapFlags.in, "in", "", "directory of *-SCORECARD.md / *_score.json sidecars (offline mode)")
	kbScorecardHeatmapCmd.Flags().StringVar(&kbScorecardHeatmapFlags.out, "out", "", "output markdown path (default: stdout)")
	kbScorecardHeatmapCmd.Flags().StringVar(&kbScorecardHeatmapFlags.dsn, "database", "", "postgres DSN (DB mode; ignored if --in is set)")
	kbCatalogCmd.AddCommand(kbScorecardHeatmapCmd)
}

// heatmapRow is one corpus app's row in the rendered heatmap.
type heatmapRow struct {
	PackageID   string
	Framework   string
	Mean10      int // mean_score * 10 (e.g. 858 means 85.8%)
	DimsAt80    int // 0..12
	LoopExit    bool
	RuntimeCap  bool
	DeltaVsV2_9 string // "+5.2", "-1.0", "n/a"
}

// sidecarShape models the on-disk *_score.json (richer than pure
// scorecard.Scorecard — carries package/coverage object/iterations).
type sidecarShape struct {
	KbID       string `json:"kb_id"`
	Package    string `json:"package"`
	Dimensions []struct {
		ID    string `json:"id"`
		Score int    `json:"score"`
	} `json:"dimensions"`
	Coverage struct {
		DimsAt80  int     `json:"dimensions_at_80"`
		MeanScore float64 `json:"mean_score"`
	} `json:"coverage"`
	Iterations []map[string]any `json:"iterations"`
}

func runKbScorecardHeatmap(cmd *cobra.Command, args []string) error {
	var rows []heatmapRow
	var missing []string

	switch {
	case kbScorecardHeatmapFlags.in != "":
		got, miss, err := loadSidecarRows(kbScorecardHeatmapFlags.in)
		if err != nil {
			return err
		}
		rows = got
		missing = miss
	default:
		return fmt.Errorf("DB mode not implemented in P60 (use --in <dir>); see kb_scorecards table for ingested rows")
	}

	out := io.Writer(os.Stdout)
	if kbScorecardHeatmapFlags.out != "" {
		f, err := os.Create(kbScorecardHeatmapFlags.out)
		if err != nil {
			return fmt.Errorf("create --out: %w", err)
		}
		defer func() { _ = f.Close() }()
		out = f
	}

	return renderHeatmap(out, rows, missing)
}

// loadSidecarRows scans dir for *_score.json (preferred for numeric
// fidelity) or *-SCORECARD.md (markdown fallback). Returns rows in
// stable package_id order plus a list of files that failed to parse.
func loadSidecarRows(dir string) ([]heatmapRow, []string, error) {
	jsonMatches, _ := filepath.Glob(filepath.Join(dir, "*_score.json"))
	mdMatches, _ := filepath.Glob(filepath.Join(dir, "*-SCORECARD.md"))

	// Index by package_id; JSON wins over MD (numeric fidelity).
	byPkg := map[string]heatmapRow{}
	var missing []string

	for _, p := range jsonMatches {
		pkg, row, err := parseSidecarJSON(p)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s: %v", filepath.Base(p), err))
			continue
		}
		byPkg[pkg] = row
	}
	for _, p := range mdMatches {
		pkg, row, err := parseSidecarMD(p)
		if err != nil {
			missing = append(missing, fmt.Sprintf("%s: %v", filepath.Base(p), err))
			continue
		}
		if _, exists := byPkg[pkg]; !exists {
			byPkg[pkg] = row
		}
	}

	keys := make([]string, 0, len(byPkg))
	for k := range byPkg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]heatmapRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, byPkg[k])
	}
	return rows, missing, nil
}

func parseSidecarJSON(path string) (string, heatmapRow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", heatmapRow{}, err
	}
	var s sidecarShape
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", heatmapRow{}, fmt.Errorf("unmarshal: %w", err)
	}
	pkg := s.Package
	if pkg == "" {
		// Fallback: derive from filename (strip _score.json suffix).
		base := strings.TrimSuffix(filepath.Base(path), "_score.json")
		base = strings.TrimSuffix(base, "-SCORECARD")
		pkg = base
	}
	// T-60-05 mitigation: reject mismatch between filename and inner
	// package_id. Conservative — log + skip.
	if filenamePkg := strings.TrimSuffix(filepath.Base(path), "_score.json"); filenamePkg != "" && s.Package != "" && filenamePkg != s.Package {
		// Allow but flag — operator may have renamed; surface in markdown
		// 'Missing' section.
		return "", heatmapRow{}, fmt.Errorf("package_id mismatch: filename=%q inner=%q", filenamePkg, s.Package)
	}
	row := heatmapRow{
		PackageID:   pkg,
		Framework:   detectFramework(s),
		Mean10:      int(s.Coverage.MeanScore*10 + 0.5),
		DimsAt80:    s.Coverage.DimsAt80,
		LoopExit:    detectLoopExit(s),
		RuntimeCap:  detectRuntimeCap(s),
		DeltaVsV2_9: "n/a",
	}
	return pkg, row, nil
}

func parseSidecarMD(path string) (string, heatmapRow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", heatmapRow{}, err
	}
	pkg := strings.TrimSuffix(filepath.Base(path), "-SCORECARD.md")
	row := heatmapRow{
		PackageID:   pkg,
		Framework:   "unknown",
		DeltaVsV2_9: "n/a",
	}
	// Cheap parse: look for "Mean score: NN.N%".
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "- Mean score:") {
			pct := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(l, "- Mean score:"), "%"))
			var f float64
			if _, err := fmt.Sscanf(pct, "%f", &f); err == nil {
				row.Mean10 = int(f*10 + 0.5)
			}
		}
		if strings.HasPrefix(l, "- Dimensions ≥80%:") {
			rest := strings.TrimSpace(strings.TrimPrefix(l, "- Dimensions ≥80%:"))
			var n, d int
			if _, err := fmt.Sscanf(rest, "%d/%d", &n, &d); err == nil {
				row.DimsAt80 = n
			}
		}
		if strings.HasPrefix(l, "**Loop exit:**") {
			row.LoopExit = strings.Contains(l, "True")
		}
	}
	return pkg, row, nil
}

func detectFramework(s sidecarShape) string {
	for _, it := range s.Iterations {
		if fw, ok := it["framework"].(string); ok && fw != "" {
			return fw
		}
	}
	return "unknown"
}

func detectLoopExit(s sidecarShape) bool {
	// Walk iterations newest-first looking for last W-11 record.
	for i := len(s.Iterations) - 1; i >= 0; i-- {
		it := s.Iterations[i]
		if id, _ := it["id"].(string); id == "W-11" {
			if v, ok := it["loop_exit"].(bool); ok {
				return v
			}
		}
	}
	return false
}

func detectRuntimeCap(s sidecarShape) bool {
	for _, it := range s.Iterations {
		if id, _ := it["id"].(string); id == "W-13" {
			return true
		}
	}
	return false
}

// renderHeatmap writes the markdown report. Line 1 is the verbatim v2.9
// header; remaining structure mirrors out/reports/CORPUS-MATURITY.md.
func renderHeatmap(w io.Writer, rows []heatmapRow, missing []string) error {
	var b strings.Builder
	// LINE 1 verbatim from v2.9 P52/P53 (Wave-0 capture).
	b.WriteString("# Corpus Maturity Heatmap (P52 / ELEC-04)\n")
	b.WriteString("\n")
	b.WriteString("_Regenerated for v2.10 by `unravel kb scorecard-heatmap` (P60 / VALD-03)._\n")
	b.WriteString("\n")
	b.WriteString("| package_id | framework | mean | dims_at_80 | loop_exit | runtime_cap | Δ_vs_v2_9 |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		mean := fmt.Sprintf("%d.%d%%", r.Mean10/10, r.Mean10%10)
		loop := "no"
		if r.LoopExit {
			loop = "yes"
		}
		runtime := "no"
		if r.RuntimeCap {
			runtime = "yes"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d/12 | %s | %s | %s |\n",
			r.PackageID, r.Framework, mean, r.DimsAt80, loop, runtime, r.DeltaVsV2_9)
	}
	if len(missing) > 0 {
		b.WriteString("\n## Missing / unparseable sidecars\n\n")
		for _, m := range missing {
			fmt.Fprintf(&b, "- %s\n", m)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
