/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"

	"github.com/spf13/cobra"
)

var kbTimelineFlags struct {
	reverse bool
	json    bool
	dsn     string
}

var timelineCmd = &cobra.Command{
	Use:   "timeline <kb_id>",
	Short: "Show chronological epoch deltas for a KB app",
	Args:  cobra.ExactArgs(1),
	RunE:  runKbTimeline,
}

func init() {
	timelineCmd.Flags().BoolVar(&kbTimelineFlags.reverse, "reverse", false, "reverse order (latest first)")

	kb_output.BindJSONFlag(timelineCmd, &kbTimelineFlags.json)
	kb_output.BindDSNFlag(timelineCmd, &kbTimelineFlags.dsn)

	kbCatalogCmd.AddCommand(timelineCmd)
}

func runKbTimeline(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	dsn, err := kb_output.ResolveDSN(kbTimelineFlags.dsn)
	if err != nil {
		return err
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer db.Close()

	// 1) Resolve Alias
	kbID := args[0]
	canonical, err := identity.ResolveAlias(ctx, db, kbID)
	if err != nil {
		return fmt.Errorf("resolve alias: %w", err)
	}
	if canonical != kbID {
		fmt.Fprintf(os.Stderr, "(resolved from alias %s -> canonical %s)\n", kbID, canonical)
		kbID = canonical
	}

	// 2) Query Evolution + Metadata (merged query for efficiency)
	// We use LAG over kb_id partition to ensure correct deltas even if app name changed.
	rows, err := db.QueryContext(ctx, `
		SELECT epoch, captured_at, app_version, risk_level, depth_score, modules_indexed,
		       modules_indexed - LAG(modules_indexed) OVER (ORDER BY epoch) as modules_delta
		FROM knowledge_sources
		WHERE kb_id = $1
		ORDER BY epoch ASC
	`, kbID)
	if err != nil {
		return fmt.Errorf("query evolution: %w", err)
	}
	defer rows.Close()

	type epochInfo struct {
		Epoch          int            `json:"epoch" jsonschema:"monotonic per-kb epoch number; first capture is 1"`
		CapturedAt     int64          `json:"captured_at" jsonschema:"unix-millisecond timestamp when this epoch was captured"`
		AppVersion     *string        `json:"app_version" jsonschema:"app version string at this epoch; null when unknown"`
		RiskLevel      *string        `json:"risk_level" jsonschema:"risk level at this epoch (low, medium, high, critical); null when unscored"`
		DepthScore     *int           `json:"depth_score" jsonschema:"depth-of-analysis score at this epoch; null when unscored"`
		ModulesIndexed int            `json:"modules_indexed" jsonschema:"total modules indexed at this epoch"`
		ModulesDelta   int            `json:"modules_delta" jsonschema:"signed change in modules_indexed vs. previous epoch (0 for first epoch)"`
		DiffCounts     map[string]int `json:"diff_counts" jsonschema:"per-category diff counts vs. previous epoch (file, dep, capability, url, risk, cert, fact, module, component)"`
	}

	var epochs []epochInfo
	for rows.Next() {
		var ei epochInfo
		var av, rl *string
		var ds *int
		var md *int // LAG can be NULL for first row
		if err := rows.Scan(&ei.Epoch, &ei.CapturedAt, &av, &rl, &ds, &ei.ModulesIndexed, &md); err != nil {
			return fmt.Errorf("scan evolution: %w", err)
		}
		ei.AppVersion = av
		ei.RiskLevel = rl
		ei.DepthScore = ds
		if md != nil {
			ei.ModulesDelta = *md
		}
		ei.DiffCounts = make(map[string]int)
		epochs = append(epochs, ei)
	}

	// 3) Query Diff Counts
	dRows, err := db.QueryContext(ctx, `
		SELECT ks.epoch, d.category, COUNT(*)
		FROM kb_diffs d
		JOIN knowledge_sources ks ON ks.id = d.to_source_id
		WHERE ks.kb_id = $1
		GROUP BY ks.epoch, d.category
	`, kbID)
	if err != nil {
		return fmt.Errorf("query diff counts: %w", err)
	}
	defer dRows.Close()

	epochMap := make(map[int]*epochInfo)
	for i := range epochs {
		epochMap[epochs[i].Epoch] = &epochs[i]
	}

	for dRows.Next() {
		var te int
		var cat string
		var count int
		if err := dRows.Scan(&te, &cat, &count); err != nil {
			return fmt.Errorf("scan diff count: %w", err)
		}
		if ei, ok := epochMap[te]; ok {
			ei.DiffCounts[cat] = count
		}
	}

	if kbTimelineFlags.reverse {
		sort.Slice(epochs, func(i, j int) bool {
			return epochs[i].Epoch > epochs[j].Epoch
		})
	}

	if kbTimelineFlags.json {
		payload := map[string]any{
			"kb_id":  kbID,
			"epochs": epochs,
		}
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, payload)
	}

	headers := []string{"EPOCH", "CAPTURED_AT", "VERSION", "RISK", "DEPTH", "MODS", "DELTA", "DIFF_SUMMARY"}
	var tableRows [][]string
	for _, ei := range epochs {
		ver := "n/a"
		if ei.AppVersion != nil {
			ver = *ei.AppVersion
		}
		risk := "n/a"
		if ei.RiskLevel != nil {
			risk = *ei.RiskLevel
		}
		depth := "n/a"
		if ei.DepthScore != nil {
			depth = strconv.Itoa(*ei.DepthScore)
		}

		var diffSummary []string
		var cats []string
		for cat := range ei.DiffCounts {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			diffSummary = append(diffSummary, fmt.Sprintf("%s:%d", cat, ei.DiffCounts[cat]))
		}

		deltaStr := strconv.Itoa(ei.ModulesDelta)
		if ei.ModulesDelta > 0 {
			deltaStr = "+" + deltaStr
		}

		tableRows = append(tableRows, []string{
			strconv.Itoa(ei.Epoch),
			time.UnixMilli(ei.CapturedAt).Format(time.RFC3339),
			ver,
			risk,
			depth,
			strconv.Itoa(ei.ModulesIndexed),
			deltaStr,
			strings.Join(diffSummary, ", "),
		})
	}

	return kb_output.WriteTable(cmd.OutOrStdout(), headers, tableRows)
}
