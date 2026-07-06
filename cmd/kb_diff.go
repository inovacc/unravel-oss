/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/diff"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

var (
	kbDiffFrom     int64
	kbDiffTo       int64
	kbDiffCategory []string
	kbDiffJSON     bool
	kbDiffDSN      string
)

var diffCmd = &cobra.Command{
	Use:   "diff <kb_id>",
	Short: "Compare two KB epochs (typed diffs)",
	Long: `Compare any two epochs of a kb_id.

If the gap is exactly 1 (e.g. --from 1 --to 2), it reads pre-computed
typed diffs from the kb_diffs table (consecutive mode).

If the gap is > 1 (e.g. --from 1 --to 5), it computes a set-difference
of all facts directly from app_facts (long-range mode). Long-range
diffs are capped at 20 epochs for performance.`,
	Args: cobra.ExactArgs(1),
	RunE: runKbDiff,
}

func init() {
	diffCmd.Flags().Int64Var(&kbDiffFrom, "from", 0, "starting epoch (required)")
	diffCmd.Flags().Int64Var(&kbDiffTo, "to", 0, "ending epoch (required)")
	diffCmd.Flags().StringSliceVar(&kbDiffCategory, "category", nil, "comma-separated categories to filter (file,dep,capability,url,risk,cert,fact,module,component)")
	kb_output.BindJSONFlag(diffCmd, &kbDiffJSON)
	kb_output.BindDSNFlag(diffCmd, &kbDiffDSN)

	_ = diffCmd.MarkFlagRequired("from")
	_ = diffCmd.MarkFlagRequired("to")

	kbTransferCmd.AddCommand(diffCmd)
}

func runKbDiff(cmd *cobra.Command, args []string) error {
	kbID := args[0]
	if kbDiffFrom >= kbDiffTo {
		return fmt.Errorf("from (%d) must be less than to (%d)", kbDiffFrom, kbDiffTo)
	}

	// Validate categories
	validCategories := map[string]bool{
		"file":       true,
		"dep":        true,
		"capability": true,
		"url":        true,
		"risk":       true,
		"cert":       true,
		"fact":       true,
		"module":     true,
		"component":  true,
	}
	for _, cat := range kbDiffCategory {
		if !validCategories[cat] {
			return fmt.Errorf("unknown category %q; valid: file, dep, capability, url, risk, cert, fact, module, component", cat)
		}
	}

	dsn, err := kb_output.ResolveDSN(kbDiffDSN)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb: %w", err)
	}
	defer func() { _ = db.Close() }()

	canonical, err := identity.ResolveAlias(ctx, db, kbID)
	if err != nil {
		return fmt.Errorf("resolve alias: %w", err)
	}
	if canonical != kbID {
		fmt.Fprintf(os.Stderr, "WARN: resolved from alias %s -> canonical %s\n", kbID, canonical)
	}

	gap := kbDiffTo - kbDiffFrom
	if gap == 1 {
		return handleConsecutiveDiff(ctx, db, cmd.OutOrStdout(), canonical, kbDiffFrom, kbDiffTo)
	}
	return handleLongRangeDiff(ctx, db, cmd.OutOrStdout(), canonical, kbDiffFrom, kbDiffTo)
}

// DiffResult is the JSON output structure (schema_version=1).
type DiffResult struct {
	KbID       string                        `json:"kb_id" jsonschema:"canonical knowledge-base identifier (alias-resolved fingerprint)"`
	FromEpoch  int64                         `json:"from_epoch" jsonschema:"starting epoch (inclusive); must be < to_epoch"`
	ToEpoch    int64                         `json:"to_epoch" jsonschema:"ending epoch (inclusive); must be > from_epoch"`
	Mode       string                        `json:"mode" jsonschema:"diff routing mode: 'consecutive' (gap=1, reads kb_diffs) or 'longrange' (gap>1, computed via set-difference, capped at 20 epochs)"`
	Categories map[string]*CategoryDiffItems `json:"categories" jsonschema:"map of category (file, dep, capability, url, risk, cert, fact, module, component) to added/removed/modified items"`
}

type CategoryDiffItems struct {
	Added    []any `json:"added,omitempty" jsonschema:"items added between from_epoch and to_epoch in this category"`
	Removed  []any `json:"removed,omitempty" jsonschema:"items removed between from_epoch and to_epoch in this category"`
	Modified []any `json:"modified,omitempty" jsonschema:"items modified between from_epoch and to_epoch in this category"`
}

func handleConsecutiveDiff(ctx context.Context, db *sql.DB, out io.Writer, kbID string, from, to int64) error {
	query := `
SELECT d.category, d.change_type, d.identifier, d.payload
FROM kb_diffs d
JOIN knowledge_sources s1 ON d.from_source_id = s1.id
JOIN knowledge_sources s2 ON d.to_source_id = s2.id
WHERE s1.kb_id = $1 AND s1.epoch = $2 AND s2.epoch = $3 AND s2.kb_id = $1`

	var args []any
	args = append(args, kbID, from, to)

	if len(kbDiffCategory) > 0 {
		query += " AND d.category = ANY($4)"
		args = append(args, kbDiffCategory)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("query kb_diffs: %w", err)
	}
	defer rows.Close()

	res := &DiffResult{
		KbID:       kbID,
		FromEpoch:  from,
		ToEpoch:    to,
		Mode:       "consecutive",
		Categories: make(map[string]*CategoryDiffItems),
	}

	for rows.Next() {
		var cat, changeType, identifier string
		var payloadJSON []byte
		if err := rows.Scan(&cat, &changeType, &identifier, &payloadJSON); err != nil {
			return fmt.Errorf("scan kb_diff: %w", err)
		}

		if res.Categories[cat] == nil {
			res.Categories[cat] = &CategoryDiffItems{}
		}

		var payload any
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			payload = string(payloadJSON)
		}

		item := map[string]any{
			"identifier": identifier,
			"data":       payload,
		}

		switch changeType {
		case "added":
			res.Categories[cat].Added = append(res.Categories[cat].Added, item)
		case "removed":
			res.Categories[cat].Removed = append(res.Categories[cat].Removed, item)
		case "modified":
			res.Categories[cat].Modified = append(res.Categories[cat].Modified, item)
		}
	}

	if kbDiffJSON {
		return kb_output.WriteJSON(out, 1, res)
	}

	renderPlainText(out, res)
	return nil
}

func handleLongRangeDiff(ctx context.Context, db *sql.DB, out io.Writer, kbID string, from, to int64) error {
	payload, err := diff.LongRangeDiff(ctx, db, kbID, from, to)
	if err != nil {
		return err // Propagate 20-epoch cap error
	}

	res := &DiffResult{
		KbID:       kbID,
		FromEpoch:  from,
		ToEpoch:    to,
		Mode:       "longrange",
		Categories: make(map[string]*CategoryDiffItems),
	}

	filter := make(map[string]bool)
	for _, c := range kbDiffCategory {
		filter[c] = true
	}

	// LongRangeDiff returns map[category][]FactDiffEntry in Added/Removed/Modified fields.
	for cat, items := range payload.Added {
		if len(filter) > 0 && !filter[cat] {
			continue
		}
		if res.Categories[cat] == nil {
			res.Categories[cat] = &CategoryDiffItems{}
		}
		for _, item := range items {
			res.Categories[cat].Added = append(res.Categories[cat].Added, item)
		}
	}
	for cat, items := range payload.Removed {
		if len(filter) > 0 && !filter[cat] {
			continue
		}
		if res.Categories[cat] == nil {
			res.Categories[cat] = &CategoryDiffItems{}
		}
		for _, item := range items {
			res.Categories[cat].Removed = append(res.Categories[cat].Removed, item)
		}
	}
	for cat, items := range payload.Modified {
		if len(filter) > 0 && !filter[cat] {
			continue
		}
		if res.Categories[cat] == nil {
			res.Categories[cat] = &CategoryDiffItems{}
		}
		for _, item := range items {
			res.Categories[cat].Modified = append(res.Categories[cat].Modified, item)
		}
	}

	if kbDiffJSON {
		return kb_output.WriteJSON(out, 1, res)
	}

	renderPlainText(out, res)
	return nil
}

func renderPlainText(out io.Writer, res *DiffResult) {
	fmt.Fprintf(out, "Diff for %s: epoch %d -> %d (%s mode)\n\n", res.KbID, res.FromEpoch, res.ToEpoch, res.Mode)

	if len(res.Categories) == 0 {
		fmt.Fprintln(out, "No changes found.")
		return
	}

	cats := make([]string, 0, len(res.Categories))
	for c := range res.Categories {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	for _, cat := range cats {
		items := res.Categories[cat]
		fmt.Fprintf(out, "=== %s ===\n", cat)
		for _, it := range items.Added {
			fmt.Fprintf(out, "+ added: %s\n", formatItem(it))
		}
		for _, it := range items.Removed {
			fmt.Fprintf(out, "- removed: %s\n", formatItem(it))
		}
		for _, it := range items.Modified {
			fmt.Fprintf(out, "~ modified: %s\n", formatItem(it))
		}
		fmt.Fprintln(out)
	}
}

func formatItem(it any) string {
	switch v := it.(type) {
	case map[string]any:
		if ident, ok := v["identifier"].(string); ok {
			return ident
		}
		// FactDiffEntry field names when unmarshaled from JSON
		if key, ok := v["key"].(string); ok {
			return key
		}
		return fmt.Sprintf("%v", v)
	case diff.FactDiffEntry:
		return v.Key
	default:
		return fmt.Sprintf("%v", it)
	}
}
