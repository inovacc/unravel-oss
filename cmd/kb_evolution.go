/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"

	"github.com/spf13/cobra"
)

var kbEvolutionFlags struct {
	field string
	json  bool
	dsn   string
}

var evolutionCmd = &cobra.Command{
	Use:   "evolution <kb_id>",
	Short: "Plot a single field over app epochs",
	Args:  cobra.ExactArgs(1),
	RunE:  runKbEvolution,
}

func init() {
	evolutionCmd.Flags().StringVar(&kbEvolutionFlags.field, "field", "", "field to plot (risk_score, risk_level, depth_score, modules_indexed, bodies_indexed)")
	_ = cobra.MarkFlagRequired(evolutionCmd.Flags(), "field")

	kb_output.BindJSONFlag(evolutionCmd, &kbEvolutionFlags.json)
	kb_output.BindDSNFlag(evolutionCmd, &kbEvolutionFlags.dsn)

	kbCatalogCmd.AddCommand(evolutionCmd)
}

func runKbEvolution(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Validate field before building SQL
	var col string
	switch kbEvolutionFlags.field {
	case "risk_score":
		col = "risk_score"
	case "risk_level":
		col = "risk_level"
	case "depth_score":
		col = "depth_score"
	case "modules_indexed":
		col = "modules_indexed"
	case "bodies_indexed":
		col = "bodies_indexed"
	default:
		return fmt.Errorf("field must be one of: risk_score, risk_level, depth_score, modules_indexed, bodies_indexed")
	}

	dsn, err := kb_output.ResolveDSN(kbEvolutionFlags.dsn)
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

	// 2) Query Evolution
	// All fields are now in knowledge_sources (P29/P30).
	query := fmt.Sprintf(`
		SELECT epoch, captured_at, %s
		FROM knowledge_sources
		WHERE kb_id = $1
		ORDER BY epoch ASC
	`, col)

	rows, err := db.QueryContext(ctx, query, kbID)
	if err != nil {
		return fmt.Errorf("query evolution: %w", err)
	}
	defer rows.Close()

	type point struct {
		Epoch      int     `json:"epoch"`
		CapturedAt int64   `json:"captured_at"`
		Value      any     `json:"value"`
		IsNumeric  bool    `json:"-"`
		FloatValue float64 `json:"-"`
	}

	var points []point
	var numericValues []float64
	for rows.Next() {
		var p point
		var val any
		if err := rows.Scan(&p.Epoch, &p.CapturedAt, &val); err != nil {
			return fmt.Errorf("scan evolution: %w", err)
		}

		p.Value = val
		if val != nil {
			if f, ok := val.(float64); ok {
				p.IsNumeric = true
				p.FloatValue = f
				numericValues = append(numericValues, f)
			} else if i, ok := val.(int64); ok {
				p.IsNumeric = true
				p.FloatValue = float64(i)
				numericValues = append(numericValues, p.FloatValue)
			} else if i, ok := val.(int32); ok {
				p.IsNumeric = true
				p.FloatValue = float64(i)
				numericValues = append(numericValues, p.FloatValue)
			} else if i, ok := val.(int); ok {
				p.IsNumeric = true
				p.FloatValue = float64(i)
				numericValues = append(numericValues, p.FloatValue)
			}
		}

		points = append(points, p)
	}

	if kbEvolutionFlags.json {
		payload := map[string]any{
			"kb_id":  kbID,
			"field":  kbEvolutionFlags.field,
			"points": points,
		}
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, payload)
	}

	if kbEvolutionFlags.field == "risk_level" {
		headers := []string{"EPOCH", "CAPTURED_AT", "RISK_LEVEL"}
		var tableRows [][]string
		for _, p := range points {
			v := "n/a"
			if p.Value != nil {
				v = fmt.Sprintf("%v", p.Value)
			}
			tableRows = append(tableRows, []string{
				strconv.Itoa(p.Epoch),
				time.UnixMilli(p.CapturedAt).Format(time.RFC3339),
				v,
			})
		}
		return kb_output.WriteTable(cmd.OutOrStdout(), headers, tableRows)
	}

	// Numeric sparkline
	if len(numericValues) > 0 {
		sparkline := kb_output.Sparkline(numericValues)
		minV := numericValues[0]
		maxV := numericValues[0]
		for _, v := range numericValues {
			if v < minV {
				minV = v
			}
			if v > maxV {
				maxV = v
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Field: %s\n", kbEvolutionFlags.field)
		fmt.Fprintf(cmd.OutOrStdout(), "Trend: %s\n", sparkline)
		fmt.Fprintf(cmd.OutOrStdout(), "Stats: min=%.2f max=%.2f last=%.2f\n", minV, maxV, numericValues[len(numericValues)-1])
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "No numeric data found for field: %s\n", kbEvolutionFlags.field)
	return nil
}
