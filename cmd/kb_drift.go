/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
)

var (
	driftCheckThresholdRelative float64
	driftCheckMinRunSize        int
	driftCheckRunID             string
	driftBaselineForce          bool
	driftHistoryLimit           int
	driftCheckDSN               string
	driftBaselineSetDSN         string
	driftBaselineClearDSN       string
	driftBaselineShowDSN        string
	driftHistoryDSN             string
)

var driftCheckCmd = &cobra.Command{
	Use:   "check <app>",
	Short: "Run a Phase G drift check against an enrich run for app",
	Long: `Compares an enrich run's metrics against the per-app baseline.
By default uses the most recent enrich_runs row for <app>; override with
--run-id. Output is the DriftVerdict as indented JSON on stdout.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		dsn, err := kb_output.ResolveDSN(driftCheckDSN)
		if err != nil {
			return err
		}
		db, err := kbdb.Open(ctx, dsn)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()

		app := args[0]
		runID := driftCheckRunID
		if runID == "" {
			if err := db.QueryRowContext(ctx,
				`SELECT run_id::text FROM enrich_runs WHERE app = $1 ORDER BY started_at DESC LIMIT 1`,
				app).Scan(&runID); err != nil {
				return fmt.Errorf("no enrich runs for app %q: %w", app, err)
			}
		}
		o := drift.DefaultOpts()
		if driftCheckThresholdRelative > 0 {
			o.ThresholdRelative = driftCheckThresholdRelative
		}
		if driftCheckMinRunSize > 0 {
			o.MinRunSize = driftCheckMinRunSize
		}
		v, err := drift.Check(ctx, db, runID, o)
		if err != nil {
			return err
		}
		buf, _ := json.MarshalIndent(v, "", "  ")
		_, _ = fmt.Fprintln(os.Stdout, string(buf))
		return nil
	},
}

var driftBaselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage the per-app drift baseline (set/clear/show)",
}

var driftBaselineSetCmd = &cobra.Command{
	Use:   "set <app> <run_id>",
	Short: "Promote run_id to be the baseline for app",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		runID := args[1]
		dsn, err := kb_output.ResolveDSN(driftBaselineSetDSN)
		if err != nil {
			return err
		}
		db, err := kbdb.Open(ctx, dsn)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()
		return drift.SetBaseline(ctx, db, args[0], runID, driftBaselineForce, drift.DefaultOpts().MinRunSize)
	},
}

var driftBaselineClearCmd = &cobra.Command{
	Use:   "clear <app>",
	Short: "Remove the baseline tag for app",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		dsn, err := kb_output.ResolveDSN(driftBaselineClearDSN)
		if err != nil {
			return err
		}
		db, err := kbdb.Open(ctx, dsn)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()
		return drift.ClearBaseline(ctx, db, args[0])
	},
}

var driftBaselineShowCmd = &cobra.Command{
	Use:   "show <app>",
	Short: "Print the run_id currently tagged as baseline for app",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		dsn, err := kb_output.ResolveDSN(driftBaselineShowDSN)
		if err != nil {
			return err
		}
		db, err := kbdb.Open(ctx, dsn)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()
		id, err := drift.ShowBaseline(ctx, db, args[0])
		if errors.Is(err, drift.ErrNoBaseline) {
			_, _ = fmt.Fprintln(os.Stdout, "(no baseline set)")
			return nil
		}
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stdout, id)
		return nil
	},
}

var driftHistoryCmd = &cobra.Command{
	Use:   "history <app>",
	Short: "List recent drift_alerts rows for app (newest first)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		dsn, err := kb_output.ResolveDSN(driftHistoryDSN)
		if err != nil {
			return err
		}
		db, err := kbdb.Open(ctx, dsn)
		if err != nil {
			return fmt.Errorf("open kb: %w", err)
		}
		defer func() { _ = db.Close() }()
		rows, err := db.QueryContext(ctx,
			`SELECT id, run_id, baseline_run_id, metric, baseline_value,
			        recent_value, relative_delta, threshold_relative,
			        created_at::text
			   FROM drift_alerts
			  WHERE app = $1
			  ORDER BY created_at DESC
			  LIMIT $2`, args[0], driftHistoryLimit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		type row struct {
			ID                int64   `json:"id"`
			RunID             string  `json:"run_id"`
			BaselineRunID     string  `json:"baseline_run_id"`
			Metric            string  `json:"metric"`
			BaselineValue     float64 `json:"baseline_value"`
			RecentValue       float64 `json:"recent_value"`
			RelativeDelta     float64 `json:"relative_delta"`
			ThresholdRelative float64 `json:"threshold_relative"`
			CreatedAt         string  `json:"created_at"`
		}
		out := make([]row, 0)
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.ID, &r.RunID, &r.BaselineRunID, &r.Metric,
				&r.BaselineValue, &r.RecentValue, &r.RelativeDelta,
				&r.ThresholdRelative, &r.CreatedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		buf, _ := json.MarshalIndent(out, "", "  ")
		_, _ = fmt.Fprintln(os.Stdout, string(buf))
		return nil
	},
}

func init() {
	kb_output.BindDSNFlag(driftCheckCmd, &driftCheckDSN)
	driftCheckCmd.Flags().Float64Var(&driftCheckThresholdRelative, "threshold-relative", 0, "override relative-delta threshold (default 0.20)")
	driftCheckCmd.Flags().IntVar(&driftCheckMinRunSize, "min-run-size", 0, "override min modules processed (default 25)")
	driftCheckCmd.Flags().StringVar(&driftCheckRunID, "run-id", "", "specific enrich_runs.run_id uuid (default: most recent for app)")

	kb_output.BindDSNFlag(driftBaselineSetCmd, &driftBaselineSetDSN)
	driftBaselineSetCmd.Flags().BoolVar(&driftBaselineForce, "force", false, "allow setting a baseline below min-run-size")

	kb_output.BindDSNFlag(driftBaselineClearCmd, &driftBaselineClearDSN)
	kb_output.BindDSNFlag(driftBaselineShowCmd, &driftBaselineShowDSN)

	kb_output.BindDSNFlag(driftHistoryCmd, &driftHistoryDSN)
	driftHistoryCmd.Flags().IntVar(&driftHistoryLimit, "limit", 20, "max rows to return")

	driftBaselineCmd.AddCommand(driftBaselineSetCmd, driftBaselineClearCmd, driftBaselineShowCmd)

	kbDriftCmd.AddCommand(driftCheckCmd, driftBaselineCmd, driftHistoryCmd)
}
