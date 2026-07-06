/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/goversions"
)

var (
	goversionsDB        string
	goversionsNoRefresh bool
)

var goversionsCmd = &cobra.Command{
	Use:   "goversions",
	Short: "Catalog of Go releases: artifacts, checksums, dates, and CVE posture",
	Long: `Maintain and query a knowledge base of every Go release from go.dev/dl,
including per-file checksums and vuln.go.dev CVE posture. Auto-refreshes if the
local catalog is older than 24h (skip with --no-refresh).`,
}

func init() {
	goversionsCmd.PersistentFlags().StringVar(&goversionsDB, "database", "", "DSN override (defaults to config.yaml)")
	goversionsCmd.PersistentFlags().BoolVar(&goversionsNoRefresh, "no-refresh", false, "do not auto-sync stale catalog")
	rootCmd.AddCommand(goversionsCmd)
}

const refreshMaxAgeMS = 24 * 60 * 60 * 1000

// stale reports whether lastSync (epoch ms; 0 = never) is older than maxAgeMS.
func stale(lastSync, now, maxAgeMS int64) bool {
	return lastSync == 0 || now-lastSync > maxAgeMS
}

// ensureFresh lazily syncs if the catalog is stale (unless --no-refresh).
func ensureFresh(ctx context.Context, db *sql.DB) {
	if goversionsNoRefresh {
		return
	}
	last, err := goversions.Freshness(db)
	if err != nil {
		slog.Warn("goversions freshness check failed", "err", err)
		return
	}
	now := time.Now().UnixMilli()
	if !stale(last, now, refreshMaxAgeMS) {
		return
	}
	slog.Info("goversions catalog stale; auto-syncing")
	if _, err := goversions.Sync(ctx, db, goversions.NewHTTPSources(), now); err != nil {
		slog.Warn("goversions auto-sync failed; serving stale data", "err", err)
	}
}
