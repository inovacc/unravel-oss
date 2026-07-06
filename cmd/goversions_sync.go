/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/goversions"
)

var goversionsSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Fetch go.dev/dl + vuln.go.dev and upsert the catalog",
	RunE: func(_ *cobra.Command, _ []string) error {
		db, err := kbOpenDB(goversionsDB)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		rep, err := goversions.Sync(context.Background(), db, goversions.NewHTTPSources(), time.Now().UnixMilli())
		if err != nil {
			return err
		}
		fmt.Printf("synced: releases=%d files=%d vulns=%d new_versions=%d new_vulns=%d\n",
			rep.Releases, rep.Files, rep.Vulns, len(rep.NewVersions), len(rep.NewVulns))
		for _, v := range rep.NewVersions {
			fmt.Printf("  + %s\n", v)
		}
		for _, e := range rep.Errors {
			fmt.Printf("  ! %s\n", e)
		}
		return nil
	},
}

func init() { goversionsCmd.AddCommand(goversionsSyncCmd) }
