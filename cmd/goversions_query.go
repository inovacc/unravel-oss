/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/goversions"
)

var goversionsStableOnly bool
var goversionsLimit int
var goversionsVerifySHA string
var goversionsVerifyFile string

var goversionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List known Go versions (newest first)",
	RunE: func(_ *cobra.Command, _ []string) error {
		db, err := kbOpenDB(goversionsDB)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		ensureFresh(context.Background(), db)
		rels, err := goversions.ListReleases(db, goversionsStableOnly, goversionsLimit)
		if err != nil {
			return err
		}
		for _, r := range rels {
			tag := "stable"
			if !r.Stable {
				tag = "unstable"
			}
			fmt.Printf("%-12s %s\n", r.Version, tag)
		}
		return nil
	},
}

var goversionsInfoCmd = &cobra.Command{
	Use:   "info <go1.x.y>",
	Short: "Show files, checksums, date, security note, and CVE posture for a version",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		db, err := kbOpenDB(goversionsDB)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		ensureFresh(context.Background(), db)
		v := args[0]
		rel, meta, files, err := goversions.ReleaseInfo(db, v)
		if err != nil {
			return fmt.Errorf("release %s: %w", v, err)
		}
		fmt.Printf("%s  stable=%v  date=%s\n", rel.Version, rel.Stable, meta.Date)
		if meta.Security != "" {
			fmt.Printf("security: %s\n", meta.Security)
		}
		for _, f := range files {
			fmt.Printf("  %-36s %-7s %-7s %-9s %s\n", f.Filename, f.OS, f.Arch, f.Kind, f.SHA256)
		}
		p, _ := goversions.CVEPostureFor(db, v)
		fmt.Printf("CVEs exposed: %d\n", len(p.Exposed))
		for _, e := range p.Exposed {
			fix := e.FixedIn
			if fix == "" {
				fix = "unfixed"
			}
			fmt.Printf("  %s (fixed: %s) %s\n", e.ID, fix, e.Summary)
		}
		return nil
	},
}

var goversionsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check whether a sha256 (or file) is an official Go artifact",
	RunE: func(_ *cobra.Command, _ []string) error {
		db, err := kbOpenDB(goversionsDB)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		ensureFresh(context.Background(), db)
		h := goversionsVerifySHA
		if goversionsVerifyFile != "" {
			b, err := os.ReadFile(goversionsVerifyFile)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			h = hex.EncodeToString(sum[:])
		}
		if h == "" {
			return fmt.Errorf("provide --sha256 or --file")
		}
		ver, file, ok, err := goversions.VerifyArtifact(db, h)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("unknown: %s is not a known official Go artifact\n", h)
			os.Exit(1)
		}
		fmt.Printf("official: %s  %s\n", ver, file)
		return nil
	},
}

var goversionsCVECmd = &cobra.Command{
	Use:   "cve <go1.x.y>",
	Short: "Show CVE posture for a version (exposed vs fixed)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		db, err := kbOpenDB(goversionsDB)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		ensureFresh(context.Background(), db)
		p, err := goversions.CVEPostureFor(db, args[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s exposed to %d CVE(s)\n", args[0], len(p.Exposed))
		for _, e := range p.Exposed {
			fix := e.FixedIn
			if fix == "" {
				fix = "unfixed"
			}
			fmt.Printf("  %s (fixed: %s)\n", e.ID, fix)
		}
		return nil
	},
}

func init() {
	goversionsListCmd.Flags().BoolVar(&goversionsStableOnly, "stable", false, "stable releases only")
	goversionsListCmd.Flags().IntVar(&goversionsLimit, "limit", 0, "max rows (0 = all)")
	goversionsVerifyCmd.Flags().StringVar(&goversionsVerifySHA, "sha256", "", "artifact sha256 to verify")
	goversionsVerifyCmd.Flags().StringVar(&goversionsVerifyFile, "file", "", "file to hash + verify")
	goversionsCmd.AddCommand(goversionsListCmd, goversionsInfoCmd, goversionsVerifyCmd, goversionsCVECmd)
}
