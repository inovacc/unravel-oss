/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"

	"github.com/lib/pq"
	"github.com/spf13/cobra"
)

var kbShowFlags struct {
	epoch int
	json  bool
	dsn   string
}

var showCmd = &cobra.Command{
	Use:   "show <kb_id>",
	Short: "Show KB app identity and snapshot detail",
	Args:  cobra.ExactArgs(1),
	RunE:  runKbShow,
}

func init() {
	showCmd.Flags().IntVar(&kbShowFlags.epoch, "epoch", 0, "epoch to show (0 = latest)")

	kb_output.BindJSONFlag(showCmd, &kbShowFlags.json)
	kb_output.BindDSNFlag(showCmd, &kbShowFlags.dsn)

	kbCatalogCmd.AddCommand(showCmd)
}

func runKbShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if kbShowFlags.epoch < 0 {
		return fmt.Errorf("epoch must be >= 0")
	}

	dsn, err := kb_output.ResolveDSN(kbShowFlags.dsn)
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
		fmt.Fprintf(cmd.ErrOrStderr(), "(resolved from alias %s -> canonical %s)\n", kbID, canonical)
		kbID = canonical
	}

	// 2) Resolve Target Epoch
	targetEpoch := int64(kbShowFlags.epoch)
	if targetEpoch == 0 {
		err = db.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(epoch), 0) FROM knowledge_sources WHERE kb_id = $1`,
			kbID).Scan(&targetEpoch)
		if err != nil {
			return fmt.Errorf("resolve latest epoch: %w", err)
		}
		if targetEpoch == 0 {
			return fmt.Errorf("no snapshots found for %s", kbID)
		}
	}

	// 3) Identity Row
	type identityInfo struct {
		KBID          string   `json:"kb_id"`
		CanonicalName string   `json:"canonical_name"`
		DisplayName   string   `json:"display_name"`
		Platform      string   `json:"platform"`
		PublisherCN   *string  `json:"publisher_cn"`
		Framework     *string  `json:"framework"`
		PackageID     *string  `json:"package_id"`
		Tags          []string `json:"tags"`
		FirstSeenAt   int64    `json:"first_seen_at"`
		LastSeenAt    int64    `json:"last_seen_at"`
	}
	var iden identityInfo
	var pub, fw, pkg *string
	err = db.QueryRowContext(ctx, `
		SELECT kb_id, canonical_name, display_name, platform, publisher_cn, 
		       framework, package_id, tags, first_seen_at, last_seen_at 
		FROM kb_apps WHERE kb_id = $1`,
		kbID).Scan(
		&iden.KBID, &iden.CanonicalName, &iden.DisplayName, &iden.Platform, &pub,
		&fw, &pkg, (*pq.StringArray)(&iden.Tags), &iden.FirstSeenAt, &iden.LastSeenAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("app %s not found in kb_apps", kbID)
		}
		return fmt.Errorf("query identity: %w", err)
	}
	iden.PublisherCN = pub
	iden.Framework = fw
	iden.PackageID = pkg

	// 4) Snapshot Row
	type snapshotInfo struct {
		Epoch          int     `json:"epoch"`
		CapturedAt     int64   `json:"captured_at"`
		AppVersion     *string `json:"app_version"`
		BinarySha256   *string `json:"binary_sha256"`
		RiskScore      *int    `json:"risk_score"`
		RiskLevel      *string `json:"risk_level"`
		DepthScore     *int    `json:"depth_score"`
		ModulesIndexed int     `json:"modules_indexed"`
		BodiesIndexed  int     `json:"bodies_indexed"`
	}
	var snap snapshotInfo
	err = db.QueryRowContext(ctx, `
		SELECT epoch, captured_at, app_version, binary_sha256, risk_score, risk_level, 
		       depth_score, modules_indexed, bodies_indexed 
		FROM knowledge_sources 
		WHERE kb_id = $1 AND epoch = $2`,
		kbID, targetEpoch).Scan(
		&snap.Epoch, &snap.CapturedAt, &snap.AppVersion, &snap.BinarySha256,
		&snap.RiskScore, &snap.RiskLevel, &snap.DepthScore,
		&snap.ModulesIndexed, &snap.BodiesIndexed)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("epoch %d not found for app %s", targetEpoch, kbID)
		}
		return fmt.Errorf("query snapshot: %w", err)
	}

	// 5) Recent Diffs
	type diffPair struct {
		FromEpoch int            `json:"from_epoch"`
		ToEpoch   int            `json:"to_epoch"`
		Counts    map[string]int `json:"counts"`
	}
	dRows, err := db.QueryContext(ctx, `
		SELECT ks_from.epoch, ks_to.epoch, d.category, COUNT(*)
		FROM kb_diffs d
		JOIN knowledge_sources ks_to ON ks_to.id = d.to_source_id
		JOIN knowledge_sources ks_from ON ks_from.id = d.from_source_id
		WHERE ks_to.kb_id = $1
		GROUP BY ks_from.epoch, ks_to.epoch, d.category
		ORDER BY ks_to.epoch DESC, d.category ASC
	`, kbID)
	if err != nil {
		return fmt.Errorf("query diffs: %w", err)
	}
	defer dRows.Close()

	diffMap := make(map[string]*diffPair)
	var pairKeys []string
	for dRows.Next() {
		var fe, te int
		var cat string
		var count int
		if err := dRows.Scan(&fe, &te, &cat, &count); err != nil {
			return fmt.Errorf("scan diff: %w", err)
		}
		key := fmt.Sprintf("%d->%d", fe, te)
		if _, ok := diffMap[key]; !ok {
			if len(pairKeys) >= 5 {
				continue
			}
			pairKeys = append(pairKeys, key)
			diffMap[key] = &diffPair{FromEpoch: fe, ToEpoch: te, Counts: make(map[string]int)}
		}
		diffMap[key].Counts[cat] = count
	}
	var recentDiffs []diffPair
	for _, k := range pairKeys {
		recentDiffs = append(recentDiffs, *diffMap[k])
	}

	if kbShowFlags.json {
		payload := map[string]any{
			"kb_id":        kbID,
			"identity":     iden,
			"snapshot":     snap,
			"recent_diffs": recentDiffs,
		}
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, payload)
	}

	// Plain text output
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "IDENTITY\n")
	fmt.Fprintf(out, "  KB_ID:        %s\n", iden.KBID)
	fmt.Fprintf(out, "  Display Name: %s\n", iden.DisplayName)
	fmt.Fprintf(out, "  Platform:     %s\n", iden.Platform)
	if iden.PublisherCN != nil {
		fmt.Fprintf(out, "  Publisher:    %s\n", *iden.PublisherCN)
	}
	if iden.Framework != nil {
		fmt.Fprintf(out, "  Framework:    %s\n", *iden.Framework)
	}
	if iden.PackageID != nil {
		fmt.Fprintf(out, "  Package ID:   %s\n", *iden.PackageID)
	}
	fmt.Fprintf(out, "  Tags:         %s\n", strings.Join(iden.Tags, ", "))
	fmt.Fprintf(out, "  First Seen:   %s\n", time.UnixMilli(iden.FirstSeenAt).Format(time.RFC3339))
	fmt.Fprintf(out, "  Last Seen:    %s\n", time.UnixMilli(iden.LastSeenAt).Format(time.RFC3339))

	fmt.Fprintf(out, "\nSNAPSHOT EPOCH %d\n", snap.Epoch)
	fmt.Fprintf(out, "  Captured At:  %s\n", time.UnixMilli(snap.CapturedAt).Format(time.RFC3339))
	if snap.AppVersion != nil {
		fmt.Fprintf(out, "  App Version:  %s\n", *snap.AppVersion)
	}
	if snap.BinarySha256 != nil {
		fmt.Fprintf(out, "  Binary SHA:   %s\n", *snap.BinarySha256)
	}

	rl := "n/a"
	if snap.RiskLevel != nil {
		rl = *snap.RiskLevel
	}
	rs := "n/a"
	if snap.RiskScore != nil {
		rs = strconv.Itoa(*snap.RiskScore)
	}
	ds := "n/a"
	if snap.DepthScore != nil {
		ds = strconv.Itoa(*snap.DepthScore)
	}
	fmt.Fprintf(out, "  Risk:         %s (score: %s)\n", rl, rs)
	fmt.Fprintf(out, "  Depth Score:  %s\n", ds)
	fmt.Fprintf(out, "  Modules:      %d indexed\n", snap.ModulesIndexed)
	fmt.Fprintf(out, "  Bodies:       %d indexed\n", snap.BodiesIndexed)

	var cumulativeModules int
	if err := db.QueryRowContext(ctx, `
		SELECT count(DISTINCT m.id)
		  FROM modules m
		  JOIN knowledge_sources ks ON ks.id = m.first_source_id
		 WHERE ks.kb_id = $1`, kbID).Scan(&cumulativeModules); err != nil {
		return fmt.Errorf("cumulative module count: %w", err)
	}
	fmt.Fprintf(out, "  Modules (cumulative across all epochs): %d\n", cumulativeModules)

	if len(recentDiffs) > 0 {
		fmt.Fprintf(out, "\nRECENT DIFFS\n")
		var diffHeaders []string
		for _, d := range recentDiffs {
			diffHeaders = append(diffHeaders, fmt.Sprintf("E%d->E%d", d.FromEpoch, d.ToEpoch))
		}

		// Collect all categories
		catMap := make(map[string]bool)
		for _, d := range recentDiffs {
			for c := range d.Counts {
				catMap[c] = true
			}
		}
		var cats []string
		for c := range catMap {
			cats = append(cats, c)
		}
		sort.Strings(cats)

		var diffTable [][]string
		for _, cat := range cats {
			row := []string{cat}
			for _, d := range recentDiffs {
				row = append(row, strconv.Itoa(d.Counts[cat]))
			}
			diffTable = append(diffTable, row)
		}

		headers := append([]string{"CATEGORY"}, diffHeaders...)
		return kb_output.WriteTable(out, headers, diffTable)
	}

	return nil
}
