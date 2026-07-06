/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"

	"github.com/lib/pq"
	"github.com/spf13/cobra"
)

var kbAppsFlags struct {
	platform       string
	framework      string
	risk           string
	tags           []string
	since          string
	limit          int
	includeAliases bool
	json           bool
	dsn            string
	meanMin        int // P59-03b: filter by kb_scorecards.mean_score >= meanMin*10
}

var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "List registered KB apps",
	RunE:  runKbApps,
}

func init() {
	appsCmd.Flags().StringVar(&kbAppsFlags.platform, "platform", "", "filter by platform")
	appsCmd.Flags().StringVar(&kbAppsFlags.framework, "framework", "", "filter by framework")
	appsCmd.Flags().StringVar(&kbAppsFlags.risk, "risk", "", "filter by risk level (low, medium, high, critical)")
	appsCmd.Flags().StringSliceVar(&kbAppsFlags.tags, "tag", nil, "filter by tags (ANY match)")
	appsCmd.Flags().StringVar(&kbAppsFlags.since, "since", "", "filter by last seen duration (e.g. 30d, 2y) or RFC3339 date")
	appsCmd.Flags().IntVar(&kbAppsFlags.limit, "limit", 100, "limit result count")
	appsCmd.Flags().BoolVar(&kbAppsFlags.includeAliases, "include-aliases", false, "include app aliases in output")
	appsCmd.Flags().IntVar(&kbAppsFlags.meanMin, "mean-min", 0, "filter to apps whose latest scorecard mean is >= N percent (0 = no filter)")

	kb_output.BindJSONFlag(appsCmd, &kbAppsFlags.json)
	kb_output.BindDSNFlag(appsCmd, &kbAppsFlags.dsn)

	kbCatalogCmd.AddCommand(appsCmd)
}

func runKbApps(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Validate risk level
	if kbAppsFlags.risk != "" {
		validRisks := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !validRisks[strings.ToLower(kbAppsFlags.risk)] {
			return fmt.Errorf("invalid risk level %q: must be one of low, medium, high, critical", kbAppsFlags.risk)
		}
	}

	// Cap limit
	limit := kbAppsFlags.limit
	if limit > 1000 {
		limit = 1000
	}

	// Parse since
	var sinceMillis *int64
	if kbAppsFlags.since != "" {
		t, err := kb_output.ParseSince(kbAppsFlags.since)
		if err != nil {
			return err
		}
		m := t.UnixMilli()
		sinceMillis = &m
	}

	dsn, err := kb_output.ResolveDSN(kbAppsFlags.dsn)
	if err != nil {
		return err
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer db.Close()

	// 1) Primary query for apps. P59-03b: when --mean-min N is given, JOIN
	// kb_scorecards via knowledge_sources(id) and filter mean_score >= N*10
	// (mean_score is mean10). Without --mean-min, the LATERAL kb_scorecards
	// LEFT JOIN still runs so the JSON output can carry mean10 / mean_pct
	// for apps that have a scorecard.
	rows, err := db.QueryContext(ctx, `
		SELECT a.kb_id, a.canonical_name, a.display_name, a.platform, a.publisher_cn,
		       a.framework, a.package_id, a.tags,
		       ks.epoch, ks.risk_score, ks.risk_level, ks.depth_score, ks.captured_at, a.last_seen_at,
		       sc.mean_score
		FROM kb_apps a
		LEFT JOIN LATERAL (
		  SELECT id, epoch, risk_score, risk_level, depth_score, captured_at
		  FROM knowledge_sources
		  WHERE kb_id = a.kb_id
		  ORDER BY epoch DESC LIMIT 1
		) ks ON TRUE
		LEFT JOIN LATERAL (
		  SELECT mean_score
		  FROM kb_scorecards
		  WHERE source_id = ks.id
		  ORDER BY generated_at DESC LIMIT 1
		) sc ON TRUE
		WHERE ($1::text IS NULL OR a.platform = $1)
		  AND ($2::text IS NULL OR a.framework = $2)
		  AND ($3::text IS NULL OR ks.risk_level = $3)
		  AND ($4::text[] IS NULL OR a.tags && $4)
		  AND ($5::bigint IS NULL OR a.last_seen_at >= $5)
		  AND ($7::int = 0 OR (sc.mean_score IS NOT NULL AND sc.mean_score >= $7))
		ORDER BY a.last_seen_at DESC NULLS LAST
		LIMIT $6
	`,
		nullable(kbAppsFlags.platform),
		nullable(kbAppsFlags.framework),
		nullable(strings.ToLower(kbAppsFlags.risk)),
		nullableSlice(kbAppsFlags.tags),
		sinceMillis,
		limit,
		kbAppsFlags.meanMin*10,
	)
	if err != nil {
		return fmt.Errorf("query apps: %w", err)
	}
	defer rows.Close()

	type appItem struct {
		KBID             string   `json:"kb_id" jsonschema:"canonical knowledge-base identifier (alias-resolved fingerprint)"`
		CanonicalName    string   `json:"canonical_name" jsonschema:"normalized canonical app name used for cross-epoch matching"`
		DisplayName      string   `json:"display_name" jsonschema:"human-readable application display name"`
		Platform         string   `json:"platform" jsonschema:"app platform (e.g. android, electron, tauri, dotnet, ios)"`
		PublisherCN      *string  `json:"publisher_cn" jsonschema:"signing certificate publisher common name; null when unsigned or unknown"`
		Framework        *string  `json:"framework" jsonschema:"detected framework (electron, tauri, flutter, react-native, ...); null when not detected"`
		PackageID        *string  `json:"package_id" jsonschema:"platform-specific package identifier (e.g. android applicationId); null when unavailable"`
		Tags             []string `json:"tags" jsonschema:"free-form labels attached to the app (aggregated across captures)"`
		LatestEpoch      *int     `json:"latest_epoch" jsonschema:"highest epoch number captured for this kb_id; null when no captures exist"`
		LatestRiskScore  *int     `json:"latest_risk_score" jsonschema:"latest numeric risk score (0-100); null when no captures exist"`
		LatestRiskLevel  *string  `json:"latest_risk_level" jsonschema:"latest risk level (low, medium, high, critical); null when no captures exist"`
		LatestDepthScore *int     `json:"latest_depth_score" jsonschema:"latest depth-of-analysis score; null when no captures exist"`
		CapturedAt       *int64   `json:"captured_at,omitempty" jsonschema:"unix-millisecond timestamp of the latest capture; omitted when no captures exist"`
		LastSeenAt       int64    `json:"last_seen_at" jsonschema:"unix-millisecond timestamp of the most recent kb_apps row update"`
		Aliases          []string `json:"aliases,omitempty" jsonschema:"alias kb_ids that resolve to this canonical kb_id; populated only when include_aliases=true"`
		// P59-03b: latest scorecard aggregates. mean10 is the integer
		// percent-times-ten (e.g. 858 = 85.8%); mean_pct is the formatted
		// human form. Both omitempty when no kb_scorecards row exists.
		Mean10  *int   `json:"mean10,omitempty" jsonschema:"latest scorecard mean expressed as integer percent*10 (e.g. 858 == 85.8%); omitted when no scorecard"`
		MeanPct string `json:"mean_pct,omitempty" jsonschema:"latest scorecard mean formatted as %d.%d%% (e.g. \"85.8%%\"); omitted when no scorecard"`
	}

	var items []appItem
	for rows.Next() {
		var it appItem
		var pub, fw, pkg, rl *string
		var epoch, rs, ds *int
		var ca *int64
		var meanScore *int
		if err := rows.Scan(
			&it.KBID, &it.CanonicalName, &it.DisplayName, &it.Platform, &pub,
			&fw, &pkg, (*pq.StringArray)(&it.Tags),
			&epoch, &rs, &rl, &ds, &ca, &it.LastSeenAt,
			&meanScore,
		); err != nil {
			return fmt.Errorf("scan app: %w", err)
		}
		it.PublisherCN = pub
		it.Framework = fw
		it.PackageID = pkg
		it.LatestEpoch = epoch
		it.LatestRiskScore = rs
		it.LatestRiskLevel = rl
		it.LatestDepthScore = ds
		it.CapturedAt = ca
		if meanScore != nil {
			m := *meanScore
			it.Mean10 = &m
			it.MeanPct = fmt.Sprintf("%d.%d%%", m/10, m%10)
		}
		items = append(items, it)
	}

	// 2) Handle aliases if requested
	if kbAppsFlags.includeAliases && len(items) > 0 {
		ids := make([]string, len(items))
		itemMap := make(map[string]*appItem)
		for i := range items {
			ids[i] = items[i].KBID
			itemMap[items[i].KBID] = &items[i]
		}

		aRows, err := db.QueryContext(ctx, `
			SELECT alias_kb_id, canonical_kb_id 
			FROM kb_aliases 
			WHERE canonical_kb_id = ANY($1)
		`, ids)
		if err != nil {
			return fmt.Errorf("query aliases: %w", err)
		}
		defer aRows.Close()
		for aRows.Next() {
			var alias, canonical string
			if err := aRows.Scan(&alias, &canonical); err != nil {
				return fmt.Errorf("scan alias: %w", err)
			}
			if it, ok := itemMap[canonical]; ok {
				it.Aliases = append(it.Aliases, alias)
			}
		}
	}

	if kbAppsFlags.json {
		payload := map[string]any{
			"returned": len(items),
			"items":    items,
		}
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, payload)
	}

	headers := []string{"KB_ID", "DISPLAY_NAME", "PLATFORM", "FRAMEWORK", "EPOCH", "RISK", "LAST_SEEN"}
	var tableRows [][]string
	for _, it := range items {
		epoch := "n/a"
		if it.LatestEpoch != nil {
			epoch = strconv.Itoa(*it.LatestEpoch)
		}
		risk := "n/a"
		if it.LatestRiskLevel != nil {
			risk = *it.LatestRiskLevel
		}
		fw := "n/a"
		if it.Framework != nil {
			fw = *it.Framework
		}
		lastSeen := time.UnixMilli(it.LastSeenAt).Format(time.RFC3339)

		tableRows = append(tableRows, []string{
			it.KBID,
			it.DisplayName,
			it.Platform,
			fw,
			epoch,
			risk,
			lastSeen,
		})
	}

	return kb_output.WriteTable(cmd.OutOrStdout(), headers, tableRows)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableSlice(s []string) any {
	if len(s) == 0 {
		return nil
	}
	return s
}
