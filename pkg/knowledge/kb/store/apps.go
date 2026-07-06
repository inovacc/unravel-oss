/*
Copyright (c) 2026 Security Research
*/
// kb_apps listing — extracted from pkg/mcp/tools/kb.go kbAppsHandler
// (Phase A-Apps) so the supervisor dispatcher (kb.apps verb) and the MCP
// tool share one source of truth. The wire shape (AppsPayload, AppInfo)
// is field-for-field compatible with the JSON the MCP tool emitted prior
// to the extraction (see pkg/mcp/tools/kb.go:252 kbAppItem).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

// AppsOptions controls which kb_apps rows Apps returns. All fields are
// optional; an empty AppsOptions returns the most recently seen apps
// (capped by Limit, default 100, hard cap 1000).
type AppsOptions struct {
	Platform       string   `json:"platform,omitempty"`
	Framework      string   `json:"framework,omitempty"`
	Risk           string   `json:"risk,omitempty"`
	Tag            []string `json:"tag,omitempty"`
	SinceMillis    *int64   `json:"since_millis,omitempty"`
	Limit          int      `json:"limit,omitempty"`
	IncludeAliases bool     `json:"include_aliases,omitempty"`
}

// AppInfo mirrors the kbAppItem in pkg/mcp/tools/kb.go prior to the
// extraction. JSON tags are snake_case and field-for-field stable.
type AppInfo struct {
	KBID             string   `json:"kb_id"`
	CanonicalName    string   `json:"canonical_name"`
	DisplayName      string   `json:"display_name"`
	Platform         string   `json:"platform"`
	PublisherCN      *string  `json:"publisher_cn"`
	Framework        *string  `json:"framework"`
	PackageID        *string  `json:"package_id"`
	Tags             []string `json:"tags"`
	LatestEpoch      *int     `json:"latest_epoch"`
	LatestRiskScore  *int     `json:"latest_risk_score"`
	LatestRiskLevel  *string  `json:"latest_risk_level"`
	LatestDepthScore *int     `json:"latest_depth_score"`
	CapturedAt       *int64   `json:"captured_at,omitempty"`
	LastSeenAt       int64    `json:"last_seen_at"`
	Aliases          []string `json:"aliases,omitempty"`
}

// AppsPayload is the response body for Apps. Returned counts mirror the
// MCP tool's "returned" + "items" wire shape.
type AppsPayload struct {
	Returned int       `json:"returned"`
	Items    []AppInfo `json:"items"`
}

// Apps returns kb_apps rows filtered by opts, joined LATERAL against the
// most recent knowledge_sources row to surface the latest epoch / risk /
// depth signals. When opts.IncludeAliases is true a follow-up
// kb_aliases query attaches per-app alias kb_ids.
//
// Returns an empty (non-nil) AppsPayload when no rows match.
func Apps(ctx context.Context, db *sql.DB, opts AppsOptions) (*AppsPayload, error) {
	if db == nil {
		return nil, errors.New("kb_apps: nil db")
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	rows, err := db.QueryContext(ctx, `
		SELECT a.kb_id, a.canonical_name, a.display_name, a.platform, a.publisher_cn,
		       a.framework, a.package_id, a.tags,
		       ks.epoch, ks.risk_score, ks.risk_level, ks.depth_score, ks.captured_at, a.last_seen_at
		FROM kb_apps a
		LEFT JOIN LATERAL (
		  SELECT epoch, risk_score, risk_level, depth_score, captured_at
		  FROM knowledge_sources
		  WHERE kb_id = a.kb_id
		  ORDER BY epoch DESC LIMIT 1
		) ks ON TRUE
		WHERE ($1::text IS NULL OR a.platform = $1)
		  AND ($2::text IS NULL OR a.framework = $2)
		  AND ($3::text IS NULL OR ks.risk_level = $3)
		  AND ($4::text[] IS NULL OR a.tags && $4)
		  AND ($5::bigint IS NULL OR a.last_seen_at >= $5)
		ORDER BY a.last_seen_at DESC NULLS LAST
		LIMIT $6
	`,
		nullStr(opts.Platform),
		nullStr(opts.Framework),
		nullStr(strings.ToLower(opts.Risk)),
		nullStrSlice(opts.Tag),
		opts.SinceMillis,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("kb_apps: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]AppInfo, 0)
	for rows.Next() {
		var it AppInfo
		var pub, fw, pkgID, rl *string
		var epoch, rs, ds *int
		var ca *int64
		if err := rows.Scan(
			&it.KBID, &it.CanonicalName, &it.DisplayName, &it.Platform, &pub,
			&fw, &pkgID, (*pq.StringArray)(&it.Tags),
			&epoch, &rs, &rl, &ds, &ca, &it.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("kb_apps: scan: %w", err)
		}
		it.PublisherCN = pub
		it.Framework = fw
		it.PackageID = pkgID
		it.LatestEpoch = epoch
		it.LatestRiskScore = rs
		it.LatestRiskLevel = rl
		it.LatestDepthScore = ds
		it.CapturedAt = ca
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kb_apps: iterate: %w", err)
	}

	if opts.IncludeAliases && len(items) > 0 {
		ids := make([]string, len(items))
		idx := make(map[string]*AppInfo, len(items))
		for i := range items {
			ids[i] = items[i].KBID
			idx[items[i].KBID] = &items[i]
		}
		aRows, err := db.QueryContext(ctx, `
			SELECT alias_kb_id, canonical_kb_id
			FROM kb_aliases
			WHERE canonical_kb_id = ANY($1)
		`, pq.Array(ids))
		if err != nil {
			return nil, fmt.Errorf("kb_apps: query aliases: %w", err)
		}
		for aRows.Next() {
			var alias, canonical string
			if err := aRows.Scan(&alias, &canonical); err != nil {
				_ = aRows.Close()
				return nil, fmt.Errorf("kb_apps: scan alias: %w", err)
			}
			if it, ok := idx[canonical]; ok {
				it.Aliases = append(it.Aliases, alias)
			}
		}
		if err := aRows.Err(); err != nil {
			_ = aRows.Close()
			return nil, fmt.Errorf("kb_apps: iterate aliases: %w", err)
		}
		_ = aRows.Close()
	}

	return &AppsPayload{Returned: len(items), Items: items}, nil
}

// nullStr returns nil for empty strings; otherwise the string. Used so
// the SQL query can short-circuit empty filters with ($1::text IS NULL).
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullStrSlice returns nil for empty/nil slices; otherwise a pq.StringArray.
func nullStrSlice(s []string) any {
	if len(s) == 0 {
		return nil
	}
	return pq.StringArray(s)
}
