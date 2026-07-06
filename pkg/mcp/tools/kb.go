/*
Copyright (c) 2026 Security Research

kb.go — direct-mode MCP handlers for the 5 unravel_kb_* tools landing in
Phase 33 (MCPK-01..05). Handlers call the same library primitives the
P32 CLI uses (db.Open, identity.ResolveAlias, diff.LongRangeDiff,
ingest.Run, classify.Run) and return JSON byte-equivalent to
`unravel kb <cmd> --json` for the same inputs (D-33-CLI-PARITY-INVARIANT).

Wave-2 invariants honoured:
  - D-33-DSN-SOURCE         DSN read once at server start; no per-call DSN.
  - D-33-DSN-FAIL-AT-CALL   kbDB == nil → IsError result with hint.
  - D-33-NO-PER-CALL-DSN    Tool inputs do NOT accept a dsn field.
  - D-33-NO-DSN-IN-INPUT    Same — defence in depth.
  - D-33-INPUT-MATCH-CLI    Input fields mirror cmd/kb_*.go flag set 1:1.
  - D-33-CAPTURE-SYNC       capture is synchronous; ctx.WithTimeout passes
    through; default 600s; clamped to [60, 1800].
  - D-33-CAPTURE-FORCE-DEFAULT  force=false default.
  - D-33-CAPTURE-PATH-VALIDATION filepath.Clean → reject relative or "..".
  - D-33-NO-MODULE-TOPICS-WRITES Honoured by reusing classify.Run only.
  - D-09 (CLAUDE.md)        No direct LLM SDK imports.

Tool-count invariant 129 → 134 is bumped atomically by 33-06 once all
five registrations land. This file MUST register exactly 5 tools.

License: BSD-3-Clause.
*/
package mcptools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate classify rule registry
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// kbDB is the package-level Postgres pool wired by RegisterKB at MCP
// server startup (cmd/mcp.go, D-33-DSN-SOURCE) from config.yaml. When nil
// all five kb_* handlers return IsError=true with the canonical config.yaml
// hint (D-33-DSN-FAIL-AT-CALL) — tool advertisement remains independent of
// runtime DSN availability so the 137-tool count invariant holds.
var kbDB *sql.DB

// kbPoolInfoVal holds the ResolvedInfo for the startup-wired kbDB pool,
// written once in RegisterKB and read concurrently by handlers. Stored
// via atomic.Value so the write has a happens-before edge to all reads
// (Go memory model; -race safe). Zero value until RegisterKB populates it.
var kbPoolInfoVal atomic.Value // stores ResolvedInfo

// kbPoolResolvedInfo returns the captured pool ResolvedInfo, or a zero
// ResolvedInfo if RegisterKB never populated it (DB unset at startup).
func kbPoolResolvedInfo() ResolvedInfo {
	if v, ok := kbPoolInfoVal.Load().(ResolvedInfo); ok {
		return v
	}
	return ResolvedInfo{}
}

// kbPoolInfoOr returns an empty-result diagnostic string for the pool
// path, always non-empty even before RegisterKB populates the info.
func kbPoolInfoOr(what string) string {
	text, _ := emptyResultDiagnostic(kbPoolResolvedInfo(), what)
	return text
}

// kbDSNHint is the canonical IsError text returned when kbDB == nil.
// Bridge-mode (33-05) and gRPC server-mode (33-03) MUST emit this exact
// string so direct + bridge are byte-equivalent (D-33-RESULT-PARITY).
const kbDSNHint = "unravel_kb_* tools need a KB DSN: run `unravel db setup` to write config.yaml"

// kbCaptureTimeoutMsgFmt is the canonical IsError text for capture
// timeout. Format args: seconds (int). MUST match 33-03 server impl.
const kbCaptureTimeoutMsgFmt = "kb_capture timed out after %ds; partial state rolled back"

// RegisterKB wires the 5 unravel_kb_* MCP tools onto server. db may be
// nil (DSN unset at server start) — handlers will short-circuit with
// kbDSNHint at call time. Called once from cmd/mcp.go after the other
// register*Tools calls.
func RegisterKB(server *mcp.Server, db *sql.DB) {
	kbDB = db
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var info ResolvedInfo
		info.Source = resolveSource("")
		_ = db.QueryRowContext(ctx,
			`SELECT current_database(), current_user,
			        host(coalesce(inet_server_addr(),'127.0.0.1'::inet)),
			        coalesce(inet_server_port(),5432)`).
			Scan(&info.Database, &info.User, &info.Host, &info.Port)
		info.Catalog = summarizeCatalog(ctx, db)
		kbPoolInfoVal.Store(info)
		cancel()
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_catalog_apps",
		Description: "List applications in the knowledge base with optional filters (platform, framework, risk, tag, since, limit, include_aliases)",
	}, kbAppsHandler)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_catalog_timeline",
		Description: "Show chronological epoch deltas for a knowledge-base app (kb_id, optional reverse order)",
	}, kbTimelineHandler)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_transfer_diff",
		Description: "Compare two knowledge-base epochs of an app (consecutive mode for gap=1, long-range mode for gap>1, capped at 20 epochs)",
	}, kbDiffHandler)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_catalog_search",
		Description: "Search knowledge-base modules using trigram fuzzy match (query, optional filters: app, component, fact_type, lang, since, limit, cursor)",
	}, kbSearchHandler)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "unravel_kb_capture",
		Description: "Capture an application into the knowledge-base versioned store (synchronous; default 600s timeout, range 60-1800)",
	}, kbCaptureHandler)
}

// kbErrResult builds a canonical IsError MCP CallToolResult.
func kbErrResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// kbJSONResult marshals payload + injects schema_version=1 into the
// top-level object — byte-equivalent to cmd/kb_output.WriteJSON.
func kbJSONResult(payload any) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return kbErrResult(fmt.Sprintf("marshal payload: %v", err)), nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return kbErrResult("payload must marshal to JSON object"), nil
	}
	m["schema_version"] = 1
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return kbErrResult(fmt.Sprintf("marshal payload: %v", err)), nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(out)}},
	}, nil
}

// kbParseSince mirrors cmd/kb_output.ParseSince exactly. Accepts RFC3339,
// `<n>d`/`<n>w`/`<n>y`, or any time.ParseDuration string.
func kbParseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if len(s) >= 2 {
		last := s[len(s)-1]
		if last == 'd' || last == 'w' || last == 'y' {
			if v, err := parseInt64(s[:len(s)-1]); err == nil {
				var d time.Duration
				switch last {
				case 'd':
					d = time.Duration(v) * 24 * time.Hour
				case 'w':
					d = time.Duration(v) * 7 * 24 * time.Hour
				case 'y':
					d = time.Duration(v) * 365 * 24 * time.Hour
				}
				return time.Now().Add(-d), nil
			}
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid duration: %w", err)
	}
	return time.Now().Add(-d), nil
}

func parseInt64(s string) (int64, error) {
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("non-numeric")
		}
		v = v*10 + int64(c-'0')
	}
	return v, nil
}

// ---------------------------------------------------------------------
// kb_apps
// ---------------------------------------------------------------------

// kbAppsInput mirrors cmd/kb_apps.go flags 1:1 (D-33-INPUT-MATCH-CLI).
type kbAppsInput struct {
	Platform       string   `json:"platform,omitempty"        jsonschema:"filter by platform (windows|linux|macos|android|ios|web|electron|tauri|...)"`
	Framework      string   `json:"framework,omitempty"       jsonschema:"filter by framework (electron|tauri|react-native|flutter|webview2|winui|uwp|...)"`
	Risk           string   `json:"risk,omitempty"            jsonschema:"filter by risk bucket (low|medium|high|critical)"`
	Tag            []string `json:"tag,omitempty"             jsonschema:"filter by capture tag (ANY-match; repeatable)"`
	Since          string   `json:"since,omitempty"           jsonschema:"filter to apps last seen since duration (e.g. 30d, 2y, 1h) or RFC3339 date"`
	Limit          int      `json:"limit,omitempty"           jsonschema:"max apps to return (default 100, hard cap 1000)"`
	IncludeAliases bool     `json:"include_aliases,omitempty" jsonschema:"include alias kb_ids resolving to each canonical kb_id"`
}

// kbAppItem mirrors the anonymous appItem struct in cmd/kb_apps.go.
type kbAppItem struct {
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

func kbAppsHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbAppsInput) (*mcp.CallToolResult, any, error) {
	if in.Risk != "" {
		validRisks := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !validRisks[strings.ToLower(in.Risk)] {
			return kbErrResult(fmt.Sprintf("invalid risk level %q: must be one of low, medium, high, critical", in.Risk)), nil, nil
		}
	}

	var sinceMillis *int64
	if in.Since != "" {
		t, err := kbParseSince(in.Since)
		if err != nil {
			return kbErrResult(err.Error()), nil, nil
		}
		m := t.UnixMilli()
		sinceMillis = &m
	}

	// Phase B1: route through supervisor thin-client. Wire shape preserved.
	cli, err := getKBClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return kbErrResult(fmt.Sprintf("daemon unavailable; check `unravel daemon serve`: %v", err)), nil, nil
		}
		return kbErrResult(err.Error()), nil, nil
	}
	out, err := cli.Apps(ctx, supervisor.KBAppsParams{
		Platform:       in.Platform,
		Framework:      in.Framework,
		Risk:           in.Risk,
		Tag:            in.Tag,
		SinceMillis:    sinceMillis,
		Limit:          in.Limit,
		IncludeAliases: in.IncludeAliases,
	})
	if err != nil {
		return kbErrResult(err.Error()), nil, nil
	}

	payload := map[string]any{
		"returned": out.Returned,
		"items":    out.Items,
	}
	return mustKBJSON(kbJSONResult(payload))
}

// ---------------------------------------------------------------------
// kb_timeline
// ---------------------------------------------------------------------

type kbTimelineInput struct {
	KbID    string `json:"kb_id"             jsonschema:"canonical kb_id (alias resolved server-side)"`
	Reverse bool   `json:"reverse,omitempty" jsonschema:"reverse order (latest epoch first)"`
}

func kbTimelineHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbTimelineInput) (*mcp.CallToolResult, any, error) {
	if in.KbID == "" {
		return kbErrResult("kb_id is required"), nil, nil
	}

	// Phase B2: route through supervisor thin-client. Wire shape preserved
	// (KBTimelineResult is a type-alias of kbstore.TimelinePayload).
	//
	// Alias resolution NOTE: the supervisor expects a canonical kb_id —
	// callers are responsible for running pkg/knowledge/kb/identity.ResolveAlias
	// up front (matches the supervisor verb contract). The legacy MCP
	// handler did the resolution client-side using kbDB; that path is
	// gone in v2.17. Aliased ids will now surface a supervisor-side
	// "kb_id not found" error.
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return kbErrResult(err.Error()), nil, nil
	}

	out, err := cli.Timeline(ctx, supervisor.KBTimelineParams{
		KbID:    in.KbID,
		Reverse: in.Reverse,
	})
	if err != nil {
		return kbErrResult(err.Error()), nil, nil
	}

	payload := map[string]any{
		"kb_id":  out.KBID,
		"epochs": out.Epochs,
	}
	return mustKBJSON(kbJSONResult(payload))
}

// ---------------------------------------------------------------------
// kb_diff
// ---------------------------------------------------------------------

type kbDiffInput struct {
	KbID      string   `json:"kb_id"               jsonschema:"canonical kb_id (alias resolved server-side)"`
	FromEpoch int64    `json:"from_epoch"          jsonschema:"starting epoch (inclusive); must be < to_epoch"`
	ToEpoch   int64    `json:"to_epoch"            jsonschema:"ending epoch (inclusive); must be > from_epoch"`
	Category  []string `json:"category,omitempty"  jsonschema:"filter to categories (file, dep, capability, url, risk, cert, fact, module, component)"`
}

type kbCategoryDiffItems struct {
	Added    []any `json:"added,omitempty"`
	Removed  []any `json:"removed,omitempty"`
	Modified []any `json:"modified,omitempty"`
}

type kbDiffResult struct {
	KbID       string                          `json:"kb_id"`
	FromEpoch  int64                           `json:"from_epoch"`
	ToEpoch    int64                           `json:"to_epoch"`
	Mode       string                          `json:"mode"`
	Categories map[string]*kbCategoryDiffItems `json:"categories"`
}

func kbDiffHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbDiffInput) (*mcp.CallToolResult, any, error) {
	if in.KbID == "" {
		return kbErrResult("kb_id is required"), nil, nil
	}
	if in.FromEpoch >= in.ToEpoch {
		return kbErrResult(fmt.Sprintf("from (%d) must be less than to (%d)", in.FromEpoch, in.ToEpoch)), nil, nil
	}
	validCategories := map[string]bool{
		"file": true, "dep": true, "capability": true, "url": true, "risk": true,
		"cert": true, "fact": true, "module": true, "component": true,
	}
	for _, cat := range in.Category {
		if !validCategories[cat] {
			return kbErrResult(fmt.Sprintf("unknown category %q; valid: file, dep, capability, url, risk, cert, fact, module, component", cat)), nil, nil
		}
	}
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}
	out, err := cli.Diff(ctx, supervisor.KBDiffParams{
		KBID:       in.KbID,
		FromEpoch:  in.FromEpoch,
		ToEpoch:    in.ToEpoch,
		Categories: in.Category,
	})
	if err != nil {
		return kbErrResult(err.Error()), nil, nil
	}
	// Adapt kbstore.DiffPayload (snake_case) → legacy kbDiffResult (mixed-case
	// for backward compat with the pre-v2.17.1 wire shape).
	res := &kbDiffResult{
		KbID:       out.KBID,
		FromEpoch:  out.FromEpoch,
		ToEpoch:    out.ToEpoch,
		Mode:       out.Mode,
		Categories: make(map[string]*kbCategoryDiffItems, len(out.Categories)),
	}
	for cat, bucket := range out.Categories {
		res.Categories[cat] = &kbCategoryDiffItems{
			Added:    bucket.Added,
			Removed:  bucket.Removed,
			Modified: bucket.Modified,
		}
	}
	return mustKBJSON(kbJSONResult(res))
}

// kbDiffConsecutive + kbDiffLongRange removed in v2.17.1 T2 — their SQL +
// bucket-merge logic moved to kbstore.Diff (pkg/knowledge/kb/store/diff.go)
// and the kbDiffHandler above now adapts the supervisor's response into
// the legacy kbDiffResult wire envelope client-side.

// ---------------------------------------------------------------------
// kb_search
// ---------------------------------------------------------------------

type kbSearchToolInput struct {
	Query     string `json:"query"               jsonschema:"trigram fuzzy-match search string (required)"`
	App       string `json:"app,omitempty"       jsonschema:"filter by app kb_id"`
	Component string `json:"component,omitempty" jsonschema:"filter by component bucket (auth, communication, ui, ipc, security, stealth, telemetry, storage, crypto, protocol, other)"`
	Topic     string `json:"topic,omitempty"     jsonschema:"filter by deterministic topic"`
	FactType  string `json:"fact_type,omitempty" jsonschema:"filter by fact type category (matches app_facts.category)"`
	Lang      string `json:"lang,omitempty"      jsonschema:"filter by detected source language (e.g. javascript, java, kotlin)"`
	Since     string `json:"since,omitempty"     jsonschema:"filter to captures since duration (e.g. 30d, 2y) or RFC3339"`
	Limit     int    `json:"limit,omitempty"     jsonschema:"max results to return (default 50, hard cap 500)"`
	Cursor    string `json:"cursor,omitempty"    jsonschema:"opaque base64 cursor token from a previous response (next_cursor)"`
}

type kbSearchItem struct {
	ModuleID           int64   `json:"module_id"`
	Name               string  `json:"name"`
	BodyExcerptSnippet string  `json:"body_excerpt_snippet"`
	Similarity         float32 `json:"similarity"`
	AppKbID            string  `json:"app_kb_id"`
	AppDisplayName     string  `json:"app_display_name"`
	CapturedAt         int64   `json:"captured_at"`
	Lang               string  `json:"lang"`
	Component          string  `json:"component"`
	Summary            string  `json:"summary"`
	Role               string  `json:"role"`
	Tags               string  `json:"tags"`
	SyntheticName      string  `json:"synthetic_name"`
	Topic              string  `json:"topic,omitempty"`
}

type kbCursorTok struct {
	Similarity float32 `json:"s"`
	CapturedAt int64   `json:"c"`
	ModuleID   int64   `json:"m"`
}

func kbSearchHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbSearchToolInput) (*mcp.CallToolResult, any, error) {
	if in.Query == "" {
		return kbErrResult("query is required"), nil, nil
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		return kbErrResult("limit must be <= 500"), nil, nil
	}
	if in.Component != "" {
		valid := false
		for _, b := range component.Buckets {
			if b == in.Component {
				valid = true
				break
			}
		}
		if !valid {
			return kbErrResult(fmt.Sprintf("invalid component %q; valid: %s", in.Component, strings.Join(component.Buckets, ", "))), nil, nil
		}
	}

	// Tampered cursor → restart, NOT error (D-33-SEARCH-CURSOR / D-32-SEARCH-PAGINATION).
	var cursor *kbstore.SearchCursor
	if in.Cursor != "" {
		if data, err := base64.URLEncoding.DecodeString(in.Cursor); err == nil {
			var c kbstore.SearchCursor
			if err := json.Unmarshal(data, &c); err == nil {
				cursor = &c
			}
		}
	}

	var sinceMS int64
	if in.Since != "" {
		t, err := kbParseSince(in.Since)
		if err != nil {
			return kbErrResult(fmt.Sprintf("parse since: %v", err)), nil, nil
		}
		sinceMS = t.UnixMilli()
	}

	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}
	res, err := cli.Search(ctx, supervisor.KBSearchParams{
		Query:       in.Query,
		App:         in.App,
		Component:   in.Component,
		Topic:       in.Topic,
		FactType:    in.FactType,
		Lang:        in.Lang,
		SinceMillis: sinceMS,
		TopK:        limit,
		Cursor:      cursor,
	})
	if err != nil {
		return kbErrResult(fmt.Sprintf("search: %v", err)), nil, nil
	}

	// Convert kbstore.SearchItem → kbSearchItem (wire-shape parity) and
	// trim each raw body_excerpt down to a query-centred snippet.
	items := make([]kbSearchItem, 0, len(res.Items))
	for _, it := range res.Items {
		items = append(items, kbSearchItem{
			ModuleID:           it.ModuleID,
			Name:               it.Name,
			BodyExcerptSnippet: kbExtractSnippet(it.BodyExcerptSnippet, in.Query),
			Similarity:         it.Similarity,
			AppKbID:            it.AppKbID,
			AppDisplayName:     it.AppDisplayName,
			CapturedAt:         it.CapturedAt,
			Lang:               it.Lang,
			Component:          it.Component,
			Summary:            it.Summary,
			Role:               it.Role,
			Tags:               it.Tags,
			SyntheticName:      it.SyntheticName,
			Topic:              it.Topic,
		})
	}

	var nextCursorStr *string
	if res.NextCursor != nil {
		data, _ := json.Marshal(res.NextCursor)
		token := base64.URLEncoding.EncodeToString(data)
		nextCursorStr = &token
	}

	banner := ""
	if res.FallbackUsed == "fts_over_bodies" {
		banner = fmt.Sprintf("enrichment coverage %d%% — falling back to FTS over raw bodies", res.EnrichmentCoveragePct)
	}

	payload := map[string]any{
		"query":                   in.Query,
		"returned":                len(items),
		"next_cursor":             nextCursorStr,
		"items":                   items,
		"enrichment_coverage_pct": res.EnrichmentCoveragePct,
		"fallback_used":           res.FallbackUsed,
		"fallback_banner":         banner,
	}
	if len(items) == 0 {
		text, structured := emptyResultDiagnostic(kbPoolResolvedInfo(), "modules")
		structured["query"] = in.Query
		structured["enrichment_coverage_pct"] = res.EnrichmentCoveragePct
		structured["fallback_used"] = res.FallbackUsed
		structured["fallback_banner"] = banner
		structured["schema_version"] = 1
		return kbJSONResultWithText(structured, text)
	}
	if banner != "" {
		return kbJSONResultWithText(payload, banner)
	}
	return mustKBJSON(kbJSONResult(payload))
}

// kbEnrichmentCoveragePct mirrors cmd.enrichmentCoveragePct using the
// package-level kbDB pool. Returns 0 on error (best-effort).
func kbEnrichmentCoveragePct(ctx context.Context, appKbID string) int {
	if kbDB == nil {
		return 0
	}
	var q string
	var args []any
	if appKbID != "" {
		q = `SELECT COALESCE(SUM(CASE WHEN m.summary IS NOT NULL THEN 1 ELSE 0 END) * 100 / NULLIF(COUNT(*),0), 0)
			 FROM modules m
			 JOIN module_app_refs mar ON mar.body_sha256 = m.body_sha256
			 JOIN knowledge_sources ks ON ks.id = mar.source_id
			 WHERE ks.kb_id = $1`
		args = []any{appKbID}
	} else {
		q = `SELECT COALESCE(SUM(CASE WHEN summary IS NOT NULL THEN 1 ELSE 0 END) * 100 / NULLIF(COUNT(*),0), 0)
			 FROM modules`
	}
	var pct int
	if err := kbDB.QueryRowContext(ctx, q, args...).Scan(&pct); err != nil {
		return 0
	}
	return pct
}

// kbExtractSnippet mirrors cmd/kb_search.extractSnippet exactly.
func kbExtractSnippet(text, query string) string {
	if text == "" {
		return ""
	}
	idx := strings.Index(strings.ToLower(text), strings.ToLower(query))
	if idx == -1 {
		if len(text) > 200 {
			return text[:200]
		}
		return text
	}
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := start + 200
	if end > len(text) {
		end = len(text)
		start = end - 200
		if start < 0 {
			start = 0
		}
	}
	snippet := text[start:end]
	return strings.ReplaceAll(snippet, "\n", " ")
}

// ---------------------------------------------------------------------
// kb_capture
// ---------------------------------------------------------------------

type kbCaptureToolInput struct {
	Path           string   `json:"path"                       jsonschema:"absolute filesystem path to the application binary or directory to capture"`
	Tag            []string `json:"tag,omitempty"              jsonschema:"capture tags (free-form labels attached to this capture; repeatable)"`
	Reason         string   `json:"reason,omitempty"           jsonschema:"human-readable reason for the capture (audit trail)"`
	By             string   `json:"by,omitempty"               jsonschema:"actor identifier (user, ci-job, agent-name) attributed to this capture"`
	Force          bool     `json:"force,omitempty"            jsonschema:"bypass idempotency check; create new epoch even if binary_sha256 matches latest (default false)"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"  jsonschema:"override default 600s capture timeout (allowed range 60-1800)"`
}

func kbCaptureHandler(ctx context.Context, _ *mcp.CallToolRequest, in kbCaptureToolInput) (*mcp.CallToolResult, any, error) {
	if kbDB == nil {
		return kbErrResult(kbDSNHint), nil, nil
	}
	if in.Path == "" {
		return kbErrResult("path is required"), nil, nil
	}

	// D-33-CAPTURE-PATH-VALIDATION: filepath.Clean → reject relative or '..'.
	clean := filepath.Clean(in.Path)
	if !filepath.IsAbs(clean) {
		return kbErrResult(fmt.Sprintf("path must be absolute (got %q)", in.Path)), nil, nil
	}
	// After Clean, ".." can only appear if the original path escaped its root.
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for _, p := range parts {
		if p == ".." {
			return kbErrResult(fmt.Sprintf("path must not contain '..' (got %q)", in.Path)), nil, nil
		}
	}

	// D-33-CAPTURE-SYNC: timeout 0 → 600s default; clamp to [60, 1800].
	timeoutSecs := in.TimeoutSeconds
	if timeoutSecs == 0 {
		timeoutSecs = 600
	}
	if timeoutSecs < 60 {
		timeoutSecs = 60
	}
	if timeoutSecs > 1800 {
		timeoutSecs = 1800
	}

	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	res, err := kbCaptureRun(cctx, clean, in.Tag, in.Reason, in.By, in.Force)
	if err != nil {
		// On deadline: deterministic error text (D-33-CAPTURE-SYNC).
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return kbErrResult(fmt.Sprintf(kbCaptureTimeoutMsgFmt, timeoutSecs)), nil, nil
		}
		return kbErrResult(err.Error()), nil, nil
	}

	return mustKBJSON(kbJSONResult(res))
}

// sha256OfFile returns the hex-encoded SHA-256 of the file at path.
// Used to seed ingest.Options.BinarySHA256 from the source-binary input.
func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// kbCaptureRun mirrors runKbCapture in cmd/kb_capture.go: stage → fingerprint
// → promote → ingest → best-effort classify. Logger writes only to stderr.
func kbCaptureRun(ctx context.Context, appPath string, tags []string, reason, by string, force bool) (*ingest.Result, error) {
	stagingDir, clrModules, err := kbStageAnalysis(appPath)
	if err != nil {
		return nil, fmt.Errorf("stage analysis: %w", err)
	}
	fpIn, err := kbLoadFingerprintInputs(stagingDir)
	if err != nil {
		return nil, fmt.Errorf("load fingerprint inputs: %w", err)
	}
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		return nil, fmt.Errorf("fingerprint staging: %w", err)
	}
	ksDir, err := kbPromoteStaging(stagingDir, kbID, ksID)
	if err != nil {
		return nil, fmt.Errorf("promote staging: %w", err)
	}

	storeRoot, err := fsutil.KBStoreRoot()
	if err != nil {
		return nil, fmt.Errorf("resolve kb-store root: %w", err)
	}

	// Source-binary SHA from the input file — authoritative for
	// idempotency (D-30-IDEMPOTENCY) on archive inputs (APK/IPA) whose
	// staged tree lacks a top-level PE/ELF/Mach-O. For directory inputs
	// (MSIX install dirs, source repos) leave it empty so the ingest
	// writer falls back to walk-derived — hashing a directory entry as
	// a file errors with "Incorrect function" on Windows.
	var binarySHA string
	if fi, statErr := os.Stat(appPath); statErr == nil && fi.Mode().IsRegular() {
		var hashErr error
		binarySHA, hashErr = sha256OfFile(appPath)
		if hashErr != nil {
			return nil, fmt.Errorf("hash input file: %w", hashErr)
		}
	}

	res, err := ingest.Run(ctx, kbDB, kbID, ksID, ksDir, ingest.Options{
		Tags:          tags,
		Reason:        reason,
		By:            by,
		Force:         force,
		ResolveAlias:  true,
		AllowedRoots:  []string{storeRoot},
		PackageID:     fpIn.PackageID,
		Platform:      fpIn.Platform,
		DisplayName:   fpIn.DisplayName,
		CanonicalName: identity.CanonicalName(fpIn.DisplayName),
		BinarySHA256:  binarySHA,
		CLRModules:    clrModules,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr,
			"warning: db ingest failed; kb-store folder %q is orphan; run 'kb gc --orphan-folders' (Phase 34) to clean up\n",
			ksDir)
		return nil, fmt.Errorf("ingest run: %w", err)
	}

	// Best-effort post-ingest classify (D-31-APPLY-POST-INGEST). Failure is
	// logged at WARN to stderr — never fails the capture handler.
	if rep, cerr := classify.Run(ctx, kbDB, res.KBID, res.Epoch); cerr != nil {
		slog.Warn("classifier failed; module_components rows skipped",
			"kb_id", res.KBID, "epoch", res.Epoch, "err", cerr)
	} else if rep != nil {
		slog.Info("post-ingest classify",
			"kb_id", rep.KBID, "epoch", rep.Epoch,
			"classified", rep.ModulesClassified, "skipped", rep.Skipped)
	}

	return res, nil
}

// kbStageAnalysis runs the knowledge analysis into a fresh staging dir and
// returns that dir plus the native CLR modules captured in-memory (FIX #1). The
// modules are threaded through to ingest.Options.CLRModules so .NET lang='cil'
// rows persist without a sidecar file; the slice is nil for non-.NET inputs.
func kbStageAnalysis(appPath string) (string, []clr.TypeModule, error) {
	root, err := fsutil.KBStoreRoot()
	if err != nil {
		return "", nil, fmt.Errorf("resolve kb-store root: %w", err)
	}
	id, err := kbRandID()
	if err != nil {
		return "", nil, fmt.Errorf("alloc staging id: %w", err)
	}
	staging := filepath.Join(root, "staging", id)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", nil, fmt.Errorf("mkdir staging: %w", err)
	}
	kr, err := knowledge.Run(appPath, knowledge.Options{
		OutputDir: staging,
		Verbose:   false,
	})
	if err != nil {
		return "", nil, fmt.Errorf("knowledge analysis: %w", err)
	}
	return staging, kr.CLRModules, nil
}

func kbPromoteStaging(stagingDir, kbID, ksID string) (string, error) {
	root, err := fsutil.KBStoreRoot()
	if err != nil {
		return "", fmt.Errorf("resolve kb-store root: %w", err)
	}
	ksFS, err := fsutil.EncodeKsID(ksID)
	if err != nil {
		return "", fmt.Errorf("encode ks_id: %w", err)
	}
	target := filepath.Join(root, "apps", kbID, "versions", ksFS)
	target = fsutil.WrapLongPath(target)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", fmt.Errorf("mkdir target parent: %w", err)
	}
	if err := os.Rename(stagingDir, target); err != nil {
		return "", fmt.Errorf("rename staging to target: %w", err)
	}
	return target, nil
}

func kbLoadFingerprintInputs(stagingDir string) (identity.FingerprintInputs, error) {
	in := identity.FingerprintInputs{CapturedAt: time.Now().UnixMilli()}
	f, err := os.Open(filepath.Join(stagingDir, "knowledge.json"))
	if err != nil {
		return in, fmt.Errorf("open knowledge.json: %w", err)
	}
	defer func() { _ = f.Close() }()
	const maxKnowledgeJSON = 64 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(f, maxKnowledgeJSON))
	if err != nil {
		return in, fmt.Errorf("read knowledge.json: %w", err)
	}
	raw := map[string]any{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return in, fmt.Errorf("parse knowledge.json: %w", err)
	}
	if v, ok := raw["platform"].(string); ok {
		in.Platform = v
	}
	if v, ok := raw["package_id"].(string); ok {
		in.PackageID = v
	}
	if v, ok := raw["display_name"].(string); ok {
		in.DisplayName = v
	}
	if v, ok := raw["app_version"].(string); ok {
		in.AppVersion = v
	}
	if v, ok := raw["captured_at"].(float64); ok && v > 0 {
		in.CapturedAt = int64(v)
	}
	if in.Platform == "" {
		return in, errors.New("knowledge.json missing platform field")
	}
	return in, nil
}

func kbRandID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// ---------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------

// kbOpen is a convenience the cmd-side wiring (cmd/mcp.go) calls when
// initialising kbDB from UNRAVEL_KB_DSN. Kept here so the open semantics
// (timeouts, pool tuning) stay co-located with the handlers that use it.
func kbOpen(ctx context.Context, dsn string) (*sql.DB, error) {
	db, _, err := kbResolve(ctx, dsn)
	return db, err
}

// mustKBJSON adapts the (result, error) from kbJSONResult to the
// (result, any, error) handler signature required by mcp.AddTool.
func mustKBJSON(r *mcp.CallToolResult, err error) (*mcp.CallToolResult, any, error) {
	return r, nil, err
}

// kbJSONResultWithText marshals payload via kbJSONResult then appends an
// extra TextContent element carrying diagnostic text (e.g. empty-result
// hints). If marshalling fails the error result is returned unchanged.
func kbJSONResultWithText(v any, text string) (*mcp.CallToolResult, any, error) {
	r, err := kbJSONResult(v)
	if err == nil && r != nil {
		r.Content = append(r.Content, &mcp.TextContent{Text: text})
	}
	return r, nil, err
}
