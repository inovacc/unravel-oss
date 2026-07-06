/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ipc"

	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// ---------- request / response shapes ----------

// KBSearchParams is the request body for kb.search.
//
// As of v2.17 thin-client B1.1 the verb backs the full kbSearchHandler
// surface: 7 filter fields, opaque-cursor pagination, FTS-fallback
// transparency, and enrichment-coverage reporting. The Query field is
// required; everything else is optional.
type KBSearchParams struct {
	Query       string                `json:"query"`
	App         string                `json:"app,omitempty"`
	Component   string                `json:"component,omitempty"`
	Topic       string                `json:"topic,omitempty"`
	FactType    string                `json:"fact_type,omitempty"`
	Lang        string                `json:"lang,omitempty"`
	SinceMillis int64                 `json:"since_millis,omitempty"`
	TopK        int                   `json:"top_k,omitempty"`
	Cursor      *kbstore.SearchCursor `json:"cursor,omitempty"`
}

// KBSearchResult is the response body for kb.search. Wire-shape alias
// over kbstore.SearchPayload — the MCP tool slot-in is one-to-one
// (Query, Returned, NextCursor, Items, EnrichmentCoveragePct, FallbackUsed).
type KBSearchResult = kbstore.SearchPayload

// KBFactsParams is the request body for kb.facts and kb.gaps.
type KBFactsParams struct {
	App      string `json:"app,omitempty"`
	Category string `json:"category,omitempty"`
	ModuleID int    `json:"module_id,omitempty"`
	Filter   string `json:"filter,omitempty"`
}

// KBFactsResult is the response body for kb.facts and kb.gaps.
type KBFactsResult struct {
	Facts []kbstore.FactRow `json:"facts"`
}

// KBGapsResult is the response body for kb.gaps.
type KBGapsResult struct {
	Gaps []kbstore.FactRow `json:"gaps"`
}

// KBStatsParams is the request body for kb.stats.
type KBStatsParams struct {
	App string `json:"app,omitempty"`
}

// KBStatsResult is the response body for kb.stats.
type KBStatsResult struct {
	Counts []kbstore.StatsRow `json:"counts"`
}

// KBAppsParams is the request body for kb.apps. All fields are optional;
// when omitted the verb returns the most recently seen apps (capped by
// Limit, default 100, hard cap 1000).
type KBAppsParams struct {
	Platform       string   `json:"platform,omitempty"`
	Framework      string   `json:"framework,omitempty"`
	Risk           string   `json:"risk,omitempty"`
	Tag            []string `json:"tag,omitempty"`
	SinceMillis    *int64   `json:"since_millis,omitempty"`
	Limit          int      `json:"limit,omitempty"`
	IncludeAliases bool     `json:"include_aliases,omitempty"`
}

// KBAppsResult is the response body for kb.apps. Wire-shape is the
// kbstore.AppsPayload — fields are field-for-field compatible with what
// unravel_kb_apps emitted prior to the A-Apps extraction.
type KBAppsResult = kbstore.AppsPayload

// KBVendoredCandidatesParams is the request body for kb.vendored_candidates.
type KBVendoredCandidatesParams struct {
	App      string `json:"app,omitempty"`
	MinCount int    `json:"min_count,omitempty"`
	Top      int    `json:"top,omitempty"`
}

// KBVendoredCandidatesResult is the response body for kb.vendored_candidates.
// Wire-shape alias over kbstore.VendoredCandidatesPayload — the MCP tool
// adds its own env_line presentation field on top of this.
type KBVendoredCandidatesResult = kbstore.VendoredCandidatesPayload

// KBDiffParams is the request body for kb.diff (v2.17.1).
type KBDiffParams struct {
	KBID       string   `json:"kb_id"`
	FromEpoch  int64    `json:"from_epoch"`
	ToEpoch    int64    `json:"to_epoch"`
	Categories []string `json:"categories,omitempty"`
}

// KBDiffResult is the response body for kb.diff — alias over the
// kbstore.DiffPayload wire shape.
type KBDiffResult = kbstore.DiffPayload

// KBDiffAppsParams is the request body for kb.diff_apps.
type KBDiffAppsParams struct {
	AppA     string `json:"app_a"`
	AppB     string `json:"app_b"`
	Category string `json:"category,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// KBDiffAppsResult is the response body for kb.diff_apps. Wire-shape is
// the kbstore.DiffAppsResult — fields are field-for-field compatible
// with what unravel_kb_diff_apps emits.
type KBDiffAppsResult = kbstore.DiffAppsResult

// KBExportParams is the request body for kb.export. KBID is required;
// LatestOnly mirrors the legacy `--latest-only` CLI flag.
type KBExportParams struct {
	KBID       string `json:"kb_id"`
	LatestOnly bool   `json:"latest_only,omitempty"`
}

// KBExportResult is the response body for kb.export. Wire-shape is the
// kbstore.ExportPayload — fields are field-for-field compatible with the
// legacy kb-export.json file the CLI emits prior to the A2 extraction.
type KBExportResult = kbstore.ExportPayload

// KBImportParams is the request body for kb.import.
type KBImportParams struct {
	Path string `json:"path"`
	App  string `json:"app,omitempty"`
	// VerifyKeyPath optionally carries a pinned Ed25519 public key path so
	// the supervisor import path can enforce bundle-signature verification
	// at CLI parity (hardening finding #7). Empty = opt-in skip (ADR-0007
	// default). Additive: omitting it preserves prior behavior.
	VerifyKeyPath string `json:"verify_key_path,omitempty"`
}

// KBImportResult is the response body for kb.import. Wire-shape is the
// kbstore.ImportPayload — counts per table plus the convenience
// imported_count scalar. Field-for-field compatible with the snake_case
// payload the kb_import CLI surfaces.
type KBImportResult = kbstore.ImportPayload

// KBDumpParams is the request body for kb.dump.
type KBDumpParams struct {
	ID  int    `json:"id"`
	App string `json:"app,omitempty"`
	Fmt string `json:"fmt,omitempty"`
}

// KBDumpResult is the response body for kb.dump.
type KBDumpResult struct {
	Row *kbstore.DumpRow `json:"row"`
}

// KBTimelineParams is the request body for kb.timeline. KbID is required
// and must already be canonical (the supervisor does not resolve aliases —
// callers run pkg/knowledge/kb/identity.ResolveAlias up front). Reverse
// mirrors the legacy `--reverse` CLI flag.
type KBTimelineParams struct {
	KbID    string `json:"kb_id"`
	Reverse bool   `json:"reverse,omitempty"`
}

// KBTimelineResult is the response body for kb.timeline. Wire-shape is
// the kbstore.TimelinePayload — fields are byte-for-byte compatible with
// what unravel_kb_timeline emitted prior to the A4 extraction.
type KBTimelineResult = kbstore.TimelinePayload

// KBPullGapParams is the request body for kb.pull_gap. App is required.
// Op selects the prompt template (defaults to fact_resolve). EvidenceLimit
// caps the supporting modules hydrated alongside the gap (defaults to 8).
type KBPullGapParams struct {
	App           string `json:"app"`
	Op            string `json:"op,omitempty"`
	EvidenceLimit int    `json:"evidence_limit,omitempty"`
}

// KBPullGapResult is the response body for kb.pull_gap. Wire-shape is the
// kbstore.GapPayload — fields are field-for-field compatible with what
// unravel_kb_pull_gap emitted prior to the A5 extraction.
type KBPullGapResult = kbstore.GapPayload

// KBPushAnswerParams is the request body for kb.push_answer. GapID and
// Value are required.
type KBPushAnswerParams struct {
	GapID       int64   `json:"gap_id"`
	Value       string  `json:"value"`
	EvidenceIDs []int64 `json:"evidence_ids,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	SourceStep  string  `json:"source_step,omitempty"`
}

// KBPushAnswerResult is the response body for kb.push_answer. Wire-shape
// is the kbstore.PushAnswerPayload — fields are field-for-field compatible
// with what unravel_kb_push_answer emitted prior to the A6 extraction.
type KBPushAnswerResult = kbstore.PushAnswerPayload

// KBDoctorParams is the request body for kb.doctor.
type KBDoctorParams struct {
	App string `json:"app,omitempty"`
}

// KBDoctorResult is the response body for kb.doctor. Wire-shape is the
// kbstore.DoctorReport — fields are field-for-field compatible with the
// snake_case payload the kb_doctor CLI surfaces.
type KBDoctorResult = kbstore.DoctorReport

// ---------- registration ----------

// errKBNoDB is returned when a kb.* verb is invoked but the supervisor
// has no DB pool wired (Config.DSN was empty).
func errKBNoDB() *ipc.ErrorBody {
	return &ipc.ErrorBody{
		Code:    ipc.CodeUnavailable,
		Message: "kb: supervisor has no DB pool (Config.DSN empty)",
	}
}

// registerKBVerbs wires the kb.* verb group. Called from New().
//
// The 13 verbs in this group are the thin-client surface that
// pkg/mcp/tools/ will eventually call through instead of opening *sql.DB
// directly. PG-V17-5 lands the wire surface + the read verbs that have a
// 1:1 backing implementation in pkg/knowledge/kb/store; verbs without a
// store-level implementation (kb.pull_gap, kb.push_answer)
// are registered but return
// CodeUpstream to flag "not_implemented" so the wire contract is stable
// while higher-level migration work continues.
func (sv *Supervisor) registerKBVerbs() {
	sv.RegisterVerb("kb.search", sv.kbSearch)
	sv.RegisterVerb("kb.facts", sv.kbFacts)
	sv.RegisterVerb("kb.gaps", sv.kbGaps)
	sv.RegisterVerb("kb.stats", sv.kbStats)
	sv.RegisterVerb("kb.apps", sv.kbApps)
	sv.RegisterVerb("kb.diff_apps", sv.kbDiffApps)
	sv.RegisterVerb("kb.export", sv.kbExport)
	sv.RegisterVerb("kb.import", sv.kbImport)
	sv.RegisterVerb("kb.dump", sv.kbDump)
	sv.RegisterVerb("kb.timeline", sv.kbTimeline)
	sv.RegisterVerb("kb.pull_gap", sv.kbPullGap)
	sv.RegisterVerb("kb.push_answer", sv.kbPushAnswer)
	sv.RegisterVerb("kb.doctor", sv.kbDoctor)
	sv.RegisterVerb("kb.vendored_candidates", sv.kbVendoredCandidates)
	sv.RegisterVerb("kb.diff", sv.kbDiff)
}

// ---------- handlers (read verbs backed by kbstore) ----------

func (sv *Supervisor) kbSearch(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBSearchParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.search: " + err.Error()}
	}
	if p.Query == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.search: query required"}
	}
	out, err := kbstore.SearchAdvanced(ctx, sv.db, kbstore.SearchOptions{
		Query:       p.Query,
		App:         p.App,
		Component:   p.Component,
		Topic:       p.Topic,
		FactType:    p.FactType,
		Lang:        p.Lang,
		SinceMillis: p.SinceMillis,
		Limit:       p.TopK,
		Cursor:      p.Cursor,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.search: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) kbFacts(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBFactsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.facts: " + err.Error()}
	}
	rows, err := kbstore.Facts(sv.db, p.App, p.Category, false)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.facts: %w", err).Error()}
	}
	return KBFactsResult{Facts: rows}, nil
}

func (sv *Supervisor) kbGaps(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBFactsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.gaps: " + err.Error()}
	}
	rows, err := kbstore.Gaps(sv.db, p.App, p.Category)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.gaps: %w", err).Error()}
	}
	return KBGapsResult{Gaps: rows}, nil
}

func (sv *Supervisor) kbStats(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBStatsParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.stats: " + err.Error()}
		}
	}
	rows, err := kbstore.Stats(sv.db)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.stats: %w", err).Error()}
	}
	// Optional client-side filter by app (kbstore.Stats has no per-app filter).
	if p.App != "" {
		filtered := rows[:0]
		for _, r := range rows {
			if r.App == p.App {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	return KBStatsResult{Counts: rows}, nil
}

func (sv *Supervisor) kbDump(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBDumpParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.dump: " + err.Error()}
	}
	if p.ID == 0 {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.dump: id required"}
	}
	row, err := kbstore.Dump(sv.db, p.ID, 10)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: fmt.Sprintf("kb.dump: module id %d not found", p.ID)}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.dump: %w", err).Error()}
	}
	return KBDumpResult{Row: row}, nil
}

func (sv *Supervisor) kbApps(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBAppsParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.apps: " + err.Error()}
		}
	}
	out, err := kbstore.Apps(ctx, sv.db, kbstore.AppsOptions{
		Platform:       p.Platform,
		Framework:      p.Framework,
		Risk:           p.Risk,
		Tag:            p.Tag,
		SinceMillis:    p.SinceMillis,
		Limit:          p.Limit,
		IncludeAliases: p.IncludeAliases,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.apps: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) kbDoctor(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBDoctorParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.doctor: " + err.Error()}
		}
	}
	out, err := kbstore.Doctor(ctx, sv.db, kbstore.DoctorOptions{App: p.App})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.doctor: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) kbDiff(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBDiffParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.diff: " + err.Error()}
	}
	out, err := kbstore.Diff(ctx, sv.db, kbstore.DiffOptions{
		KBID:       p.KBID,
		FromEpoch:  p.FromEpoch,
		ToEpoch:    p.ToEpoch,
		Categories: p.Categories,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.diff: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) kbVendoredCandidates(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBVendoredCandidatesParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.vendored_candidates: " + err.Error()}
		}
	}
	out, err := kbstore.VendoredCandidates(ctx, sv.db, kbstore.VendoredCandidatesOptions{
		App:      p.App,
		MinCount: p.MinCount,
		Top:      p.Top,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.vendored_candidates: %w", err).Error()}
	}
	return out, nil
}

// ---------- handlers (placeholder: wire surface only) ----------
//
// These verbs are registered so the kb.* contract is complete and the
// client wrapper can target stable method names. The body returns
// CodeUpstream ("not_implemented") because the underlying store helpers
// do not exist yet — implementing them is tracked by the follow-up
// task that ports each pkg/mcp/tools/kb_*.go handler to call kbClient.X.

func (sv *Supervisor) kbDiffApps(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBDiffAppsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.diff_apps: " + err.Error()}
	}
	if p.AppA == "" || p.AppB == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.diff_apps: app_a and app_b required"}
	}
	if p.AppA == p.AppB {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.diff_apps: app_a and app_b must differ"}
	}
	res, err := kbstore.DiffApps(ctx, sv.db, p.AppA, p.AppB, kbstore.DiffAppsOptions{
		Category: p.Category,
		Limit:    p.Limit,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.diff_apps: %w", err).Error()}
	}
	return res, nil
}

func (sv *Supervisor) kbExport(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p KBExportParams
	if e := sv.decodeParams("kb.export", params, &p, errKBNoDB); e != nil {
		return nil, e
	}
	if p.KBID == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.export: kb_id required"}
	}
	res, err := kbstore.Export(ctx, sv.db, p.KBID, kbstore.ExportOptions{LatestOnly: p.LatestOnly})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.export: %w", err).Error()}
	}
	return res, nil
}

func (sv *Supervisor) kbImport(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p KBImportParams
	if e := sv.decodeParams("kb.import", params, &p, errKBNoDB); e != nil {
		return nil, e
	}
	if p.Path == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.import: path required"}
	}
	res, err := kbstore.Import(ctx, sv.db, kbstore.ImportOptions{
		BundlePath:    p.Path,
		App:           p.App,
		VerifyKeyPath: p.VerifyKeyPath,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.import: %w", err).Error()}
	}
	return res, nil
}

func (sv *Supervisor) kbTimeline(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p KBTimelineParams
	if e := sv.decodeParams("kb.timeline", params, &p, errKBNoDB); e != nil {
		return nil, e
	}
	if p.KbID == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.timeline: kb_id required"}
	}
	out, err := kbstore.Timeline(ctx, sv.db, kbstore.TimelineOptions{KbID: p.KbID, Reverse: p.Reverse})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.timeline: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) kbPullGap(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBPullGapParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.pull_gap: " + err.Error()}
		}
	}
	if p.App == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.pull_gap: app required"}
	}
	out, err := kbstore.PullGap(ctx, sv.db, kbstore.PullGapOptions{
		App:           p.App,
		Op:            p.Op,
		EvidenceLimit: p.EvidenceLimit,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.pull_gap: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) kbPushAnswer(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errKBNoDB()
	}
	var p KBPushAnswerParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.push_answer: " + err.Error()}
	}
	if p.GapID == 0 {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "kb.push_answer: gap_id required"}
	}
	out, err := kbstore.PushAnswer(ctx, sv.db, kbstore.PushAnswerOptions{
		GapID:       p.GapID,
		Value:       p.Value,
		EvidenceIDs: p.EvidenceIDs,
		Confidence:  p.Confidence,
		SourceStep:  p.SourceStep,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("kb.push_answer: %w", err).Error()}
	}
	return out, nil
}
