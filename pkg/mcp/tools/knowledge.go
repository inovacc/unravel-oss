/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// openKB opens the Postgres-backed knowledge catalog. dsnOverride is the
// optional --database / in.DB value — when empty, kbdb.Open reads config.yaml
// and decrypts the password via keychain.
//
// As of v3.0 the catalog is Postgres-only. UNRAVEL_KB_DB used to point at
// a SQLite file and is preserved as a DSN env override (treat the value
// as a postgres:// URL).
func openKB(ctx context.Context, dsnOverride string) (*sql.DB, error) {
	db, _, err := openKBInfo(ctx, dsnOverride)
	return db, err
}

// openKBInfo is the diagnostic-aware variant; handlers use it so an
// empty result can name the resolved catalog.
//
// The ctx parameter bounds the DB-open phase: a client disconnect during
// an unhealthy Postgres handshake now propagates cancellation rather
// than holding a connection open until kbResolve's internal timeout
// expires. Pass context.Background() from non-MCP call sites (e.g.
// tests / one-shot tooling) for the historical behaviour.
func openKBInfo(ctx context.Context, dsnOverride string) (*sql.DB, ResolvedInfo, error) {
	return kbResolve(ctx, dsnOverride)
}

// jsonResultWithText returns the structured JSON result plus an extra
// human-readable text content line (used for loud empty-result diagnostics).
func jsonResultWithText(v any, text string) *mcp.CallToolResult {
	r := jsonResult(v)
	if r != nil {
		r.Content = append(r.Content, &mcp.TextContent{Text: text})
	}
	return r
}

type knowledgeInput struct {
	Path                 string `json:"path" jsonschema:"Path to app directory, ASAR, APK, or binary"`
	OutputDir            string `json:"output_dir,omitempty" jsonschema:"Output directory for knowledge files (optional)"`
	JSON                 bool   `json:"json,omitempty" jsonschema:"Return JSON instead of writing directory"`
	Enrich               bool   `json:"enrich,omitempty" jsonschema:"Phase 14: enrich dependency list with CVE/CWE/version-freshness data (sends dep names to OSV/NVD/GHSA — opt-in per D-08)"`
	EnrichIncludePrivate bool   `json:"enrich_include_private,omitempty" jsonschema:"Phase 14: do NOT skip scoped/private packages during enrichment (overrides D-08 default)"`
}

type knowledgeDiffInput struct {
	OldDir string `json:"old_dir" jsonschema:"Path to the old knowledge directory"`
	NewDir string `json:"new_dir" jsonschema:"Path to the new knowledge directory"`
}

func registerKnowledgeTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_knowledge",
		Description: "Generate structured knowledge source for an Electron/Tauri/Android app. Produces layered JSON+markdown covering communication, auth, UI framework, IPC, security, stealth, telemetry, and source files + component-grouped source tree at <kb>/sources/<component>/ + per-file _meta.json provenance + manifest.json files inventory (Phase 7).",
	}, handleKnowledge)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_transfer_diff_dirs",
		Description: "Compare two KBs across permissions, security config, structural delta, text equivalence; severity-tagged regressions (BLOCK/FLAG/PASS); JSON + Markdown report.",
	}, handleKnowledgeDiff)

	// Phase 7 plan 04: cross-framework migration + per-component classifier
	// + regression-only diff. See pkg/mcptools/knowledge_phase7.go.
	registerKnowledgePhase7Tools(s)

	// --- catalog-backed tools (knowledge.db) ---

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_catalog_stats",
		Description: "Per-app counts in the knowledge.db catalog: total modules, summarized count, average body size, distinct hashes.",
	}, handleKBStats)

	// Note: legacy SQLite-FTS5 search-tool registration removed in 33-06.
	// Canonical handler now lives in pkg/mcptools/kb.go as
	// unravel_kb_catalog_search (trigram fuzzy match over the
	// Postgres-backed kb store; replaces the SQLite FTS5 implementation).

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_catalog_dump",
		Description: "Print one module row by id — full body excerpt, extracted symbols, prior summary, sightings list.",
	}, handleKBDump)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_catalog_facts",
		Description: "Show answered facts in app_facts (filled rows). Filter by app/category.",
	}, handleKBFacts)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_gaps_list",
		Description: "List open fact gaps (rows in app_facts where value IS NULL).",
	}, handleKBGaps)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_ops_doctor",
		Description: "Diagnose KB catalog resolution: resolved Postgres host/db/user (password-free), config source, kb_apps/knowledge_sources counts, schema migration version. Use when kb_* tools return empty.",
	}, handleKBDoctor)

	// KBC-ENRICH-SESSION-MONITOR: cross-session visibility + selective retry.
	// The legacy sampling-only enrich tool (broken under
	// the Claude Code MCP client) was removed 2026-05-23 in favour of the
	// /unravel-enrich plugin command which orchestrates Task subagents.
	registerKnowledgeEnrichStatusTool(s)
	registerKnowledgeEnrichRetryTool(s)
	registerKnowledgeEnrichHumanReviewTool(s)
	registerKBDiffAppsTool(s)
	// Phase G drift detection.
	registerKbDriftCheckTool(s)
	registerKbDriftBaselineTool(s)
	registerKbDriftHistoryTool(s)
}

type kbStatsInput struct {
	// DB is accepted-and-ignored for backward compatibility. The DSN is
	// now owned by the supervisor (Phase B1 thin-client refactor).
	DB  string `json:"db,omitempty"  jsonschema:"DEPRECATED: ignored. The supervisor owns the DSN."`
	App string `json:"app,omitempty" jsonschema:"optional app kb_id filter"`
}

type kbDumpInput struct {
	DB string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored. The supervisor owns the DSN."`
	ID int    `json:"id" jsonschema:"module id from a search result"`
}

type kbFactsInput struct {
	DB       string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored. The supervisor owns the DSN."`
	App      string `json:"app,omitempty"`
	Category string `json:"category,omitempty"`
}

type kbGapsInput = kbFactsInput

// supervisorUnavailableResult maps ErrSupervisorUnavailable to a friendly
// MCP error result. Returns nil if err is not an unavailable-class error
// (caller falls through to other mappings).
func supervisorUnavailableResult(err error) *mcp.CallToolResult {
	if errors.Is(err, ErrSupervisorUnavailable) {
		return errorResult(fmt.Errorf("daemon unavailable; check `unravel daemon serve`: %w", err))
	}
	return nil
}

func handleKBStats(ctx context.Context, _ *mcp.CallToolRequest, in kbStatsInput) (*mcp.CallToolResult, any, error) {
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}
	out, err := cli.Stats(ctx, in.App)
	if err != nil {
		return errorResult(err), nil, nil
	}
	if out == nil || len(out.Counts) == 0 {
		text, structured := emptyResultDiagnostic(ResolvedInfo{}, "knowledge_sources")
		return jsonResultWithText(structured, text), nil, nil
	}
	return jsonResult(out.Counts), nil, nil
}

func handleKBDump(ctx context.Context, _ *mcp.CallToolRequest, in kbDumpInput) (*mcp.CallToolResult, any, error) {
	if in.ID == 0 {
		return errorResult(fmt.Errorf("id is required")), nil, nil
	}
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}
	out, err := cli.Dump(ctx, in.ID)
	if err != nil {
		// kb.dump maps sql.ErrNoRows → ipc.CodeNotFound on the wire, which
		// the kb client translates via translateKBErr / translateErr. The
		// thin-client client.Dump returns the not-found sentinel-wrapped
		// error; surface it as an honest-empty diagnostic like the legacy
		// direct-DB path did.
		if errors.Is(err, sql.ErrNoRows) || isNotFoundErr(err) {
			text, structured := emptyResultDiagnostic(ResolvedInfo{}, fmt.Sprintf("module id %d", in.ID))
			return jsonResultWithText(structured, text), nil, nil
		}
		return errorResult(err), nil, nil
	}
	if out == nil || out.Row == nil {
		text, structured := emptyResultDiagnostic(ResolvedInfo{}, fmt.Sprintf("module id %d", in.ID))
		return jsonResultWithText(structured, text), nil, nil
	}
	return jsonResult(out.Row), nil, nil
}

// isNotFoundErr returns true when err carries the IPC CodeNotFound sentinel
// (set by the supervisor for missing-row paths). The KB client wraps these
// using translateKBErr → translateErr, which preserves the *ipc.ErrorBody
// in the chain via errors.As.
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	var eb *ipc.ErrorBody
	if errors.As(err, &eb) {
		return eb.Code == ipc.CodeNotFound
	}
	return false
}

func handleKBFacts(ctx context.Context, _ *mcp.CallToolRequest, in kbFactsInput) (*mcp.CallToolResult, any, error) {
	return queryFacts(ctx, in, false)
}

func handleKBGaps(ctx context.Context, _ *mcp.CallToolRequest, in kbGapsInput) (*mcp.CallToolResult, any, error) {
	return queryFacts(ctx, in, true)
}

func queryFacts(ctx context.Context, in kbFactsInput, gapsOnly bool) (*mcp.CallToolResult, any, error) {
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}

	params := supervisor.KBFactsParams{App: in.App, Category: in.Category}
	var rows []kbFactRow
	if gapsOnly {
		out, gerr := cli.Gaps(ctx, params)
		if gerr != nil {
			return errorResult(gerr), nil, nil
		}
		if out != nil {
			for _, r := range out.Gaps {
				rows = append(rows, factRowFromStore(r))
			}
		}
	} else {
		out, gerr := cli.Facts(ctx, params)
		if gerr != nil {
			return errorResult(gerr), nil, nil
		}
		if out != nil {
			for _, r := range out.Facts {
				rows = append(rows, factRowFromStore(r))
			}
		}
	}

	// Honest-empty diagnostic mirrors the legacy direct-DB path. The
	// populated_categories signal is now best-effort: in this thin-client
	// surface we don't have a dedicated supervisor verb for it, so we
	// pass nil (marshals as null) to keep the wire shape stable.
	layerStatus := "populated"
	if len(rows) == 0 {
		layerStatus = "empty"
	}
	if len(rows) == 0 {
		text, structured := emptyResultDiagnostic(ResolvedInfo{}, "facts")
		structured["layer_status"] = layerStatus
		structured["populated_categories"] = nil
		banner := "no facts found; app_facts layer is empty for this filter (run enrichment to populate)"
		return jsonResultWithText(structured, banner+"\n"+text), nil, nil
	}
	payload := map[string]any{
		"rows":                 rows,
		"returned":             len(rows),
		"layer_status":         layerStatus,
		"populated_categories": nil,
	}
	return jsonResult(payload), nil, nil
}

// kbFactRow is the wire shape for fact rows; identical to kbstore.FactRow
// since supervisor.KBFactsResult.Facts is []kbstore.FactRow directly.
type kbFactRow = kbstore.FactRow

func factRowFromStore(r kbstore.FactRow) kbFactRow { return r }

// factsPopulatedCategories is preserved as a nil-safe stub. The legacy
// direct-DB implementation queried distinct categories from app_facts to
// surface "what IS present" alongside an honest-empty result. The
// thin-client port (Phase B1) routes facts/gaps through the supervisor
// which does not expose a per-category populated list — callers now read
// populated_categories as nil on empty results. The helper is retained
// for the existing unit test (TestFactsPopulatedCategoriesNilDB) and as
// a future seam if the supervisor grows the verb. Always returns nil
// today; safe to pass nil *sql.DB.
func factsPopulatedCategories(db *sql.DB, _ string, _ bool) []string {
	_ = db
	return nil
}

func handleKnowledge(_ context.Context, _ *mcp.CallToolRequest, input knowledgeInput) (*mcp.CallToolResult, any, error) {
	opts := knowledge.Options{
		OutputDir:            input.OutputDir,
		Enrich:               input.Enrich,
		EnrichIncludePrivate: input.EnrichIncludePrivate,
	}
	if input.JSON {
		opts.OutputDir = ""
	}

	result, err := knowledge.Run(input.Path, opts)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}

func handleKnowledgeDiff(_ context.Context, _ *mcp.CallToolRequest, input knowledgeDiffInput) (*mcp.CallToolResult, any, error) {
	result, err := knowledge.Diff(input.OldDir, input.NewDir)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
