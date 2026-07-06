/*
Copyright (c) 2026 Security Research
*/
// Package kbenrich provides EnrichCore — the pure-logic KB enrichment engine
// shared by the `unravel knowledge enrich` CLI command and the
// unravel_knowledge_enrich MCP tool.
//
// Extracting the engine here breaks the circular import that would result from
// pkg/mcptools importing cmd (cmd already imports pkg/mcptools for the MCP
// server). Both cmd and pkg/mcptools import kbenrich instead.
//
// D-09 invariant: the AI seam is the CallFn parameter — callers pass
// kbllm.Call (or a test fake). No direct anthropic SDK imports here.
package kbenrich

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"

	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
)

// CallFn is the AI seam type: callers pass kbllm.Call or a test fake.
type CallFn func(ctx context.Context, model, prompt string, timeout time.Duration) (string, error)

// Opts carries every knob for EnrichCore. Zero values trigger Phase A
// winning-recipe defaults (sonnet model, concurrent=8, prompt-batch=10, limit=100).
// Note: Phase A measurement (docs/KB-CONSUMPTION-CALIBRATION.md) found Haiku 4.5
// fastest at 44.4 mod/min; Sonnet 4.6 is the quality default — pass --model haiku
// for the speed-optimised recipe.
type Opts struct {
	App          string // filter by app (empty = all)
	Limit        int    // max modules to enrich (0 → 100)
	Concurrent   int    // parallel claude invocations (0 → 8)
	Model        string // claude model alias (empty → "sonnet"; only "sonnet"/"haiku" accepted)
	BoundedInput bool   // send symbols + 2KB body head instead of full body
	PromptBatch  int    // wrap N modules into one claude call (0 → 1)
	Force        bool   // re-enrich already-summarised modules
	NamedOnly    bool   // only semantic-named modules
	TimeoutSec   int    // per-module claude timeout in seconds (0 → 90)

	// Monitor knobs (additive — zero values preserve historical behaviour).
	MonitorDisabled   bool          // opt-out switch (tests / dry-runs)
	HeartbeatInterval time.Duration // 0 → 30s default when Monitor enabled
	StaleAfter        time.Duration // 0 → 10min default; also used by sweeper
	ResumeRunID       string        // explicit resume; empty → auto-detect
	ForceNewRun       bool          // bypass resume detection
	ParentRunID       string        // set by retry tool — recorded on the new run
	ModuleIDs         []int64       // when set, EnrichCore restricts to these ids (retry path)
	NoDrift           bool          // skip Phase G drift detection at end of run (default: run it)
}

// Summary is the structured result returned by EnrichCore.
type Summary struct {
	Enriched       int     `json:"enriched"`
	Failed         int     `json:"failed"`
	Skipped        int     `json:"skipped"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	ModulesPerMin  float64 `json:"modules_per_min"`
	ModelUsed      string  `json:"model_used"`

	// Monitor metadata (additive — empty / zero when MonitorDisabled).
	RunID       string `json:"run_id,omitempty"`
	Resumed     bool   `json:"resumed,omitempty"`
	Interrupted int    `json:"interrupted,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL helpers
// ─────────────────────────────────────────────────────────────────────────────

// SemanticNameSQL is the Postgres predicate that keeps only semantic-named
// modules: excludes stripped Teams IDs and bare hashes, requires a letter
// and length >= 3.
const SemanticNameSQL = "(m.name !~ '^teams_module_[0-9]+$' " +
	"AND m.name !~ '^[0-9a-fA-F]{8,}$' " +
	"AND m.name ~ '[A-Za-z]' " +
	"AND length(m.name) >= 3)"

// EligibleNameSQL admits a module for --named-only enrichment when its name is
// semantic OR a pure-Go synthetic_name was backfilled (sub-project vii).
const EligibleNameSQL = "((" + SemanticNameSQL +
	") OR (m.synthetic_name IS NOT NULL AND m.synthetic_name <> ''))"

// ─────────────────────────────────────────────────────────────────────────────
// Internal types
// ─────────────────────────────────────────────────────────────────────────────

type pendingRow struct {
	id          int
	app         string
	name        string
	body        string
	sha256      string
	symbolsJSON string
}

type enrichResult struct {
	Summary     string          `json:"summary"`
	LongSummary string          `json:"long_summary"`
	Role        string          `json:"role"`
	Inputs      json.RawMessage `json:"inputs"`
	Outputs     json.RawMessage `json:"outputs"`
	SideEffects []string        `json:"side_effects"`
	Deps        []string        `json:"deps"`
	Tags        []string        `json:"tags"`
}

type batchEntry struct {
	ID          int             `json:"id"`
	Summary     string          `json:"summary"`
	LongSummary string          `json:"long_summary"`
	Role        string          `json:"role"`
	Inputs      json.RawMessage `json:"inputs"`
	Outputs     json.RawMessage `json:"outputs"`
	SideEffects []string        `json:"side_effects"`
	Deps        []string        `json:"deps"`
	Tags        []string        `json:"tags"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Prompt templates (mirrors cmd/knowledge_kb_enrich.go)
// ─────────────────────────────────────────────────────────────────────────────

const kbEnrichPrompt = `You are reverse-engineering a single minified JS module from a desktop app
bundle. Translate it into structured natural-language analysis a clean-room
re-implementer can use without ever reading the original source.

Respond with a SINGLE JSON object — no prose before or after, no markdown
code-fence. Use exactly these fields:

{
  "summary":      "<one sentence, < 200 chars, plain English: what does this module do>",
  "long_summary": "<3-6 sentence description; cover purpose, mechanism, and why a caller would use it>",
  "role":         "<one of: send | receive | auth | pair | storage | sync | protocol | crypto | media | presence | call | ui | telemetry | util | other>",
  "inputs":       [{"name":"...", "type":"...", "required":true|false, "description":"..."}],
  "outputs":      [{"name":"...", "type":"...", "description":"..."}],
  "side_effects": ["<string>", "..."],
  "deps":         ["<other module name>", "..."],
  "tags":         ["<short tag>", "..."]
}

Rules:
- If a field truly has no entries, return an empty array.
- Use the actual minified identifiers you see (e.g. "addAndSendMsgToChat") rather than guessing canonical names.
- "deps" lists other module names the body resolves via require()/import.
- long_summary MUST quote VERBATIM every load-bearing literal: exact IPC/event/channel/message names, string keys, opcodes, regex sources, numeric thresholds/timeouts/limits, config defaults — copy them character-for-character, never paraphrase or round.
- inputs/outputs MUST list every exported/public symbol with its real name and full signature (encode params in the type, e.g. "(env: Envelope, opts?: SendOpts) => Promise<Ack>"); set required=false for optional/defaulted params.
- side_effects MUST name the exact channel/event/topic/storage key touched (e.g. "fires 'chat-event:new'", "writes LevelDB key 'conv:'+id"), never a generic phrase.
- long_summary MUST state error/edge behavior: what it throws/rejects, the guard conditions, and the empty/edge-case path.
- Concrete beats canonical: a hardcoded value you actually see wins over any inferred name.
- Output MUST be valid JSON. Anything after the closing brace will be ignored.

App: %s
Module: %s
Body excerpt (up to 16 KB):
%s
`

const kbEnrichBatchPromptHeader = `You are reverse-engineering minified JS modules from a desktop app bundle.
For EACH module below, produce a structured natural-language analysis.

Respond with a SINGLE JSON array — one element per module, no prose,
no markdown fences. Each element MUST include the input "id" field plus:

{
  "id":          <integer — MUST match the input id>,
  "summary":      "<one sentence, <200 chars>",
  "long_summary": "<3-6 sentences: purpose, mechanism, caller value>",
  "role":         "<send|receive|auth|pair|storage|sync|protocol|crypto|media|presence|call|ui|telemetry|util|other>",
  "inputs":       [{"name":"...","type":"...","required":true|false,"description":"..."}],
  "outputs":      [{"name":"...","type":"...","description":"..."}],
  "side_effects": ["<string>",...],
  "deps":         ["<module name>",...],
  "tags":         ["<tag>",...]
}

Rules:
- If a field has no entries, return an empty array.
- long_summary MUST quote VERBATIM every load-bearing literal: exact IPC/event/channel/message names, string keys, opcodes, regex sources, numeric thresholds/timeouts/limits, config defaults — never paraphrase or round.
- inputs/outputs MUST list every exported/public symbol with its real name and full signature (params encoded in the type); required=false for optional/defaulted params.
- side_effects MUST name the exact channel/event/topic/storage key touched, never a generic phrase.
- long_summary MUST state error/edge behavior: what it throws/rejects, the guard conditions, and the empty/edge-case path.
- Concrete beats canonical: a hardcoded value you actually see wins over any inferred name.
- Output MUST be a valid JSON array. Anything after the closing ] is ignored.
- Every input id MUST appear exactly once in the output array.

`

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func buildEnrichBody(body, symbolsJSON string, bounded bool) string {
	if !bounded {
		return body
	}
	head := body
	if len(head) > 8192 {
		head = head[:8192]
	}
	return "symbols: " + symbolsJSON + "\nbody:\n" + head
}

func buildPromptBatch(rows []pendingRow, bounded bool) string {
	var sb strings.Builder
	sb.WriteString(kbEnrichBatchPromptHeader)
	for i, r := range rows {
		bodySection := buildEnrichBody(r.body, r.symbolsJSON, bounded)
		fmt.Fprintf(&sb, "--- Module %d of %d ---\nApp: %s\nID: %d\nName: %s\nBody:\n%s\n\n",
			i+1, len(rows), r.app, r.id, r.name, bodySection)
	}
	return sb.String()
}

func parseEnrichJSON(raw string) (*enrichResult, error) {
	// Strip leading prose / fences before the first '{'.
	start := strings.Index(raw, "{")
	if start >= 0 {
		raw = raw[start:]
	}
	end := strings.LastIndex(raw, "}")
	if end >= 0 {
		raw = raw[:end+1]
	}
	var r enrichResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	if r.Summary == "" {
		return nil, fmt.Errorf("response missing 'summary' field")
	}
	return &r, nil
}

func parsePromptBatchJSON(raw string, ids []int) (map[int]*enrichResult, error) {
	start := strings.Index(raw, "[")
	if start < 0 {
		return nil, fmt.Errorf("batch response: no JSON array found")
	}
	raw = raw[start:]
	end := strings.LastIndex(raw, "]")
	if end < 0 {
		return nil, fmt.Errorf("batch response: no closing ] found")
	}
	raw = raw[:end+1]

	var entries []batchEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("batch unmarshal: %w", err)
	}

	out := make(map[int]*enrichResult, len(entries))
	for i := range entries {
		e := &entries[i]
		out[e.ID] = &enrichResult{
			Summary:     e.Summary,
			LongSummary: e.LongSummary,
			Role:        e.Role,
			Inputs:      e.Inputs,
			Outputs:     e.Outputs,
			SideEffects: e.SideEffects,
			Deps:        e.Deps,
			Tags:        e.Tags,
		}
	}
	for _, id := range ids {
		if _, ok := out[id]; !ok {
			return nil, fmt.Errorf("batch response missing id %d (got %d/%d entries)", id, len(entries), len(ids))
		}
	}
	return out, nil
}

func progressEvery(done, every, total int) bool {
	if every <= 0 {
		every = 25
	}
	return done == total || done%every == 0
}

func writeEnrichment(ctx context.Context, db *sql.DB, moduleID int, app, sha256, raw, model string, res *enrichResult) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	tagsCSV := strings.Join(res.Tags, ",")
	if _, err := tx.ExecContext(ctx,
		`UPDATE modules SET summary = $1, tags = $2 WHERE id = $3`,
		res.Summary, tagsCSV, moduleID,
	); err != nil {
		return fmt.Errorf("update modules: %w", err)
	}

	seJSON, _ := json.Marshal(res.SideEffects)
	depsJSON, _ := json.Marshal(res.Deps)
	if _, err := tx.ExecContext(ctx, `INSERT INTO module_enrichment
		(module_id, long_summary, role, inputs_json, outputs_json, side_effects, deps_json, raw_response, model, body_sha256, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT(module_id) DO UPDATE SET
			long_summary = excluded.long_summary,
			role         = excluded.role,
			inputs_json  = excluded.inputs_json,
			outputs_json = excluded.outputs_json,
			side_effects = excluded.side_effects,
			deps_json    = excluded.deps_json,
			raw_response = excluded.raw_response,
			model        = excluded.model,
			body_sha256  = excluded.body_sha256,
			created_at   = excluded.created_at`,
		moduleID, res.LongSummary, res.Role,
		string(res.Inputs), string(res.Outputs),
		string(seJSON), string(depsJSON),
		raw, model, sha256, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("upsert enrichment: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM module_deps WHERE from_id = $1`, moduleID); err != nil {
		return fmt.Errorf("delete deps: %w", err)
	}

	// Collapse 2N round trips to 2: one ANY-array name resolve + one
	// multi-VALUES insert. Cuts write_enrichment p90 from ~500ms toward
	// ~150ms on modules with 5+ deps (KBC-WRITE-ENRICH-DEP-BATCH).
	nonEmpty := make([]string, 0, len(res.Deps))
	seen := make(map[string]struct{}, len(res.Deps))
	for _, dep := range res.Deps {
		if dep == "" {
			continue
		}
		if _, dup := seen[dep]; dup {
			continue
		}
		seen[dep] = struct{}{}
		nonEmpty = append(nonEmpty, dep)
	}
	if len(nonEmpty) > 0 {
		nameToID := make(map[string]int64, len(nonEmpty))
		rows, err := tx.QueryContext(ctx,
			`SELECT name, id FROM modules WHERE app = $1 AND name = ANY($2::text[])`,
			app, pq.Array(nonEmpty),
		)
		if err != nil {
			return fmt.Errorf("resolve dep names: %w", err)
		}
		for rows.Next() {
			var n string
			var id int64
			if err := rows.Scan(&n, &id); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan dep row: %w", err)
			}
			nameToID[n] = id
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("iter dep rows: %w", err)
		}
		_ = rows.Close()

		var sb strings.Builder
		sb.WriteString(`INSERT INTO module_deps (from_id, to_name, to_id) VALUES `)
		args := []any{moduleID}
		ph := 2
		for i, dep := range nonEmpty {
			if i > 0 {
				sb.WriteString(",")
			}
			if id, ok := nameToID[dep]; ok {
				fmt.Fprintf(&sb, "($1, $%d, $%d)", ph, ph+1)
				args = append(args, dep, id)
				ph += 2
			} else {
				fmt.Fprintf(&sb, "($1, $%d, NULL)", ph)
				args = append(args, dep)
				ph++
			}
		}
		sb.WriteString(` ON CONFLICT (from_id, to_name) DO NOTHING`)
		if _, err := tx.ExecContext(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("insert deps batch (%d): %w", len(nonEmpty), err)
		}
	}

	// T1.4 (KB-OVERSEG P1) cross-app dedup fan-out: body_sha256 is UNIQUE per
	// app (migration 000001), so identical bodies only ever appear as siblings
	// under DIFFERENT apps (e.g. WhatsApp + Teams bundling the same minified
	// vendor chunk). Propagate this enrichment to every STILL-PENDING sibling
	// sharing the same NON-EMPTY body hash, so each distinct body is enriched
	// once and all N clear from pending. Safe because: only empty (summary IS
	// NULL), non-human-flagged rows are touched, and identical bytes ⇒
	// identical behaviour. Opt out with UNRAVEL_ENRICH_NO_CROSS_APP_PROPAGATE.
	// Order matters: fill module_enrichment for siblings (gated summary IS
	// NULL) BEFORE the modules.summary UPDATE, else step 1 would clear the
	// summary-IS-NULL set step 2 needs.
	if sha256 != "" && !crossAppPropagationDisabled() {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO module_enrichment
			  (module_id, long_summary, role, inputs_json, outputs_json, side_effects, deps_json, raw_response, model, body_sha256, created_at)
			SELECT s.id, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
			  FROM modules s
			 WHERE s.body_sha256 = $11
			   AND s.body_sha256 <> ''
			   AND s.id <> $12
			   AND s.summary IS NULL
			   AND s.needs_human_verification = false
			ON CONFLICT(module_id) DO UPDATE SET
			   long_summary = excluded.long_summary,
			   role         = excluded.role,
			   inputs_json  = excluded.inputs_json,
			   outputs_json = excluded.outputs_json,
			   side_effects = excluded.side_effects,
			   deps_json    = excluded.deps_json,
			   raw_response = excluded.raw_response,
			   model        = excluded.model,
			   body_sha256  = excluded.body_sha256,
			   created_at   = excluded.created_at`,
			res.LongSummary, res.Role, string(res.Inputs), string(res.Outputs),
			string(seJSON), string(depsJSON), raw, model, sha256, time.Now().Unix(),
			sha256, moduleID,
		); err != nil {
			return fmt.Errorf("propagate enrichment to siblings: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE modules
			   SET summary = $1, tags = $2
			 WHERE body_sha256 = $3
			   AND body_sha256 <> ''
			   AND summary IS NULL
			   AND needs_human_verification = false
			   AND id <> $4`,
			res.Summary, tagsCSV, sha256, moduleID,
		); err != nil {
			return fmt.Errorf("propagate summary to siblings: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// crossAppPropagationDisabled reports whether the operator opted OUT of T1.4
// cross-app dedup fan-out via UNRAVEL_ENRICH_NO_CROSS_APP_PROPAGATE. Default
// is propagation ON (the only configuration in which T1.4 does anything, since
// same-body siblings are always cross-app).
func crossAppPropagationDisabled() bool {
	switch os.Getenv("UNRAVEL_ENRICH_NO_CROSS_APP_PROPAGATE") {
	case "1", "true", "yes", "TRUE", "YES":
		return true
	default:
		return false
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// EnrichCore — the shared engine
// ─────────────────────────────────────────────────────────────────────────────

// EnrichCore runs the enrich worker pool against db using opts. callFn is the
// AI seam — pass kbllm.Call from production callers and a fake from tests.
// All behaviour is governed by opts; no cobra flag globals are read.
//
// Progress is written to stderr via slog (stdout is reserved for output data).
func EnrichCore(ctx context.Context, db *sql.DB, opts Opts, callFn CallFn) (Summary, error) {
	start := time.Now()

	// Apply Phase A winning-recipe defaults.
	if opts.Concurrent < 1 {
		opts.Concurrent = 8
	}
	if opts.Model == "" {
		opts.Model = "sonnet"
	}
	// Enrichment supports only Haiku 4.5 and Sonnet 4.6 (the two models measured
	// in docs/KB-CONSUMPTION-CALIBRATION.md Phase A). Opus and others are
	// rejected: cost/throughput unjustified vs measured Haiku quality.
	if opts.Model != "haiku" && opts.Model != "sonnet" {
		return Summary{}, fmt.Errorf("enrich model %q not supported: must be 'haiku' (4.5) or 'sonnet' (4.6)", opts.Model)
	}
	if opts.PromptBatch < 1 {
		opts.PromptBatch = 1
	}
	if opts.TimeoutSec < 1 {
		opts.TimeoutSec = 90
	}
	if opts.Limit < 1 {
		opts.Limit = 100
	}

	// Build candidate query — mirrors cmd/knowledge_kb_enrich.go runKBEnrich.
	q := `SELECT m.id, m.app, m.name, m.body_excerpt, m.body_sha256, COALESCE(m.symbols_json, '')
	  FROM modules m
	  LEFT JOIN module_enrichment e ON e.module_id = m.id`
	var conds []string
	var args []any
	ph := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if !opts.Force {
		conds = append(conds, "(m.summary IS NULL OR m.summary = '')")
		conds = append(conds, "(e.module_id IS NULL OR e.body_sha256 != m.body_sha256)")
	}
	if opts.App != "" {
		conds = append(conds, "m.app = "+ph(opts.App))
	}
	if opts.NamedOnly {
		conds = append(conds, EligibleNameSQL)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	// Retry path: when ModuleIDs is non-empty, override the pending query
	// to target exactly those ids (skipping the summary-IS-NULL gate so
	// already-summarised modules can be re-tried explicitly).
	if len(opts.ModuleIDs) > 0 {
		// Reset args + use pq.Array so lib/pq binds the []int64 as a
		// typed bigint[] (Postgres cannot infer the data type of a bare
		// $1 parameter — SQLSTATE 42P18).
		args = args[:0]
		q = `SELECT m.id, m.app, m.name, m.body_excerpt, m.body_sha256, COALESCE(m.symbols_json, '')
		       FROM modules m
		      WHERE m.id = ANY(` + ph(pq.Array(opts.ModuleIDs)) + `::bigint[])
		      ORDER BY m.id LIMIT ` + ph(opts.Limit)
	} else {
		q += " ORDER BY m.id LIMIT " + ph(opts.Limit)
	}

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return Summary{}, fmt.Errorf("select pending: %w", err)
	}
	var batch []pendingRow
	for rows.Next() {
		var r pendingRow
		var body, sha, syms sql.NullString
		if err := rows.Scan(&r.id, &r.app, &r.name, &body, &sha, &syms); err != nil {
			_ = rows.Close()
			return Summary{}, fmt.Errorf("scan: %w", err)
		}
		r.body = body.String
		r.sha256 = sha.String
		r.symbolsJSON = syms.String
		batch = append(batch, r)
	}
	_ = rows.Close()

	// Start the monitor before the early-return so that even a zero-pending
	// run leaves a (completed, total_target=0) audit row.
	var mon *Monitor
	if !opts.MonitorDisabled {
		m, mErr := StartMonitor(ctx, db, opts, len(batch))
		if mErr != nil {
			slog.Warn("kbenrich: monitor disabled — start failed", "err", mErr)
		} else {
			mon = m
		}
	}

	if len(batch) == 0 {
		elapsed := time.Since(start).Seconds()
		sum := Summary{ElapsedSeconds: elapsed, ModelUsed: opts.Model}
		if mon != nil {
			sum.RunID = mon.RunID()
			sum.Resumed = mon.Resumed()
			mon.Finalise("completed")
		}
		return sum, nil
	}

	slog.Info("kbenrich start",
		"total", len(batch), "concurrent", opts.Concurrent,
		"model", opts.Model, "timeout_sec", opts.TimeoutSec)

	// Chunk into prompt-batch slices.
	batchSize := opts.PromptBatch
	var chunks [][]pendingRow
	for i := 0; i < len(batch); i += batchSize {
		end := min(i+batchSize, len(batch))
		chunks = append(chunks, batch[i:end])
	}

	type outcome struct {
		row pendingRow
		res *enrichResult
		raw string
		err error
	}
	results := make(chan outcome, len(batch))
	jobs := make(chan []pendingRow, len(chunks))
	for _, c := range chunks {
		jobs <- c
	}
	close(jobs)

	model := opts.Model
	timeoutSec := opts.TimeoutSec
	boundedInput := opts.BoundedInput

	callSingle := func(r pendingRow) outcome {
		bodySection := buildEnrichBody(r.body, r.symbolsJSON, boundedInput)
		prompt := fmt.Sprintf(kbEnrichPrompt, r.app, r.name, bodySection)
		raw, callErr := callFn(ctx, model, prompt, time.Duration(timeoutSec)*time.Second)
		if callErr != nil {
			return outcome{row: r, raw: raw, err: callErr}
		}
		parsed, perr := parseEnrichJSON(raw)
		if perr != nil {
			return outcome{row: r, raw: raw, err: fmt.Errorf("parse: %w", perr)}
		}
		return outcome{row: r, res: parsed, raw: raw}
	}

	// workerPanicked is set when any worker goroutine panics out of the
	// chunk loop (e.g. a misbehaving sampling adapter or callFn).
	// EnrichCore inspects it after the result loop and unwinds via
	// mon.Abort() so the enrich_runs row is left in_progress for the
	// cross-session SweepInterrupted path to flip to 'interrupted'.
	var workerPanicked atomic.Bool

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrent; i++ {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					workerPanicked.Store(true)
					slog.Error("kbenrich worker panicked",
						"panic", fmt.Sprintf("%v", r))
				}
			}()
			for chunk := range jobs {
				if len(chunk) == 1 {
					results <- callSingle(chunk[0])
					continue
				}
				prompt := buildPromptBatch(chunk, boundedInput)
				ids := make([]int, len(chunk))
				for i, r := range chunk {
					ids[i] = r.id
				}
				raw, callErr := callFn(ctx, model, prompt, time.Duration(timeoutSec)*time.Second)
				if callErr != nil {
					slog.Warn("kbenrich batch call failed, falling back to per-module",
						"err", callErr, "batch_size", len(chunk))
					for _, r := range chunk {
						results <- callSingle(r)
					}
					continue
				}
				parsed, perr := parsePromptBatchJSON(raw, ids)
				if perr != nil {
					slog.Warn("kbenrich batch parse failed, falling back to per-module",
						"err", perr, "batch_size", len(chunk))
					for _, r := range chunk {
						results <- callSingle(r)
					}
					continue
				}
				for _, r := range chunk {
					results <- outcome{row: r, res: parsed[r.id], raw: raw}
				}
			}
		})
	}
	go func() { wg.Wait(); close(results) }()

	total := len(batch)
	var ok, fail, done int
	for o := range results {
		done++
		if o.err != nil {
			fail++
			mon.IncFailed()
			mon.RecordAttempt(int64(o.row.id), "failure", classifyErr(o.err), o.err.Error(), model, 1)
			fmt.Fprintf(os.Stderr, "[%d] %s/%s — fail: %v\n", o.row.id, o.row.app, o.row.name, o.err)
			if progressEvery(done, 25, total) {
				slog.Info("kbenrich progress", "app", opts.App, "done", done, "total", total, "failed", fail)
			}
			continue
		}
		if err := writeEnrichment(ctx, db, o.row.id, o.row.app, o.row.sha256, o.raw, model, o.res); err != nil {
			fmt.Fprintf(os.Stderr, "[%d] write enrichment failed: %v\n", o.row.id, err)
			fail++
			mon.IncFailed()
			mon.RecordAttempt(int64(o.row.id), "failure", "db_write", err.Error(), model, 1)
			if progressEvery(done, 25, total) {
				slog.Info("kbenrich progress", "app", opts.App, "done", done, "total", total, "failed", fail)
			}
			continue
		}
		ok++
		mon.IncCompleted()
		mon.RecordAttempt(int64(o.row.id), "success", "", "", model, 1)
		fmt.Fprintf(os.Stderr, "[%d] %s/%s — ok (%s)\n", o.row.id, o.row.app, o.row.name, o.res.Role)
		if progressEvery(done, 25, total) {
			slog.Info("kbenrich progress", "app", opts.App, "done", done, "total", total, "failed", fail)
		}
	}

	elapsed := time.Since(start).Seconds()
	mpm := 0.0
	if elapsed > 0 && ok+fail > 0 {
		mpm = float64(ok+fail) / elapsed * 60
	}

	sum := Summary{
		Enriched:       ok,
		Failed:         fail,
		Skipped:        0,
		ElapsedSeconds: elapsed,
		ModulesPerMin:  mpm,
		ModelUsed:      model,
	}
	if mon != nil {
		sum.RunID = mon.RunID()
		sum.Resumed = mon.Resumed()
		if workerPanicked.Load() {
			// Leave run row in_progress so cross-session SweepInterrupted
			// can flip it to 'interrupted' after StaleAfter elapses.
			sum.Interrupted = 1
			mon.Abort()
			return sum, fmt.Errorf("worker panic during enrich")
		}
		mon.Finalise("completed")
	}
	// Phase G drift detection — non-fatal; errors logged via slog only.
	if !opts.NoDrift {
		runID := sum.RunID
		if runID != "" {
			// sum.RunID is the uuid string from enrich_runs.run_id — pass directly.
			if _, driftErr := drift.Check(ctx, db, runID, drift.DefaultOpts()); driftErr != nil {
				slog.Warn("drift check failed (non-fatal)", "err", driftErr, "run_id", runID)
			}
		}
	}
	return sum, nil
}

// classifyErr maps a raw enrich error into a coarse error_class value used
// by the audit log / retry filter. Best-effort: anything unrecognised falls
// back to "other".
func classifyErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline") || strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "json") || strings.Contains(msg, "unmarshal") || strings.Contains(msg, "parse"):
		return "json_parse"
	case strings.Contains(msg, "prompt") && strings.Contains(msg, "large"):
		return "prompt_too_large"
	case strings.Contains(msg, "5") && strings.Contains(msg, "sampl"):
		return "mcp_sampling_5xx"
	default:
		return "other"
	}
}
