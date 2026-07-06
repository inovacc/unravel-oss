/*
Copyright (c) 2026 Security Research
*/

// Package kbenrich / external.go: exported helpers for callers outside this
// package (notably MCP tools that delegate the LLM call to a Claude Code
// subagent and only need the I/O — pending-row selection + result write-back).
//
// All functions here are thin wrappers around the existing private helpers
// (pendingRow / writeEnrichment / enrichResult) so the unit-tested SQL stays
// the single source of truth.
package kbenrich

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// vendoredLibrarySHAs holds sha256 hashes that PendingModules should skip
// (operator-supplied via UNRAVEL_VENDORED_SHAS, comma-separated hex). These
// modules are typically third-party libraries (React, MobX, Apollo, etc.)
// inlined into the bundle — enriching them via LLM is wasted quota because
// the result is deterministic ("vendored React core", etc.). The plugin
// orchestrator can fall back to a hard-coded summary keyed by sha256.
//
// Loaded once at package init; consumers see a stable set even if the env
// var changes mid-process.
var vendoredLibrarySHAs = func() map[string]bool {
	out := map[string]bool{}
	raw := os.Getenv("UNRAVEL_VENDORED_SHAS")
	if raw == "" {
		return out
	}
	for s := range strings.SplitSeq(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out[strings.ToLower(s)] = true
		}
	}
	return out
}()

// PendingModule is the externally-visible shape of a single row that needs
// enrichment. Mirrors the private pendingRow type but uses exported field
// names so callers can JSON-marshal it directly into an MCP response body.
type PendingModule struct {
	ID          int    `json:"id"`
	App         string `json:"app"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	BodyExcerpt string `json:"body_excerpt"`
	SymbolsJSON string `json:"symbols_json"`
}

// PendingModules returns up to limit modules that have no summary yet,
// optionally filtered by app. namedOnly excludes stripped Teams ids and
// bare hashes (mirrors the eligibleNameSQL clause used by EnrichCore).
// force bypasses the UNRAVEL_VENDORED_SHAS skip list so callers can
// re-enrich vendored libraries explicitly (e.g. the supervisor
// enrich.pending verb with force=true, or an operator running a one-off
// refresh after updating the vendored-summary catalog).
//
// This is the read side of the Understand-Anything-style plugin integration:
// a Claude Code skill fetches these rows, dispatches Task-spawned subagents
// to summarise each one, and writes results back via WriteEnrichmentJSON.
// The Go binary never makes the LLM call itself.
func PendingModules(ctx context.Context, db *sql.DB, app string, limit int, namedOnly, force bool) ([]PendingModule, error) {
	if db == nil {
		return nil, fmt.Errorf("PendingModules: nil db")
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 1000 {
		limit = 1000
	}

	// We hand-roll the WHERE so we don't import the private semanticNameSQL —
	// keep this query intentionally narrow so any drift in the named-only
	// semantics shows up here, not silently. T0.3: the named-only branch must
	// stay at PARITY with the CLI's eligibleNameSQL (enrich.go:90-93) =
	// semantic-name OR backfilled synthetic_name, so `knowledge synth-names`
	// rescues placeholders on the MCP path too (not just the CLI path).
	var (
		args []any
		// KBC-ENRICH-MODEL-ESCALATION: exclude modules already flagged
		// for human verification (migration 000015). These are modules
		// where sonnet AND opus both failed; they will not be re-enqueued
		// by normal enrichment runs. Clear the flag via the
		// unravel_knowledge_enrich_human_review MCP tool's mark_resolved
		// action after a human resolves the underlying issue.
		where = "m.summary IS NULL AND m.needs_human_verification = false"
	)
	// KB-OVERSEG P3 vendored ingest gate: never select MARKed vendored-OSS
	// rows for enrichment so bundled libraries don't burn quota. force=true
	// bypasses the gate (mirrors the UNRAVEL_VENDORED_SHAS skip below) so an
	// operator can deliberately re-enrich vendored libraries.
	if !force {
		where += " AND m.is_vendored = false"
	}
	if app != "" {
		args = append(args, app)
		where += fmt.Sprintf(" AND m.app = $%d", len(args))
	}
	if namedOnly {
		where += ` AND ((m.name !~ '^teams_module_[0-9]+$'` +
			` AND m.name !~ '^[0-9a-fA-F]{8,}$'` +
			` AND m.name ~ '[A-Za-z]'` +
			` AND length(m.name) >= 3)` +
			` OR (m.synthetic_name IS NOT NULL AND m.synthetic_name <> ''))`
	}

	args = append(args, limit)
	// T1.4 (KB-OVERSEG P1): collapse identical bodies to ONE representative so
	// each distinct body is enriched once (siblings inherit via the cross-app
	// propagation in writeEnrichment). The dedup key is NULL/empty-safe: rows
	// with an empty body_sha256 are keyed on their own id ('id:<n>') so they
	// are NEVER collapsed (un-hashed modules are distinct); hashed rows key on
	// 'sha:<hash>' and collapse to the lowest-id representative. The 'sha:'/
	// 'id:' prefixes prevent a stringified id colliding with a hash. LIMIT must
	// apply AFTER dedup, so it moves to the outer query.
	q := fmt.Sprintf(`
		SELECT m.id, m.app, m.name,
		       COALESCE(m.body_sha256, ''),
		       COALESCE(m.body_excerpt, ''),
		       COALESCE(m.symbols_json::text, '{}')
		FROM (
			SELECT DISTINCT ON (
			         CASE WHEN COALESCE(m.body_sha256,'') = ''
			              THEN 'id:' || m.id::text
			              ELSE 'sha:' || m.body_sha256
			         END
			       )
			       m.id, m.app, m.name, m.body_sha256, m.body_excerpt, m.symbols_json
			FROM modules m
			WHERE %s
			ORDER BY
			  (CASE WHEN COALESCE(m.body_sha256,'') = ''
			        THEN 'id:' || m.id::text
			        ELSE 'sha:' || m.body_sha256 END),
			  m.id
		) m
		ORDER BY m.id
		LIMIT $%d`, where, len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query pending modules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []PendingModule
	for rows.Next() {
		var p PendingModule
		if err := rows.Scan(&p.ID, &p.App, &p.Name, &p.SHA256, &p.BodyExcerpt, &p.SymbolsJSON); err != nil {
			return nil, fmt.Errorf("scan pending row: %w", err)
		}
		// Vendored-library skip: callers can mark known third-party hashes
		// via UNRAVEL_VENDORED_SHAS to prevent burning quota on bundled
		// React/MobX/Apollo/etc. (deterministic enrichment lives in the
		// plugin orchestrator, not here). force=true bypasses this skip
		// so an operator can deliberately re-enrich vendored libraries.
		if !force && p.SHA256 != "" && vendoredLibrarySHAs[strings.ToLower(p.SHA256)] {
			continue
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// validRoles is the allow-list for the role field. Mirrors the enum the
// unravel-enricher subagent contract publishes.
var validRoles = map[string]bool{
	"send": true, "receive": true, "auth": true, "pair": true,
	"storage": true, "sync": true, "protocol": true, "crypto": true,
	"media": true, "presence": true, "call": true, "ui": true,
	"telemetry": true, "util": true, "other": true,
	// Deterministic role for vendored-library skip path.
	"vendored-library": true,
}

// WriteEnrichmentJSON persists a single enrichment result. parsedJSON is the
// raw JSON object emitted by the upstream LLM caller (typically a Claude Code
// subagent spawned via the Task tool from the unravel-enrich skill).
//
// Schema-strict: this validator rejects subagent output drift caught during
// the first 50-module scale test where some subagents emitted inputs/outputs
// as bare string arrays instead of arrays of {name,type,...} objects, or
// returned a free-form role not in the enum. We coerce missing role to
// "other" and validate inputs/outputs are either an empty array or an array
// of JSON objects — string-element arrays are rewritten to empty so the
// downstream module_enrichment.inputs_json column stays well-typed.
//
// modelUsed is a free-form string written to module_enrichment.model.
//
// Deprecated: use WriteEnrichmentJSONContext so cancellation/deadline reach
// the write transaction. This shim delegates with context.Background() and
// will be removed after 2026-09-07.
func WriteEnrichmentJSON(db *sql.DB, moduleID int, app, sha256, rawResponse, modelUsed string, parsedJSON []byte) error {
	return WriteEnrichmentJSONContext(context.Background(), db, moduleID, app, sha256, rawResponse, modelUsed, parsedJSON)
}

// WriteEnrichmentJSONContext is WriteEnrichmentJSON with an explicit context
// threaded into the write transaction (hardening finding #2), so a cancelled
// enrich run / supervisor shutdown / deadline can abort a blocked connection
// acquire or a slow write mid-statement instead of pinning the worker.
func WriteEnrichmentJSONContext(ctx context.Context, db *sql.DB, moduleID int, app, sha256, rawResponse, modelUsed string, parsedJSON []byte) error {
	if db == nil {
		return fmt.Errorf("WriteEnrichmentJSON: nil db")
	}
	var res enrichResult
	if err := json.Unmarshal(parsedJSON, &res); err != nil {
		return fmt.Errorf("parse enrichment json: %w", err)
	}
	if res.Summary == "" {
		return fmt.Errorf("enrichment json missing required 'summary' field")
	}
	if res.Role == "" {
		res.Role = "other"
	}
	if !validRoles[res.Role] {
		// Drift: subagent emitted something off-contract. Coerce so we still
		// persist the long_summary etc. — the role facet just becomes "other".
		res.Role = "other"
	}
	res.Inputs = normalizeArrayOfObjects(res.Inputs)
	res.Outputs = normalizeArrayOfObjects(res.Outputs)
	if res.SideEffects == nil {
		res.SideEffects = []string{}
	}
	if res.Deps == nil {
		res.Deps = []string{}
	}
	if res.Tags == nil {
		res.Tags = []string{}
	}
	return writeEnrichment(ctx, db, moduleID, app, sha256, rawResponse, modelUsed, &res)
}

// WriteEnrichmentJSONWithEscalation is WriteEnrichmentJSON + the
// KBC-ENRICH-MODEL-ESCALATION Phase 2 escalation marker UPDATE. Persists
// the enrichment row first, then conditionally updates modules.escalated_to
// and/or modules.needs_human_verification. Both extras are independent —
// a NeedsHumanVerification=true call would typically arrive with a
// placeholder parsedJSON (empty summary, role='unparseable') and the audit
// record (raw_response + attempt history) is still preserved via the
// underlying WriteEnrichmentJSON call.
//
// Extracted from pkg/mcp/tools/kb_pending_enrich.go's handleKBWriteEnrichment
// so the supervisor enrich.write verb can apply the same semantics without
// the MCP tool needing direct DB access (v2.17 thin-client B4).
func WriteEnrichmentJSONWithEscalation(ctx context.Context, db *sql.DB, moduleID int, app, sha256, rawResponse, modelUsed string, parsedJSON []byte, escalatedTo string, needsHumanVerification bool) error {
	if err := WriteEnrichmentJSONContext(ctx, db, moduleID, app, sha256, rawResponse, modelUsed, parsedJSON); err != nil {
		return err
	}
	if escalatedTo == "" && !needsHumanVerification {
		return nil
	}
	args := []any{moduleID}
	set := []string{}
	if escalatedTo != "" {
		if escalatedTo != "opus" {
			return fmt.Errorf("escalated_to must be 'opus' when set (got %q)", escalatedTo)
		}
		args = append(args, escalatedTo)
		set = append(set, fmt.Sprintf("escalated_to = $%d", len(args)))
	}
	if needsHumanVerification {
		set = append(set, "needs_human_verification = true")
	}
	q := "UPDATE modules SET " + joinSetClauses(set) + " WHERE id = $1"
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("escalation update: %w", err)
	}
	return nil
}

// joinSetClauses returns parts joined by ", ". Kept local so callers don't
// pull in strings just for this one site.
func joinSetClauses(parts []string) string {
	var out strings.Builder
	for i, p := range parts {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteString(p)
	}
	return out.String()
}

// normalizeArrayOfObjects accepts a json.RawMessage that's expected to be an
// array of objects, and returns an array-of-objects RawMessage. If the input
// is a string array (subagent drift), empty array, or non-array, returns
// `[]`. Defends downstream consumers from polymorphic input.
func normalizeArrayOfObjects(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("[]")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return json.RawMessage("[]")
	}
	out := make([]json.RawMessage, 0, len(arr))
	for _, el := range arr {
		t := bytes.TrimSpace(el)
		if len(t) == 0 {
			continue
		}
		// Keep only elements that start with `{` (object).
		if t[0] != '{' {
			continue
		}
		out = append(out, el)
	}
	cleaned, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage("[]")
	}
	return cleaned
}
