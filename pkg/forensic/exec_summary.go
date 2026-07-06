/*
Copyright (c) 2026 Security Research

Phase 10 / RPT-04: Executive-summary delegation path. This file implements
the prompt builder, JSON parser, and sha256+modelID-keyed cache used by the
forensic report's MCP-generated executive summary section.

The shared types (ExecSummary, TopRisk, MCPClient) live in
pkg/forensic/exec_summary_types.go (Wave 0). They are NOT redeclared here.

CLI flag wiring (--ai) and the actual MCP round-trip site land in 10-03;
this plan provides only the building blocks and is opt-in (D-25).
*/
package forensic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"text/template"

	aicache "github.com/inovacc/unravel-oss/internal/ai/cache"
	"github.com/inovacc/unravel-oss/internal/ai/prompts"
)

// Sentinel constants (D-15) — re-declared locally per CONTEXT D-15
// guidance (no cross-package coupling for two short string constants).
const (
	UserFindingsBegin = "<<<USER_FINDINGS_BEGIN>>>"
	UserFindingsEnd   = "<<<USER_FINDINGS_END>>>"
)

// cacheNamespace is the on-disk subdir under store.CacheDir() (D-26).
const cacheNamespace = "forensic-summary"

// FindingsInput is the bounded payload that goes between sentinels (D-12).
// Exported so tests can construct fixtures directly.
type FindingsInput struct {
	RiskCounts  map[string]int `json:"risk_counts"`
	TopFindings []FindingSlim  `json:"top_findings"`
}

// FindingSlim is the minimum projection of a Finding sent to the LLM.
type FindingSlim struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	CWE      int    `json:"cwe,omitempty"`
	Title    string `json:"title"`
}

// normalizeSeverity collapses the Finding.Severity values that exist today
// (info/low/medium/high/critical) onto the BLOCK/FLAG/PASS bucket required
// by D-13. critical+high → BLOCK, medium → FLAG, low+info → PASS. Unknown
// values fall through to PASS so the LLM never sees an unexpected token.
func normalizeSeverity(s string) string {
	switch s {
	case "BLOCK", "FLAG", "PASS":
		return s
	case "critical", "high":
		return "BLOCK"
	case "medium":
		return "FLAG"
	default:
		return "PASS"
	}
}

// severityRank orders BLOCK < FLAG < PASS for top-N selection (D-12).
func severityRank(s string) int {
	switch s {
	case "BLOCK":
		return 0
	case "FLAG":
		return 1
	default:
		return 2
	}
}

// BuildFindingsInput extracts the bounded D-12 payload from a Report:
// risk_counts (BLOCK/FLAG/PASS totals) + top 5 findings sorted by severity
// then type alphabetical (ties broken by Title to keep determinism).
func BuildFindingsInput(r *Report) FindingsInput {
	out := FindingsInput{RiskCounts: map[string]int{"block": 0, "flag": 0, "pass": 0}}
	if r == nil {
		return out
	}
	slim := make([]FindingSlim, 0, len(r.Findings))
	for _, f := range r.Findings {
		sev := normalizeSeverity(f.Severity)
		switch sev {
		case "BLOCK":
			out.RiskCounts["block"]++
		case "FLAG":
			out.RiskCounts["flag"]++
		default:
			out.RiskCounts["pass"]++
		}
		// CWE mapping is owned by 10-01 (cwe_map.go); when absent we omit
		// the field via zero-value + omitempty in the JSON tag.
		slim = append(slim, FindingSlim{
			Type:     f.Category,
			Severity: sev,
			Title:    f.Title,
		})
	}
	sort.SliceStable(slim, func(i, j int) bool {
		if severityRank(slim[i].Severity) != severityRank(slim[j].Severity) {
			return severityRank(slim[i].Severity) < severityRank(slim[j].Severity)
		}
		if slim[i].Type != slim[j].Type {
			return slim[i].Type < slim[j].Type
		}
		return slim[i].Title < slim[j].Title
	})
	if len(slim) > 5 {
		slim = slim[:5]
	}
	out.TopFindings = slim
	return out
}

// BuildPrompt renders the executive-summary prompt body with sentinel-bounded
// findings JSON (D-15). The sentinel literals are emitted by the embedded
// prompt template; this function only injects {{.Findings}}.
func BuildPrompt(r *Report) (string, error) {
	payload := BuildFindingsInput(r)
	findingsJSON, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal findings: %w", err)
	}
	// text/template here — html/template would over-escape JSON braces.
	tmpl, err := template.New("exec-summary").Parse(prompts.ExecutiveSummaryPrompt())
	if err != nil {
		return "", fmt.Errorf("parse prompt template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ Findings string }{string(findingsJSON)}); err != nil {
		return "", fmt.Errorf("execute prompt template: %w", err)
	}
	return buf.String(), nil
}

// FindingsJSON returns the canonical (indent-stable) JSON representation of
// the bounded findings payload. Exposed so cache-key callers don't have to
// re-do the marshal.
func FindingsJSON(r *Report) ([]byte, error) {
	return json.MarshalIndent(BuildFindingsInput(r), "", "  ")
}

// ParseMCPResponse decodes the structured JSON output from the MCP delegation
// response (D-13). defer/recover guards against panics in malformed input
// (D-27). Soft-truncates oversize TopRisks/RemediationPriorities to D-14 caps.
func ParseMCPResponse(raw []byte) (out ExecSummary, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("parse mcp response panic: %v", rec)
		}
	}()
	if uerr := json.Unmarshal(raw, &out); uerr != nil {
		return ExecSummary{}, fmt.Errorf("unmarshal exec summary: %w", uerr)
	}
	if len(out.TopRisks) > 5 {
		out.TopRisks = out.TopRisks[:5]
	}
	if len(out.RemediationPriorities) > 5 {
		out.RemediationPriorities = out.RemediationPriorities[:5]
	}
	return out, nil
}

// ComputeCacheKey hashes the canonical findings JSON + modelID (D-26).
// Delegates to pkg/ai/cache.Key (Phase 11 D-08); byte-identical to the
// pre-lift implementation per pkg/ai/cache/golden_test.go vectors.
func ComputeCacheKey(findingsJSON []byte, modelID string) string {
	return aicache.Key(string(findingsJSON), modelID)
}

// CacheLookup returns the cached ExecSummary if present. Any I/O or decode
// error is treated as a miss (best-effort cache).
func CacheLookup(key string) (ExecSummary, bool) {
	body, ok := aicache.Get(cacheNamespace, key+".summary.json")
	if !ok {
		return ExecSummary{}, false
	}
	var s ExecSummary
	if err := json.Unmarshal(body, &s); err != nil {
		return ExecSummary{}, false
	}
	return s, true
}

// CacheStore writes the ExecSummary atomically (delegated to pkg/ai/cache.Put).
func CacheStore(key string, s ExecSummary) error {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	return aicache.Put(cacheNamespace, key+".summary.json", body)
}
