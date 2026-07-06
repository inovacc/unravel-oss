/*
Copyright (c) 2026 Security Research

ai.go — optional --ai second-opinion hook (D-12 default-cheap; opt-in).

Per RESEARCH OQ5: SKIP structural-preservation guard here — the AI is
producing classifications, not source content. We DO bound the prompt
size (T-07-06).
*/
package regressions

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
)

// maxAIInputBytes bounds the diff JSON forwarded to the MCP client (T-07-06).
const maxAIInputBytes = 64 * 1024

// MCPClient is a minimal interface implemented by an MCP-tool wrapper.
// The package owns the interface so callers can plug in either a real MCP
// transport or a test stub.
type MCPClient interface {
	Classify(ctx context.Context, diffJSON []byte) ([]Regression, error)
}

// AISecondOpinion forwards the diff to mcp and tags the returned
// regressions with Source="ai". When mcp is nil it returns nil (D-12).
func AISecondOpinion(ctx context.Context, snap Snapshot, current []Regression, mcp MCPClient) []Regression {
	if mcp == nil {
		return nil
	}
	payload := struct {
		Snapshot    Snapshot     `json:"snapshot"`
		Regressions []Regression `json:"regressions"`
	}{Snapshot: snap, Regressions: current}

	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("regressions.ai: marshal failed", "err", err)
		return nil
	}
	if len(data) > maxAIInputBytes {
		// T-07-06: truncate to top-N regressions by severity.
		trimmed := truncatePayload(payload)
		data, err = json.Marshal(trimmed)
		if err != nil {
			slog.Warn("regressions.ai: trim marshal failed", "err", err)
			return nil
		}
	}

	out, err := mcp.Classify(ctx, data)
	if err != nil {
		slog.Warn("regressions.ai: mcp client returned error", "err", err)
		return nil
	}
	for i := range out {
		out[i].Source = SourceAI
	}
	return out
}

// truncatePayload trims to the top regressions by severity rank
// (BLOCK > FLAG > PASS) and drops the snapshot to fit the budget.
func truncatePayload(p struct {
	Snapshot    Snapshot     `json:"snapshot"`
	Regressions []Regression `json:"regressions"`
}) any {
	regs := append([]Regression(nil), p.Regressions...)
	sort.SliceStable(regs, func(i, j int) bool {
		return severityRank(regs[i].Severity) < severityRank(regs[j].Severity)
	})
	if len(regs) > 32 {
		regs = regs[:32]
	}
	return struct {
		Regressions []Regression `json:"regressions"`
		Truncated   bool         `json:"truncated"`
	}{Regressions: regs, Truncated: true}
}

func severityRank(s string) int {
	switch s {
	case SeverityBlock:
		return 0
	case SeverityFlag:
		return 1
	case SeverityPass:
		return 2
	}
	return 3
}
