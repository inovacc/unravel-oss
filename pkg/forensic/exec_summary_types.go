/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"context"
	"errors"
	"html/template"
)

// ExecSummary is the structured output schema for the MCP-generated executive
// summary (D-13). Defined here in Wave 0 so 10-01 (HTML renderer) and 10-02
// (MCP delegation path) can both depend on this single declaration.
type ExecSummary struct {
	TLDR                  string    `json:"tldr"`
	TopRisks              []TopRisk `json:"top_risks"`
	RemediationPriorities []string  `json:"remediation_priorities"`
}

// TopRisk is one entry in ExecSummary.TopRisks (D-13).
type TopRisk struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	CWE      int    `json:"cwe,omitempty"`
}

// RegressionSection is the pre-rendered HTML body of the "Regression Analysis"
// section emitted when --diff-old/--diff-new are passed (D-19). Populated by
// 10-03's regression.go; consumed by 10-01's report.html.tmpl.
type RegressionSection struct {
	HTML template.HTML
}

// MCPClient is the package-local interface for executive-summary delegation.
// Mirrors pkg/frida/enrich/mcp_client.go MCPClient seam (Phase 9 analog).
// 10-02 will provide a nilClient default; 10-03 will wire the real backend
// from cmd/forensic.go.
type MCPClient interface {
	Summarize(ctx context.Context, prompt string) ([]byte, error)
}

// nilMCPClient is the zero-value seam. Always errors. Mirrors
// pkg/frida/enrich/mcp_client.go nilClient.
type nilMCPClient struct{}

// Summarize implements MCPClient.
func (nilMCPClient) Summarize(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("forensic: no MCP client wired (use --ai with a configured backend)")
}

// NilMCPClient returns a never-succeeds MCP client suitable for tests and
// for the default no-AI path (D-25). Exported so cmd/forensic.go can use it
// as the zero-value when --ai is absent.
func NilMCPClient() MCPClient { return nilMCPClient{} }
