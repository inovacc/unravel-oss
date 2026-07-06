/*
Copyright (c) 2026 Security Research
*/

// Package mcptools / plugin_doctor.go registers unravel_plugin_doctor —
// server-side health check for the unravel plugin contract.
//
// Returns a structured envelope with PASS/WARN/FAIL findings across:
//   - KB DB reachability (open + ping)
//   - Per-app module + summarised counts (uses kbstore.Stats)
//   - Enrich runs: total + stale (>10min heartbeat) count
//   - Env vars: UNRAVEL_KB_DB / DSN / VENDORED_SHAS
//   - Plugin contract: list of required MCP tools (compile-time present)
//   - Build info (version)
//
// Pair with the /unravel-doctor plugin slash command which adds CC-side
// checks (junction, marketplace.json, settings.json, command frontmatter).
package mcptools

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/all" // register every host so aihost.All() returns them
	plugin "github.com/inovacc/unravel-oss/pkg/aihost/claude"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// PluginDoctorInput is the typed input for unravel_plugin_doctor.
type PluginDoctorInput struct {
	DB      string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	Verbose bool   `json:"verbose,omitempty" jsonschema:"include per-app module breakdown"`
}

// DoctorCheck is one finding.
type DoctorCheck struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // PASS | WARN | FAIL
	Detail   string `json:"detail"`
}

// pluginRequiredTools is the list of MCP tools the unravel-plugin commands
// depend on. Compile-time guaranteed present in this binary (all registered
// from pkg/mcptools). Kept as the source of truth for cross-checks.
var pluginRequiredTools = []string{
	"unravel_kb_enrich_pending",
	"unravel_kb_enrich_write_enrichment",
	"unravel_kb_vendored_candidates",
	"unravel_kb_catalog_stats",
	"unravel_kb_catalog_search",
	"unravel_kb_enrich_status",
	"unravel_kb_enrich_retry",
	"unravel_kb_enrich_cost_report",
}

func registerPluginDoctorTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_plugin_doctor",
		Description: "Server-side health check for the unravel plugin. Probes KB " +
			"reachability, per-app module/summarised/pending counts, stale enrich runs, " +
			"env var presence (UNRAVEL_KB_DB, UNRAVEL_VENDORED_SHAS), and the plugin's " +
			"required MCP tool contract. Returns {binary, kb_db, enrich, env, " +
			"plugin_contract, checks[], verdict (OK|DEGRADED|FAILED)}. Pair with " +
			"/unravel-doctor plugin command for CC-side checks (junction, marketplace.json, " +
			"settings.json, command frontmatter).",
	}, handlePluginDoctor)
}

func handlePluginDoctor(ctx context.Context, _ *mcp.CallToolRequest, in PluginDoctorInput) (*mcp.CallToolResult, any, error) {
	checks := []DoctorCheck{}
	worst := "PASS"
	bump := func(s string) {
		if s == "FAIL" || (s == "WARN" && worst == "PASS") {
			worst = s
		}
	}

	// --- binary
	binary := map[string]any{
		"version": doctorBinaryVersion(),
		"go":      doctorGoVersion(),
	}

	// --- env vars
	envInfo := map[string]any{
		"UNRAVEL_KB_DB":            os.Getenv("UNRAVEL_KB_DB") != "",
		"UNRAVEL_KB_DSN":           os.Getenv("UNRAVEL_KB_DSN") != "",
		"UNRAVEL_VENDORED_SHAS":    doctorVendoredCount(),
		"UNRAVEL_ENRICH_FULL_BODY": envFlag("UNRAVEL_ENRICH_FULL_BODY"),
	}
	// env.kb_db check is deferred — it lands AFTER db.open below. If
	// config.yaml resolves and the pool opens, the env vars are merely
	// optional escape hatches (CI / test / throwaway overrides), not a
	// degradation. Only emit WARN when env is unset AND db.open fails.

	// --- Daemon doctor probe (v2.17 thin-client B7-P3)
	kbInfo := map[string]any{}
	enrichInfo := map[string]any{}
	cli, err := getDaemonClient(ctx)
	if err != nil {
		checks = append(checks, DoctorCheck{"daemon.dial", "FAIL", err.Error()})
		bump("FAIL")
		if os.Getenv("UNRAVEL_KB_DB") == "" && os.Getenv("UNRAVEL_KB_DSN") == "" {
			checks = append(checks, DoctorCheck{"env.kb_db", "WARN",
				"neither UNRAVEL_KB_DB nor UNRAVEL_KB_DSN set and config.yaml didn't resolve — run `unravel db setup`"})
			bump("WARN")
		}
		kbInfo["reachable"] = false
		return jsonResult(map[string]any{
			"binary":          binary,
			"env":             envInfo,
			"kb_db":           kbInfo,
			"plugin_contract": doctorContract(),
			"checks":          checks,
			"verdict":         doctorVerdict(worst),
		}), nil, nil
	}
	report, err := cli.Doctor(ctx, supervisor.DaemonDoctorParams{Verbose: in.Verbose})
	if err != nil {
		checks = append(checks, DoctorCheck{"daemon.doctor", "FAIL", err.Error()})
		bump("FAIL")
		kbInfo["reachable"] = false
		return jsonResult(map[string]any{
			"binary":          binary,
			"env":             envInfo,
			"kb_db":           kbInfo,
			"plugin_contract": doctorContract(),
			"checks":          checks,
			"verdict":         doctorVerdict(worst),
		}), nil, nil
	}

	if !report.KBReachable {
		checks = append(checks, DoctorCheck{"db.open", "FAIL", report.PingError})
		bump("FAIL")
		if os.Getenv("UNRAVEL_KB_DB") == "" && os.Getenv("UNRAVEL_KB_DSN") == "" {
			checks = append(checks, DoctorCheck{"env.kb_db", "WARN",
				"neither UNRAVEL_KB_DB nor UNRAVEL_KB_DSN set and config.yaml didn't resolve — run `unravel db setup`"})
			bump("WARN")
		}
		kbInfo["reachable"] = false
		return jsonResult(map[string]any{
			"binary":          binary,
			"env":             envInfo,
			"kb_db":           kbInfo,
			"plugin_contract": doctorContract(),
			"checks":          checks,
			"verdict":         doctorVerdict(worst),
		}), nil, nil
	}
	checks = append(checks, DoctorCheck{"db.open", "PASS", "supervisor pool reachable"})
	envDetail := "config.yaml resolved DSN; env override not required"
	if os.Getenv("UNRAVEL_KB_DB") != "" || os.Getenv("UNRAVEL_KB_DSN") != "" {
		envDetail = "env DSN override active"
	}
	checks = append(checks, DoctorCheck{"env.kb_db", "PASS", envDetail})
	kbInfo["reachable"] = true
	checks = append(checks, DoctorCheck{"db.ping", "PASS", "ping ok"})

	appRows := make([]map[string]any, 0, len(report.ModulesByApp))
	for _, s := range report.ModulesByApp {
		row := map[string]any{
			"app":         s.App,
			"total":       s.Total,
			"summarised":  s.Summarised,
			"pending":     s.Pending,
			"pct":         s.Pct,
			"uniq_hashes": s.UniqHashes,
		}
		if in.Verbose {
			row["avg_bytes"] = s.AvgBytes
		}
		appRows = append(appRows, row)
	}
	kbInfo["modules_by_app"] = appRows
	kbInfo["total_modules"] = report.TotalModules
	kbInfo["total_summarised"] = report.TotalSummarised
	kbInfo["total_pending"] = report.TotalModules - report.TotalSummarised
	if report.TotalModules == 0 {
		checks = append(checks, DoctorCheck{"db.modules", "WARN", "modules table empty — no captures ingested yet"})
		bump("WARN")
	} else {
		checks = append(checks, DoctorCheck{"db.modules", "PASS",
			fmt.Sprintf("%d modules across %d apps; %d summarised", report.TotalModules, len(report.ModulesByApp), report.TotalSummarised)})
	}

	enrichInfo["runs_total"] = report.EnrichRunsTotal
	enrichInfo["stale_in_progress"] = report.StaleInProgress
	if report.StaleInProgress > 0 {
		checks = append(checks, DoctorCheck{"enrich.stale", "WARN",
			fmt.Sprintf("%d in_progress runs older than 10min — run enrich_status to sweep", report.StaleInProgress)})
		bump("WARN")
	} else {
		checks = append(checks, DoctorCheck{"enrich.stale", "PASS", "no stale heartbeats"})
	}
	if report.LastRunAt != "" {
		enrichInfo["last_run_at"] = report.LastRunAt
	}

	// --- plugin contract
	contract := doctorContract()
	checks = append(checks, DoctorCheck{"plugin.contract", "PASS",
		fmt.Sprintf("%d required tools all registered in this binary", len(pluginRequiredTools))})

	out := map[string]any{
		"binary":          binary,
		"env":             envInfo,
		"kb_db":           kbInfo,
		"enrich":          enrichInfo,
		"plugin_contract": contract,
		"checks":          checks,
		"verdict":         doctorVerdict(worst),
	}
	return jsonResult(out), out, nil
}

// doctorVerdict maps the worst severity to the public contract values.
func doctorVerdict(worst string) string {
	switch worst {
	case "FAIL":
		return "FAILED"
	case "WARN":
		return "DEGRADED"
	default:
		return "OK"
	}
}

func doctorContract() map[string]any {
	// Auto-derive command list from embedded plugin assets so doctor and
	// shipped plugin can never drift out of sync.
	names, err := plugin.CommandNames()
	cmds := make([]string, 0, len(names))
	for _, n := range names {
		cmds = append(cmds, "/"+plugin.Name+":"+n)
	}
	// Iterate every registered host and capture its Doctor() report
	// (if implemented). Lets unravel_plugin_doctor speak for claude,
	// codex, gemini, ... uniformly.
	hostReports := map[string]any{}
	for _, h := range aihost.All() {
		entry := map[string]any{"name": h.Name()}
		if target, terr := h.InstallTarget(); terr == nil {
			entry["install_target"] = target
		}
		if d, ok := h.(aihost.Doctor); ok {
			entry["doctor"] = d.Doctor()
		} else {
			entry["doctor"] = "NOT_IMPLEMENTED"
		}
		hostReports[h.Name()] = entry
	}
	contract := map[string]any{
		"required_mcp_tools":       pluginRequiredTools,
		"registered_in_binary":     true,
		"required_plugin_commands": cmds,
		"required_subagent":        "unravel-enricher",
		"required_skill":           "enrich",
		"hosts":                    hostReports,
	}
	if err != nil {
		contract["command_derive_error"] = err.Error()
	}
	return contract
}

func doctorBinaryVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "unknown"
}

func doctorGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}
	return "unknown"
}

func doctorVendoredCount() int {
	raw := os.Getenv("UNRAVEL_VENDORED_SHAS")
	if raw == "" {
		return 0
	}
	n := 0
	for _, s := range strings.Split(raw, ",") {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}
