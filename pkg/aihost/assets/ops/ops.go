/*
Copyright (c) 2026 Security Research
*/
package ops

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-self-healer.md",
			Frontmatter: `name: unravel-self-healer
description: |
  Self-diagnosis and repair agent for the unravel toolkit. Triggered
  by /unravel:doctor, runs a set of health checks (binary versions,
  MCP server connectivity, Postgres KB status, keychain access)
  and proposes fixes for any detected issues.
`,
			Body: `# unravel-self-healer

Health and maintenance specialist. Your goal is to keep the unravel
environment in a known-good state.

## Required commands (run via Bash)

` + "`unravel kb ops doctor`" + `, ` + "`unravel plugin status`" + `, Bash, Read, Write.
`,
		},
		aihost.Asset{
			Path: "commands/doctor.md",
			Frontmatter: `description: Run comprehensive health checks and repair the unravel environment via unravel-self-healer subagent
argument-hint: [fix=0|1] [help=0|1]
allowed-tools: [Task, Bash, Read, Write]
`,
			Body: `# /unravel:doctor

Toolkit health check. Delegates to ` + "`unravel-self-healer`" + `.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-cve-scanner.md",
			Frontmatter: `name: unravel-cve-scanner
description: |
  Match an app's dependency manifest against CVE / advisory feeds.
  Reads npm / dotnet / java / android deps via existing MCP tools,
  fetches advisory data (offline-first via cached NVD slices when
  available), emits per-dep severity.
`,
			Body: `# unravel-cve-scanner

Dependency vulnerability scanner. Reads dep lists via the unravel CLI,
matches against advisory feeds, ranks by severity.

## Required commands (run via Bash)

` + "`unravel npm deps`" + `, ` + "`unravel npm info`" + `, ` + "`unravel npm analyze`" + `,
` + "`unravel dotnet deps`" + `, ` + "`unravel java manifest`" + `, ` + "`unravel android static manifest`" + `,
` + "`unravel kb catalog apps`" + `, plus Bash, Read, Write.
`,
		},
		aihost.Asset{
			Path: "commands/cve.md",
			Frontmatter: `description: Dependency vulnerability scan via unravel-cve-scanner subagent
argument-hint: [app=<slug>] [out=<path>] [feed=nvd|ghsa|osv] [offline=0|1] [help=0|1]
allowed-tools: [Task, Bash, Read, Write]
`,
			Body: `# /unravel:cve

Match app dependencies against CVE / advisory feeds. Delegates to
` + "`unravel-cve-scanner`" + `.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-insights-analyst.md",
			Frontmatter: `name: unravel-insights-analyst
description: |
  Self-improvement insights analyst. Runs ` + "`unravel insights rollup`" + ` and
  ` + "`unravel insights suggest`" + ` (or the equivalent MCP tools), reads the
  output, picks the top 3 highest-confidence improvement candidates,
  and recommends a single concrete next change to unravel's own
  code/prompts/defaults. Local-only — no telemetry leaves the machine.
`,
			Body: `# unravel-insights-analyst

Read-side analyst for the self-improvement insights stream. Walks
the rollup + suggestion artefacts produced by ` + "`unravel insights`" + ` and
proposes one concrete next change.

## Workflow

1. ` + "`unravel insights rollup`" + ` + ` + "`unravel insights suggest`" + ` (or
   ` + "`unravel insights status`" + `) to read the current digest.
2. Pick the top 3 highest-confidence candidates and recommend one
   concrete next change.
3. Recording the new insight and tracking it as a goal has no CLI
   verb - dispatch ` + "`Task subagent_type=\"unravel-insights-mcp\"`" + ` (flow-scoped
   MCP subagent) to call ` + "`unravel_insights_record`" + ` for the finding and
   ` + "`unravel_insights_start_goal`" + ` / ` + "`unravel_insights_complete_goal`" + ` to
   open or close the tracked goal.

## Required commands (run via Bash)

Bash, Read, Task (for record / goal-tracking via unravel-insights).
`,
		},
		aihost.Asset{
			Path: "commands/insights.md",
			Frontmatter: `description: Run insights rollup + suggest and surface top improvement candidates via unravel-insights-analyst subagent
argument-hint: [days=N] [top=N] [help=0|1]
allowed-tools: [Task, Bash, Read]
`,
			Body: `# /unravel:insights

Self-improvement digest. Delegates to ` + "`unravel-insights-analyst`" + `, which
in turn dispatches to the ` + "`unravel-insights-mcp`" + ` flow-scoped MCP subagent to
record findings and track improvement goals (no CLI verb for that step).
`,
		},
	)
}
