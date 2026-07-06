/*
Copyright (c) 2026 Security Research
*/

package claude

import (
	"fmt"
	"os"
	"path/filepath"
)

// Flow-scoped MCP subagents.
//
// The plugin no longer registers the unravel MCP server globally (no
// top-level .mcp.json entry the main session inherits). Instead, a small
// allowlist of subagents declares the unravel MCP server INLINE in their own
// frontmatter (`mcpServers:`), so MCP tools exist only inside those specific
// subagent flows — invoked explicitly via the Task tool — never in the main
// session. This keeps the main session's tool surface small while still
// giving KB-enrichment / KB-query / KB-drift flows structured MCP access.
//
// These are NOT aihost assets (Kind covers only command/agent/skill bundled
// with the plugin itself) — they are written directly to the user's
// ~/.claude/agents/ directory, alongside any agents the user manages
// themselves, so Claude Code discovers them regardless of plugin state.

// mcpAgentsDir is the directory (relative to home) subagent markdown files
// are read from by Claude Code.
const mcpAgentsDir = ".claude/agents"

// mcpScopedAgent is one allowlisted flow-scoped subagent definition.
type mcpScopedAgent struct {
	Name string // file stem; written as "<Name>.md"
	Body string // full markdown file contents, including frontmatter
}

// mcpScopedAgents enumerates the subagents that get an inline unravel MCP
// server. Keep this list small and deliberate — each entry is a flow where
// structured MCP tool access earns its keep over the plain CLI. Current
// allowlist: KB enrich / query / drift, transpile, insights.
var mcpScopedAgents = []mcpScopedAgent{
	{
		Name: "unravel-enricher-mcp",
		Body: `---
name: unravel-enricher-mcp
description: KB enrichment flow that uses structured unravel MCP tools (flow-scoped)
tools: Read, Grep, Bash, Task, Skill
mcpServers:
  unravel:
    type: stdio
    command: ` + McpCommand + `
    args: ["mcp", "serve"]
---

# unravel-enricher-mcp

Flow-scoped subagent for knowledge-base enrichment. The unravel MCP server
is declared inline above — its tools are available only inside this
subagent's run, not in the main session.

Use the unravel MCP tools to read pending modules, summarize role /
inputs / outputs / side-effects / dependencies, and persist enrichment
back into the knowledge base.
`,
	},
	{
		Name: "unravel-kb-query-mcp",
		Body: `---
name: unravel-kb-query-mcp
description: Natural-language query flow over the unravel KB using structured MCP tools (flow-scoped)
tools: Read, Grep, Task
mcpServers:
  unravel:
    type: stdio
    command: ` + McpCommand + `
    args: ["mcp", "serve"]
---

# unravel-kb-query-mcp

Flow-scoped subagent for answering natural-language questions over the
unravel knowledge base. The unravel MCP server is declared inline above —
its tools are available only inside this subagent's run, not in the main
session.

Translate the question into a sequence of unravel MCP KB-query tool calls,
aggregate the results, and answer with citations to module ids.
`,
	},
	{
		Name: "unravel-kb-drift-mcp",
		Body: `---
name: unravel-kb-drift-mcp
description: KB drift-detection flow using structured unravel MCP tools (flow-scoped)
tools: Read, Grep, Bash, Task
mcpServers:
  unravel:
    type: stdio
    command: ` + McpCommand + `
    args: ["mcp", "serve"]
---

# unravel-kb-drift-mcp

Flow-scoped subagent for detecting drift between the unravel knowledge base
and the underlying source it describes. The unravel MCP server is declared
inline above — its tools are available only inside this subagent's run,
not in the main session.

Use the unravel MCP drift tools to compare recorded enrichment against
current source hashes and report stale or contradicted entries.
`,
	},
	{
		Name: "unravel-transpiler-mcp",
		Body: `---
name: unravel-transpiler-mcp
description: Source -> Go transpile/analysis flow using structured unravel MCP tools (flow-scoped)
tools: Read, Grep, Bash, Task
mcpServers:
  unravel:
    type: stdio
    command: ` + McpCommand + `
    args: ["mcp", "serve"]
---

# unravel-transpiler-mcp

Flow-scoped subagent for the transpile analysis surface that has no CLI
verb. The unravel MCP server is declared inline above — its tools are
available only inside this subagent's run, not in the main session.

Use the unravel MCP transpile tools —
` + "`unravel_transpile_detect`" + `, ` + "`unravel_transpile_analyze`" + `,
` + "`unravel_transpile_coverage`" + `, ` + "`unravel_transpile_run`" + `,
` + "`unravel_transpile_resource_list`" + `, and ` + "`unravel_transpile_resource_get`" + ` —
to detect the source language, analyze subsystems and conversion order,
measure conversion coverage, run the transpile pipeline, and list/fetch
conversion-rule resources. Deterministic per-file conversion that IS
exposed on the CLI (` + "`unravel transpile <file>`" + `) stays a plain Bash call;
only the MCP-only analysis/coverage/resource steps route through this
subagent.
`,
	},
	{
		Name: "unravel-insights-mcp",
		Body: `---
name: unravel-insights-mcp
description: Self-improvement goal-tracking flow using structured unravel MCP tools (flow-scoped)
tools: Read, Grep, Bash, Task
mcpServers:
  unravel:
    type: stdio
    command: ` + McpCommand + `
    args: ["mcp", "serve"]
---

# unravel-insights-mcp

Flow-scoped subagent for the self-improvement insights surface that has
no CLI verb. The unravel MCP server is declared inline above — its tools
are available only inside this subagent's run, not in the main session.

Use the unravel MCP insights tools —
` + "`unravel_insights_record`" + `, ` + "`unravel_insights_start_goal`" + `, and
` + "`unravel_insights_complete_goal`" + ` — to record a new insight and to
start/complete a tracked improvement goal. The CLI's
` + "`unravel insights rollup/suggest/status`" + ` remain plain Bash calls for
reading the existing digest; only recording a new insight or driving a
goal's lifecycle routes through this subagent.
`,
	},
}

// WriteMcpScopedAgents writes the allowlisted flow-scoped subagents to
// <home>/.claude/agents/, creating the directory if needed. Returns the
// full paths written.
func WriteMcpScopedAgents(home string) ([]string, error) {
	dir := filepath.Join(home, mcpAgentsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	paths := make([]string, 0, len(mcpScopedAgents))
	for _, a := range mcpScopedAgents {
		p := filepath.Join(dir, a.Name+".md")
		if err := os.WriteFile(p, []byte(a.Body), 0o644); err != nil {
			return paths, fmt.Errorf("write %s: %w", p, err)
		}
		paths = append(paths, p)
	}

	return paths, nil
}

// RemoveMcpScopedAgents deletes the allowlisted flow-scoped subagents from
// <home>/.claude/agents/, ignoring any that are already missing. Best-effort:
// attempts all deletions, returns the first non-NotExist error (if any).
func RemoveMcpScopedAgents(home string) error {
	dir := filepath.Join(home, mcpAgentsDir)
	var firstErr error

	for _, a := range mcpScopedAgents {
		p := filepath.Join(dir, a.Name+".md")
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			if firstErr == nil {
				firstErr = fmt.Errorf("remove %s: %w", p, err)
			}
		}
	}

	return firstErr
}
