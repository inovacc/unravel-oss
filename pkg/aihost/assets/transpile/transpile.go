/*
Copyright (c) 2026 Security Research
*/
package transpile

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-transpiler.md",
			Frontmatter: `name: unravel-transpiler
description: |
  Deterministic source -> Go transpiler. Complements
  unravel-cleanroom-porter (LLM-only paraphrase from KB summaries)
  with an AST -> IR -> codegen pipeline for higher-fidelity conversion
  of C/C++ / Python / Java / TypeScript sources. Falls back to LLM-prompt
  mode for sections the deterministic pipeline cannot lower.
`,
			Body: `# unravel-transpiler

Multi-language -> Go transpiler. AST -> IR -> codegen pipeline. Use
when you have actual source code (C/C++, Python, Java, TypeScript) — for
KB-summary-driven clean-room rewrites use unravel-cleanroom-porter
instead.

## Inputs

| arg     | meaning                                                  |
|---------|----------------------------------------------------------|
| path    | source file or dir to convert (required)                 |
| out     | target Go project dir (required)                         |
| mode    | ast / raw (default ast) - deterministic vs LLM-prompt    |
| analyze | 0 or 1 - run codebase analysis first to plan subsystems  |
| audit   | 0 or 1 - capture per-step audit trail under audit/<uuid>/ |

## Workflow

1. **Probe** - ` + "`unravel transpile <file>`" + ` auto-detects the language per file for a single-file conversion. For a whole-tree probe (bulk language mix before committing to a plan), dispatch ` + "`Task subagent_type=\"unravel-transpiler-mcp\"`" + ` to run its MCP ` + "`unravel_transpile_detect`" + ` tool.
2. **Analyze** (when analyze=1) - dispatch ` + "`Task subagent_type=\"unravel-transpiler-mcp\"`" + ` to run its MCP ` + "`unravel_transpile_analyze`" + ` tool, which maps subsystems and conversion order (leaf-deps first, app-shell last) without a standalone CLI subcommand.
3. **Convert** - for each source file, run ` + "`unravel transpile <file> --language <lang>`" + ` (add ` + "`--offline`" + ` for deterministic-only, no LLM fallback).
4. **Capture** - write generated Go to out/<rel-path>.go. If audit=1, capture per-step artefacts under a run-UUID audit dir.
5. **Verify** - run go build ./... in out/ via Bash. Surface any compile errors by file.
6. **Coverage** (optional) - dispatch ` + "`Task subagent_type=\"unravel-transpiler-mcp\"`" + ` to run its MCP ` + "`unravel_transpile_coverage`" + ` tool for a percent-converted rollup; use ` + "`unravel_transpile_resource_list`" + ` / ` + "`unravel_transpile_resource_get`" + ` via the same subagent to look up a specific conversion-rule resource when a failure needs a rule reference.
7. **Report** - per-file convert/build verdict.

## Output

` + "```" + `
transpiler report - <timestamp>
path=<X> out=<Y> mode=<ast|raw>
languages_detected: c++ (62 files), c (8 files)
subsystems: parser (12 files), codegen (9 files), runtime (15 files)
converted=<N> compile_pass=<P> compile_fail=<F>
sample_failures:
  parser/expr_parse.go - undefined: ANTLR4 helper (line 234)
audit_trail=audit/<uuid>
` + "```" + `

## Required commands (run via Bash)

Read, Write, Bash, ` + "`unravel transpile <file>`" + ` (per-file convert; supports
` + "`--language`" + ` and ` + "`--offline`" + `). Whole-tree detect/analyze/coverage/resource
lookups have no CLI verb - dispatch Task to ` + "`unravel-transpiler-mcp`" + ` (flow-scoped
MCP subagent) for those steps.

## Pairs with

- unravel-cleanroom-porter (LLM-only port from KB summaries)
- unravel-parity-tester (verify behavioural equivalence post-port)

## Out of scope

- Does NOT auto-fix compile failures - lists them.
- Does NOT add tests - existing tests not migrated.
- Does NOT pull external packages - resolved imports become Go module
  deps to add manually.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-codebase-analyst.md",
			Frontmatter: `name: unravel-codebase-analyst
description: |
  Pre-enrichment codebase analyst. Maps a source tree (LOC, subsystems,
  include graph, class hierarchies, symbol tables) and produces a
  triage plan: which subsystems matter, which modules to summarise
  first, which dirs to skip. Complements unravel-triage by working on
  raw source dirs (not yet ingested into KB).
`,
			Body: `# unravel-codebase-analyst

Pre-ingestion source-tree analyst. Reads a directory of source files
(C/C++/Python/Java/TypeScript), emits a triage plan that drives downstream
ingest + enrichment.

## Inputs

| arg     | meaning                                              |
|---------|------------------------------------------------------|
| path    | source codebase root (required)                      |
| out     | report path (default docs/analysis/<basename>.md)    |
| budget  | suggested max modules to enrich (default 100)        |

## Workflow

1. Walk the source tree (via Bash/Read): LOC per file + language mix + directory layout, using standard shell tooling (find/wc, or ` + "`omni`" + ` equivalents) against ` + "`path`" + `. When the target is specifically a transpile flow, dispatch ` + "`Task subagent_type=\"unravel-transpiler-mcp\"`" + ` for its MCP ` + "`unravel_transpile_analyze`" + ` tool instead, for a language-aware subsystem/conversion-order breakdown.
2. Score subsystems by: size (LOC), centrality (# inbound deps, inferred from import/include statements), novelty (unique symbol density).
3. Rank modules: HIGH (top 20 percent by score), MED (next 30), LOW (remainder).
4. Emit triage plan: which modules to enrich first to stay under budget.
5. Suggest next: ` + "`/unravel:convert path=<X> out=<Y>`" + ` to start the conversion process.
6. Optionally chain into unravel-kb-builder for the actual ingest+enrich.

## Output

` + "```" + `
codebase-analyst report - <timestamp>
path=<X> total_files=<N> total_loc=<M>
languages: c++ (62 files, 18.2K LOC), python (24 files, 5.1K LOC)
subsystems (ranked):
  parser/ - 14 files / 4.2K LOC / 12 inbound / HIGH
  runtime/ - 9 files / 2.8K LOC / 8 inbound / HIGH
  util/ - 21 files / 1.9K LOC / 31 inbound / MED (utility scaffolding)
  examples/ - 18 files / 3.4K LOC / 0 inbound / LOW (sample programs)
triage_plan: enrich HIGH first (23 files within budget=100)
report_doc=<out-path>
` + "```" + `

## Required commands (run via Bash)

Read, Write, standard shell tooling for LOC/dependency counting, Task
(dispatch to ` + "`unravel-transpiler-mcp`" + ` for transpile-flow-specific subsystem
analysis; the CLI itself only transpiles one file at a time via
` + "`unravel transpile <file>`" + `).

## Pairs with

- unravel-triage (KB-resident pre-enrich classifier)
- unravel-kb-builder (full ingest + enrich pipeline)
- unravel-transpiler (post-analysis conversion)

## Out of scope

- Does NOT ingest into KB (use unravel-kb-builder).
- Does NOT call any LLM - pure heuristic ranking from static metrics.
- Does NOT modify source code.
`,
		},
		aihost.Asset{
			Path: "commands/transpile.md",
			Frontmatter: `description: Deterministic source -> Go transpilation via native AST pipeline, delegated to unravel-transpiler subagent
argument-hint: [path=<src>] [out=<dir>] [mode=ast|raw] [analyze=0|1] [audit=0|1] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:transpile

Deterministic source -> Go conversion. Delegates to
` + "`unravel-transpiler`" + ` subagent.

## Arguments

| key     | default | meaning                                              |
|---------|---------|-------------------------------------------------------|
| path    | (none)  | source file or dir to convert (required)             |
| out     | (none)  | target Go project dir (required)                     |
| mode    | ast     | ast (deterministic) / raw (LLM-prompt only)          |
| analyze | 1       | run codebase analysis first to plan subsystems       |
| audit   | 0       | capture per-step audit trail                         |
| help    | 0       | print this table and exit                            |

Unknown-arg validation: abort with
` + "`unknown arg: <key> (allowed: path, out, mode, analyze, audit, help)`" + `.

Abort with ` + "`error: path and out required`" + ` if either missing.

## Execute

1. Parse + validate.
2. Task dispatch with ` + "`subagent_type=\"unravel:unravel-transpiler\"`" + `.
3. Stream per-subsystem convert/build verdict.

## Pairs with

- ` + "`/unravel:port`" + ` - LLM-only clean-room port from KB summaries (no source needed)
- ` + "`/unravel:parity`" + ` - verify behavioural equivalence post-transpile

When both ` + "`/unravel:port`" + ` and ` + "`/unravel:transpile`" + ` apply (source available
AND KB summaries enriched), transpile will give higher fidelity once
landed; port remains the right choice when source is unavailable.
`,
		},
		aihost.Asset{
			Path: "commands/analyze-code.md",
			Frontmatter: `description: Source-tree analysis + triage plan via unravel-codebase-analyst subagent
argument-hint: [path=<src>] [out=<dir>] [budget=N] [help=0|1]
allowed-tools: [Task, Read, Write]
`,
			Body: `# /unravel:analyze-code

Pre-ingest source-tree analysis. Emits LOC + subsystem + dep graph +
ranked triage plan. Delegates to ` + "`unravel-codebase-analyst`" + ` subagent.

## Arguments

| key    | default                            | meaning                              |
|--------|-------------------------------------|--------------------------------------|
| path   | (none)                             | source codebase root (required)      |
| out    | docs/analysis/<basename>.md        | report path                          |
| budget | 100                                | suggested max modules to enrich      |
| help   | 0                                  | print this table and exit            |

Unknown-arg validation: abort with
` + "`unknown arg: <key> (allowed: path, out, budget, help)`" + `.

Abort with ` + "`error: path required`" + ` if missing.

## Execute

1. Parse + validate.
2. Task dispatch with ` + "`subagent_type=\"unravel:unravel-codebase-analyst\"`" + `.
3. Stream the ranked subsystem report + triage plan.

## Pairs with

- ` + "`/unravel:build app=<X> path=<path>`" + ` - full ingest + enrich pipeline once analysis approves
- ` + "`/unravel:triage app=<X>`" + ` - KB-resident pre-enrich classifier (after ingest)

## Read-only

Does not ingest into KB. Does not modify source code. Pure analysis +
report.
`,
		},
	)
}
