/*
Copyright (c) 2026 Security Research
*/
package cleanroom

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-cleanroom-porter.md",
			Frontmatter: `name: unravel-cleanroom-porter
description: |
  Clean-room port logic from an analysed app to a new target stack
  using ONLY the natural-language KB summaries as input (never the
  original source). Fans out one porter subagent per module. Produces a
  scaffolded target project that recreates behaviour without copying
  code. Uses embedded conversion rules and strategies to ensure
  idiomatic Go output.
`,
			Body: `# unravel-cleanroom-porter

Clean-room implementation generator. Reads KB summaries (long_summary,
role, inputs, outputs, side_effects, deps) and emits new source code in
the target stack. Never reads original source. Strict separation of
specification (KB) from implementation (output) preserves clean-room
defensibility.

## Required commands (run via Bash)

` + "`unravel kb catalog apps`" + `, ` + "`unravel kb catalog search`" + `, ` + "`unravel kb catalog dump`" + `,
` + "`unravel kb catalog facts`" + `, ` + "`unravel kb gaps list`" + `.

Conversion rules and architectural strategies (rules per language,
strategy notes) are bundled with the transpiler as embedded resources
under ` + "`pkg/transpile/rules`" + ` / ` + "`pkg/transpile/strategies`" + ` — no
standalone CLI verb exposes them; dispatch ` + "`Task subagent_type=\"unravel-transpiler-mcp\"`" + `
to run its MCP ` + "`unravel_transpile_resource_list`" + ` / ` + "`unravel_transpile_resource_get`" + `
tools when idiom guidance is needed. Plus Task (for porter subagent
fan-out and transpile-resource lookups), Read, Write, Bash (for target
build verification).
`,
		},
		aihost.Asset{
			Path: "commands/port.md",
			Frontmatter: `description: Clean-room port logic to a new target stack from KB summaries via unravel-cleanroom-porter subagent
argument-hint: [app=<slug>] [out=<dir>] [target=go|typescript|python|rust] [scope=all|role:<R>|module_ids=<csv>] [max_modules=N] [dry_run=0|1] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:port

Clean-room rewrite of an analysed app to a new target stack using
ONLY the KB summaries as input (never original source). Fans out one
porter subagent per module via ` + "`unravel-cleanroom-porter`" + `.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-parity-tester.md",
			Frontmatter: `name: unravel-parity-tester
description: |
  Verify a clean-room port (output of unravel-cleanroom-porter)
  behaves like the original on a set of input/output golden pairs.
  Compiles the port, runs synthetic test cases, compares behaviour,
  flags divergences.
`,
			Body: `# unravel-parity-tester

Post-port behavioural smoke test. Compiles ported project, runs a
test plan, compares outputs.
`,
		},
		aihost.Asset{
			Path: "commands/parity.md",
			Frontmatter: `description: Behavioural parity test for a clean-room port via unravel-parity-tester subagent
argument-hint: [port_dir=<X>] [target=go|typescript|python|rust] [spec_dir=<Y>] [timeout_s=N] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:parity

Verify a port behaves like the original on a golden test set.
Delegates to ` + "`unravel-parity-tester`" + `.
`,
		},
	)
}
