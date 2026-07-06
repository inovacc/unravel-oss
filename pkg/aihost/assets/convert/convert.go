/*
Copyright (c) 2026 Security Research
*/
package convert

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-router.md",
			Frontmatter: `name: unravel-router
description: |
  Top-level conversion orchestrator. Picks the best porting strategy
  based on source availability and obfuscation verdict. Routes to
  unravel-transpiler for clean source, or unravel-cleanroom-porter for
  obfuscated/minified/no-source inputs.
`,
			Body: `# unravel-router

Conversion strategy selector. Analyses the dissect/enrich verdict and
routes the job to the appropriate conversion pipeline.

## Required commands (run via Bash)

` + "`unravel app detect`" + `, ` + "`unravel app dissect`" + `, Task (for routing and
for language-detection dispatch), Read.

## Workflow

1. **Analysis** - ` + "`transpile`" + ` is a leaf CLI command (` + "`unravel transpile <file>`" + `,
   no subcommands) - there is no ` + "`unravel transpile detect`" + ` verb. Dispatch
   ` + "`Task subagent_type=\"unravel-transpiler-mcp\"`" + ` to run its MCP
   ` + "`unravel_transpile_detect`" + ` tool against ` + "`path`" + ` instead. If the detected
   language is a raw source file (C++, Java, Python, TS), proceed to **Transpile**.
2. **Dissection** - if ` + "`path`" + ` is a bundle, run ` + "`unravel app dissect`" + `. Look at the ` + "`obfuscation`" + ` and ` + "`framework`" + ` fields.
3. **Verdict**:
   - If ` + "`garble=true`" + ` or ` + "`heuristic_score > 0.7`" + ` -> **Port**.
   - If ` + "`framework=electron/tauri`" + ` and no source available -> **Port**.
   - If source is available and clean -> **Transpile**.
   - If ` + "`force`" + ` is set, respect it.
4. **Route**:
   - **Transpile**: delegate to ` + "`unravel-transpiler`" + ` with ` + "`path`" + ` and ` + "`out`" + `.
   - **Port**:
     1. If no KB captured, run ` + "`unravel-dissector app=<X>`" + ` then ` + "`unravel-kb-builder`" + ` to enrich.
     2. Delegate to ` + "`unravel-cleanroom-porter`" + ` with ` + "`app=<X>`" + ` and ` + "`out`" + `.
5. **Verify** - suggest next: ` + "`/unravel:audit-kb app=<app>`" + ` to verify the fidelity of the conversion.

## Output
`,
		},
		aihost.Asset{
			Path: "commands/convert.md",
			Frontmatter: `description: Convert a source file or bundle to Go using the best available strategy (auto-routed)
argument-hint: [path=<src>] [out=<dir>] [app=<slug>] [force=transpile|port] [help=1]
allowed-tools: [Bash, Task, Read]
`,
			Body: `# /unravel:convert

Convert a source file or application bundle to Go. Automatically
detects whether to use high-fidelity transpilation or clean-room
porting. Delegates to the ` + "`unravel-router`" + ` subagent.
`,
		},
	)
}
