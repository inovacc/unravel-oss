/*
Copyright (c) 2026 Security Research
*/
package enrich

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-enricher.md",
			Frontmatter: `name: unravel-enricher
description: |
  Low-level JS module enricher for unravel. Reads one or more
  minified/obfuscated JavaScript module bodies and emits structured
  summaries: role, inputs, outputs, side-effects, and dependencies.
  Usually fanned out as Task subagents by unravel-kb-builder.
`,
			Body: `# unravel-enricher

Reverse-engineering specialist. Your role is to look at minified or
obfuscated JavaScript source code and describe its purpose and
behavior in natural language.

## Required commands (run via Bash)

` + "`unravel kb enrich pending`" + `, ` + "`unravel kb enrich write-enrichment`" + `,
` + "`unravel jsdeob deobfuscate`" + `.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-enricher-poly.md",
			Frontmatter: `name: unravel-enricher-poly
description: |
  Non-JS module enricher for unravel. Reads decompiled or disassembled
  bodies for Java, .NET, Kotlin, Android smali/dex, native addons (.node),
  and WASM, and emits the SAME structured summary contract as
  unravel-enricher: role, inputs, outputs, side-effects, dependencies.
  Routed to by unravel-kb-builder for any pending module whose language is
  not JavaScript/TypeScript.
`,
			Body: `# unravel-enricher-poly

Reverse-engineering specialist for NON-JavaScript bodies. Your role is to read
decompiled/disassembled source (Java, C#/.NET, Kotlin, smali, native, WASM) and
describe its purpose and behavior in natural language — identical output
contract to ` + "`unravel-enricher`" + `, different input languages.

## Required commands (run via Bash)

Read pending + write back (same data plane as unravel-enricher):
` + "`unravel kb enrich pending`" + `, ` + "`unravel kb enrich write-enrichment`" + `.

Pull body context by language (do NOT call any model yourself — these are I/O):
- Java:    ` + "`unravel java decompile`" + `
- .NET:    ` + "`unravel dotnet decompile`" + `
- Android: ` + "`unravel android static smali`" + `, ` + "`kotlin`" + `, ` + "`dex`" + `, ` + "`native`" + `
- Native:  ` + "`unravel nodeaddon symbols`" + `
- WASM:    ` + "`unravel wasm info`" + `

## Contract (identical to unravel-enricher)

For each pending module you enrich, write via ` + "`unravel kb enrich write-enrichment`" + `:
- role: one-line purpose
- inputs / outputs: what it consumes and produces
- side_effects: filesystem, network, IPC, process, registry
- deps: modules/libraries it calls

Never invent behavior the body does not show. If a body is empty or
unrecoverable, mark it needs_human_verification rather than guessing.
`,
		},
		aihost.Asset{
			Path: "commands/enrich.md",
			Frontmatter: `description: Summarise and classify minified modules in the KB via unravel-enricher subagents
argument-hint: [app=<name>] [limit=N] [batch_size=N] [re_audit=0|1] [help=0|1]
allowed-tools: [Bash, Task]
`,
			Body: `# /unravel:enrich

Summarise and classify pending modules in the KB. Delegates the work
to ` + "`unravel-enricher`" + ` subagents.

## Arguments

| key      | default | meaning                                              |
|----------|---------|------------------------------------------------------|
| app      | (none)  | KB app slug (required)                               |
| limit    | 100     | max modules to enrich                                |
| re_audit | 0       | if 1, prioritize modules with open contradictions     |
| help     | 0       | print this table and exit                            |

## Workflow

1. If ` + "`re_audit=1`" + `, query ` + "`unravel kb findings list`" + ` for open ` + "`contradict`" + ` findings for the app.
2. Batch modules: first modules with open contradictions, then modules with ` + "`summary IS NULL`" + `.
3. For each batch, fan out ` + "`unravel-enricher`" + ` subagents.
4. Record results.
`,
		},
	)
}
