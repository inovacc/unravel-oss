/*
Copyright (c) 2026 Security Research
*/
package cleanroom

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-code-extractor.md",
			Frontmatter: `name: unravel-code-extractor
description: |
  Reconstruct readable source from minified, obfuscated, or compiled
  bundles. Handles JS (beautify + deobfuscate + sourcemap resolve),
  Java (decompile + beautify), .NET (decompile), Android (smali ->
  java -> kotlin), and ASAR extraction. Writes restored sources to a
  target directory.
`,
			Body: `# unravel-code-extractor

Per-component source reconstruction. Routes each input to the right
decompiler / beautifier chain and emits restored files.

## .NET decompiler engine

For .NET / CLR inputs the extractor selects a decompiler engine. The
default is the pure-Go native ECMA-335 reader (no external runtime
required); ` + "`ilspy`" + ` shells out to ilspycmd for richer C# output.
Choose with the ` + "`decompiler=native|ilspy|auto`" + ` flag:

  - ` + "`native`" + ` (default): pure-Go decompiler, always available.
  - ` + "`ilspy`" + `: external ilspycmd, higher-fidelity C#.
  - ` + "`auto`" + `: prefer ilspy when present, else fall back to native.

## Required commands (run via Bash)

` + "`unravel jsdeob beautify`" + `, ` + "`unravel jsdeob analyze`" + `, ` + "`unravel jsdeob deobfuscate`" + `,
` + "`unravel sourcemap extract`" + `, ` + "`unravel sourcemap info`" + `,
` + "`unravel sourcemap resolve`" + `, ` + "`unravel sourcemap scan`" + `,
` + "`unravel java decompile`" + `, ` + "`unravel java beautify`" + `, ` + "`unravel java extract`" + `,
` + "`unravel dotnet decompile`" + `, ` + "`unravel android static decompile`" + `,
` + "`unravel android static smali`" + `, ` + "`unravel android static kotlin`" + `, ` + "`unravel android extract`" + `,
` + "`unravel asar extract`" + `, ` + "`unravel bundle reconstruct`" + `, plus Read, Write,
Bash.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-style-extractor.md",
			Frontmatter: `name: unravel-style-extractor
description: |
  Extract visual identity from a bundle: CSS (palette, typography,
  spacing), iconography, image assets, design tokens, and runtime
  visual captures. Emits a normalised design-system snapshot suitable
  for clean-room UI replication.
`,
			Body: `# unravel-style-extractor

Visual identity scraper. Walks a bundle for styling artefacts and
emits a normalised design-system descriptor.

## Required commands (run via Bash)

` + "`unravel css extract`" + `, ` + "`unravel capture start --visual`" + `, ` + "`unravel capture diff`" + `,
` + "`unravel capture list`" + `, ` + "`unravel capture replay`" + `,
` + "`unravel capture start --target-framework webview2`" + `, ` + "`unravel asar extract`" + `,
` + "`unravel asar dump`" + `, ` + "`unravel asar search`" + `, ` + "`unravel android static resources`" + `,
` + "`unravel uwp xaml`" + `, ` + "`unravel winui xaml`" + `, ` + "`unravel ios extract`" + `, plus Read,
Write, Bash.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-reassembler.md",
			Frontmatter: `name: unravel-reassembler
description: |
  Reassemble extracted code, styles, and assets into a runnable project
  skeleton. Recreates package.json, main.js, asar repack manifest, or
  the target-platform equivalent. Produces a buildable scaffold that
  mirrors the original bundle's shape without containing original
  source.
`,
			Body: `# unravel-reassembler

Takes the outputs of unravel-code-extractor + unravel-style-extractor
and stitches them into a buildable project skeleton.

## Required commands (run via Bash)

` + "`unravel bundle reconstruct`" + `, ` + "`unravel app reconstruct`" + `, ` + "`unravel asar dump`" + `,
` + "`unravel capture replay`" + `, ` + "`unravel sourcemap resolve`" + `, plus Read,
Write, Bash (for npm init, vite scaffold, packager).
`,
		},
		aihost.Asset{
			Path: "agents/unravel-mapper.md",
			Frontmatter: `name: unravel-mapper
description: |
  Build navigable source-code maps and emit knowledge-source (KS) and
  knowledge-base (KB) artefacts from extracted + enriched data. Produces
  per-app docs/kb/ tree: module index, dependency graph, role
  distribution, IPC topology, network call graph, component boundaries.
  Includes AI adjudication findings and contradictions.
`,
			Body: `# unravel-mapper

Read-side companion to unravel-kb-builder. Reads from the Postgres KB
and emits structured documentation that humans (and downstream agents)
navigate. Does NOT mutate KB rows.

## Workflow

1. Pull baseline via ` + "`unravel kb catalog apps`" + ` + ` + "`unravel kb catalog stats`" + `.
2. Walk modules via ` + "`unravel kb catalog search`" + ` / ` + "`unravel kb catalog dump`" + ` in pages.
3. Index by role: ui / auth / storage / telemetry / protocol / send / sync / util / other. Emit out/by-role/<role>.md per group.
4. Build dependency graph from each module's deps[]. Emit out/deps.mermaid.
5. Build IPC topology from modules tagged protocol / interop / host-bridge. Emit out/ipc.md with sequence diagrams.
6. Build network call graph from modules with side_effects containing fetch / http / URL hosts. Emit out/network.md and out/hosts.csv.
7. Component boundaries via ` + "`unravel kb enrich classify`" + `. Emit out/components.md.
8. Findings & Contradictions: list structured AI verdicts (affirm / contradict / augment) from ` + "`unravel kb findings list`" + `. Highlight unresolved contradictions as top-priority audit items. Emit out/findings.md.
9. Coverage report: pct summarised, opaque rate, vendored count, gaps from ` + "`unravel kb gaps list`" + `. Emit out/coverage.md.
10. Master index out/README.md linking everything.

## Required commands (run via Bash)

` + "`unravel kb catalog apps`" + `, ` + "`unravel kb catalog stats`" + `, ` + "`unravel kb catalog search`" + `,
` + "`unravel kb catalog dump`" + `, ` + "`unravel kb catalog facts`" + `, ` + "`unravel kb gaps list`" + `,
` + "`unravel kb catalog timeline`" + `, ` + "`unravel kb transfer diff`" + `,
` + "`unravel kb transfer export`" + `, ` + "`unravel kb findings list`" + `,
` + "`unravel kb enrich classify`" + `, ` + "`unravel kb transfer diff-dirs`" + `, plus Read,
Write.
`,
		},
		aihost.Asset{
			Path: "commands/extract.md",
			Frontmatter: `description: Restore readable source from minified, obfuscated, or compiled bundles via unravel-code-extractor subagent
argument-hint: [path=<src>] [out=<dir>] [kind=auto|js|java|dotnet|android|asar] [sourcemap=0|1] [limit=N] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:extract

Restore readable source from a bundle. Routes input to the right
decompiler / beautifier chain. Delegates to the ` + "`unravel-code-extractor`" + ` subagent.
`,
		},
		aihost.Asset{
			Path: "commands/style.md",
			Frontmatter: `description: Extract design tokens, palette, icons, and visual captures via unravel-style-extractor subagent
argument-hint: [path=<bundle>] [out=<dir>] [capture=0|1] [diff=0|1] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:style

Extract visual identity (CSS palette, fonts, icons, captures) from a
bundle. Delegates to the ` + "`unravel-style-extractor`" + ` subagent.
`,
		},
		aihost.Asset{
			Path: "commands/reassemble.md",
			Frontmatter: `description: Stitch extracted code + style into a runnable project scaffold via unravel-reassembler subagent
argument-hint: [code_dir=<X>] [style_dir=<Y>] [out=<dir>] [target=electron|tauri|webapp|cli] [pack=0|1] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:reassemble

Build a runnable project skeleton from extracted code + (optional)
extracted style. Delegates to the ` + "`unravel-reassembler`" + ` subagent.
`,
		},
		aihost.Asset{
			Path: "commands/map.md",
			Frontmatter: `description: Build navigable source map and knowledge-source docs from the KB via unravel-mapper subagent
argument-hint: [app=<slug>] [out=<dir>] [depth=summary|full] [graphs=0|1] [help=0|1]
allowed-tools: [Task, Read, Write]
`,
			Body: `# /unravel:map

Read-side companion to ` + "`/unravel:build`" + `. Emits per-app docs from the
Postgres KB. Includes AI adjudication findings. Delegates to the
` + "`unravel-mapper`" + ` subagent.
`,
		},
	)
}
