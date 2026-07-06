/*
Copyright (c) 2026 Security Research
*/
package dissect

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-dissector.md",
			Frontmatter: `name: unravel-dissector
description: |
  File-system dissector for unravel. Spawned by /unravel:dissect,
  auto-detects the bundle type (ASAR, MSIX, IPA, APK, .node, WASM) and
  extracts all contained files into a structured output directory.
  Populates the unravel Postgres KB if an app slug is provided.
`,
			Body: `# unravel-dissector

Orchestrator for multi-format extraction. You delegate the heavy
lifting to format-specific unravel CLI commands via Bash.

## Required commands (run via Bash)

- ` + "`unravel app detect <path>`" + ` — identify the bundle type
- ` + "`unravel app dissect <path> --output <dir>`" + ` — extract all contents
- ` + "`unravel asar extract`" + `, ` + "`unravel msix extract`" + `, ` + "`unravel android extract`" + `,
  ` + "`unravel ios extract`" + `, ` + "`unravel nodeaddon info`" + `, ` + "`unravel wasm info`" + ` for format-specific work
- Use ` + "`--json`" + ` / ` + "`--output <dir>`" + ` and summarise; never paste raw dumps.

Tools: Bash, Read, Write.
`,
		},
		aihost.Asset{
			Path: "commands/dissect.md",
			Frontmatter: `description: Auto-detect bundle type and extract all contents via unravel-dissector subagent
argument-hint: [path=<file>] [out=<dir>] [app=<slug>] [help=0|1]
allowed-tools: [Task, Bash, Read, Write]
`,
			Body: `# /unravel:dissect

Auto-detect bundle type and extract all contents. Delegates to the
` + "`unravel-dissector`" + ` subagent.

## Arguments

| key  | default | meaning                                              |
|------|---------|------------------------------------------------------|
| path | (none)  | absolute path to bundle (required)                   |
| out  | (none)  | extraction target dir (required)                     |
| app  | (none)  | KB app slug to populate during dissect               |
| help | 0       | print this table and exit                            |

## Execute

1. Validate args.
2. Dispatch one Task call with ` + "`subagent_type=\"unravel:unravel-dissector\"`" + ` and the parsed args in the prompt.
3. Stream the subagent's report verbatim.
4. Suggest next: ` + "`/unravel:convert path=<X> out=<Y>`" + ` to port the bundle to Go.
`,
		},
	)
}
