/*
Copyright (c) 2026 Security Research
*/
package xref

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-cross-ref.md",
			Frontmatter: `name: unravel-cross-ref
description: |
  Cross-reference reasoning agent. Reads N related modules together
  (sibling webpack chunks, IPC partners, dep cluster) and emits
  relational tags (calls / calledBy / ipc_partner / shares_state).
  Unlocks graph queries beyond per-module enrichment.
`,
			Body: `# unravel-cross-ref

Relational enrichment pass. Picks groups of likely-related modules,
reads them together, persists cross-references back to KB.

## Required commands (run via Bash)

` + "`unravel kb catalog apps`" + `, ` + "`unravel kb catalog search`" + `, ` + "`unravel kb catalog dump`" + `,
` + "`unravel kb catalog facts`" + `, ` + "`unravel kb enrich write-enrichment`" + `, Task.
`,
		},
		aihost.Asset{
			Path: "commands/xref.md",
			Frontmatter: `description: Cross-reference reasoning over module groups via unravel-cross-ref subagent
argument-hint: [app=<slug>] [group=webpack_chunk|ipc|dep_cluster|role:<R>] [max_groups=N] [group_size=N] [help=0|1]
allowed-tools: [Task, Bash]
`,
			Body: `# /unravel:xref

Cross-reference enrichment. Reads N related modules together, persists
relational tags. Delegates to ` + "`unravel-cross-ref`" + `.
`,
		},
	)
}
