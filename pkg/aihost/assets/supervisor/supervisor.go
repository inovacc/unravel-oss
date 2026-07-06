/*
Copyright (c) 2026 Security Research
*/
package supervisor

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-supervisor.md",
			Frontmatter: `name: unravel-supervisor
description: |
  Master orchestrator and lifecycle manager for the unravel agent fleet.
  Manages the host-singleton daemon, handles global configuration,
  and coordinates complex multi-agent workflows.
`,
			Body: `# unravel-supervisor

Top-level lifecycle manager. Your role is to coordinate the other agents
and ensure the unravel environment is performing optimally.
`,
		},
		aihost.Asset{
			Path: "commands/pending.md",
			Frontmatter: `description: Show pending modules and enrichment progress summary
allowed-tools: [Bash]
`,
			Body: `# /unravel:pending

Show enrichment progress summary and list oldest pending modules via
` + "`unravel kb catalog stats`" + ` and ` + "`unravel kb enrich pending`" + `.
`,
		},
		aihost.Asset{
			Path: "commands/retry.md",
			Frontmatter: `description: Retry failed enrichment batches
allowed-tools: [Bash, Task]
`,
			Body: `# /unravel:retry

Retry failed enrichment batches.
`,
		},
	)
}
