/*
Copyright (c) 2026 Security Research
*/
package knowledge

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-kb-auditor.md",
			Frontmatter: `name: unravel-kb-auditor
description: |
  AI adjudication agent for the knowledge base. Scrutinizes existing
  enrichment claims (summaries, roles, deps) via an iterative,
  adversarial loop. Records verdicts as structured findings with
  evidence and stability metrics (iteration counts).
`,
			Body: `# unravel-kb-auditor

Knowledge base adjudicator. Your role is to verify the accuracy of
existing enrichment data in the unravel KB. You operate in two modes
within an adversarial loop:

1. **Auditor**: Form an interim verdict (affirm/contradict/augment)
   based on the evidence (code body, symbols, deps).
2. **Challenger**: Attempt to refute the Auditor's claim by finding
   counter-evidence or identifying ambiguities.

## Required commands (run via Bash)

` + "`unravel kb catalog apps`" + `, ` + "`unravel kb catalog dump`" + `, ` + "`unravel kb catalog facts`" + `,
` + "`unravel kb findings list`" + `, ` + "`unravel kb findings resolve`" + `,
` + "`unravel kb findings summary`" + `.

Recording a new finding verdict and logging each adversarial-loop
iteration are not yet exposed as CLI subcommands (` + "`kb findings`" + ` only
ships ` + "`list`" + `/` + "`resolve`" + `/` + "`show`" + `/` + "`summary`" + `); persist interim verdicts via
` + "`unravel kb catalog query`" + ` against the findings tables until a
dedicated write verb lands.
`,
		},
		aihost.Asset{
			Path: "commands/audit-kb.md",
			Frontmatter: `description: Scrutinize KB claims via an adversarial loop-until-stable process via unravel-kb-auditor subagent
argument-hint: [app=<slug>] [module=<id>] [target=summary|role|side_effect|dep|input|output] [max_iter=6] [k=2] [auto=0|1] [help=0|1]
allowed-tools: [Task]
`,
			Body: `# /unravel:audit-kb

Orchestrate an adversarial AI adjudication loop over KB claims.
Delegates to the ` + "`unravel-kb-auditor`" + ` subagent.

## Arguments

| key      | default | meaning                                              |
|----------|---------|--------------------------------------------------------|
| app      | (none)  | KB app slug to audit (required)                      |
| module   | (none)  | module id to audit (optional; audits app if omitted) |
| target   | summary | field to scrutinize                                  |
| max_iter | 6       | max loop passes                                      |
| k        | 2       | consecutive stable passes required to converge       |
| auto     | 0       | if 1, run a single-pass lightweight self-check       |
| help     | 0       | print this table and exit                            |

## Workflow

1. **Target Selection** - identify the claims to audit based on ` + "`app`" + ` and ` + "`module`" + `.
2. **Adversarial Loop** - for each claim, trigger the loop:
   - Propose verdict (Auditor).
   - Challenge verdict (Challenger).
   - Repeat until stable for ` + "`k`" + ` passes or ` + "`max_iter`" + ` hit.
   - If ` + "`auto=1`" + `, run only a single pass (` + "`max_iter=1`" + `).
3. **Record Findings** - persist final verdicts and per-iteration evidence via ` + "`unravel kb catalog query`" + ` against the findings tables (` + "`kb findings`" + ` does not yet ship a write verb).
`,
		},
	)
}
