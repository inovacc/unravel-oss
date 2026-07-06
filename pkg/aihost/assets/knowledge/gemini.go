/*
Copyright (c) 2026 Security Research
*/
package knowledge

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "skills/transpile/GEMINI.md",
			Body: `# unravel — Unified Conversion & Analysis Context

This Gemini CLI extension exposes the unravel MCP server for deep
reverse-engineering and code conversion.

## Capabilities

1. **JS Module Enrichment** — reverse-engineer minified JS modules
   out of the Postgres knowledge base.
2. **Multi-language Transpilation** — convert C++, Java, Python, and
   TypeScript source code into idiomatic Go.
3. **Codebase Analysis** — perform deep static analysis (LOC,
   dependencies, subsystems) to plan large-scale ports.
4. **Auto-Routing** — automatically select between high-fidelity
   transpilation and clean-room porting.

See the respective skills for detailed workflows.
`,
		},
	)
}
