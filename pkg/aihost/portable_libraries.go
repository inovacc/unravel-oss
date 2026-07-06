/*
Copyright (c) 2026 Security Research
*/

// portable_libraries.go synthesizes "library" skills that preserve command and
// agent discovery on hosts whose install surface is skills-only (codex, gemini
// have no native slash-command / agent surface). Each library is a SKILL.md
// that indexes the registered commands (or agents) so an operator on those
// hosts can still find and adapt them. Synthesized in-code (no embed.FS).

package aihost

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	CommandLibrarySkillPath = "skills/unravel-command-library/SKILL.md"
	AgentLibrarySkillPath   = "skills/unravel-agent-library/SKILL.md"
)

// PortableLibrarySkills returns the synthesized command- and agent-library
// skills. They are NOT in AllAssets() (they are derived, not registered);
// hosts opt in by yielding them from Walk.
func PortableLibrarySkills() []Asset {
	return []Asset{
		portableLibrarySkill(
			KindCommand,
			CommandLibrarySkillPath,
			"unravel-command-library",
			"Use bundled unravel slash-command prompts as portable workflow references.",
			"Command Library",
			"Use these entries when the user asks for a slash-command style workflow. Read the matching command asset by name, adapt its instructions to the current host, and execute the workflow with the active tools available in this session.",
		),
		portableLibrarySkill(
			KindAgent,
			AgentLibrarySkillPath,
			"unravel-agent-library",
			"Use bundled unravel agent prompts as portable subagent-style references.",
			"Agent Library",
			"Use these entries when the task benefits from a specialist role. Read the matching agent prompt by name, apply its role, inputs, workflow, output contract, and safety rules in the current host, and adapt host-specific tool names where needed.",
		),
	}
}

func portableLibrarySkill(kind Kind, assetPath, skillName, description, title, guidance string) Asset {
	assets := AssetsByKind(kind)
	sort.Slice(assets, func(i, j int) bool { return assets[i].Path < assets[j].Path })

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", title, guidance)
	b.WriteString("## Index\n\n")
	for _, a := range assets {
		name := strings.TrimSuffix(path.Base(a.Path), path.Ext(a.Path))
		desc := frontmatterDescription(a.Frontmatter)
		if desc == "" {
			desc = "No description provided."
		}
		fmt.Fprintf(&b, "- `%s` (`%s`) - %s\n", name, a.Path, desc)
	}
	if len(assets) == 0 {
		b.WriteString("- No assets are registered for this library.\n")
	}
	b.WriteString("\n## Adaptation Rules\n\n")
	b.WriteString("- Keep the source prompt's behavioral contract, but map Claude-only command, agent, and tool syntax onto this host's available tools.\n")
	b.WriteString("- Prefer the active unravel MCP server (tools named `mcp__unravel__*` / `unravel_*`) when available.\n")
	b.WriteString("- If a source prompt references a bundled workflow, reference, or template path, treat it as bundled prompt material and load only the parts needed for the current task.\n")

	// Frontmatter ends with '\n' — required so Render closes the block correctly.
	return Asset{
		Kind:        KindSkill,
		Path:        assetPath,
		Frontmatter: fmt.Sprintf("name: %s\ndescription: %s\n", skillName, description),
		Body:        b.String(),
	}
}

func frontmatterDescription(fm string) string {
	for _, line := range strings.Split(fm, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "description:") {
			continue
		}
		desc := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
		return strings.Trim(desc, `"'`)
	}
	return ""
}
