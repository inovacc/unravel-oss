// Package summaryview renders the enriched meaning layer (summary/role/tags)
// for kb_search consumers, shared by the CLI and the MCP tool so both surfaces
// behave identically.
package summaryview

import (
	"regexp"
	"strings"
)

// rePlaceholderName matches the Teams numeric placeholder module names.
var rePlaceholderName = regexp.MustCompile(`^teams_module_[0-9]+$`)

// DisplayName returns the name to show for a module: the synthetic_name when
// the raw name is a Teams numeric placeholder and a non-empty synthetic_name
// exists, otherwise the raw name unchanged. A real (non-placeholder) name is
// never overridden.
func DisplayName(name, syntheticName string) string {
	if strings.TrimSpace(syntheticName) != "" && rePlaceholderName.MatchString(name) {
		return strings.TrimSpace(syntheticName)
	}
	return name
}

// Prefer reports whether the enriched summary should be shown instead of a
// code snippet (true iff summary has non-whitespace content).
func Prefer(summary string) bool {
	return strings.TrimSpace(summary) != ""
}

// Line composes the single consumer-facing view from the enriched fields:
// "[role] summary {tags}", omitting role/tags when empty. Caller is
// responsible for any width truncation.
func Line(summary, role, tags string) string {
	s := strings.TrimSpace(summary)
	if r := strings.TrimSpace(role); r != "" {
		s = "[" + r + "] " + s
	}
	if t := strings.TrimSpace(tags); t != "" {
		s += " {" + t + "}"
	}
	return s
}
