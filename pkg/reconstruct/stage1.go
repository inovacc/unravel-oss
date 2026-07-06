package reconstruct

import (
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/jsdeob"
)

// Stage 1 cleanup patterns for Java decompiler artifacts.
var (
	// goto labels: "/* goto */ label_N:" or "/* goto */" comments
	javaGotoComment = regexp.MustCompile(`(?m)^\s*/\*\s*goto\s*\*/.*$`)
	javaLabelLine   = regexp.MustCompile(`(?m)^\s*label_\d+:\s*$`)

	// synthetic accessor methods: static /* synthetic */ TYPE access$NNN(...)
	javaSyntheticAccessor = regexp.MustCompile(`(?ms)^\s*static\s+/\*\s*synthetic\s*\*/\s+\w+\s+access\$\d+\s*\([^)]*\)\s*\{[^}]*\}\s*$`)
)

// StructuralCleanup performs deterministic, language-specific cleanup of
// decompiler output. This is stage 1 of the reconstruction pipeline:
// no AI involved, purely mechanical transformations.
func StructuralCleanup(content string, lang Language) string {
	switch lang {
	case LangJava:
		return cleanupJava(content)
	case LangJavaScript:
		return jsdeob.Beautify(content)
	default:
		return normalizeWhitespace(content)
	}
}

// cleanupJava removes jadx-specific artifacts from decompiled Java source.
func cleanupJava(content string) string {
	// Remove goto comments and labels.
	result := javaGotoComment.ReplaceAllString(content, "")
	result = javaLabelLine.ReplaceAllString(result, "")

	// Remove synthetic accessor methods.
	result = javaSyntheticAccessor.ReplaceAllString(result, "")

	return normalizeWhitespace(result)
}

// normalizeWhitespace collapses 3+ consecutive blank lines to 2 and trims
// trailing whitespace from each line.
func normalizeWhitespace(content string) string {
	lines := strings.Split(content, "\n")
	var out []string
	blankCount := 0

	for _, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "" {
			blankCount++
			if blankCount <= 2 {
				out = append(out, "")
			}
		} else {
			blankCount = 0
			out = append(out, trimmed)
		}
	}

	// Trim trailing blank lines.
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}

	return strings.Join(out, "\n") + "\n"
}
