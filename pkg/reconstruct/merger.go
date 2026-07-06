package reconstruct

import (
	"fmt"
	"regexp"
	"strings"
)

// importPatterns maps languages to their import statement regex patterns.
var importPatterns = map[Language]*regexp.Regexp{
	LangJava:       regexp.MustCompile(`(?m)^import\s+[\w.*]+;\s*$`),
	LangJavaScript: regexp.MustCompile(`(?m)^(?:import\s+.*(?:from\s+['"].*['"]|['"].*['"])\s*;?\s*$|const\s+\w+\s*=\s*require\(.*\)\s*;?\s*$)`),
	LangTypeScript: regexp.MustCompile(`(?m)^(?:import\s+.*(?:from\s+['"].*['"]|['"].*['"])\s*;?\s*$|const\s+\w+\s*=\s*require\(.*\)\s*;?\s*$)`),
	LangGo:         regexp.MustCompile(`(?ms)^import\s+\(.*?\)`),
	LangCSharp:     regexp.MustCompile(`(?m)^using\s+[\w.]+;\s*$`),
	LangPython:     regexp.MustCompile(`(?m)^(?:import|from)\s+.*$`),
}

// Merge reassembles chunked reconstruction output into a single source file.
// It deduplicates import blocks and overlap regions between adjacent chunks.
func Merge(chunks []Chunk, reconstructedChunks []string, lang Language) (string, error) {
	if len(reconstructedChunks) == 0 {
		return "", fmt.Errorf("no reconstructed chunks to merge")
	}

	if len(chunks) != len(reconstructedChunks) {
		return "", fmt.Errorf("chunk count mismatch: %d chunks vs %d reconstructed", len(chunks), len(reconstructedChunks))
	}

	// Single chunk: pass through unchanged.
	if len(reconstructedChunks) == 1 {
		return reconstructedChunks[0], nil
	}

	// Step 1: Extract imports from all chunks, deduplicate.
	allImports := make(map[string]bool)
	var strippedChunks []string

	pat := importPatterns[lang]

	for _, rc := range reconstructedChunks {
		if pat != nil {
			imports := pat.FindAllString(rc, -1)
			for _, imp := range imports {
				allImports[strings.TrimSpace(imp)] = true
			}
			// Strip imports from chunk body.
			stripped := pat.ReplaceAllString(rc, "")
			strippedChunks = append(strippedChunks, stripped)
		} else {
			strippedChunks = append(strippedChunks, rc)
		}
	}

	// Step 2: Deduplicate overlap regions between adjacent chunks.
	var bodyParts []string
	for i, sc := range strippedChunks {
		if i == 0 {
			bodyParts = append(bodyParts, sc)
			continue
		}

		// Find overlap between end of previous and start of current.
		prev := bodyParts[len(bodyParts)-1]
		deduped := deduplicateOverlap(prev, sc)
		bodyParts[len(bodyParts)-1] = deduped.before
		bodyParts = append(bodyParts, deduped.after)
	}

	// Step 3: Reassemble with imports at top.
	var sb strings.Builder

	if len(allImports) > 0 {
		// Collect and sort imports for deterministic output.
		var importLines []string
		for imp := range allImports {
			importLines = append(importLines, imp)
		}

		// Write imports.
		for _, imp := range importLines {
			sb.WriteString(imp)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	for i, part := range bodyParts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if i > 0 && sb.Len() > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString(trimmed)
	}

	return sb.String(), nil
}

// overlapResult holds the deduplicated before/after segments.
type overlapResult struct {
	before string
	after  string
}

// deduplicateOverlap finds matching lines between the end of prev and start of
// next, removing the duplicate from next.
func deduplicateOverlap(prev, next string) overlapResult {
	prevLines := strings.Split(prev, "\n")
	nextLines := strings.Split(next, "\n")

	// Try progressively larger overlaps (up to 50 lines).
	maxOverlap := min(min(len(prevLines), len(nextLines)), 50)

	bestOverlap := 0

	for size := 1; size <= maxOverlap; size++ {
		// Compare last `size` lines of prev with first `size` lines of next.
		match := true
		for j := 0; j < size; j++ {
			pLine := strings.TrimSpace(prevLines[len(prevLines)-size+j])
			nLine := strings.TrimSpace(nextLines[j])
			if pLine != nLine || pLine == "" {
				match = false
				break
			}
		}
		if match {
			bestOverlap = size
		}
	}

	if bestOverlap == 0 {
		return overlapResult{before: prev, after: next}
	}

	// Remove the overlapping lines from the start of next.
	trimmedNext := strings.Join(nextLines[bestOverlap:], "\n")
	return overlapResult{before: prev, after: trimmedNext}
}
