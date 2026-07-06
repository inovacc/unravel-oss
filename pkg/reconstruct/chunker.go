package reconstruct

import (
	"fmt"
	"regexp"
	"strings"
)

// Function/class boundary patterns per language.
var (
	javaBoundary = regexp.MustCompile(`(?m)^\s*(public|private|protected)?\s*(static\s+)?(class|interface|enum|[\w<>\[\]]+\s+\w+\s*\()`)
	jsBoundary   = regexp.MustCompile(`(?m)^\s*(export\s+(default\s+)?)?(function\s+\w+|class\s+\w+|const\s+\w+\s*=\s*(async\s+)?\()`)
	goBoundary   = regexp.MustCompile(`(?m)^(func\s+|type\s+\w+\s+(struct|interface))`)
	csBoundary   = regexp.MustCompile(`(?m)^\s*(public|private|internal|protected)\s+(static\s+)?(class|struct|interface|[\w<>\[\]]+\s+\w+\s*\()`)
	pyBoundary   = regexp.MustCompile(`(?m)^(class\s+\w+|def\s+\w+)`)
)

// ChunkContent splits source content into chunks for reconstruction.
// Files at or below opts.ChunkThreshold lines are returned as a single chunk.
// Larger files are split at function/class boundaries with overlap context.
func ChunkContent(content string, lang Language, opts Options) []Chunk {
	threshold := opts.ChunkThreshold
	if threshold <= 0 {
		threshold = 500
	}
	overlap := opts.OverlapLines
	if overlap <= 0 {
		overlap = 25
	}

	lines := strings.Split(content, "\n")

	if len(lines) <= threshold {
		return []Chunk{{
			Content:   content,
			StartLine: 1,
			EndLine:   len(lines),
			Index:     0,
			Total:     1,
		}}
	}

	// Find function/class boundaries.
	boundaries := findBoundaries(lines, lang)

	// If no boundaries found, fall back to blank-line splitting.
	if len(boundaries) == 0 {
		boundaries = findBlankLineBoundaries(lines, threshold)
	}

	// If still no boundaries, split at fixed intervals.
	if len(boundaries) == 0 {
		boundaries = fixedBoundaries(len(lines), threshold)
	}

	return buildChunks(lines, boundaries, overlap)
}

// findBoundaries finds function/class boundary line indices for the given language.
func findBoundaries(lines []string, lang Language) []int {
	var pattern *regexp.Regexp
	switch lang {
	case LangJava:
		pattern = javaBoundary
	case LangJavaScript, LangTypeScript:
		pattern = jsBoundary
	case LangGo:
		pattern = goBoundary
	case LangCSharp:
		pattern = csBoundary
	case LangPython:
		pattern = pyBoundary
	default:
		return nil
	}

	var bounds []int
	for i, line := range lines {
		if pattern.MatchString(line) {
			bounds = append(bounds, i)
		}
	}
	return bounds
}

// findBlankLineBoundaries finds blank lines nearest to threshold multiples.
func findBlankLineBoundaries(lines []string, threshold int) []int {
	var bounds []int
	for target := threshold; target < len(lines); target += threshold {
		best := -1
		bestDist := threshold / 2 // search within half-threshold distance
		for i := target - bestDist; i <= target+bestDist && i < len(lines); i++ {
			if i < 0 {
				continue
			}
			if strings.TrimSpace(lines[i]) == "" {
				dist := target - i
				if dist < 0 {
					dist = -dist
				}
				if best == -1 || dist < bestDist {
					best = i
					bestDist = dist
				}
			}
		}
		if best > 0 {
			bounds = append(bounds, best)
		}
	}
	return bounds
}

// fixedBoundaries creates boundaries at fixed intervals as last resort.
func fixedBoundaries(totalLines, threshold int) []int {
	var bounds []int
	for i := threshold; i < totalLines; i += threshold {
		bounds = append(bounds, i)
	}
	return bounds
}

// buildChunks creates Chunk slices from lines and boundary positions with overlap.
func buildChunks(lines []string, boundaries []int, overlap int) []Chunk {
	// Filter boundaries that are too close together.
	var filtered []int
	last := 0
	minGap := 50 // minimum lines between boundaries
	for _, b := range boundaries {
		if b-last >= minGap {
			filtered = append(filtered, b)
			last = b
		}
	}
	if len(filtered) == 0 {
		filtered = boundaries
	}

	// Build chunk ranges: [start, end) pairs.
	type rng struct{ start, end int }
	var ranges []rng

	prev := 0
	for _, b := range filtered {
		if b > prev {
			ranges = append(ranges, rng{prev, b})
			prev = b
		}
	}
	if prev < len(lines) {
		ranges = append(ranges, rng{prev, len(lines)})
	}

	if len(ranges) == 0 {
		return []Chunk{{
			Content:   strings.Join(lines, "\n"),
			StartLine: 1,
			EndLine:   len(lines),
			Index:     0,
			Total:     1,
		}}
	}

	total := len(ranges)
	chunks := make([]Chunk, total)

	// Track function names seen in previous chunks for context headers.
	var priorFuncs []string

	for i, r := range ranges {
		// Add overlap from previous chunk.
		overlapStart := r.start
		if i > 0 && overlap > 0 {
			overlapStart = max(r.start-overlap, ranges[i-1].start)
		}

		chunkLines := lines[overlapStart:r.end]

		// Build context header summarizing prior content.
		ctx := ""
		if i > 0 && len(priorFuncs) > 0 {
			ctx = fmt.Sprintf("// Context: prior functions: %s", strings.Join(priorFuncs, ", "))
		}

		chunks[i] = Chunk{
			Content:   strings.Join(chunkLines, "\n"),
			StartLine: overlapStart + 1,
			EndLine:   r.end,
			Context:   ctx,
			Index:     i,
			Total:     total,
		}

		// Collect function names from this chunk for next chunk's context.
		for _, line := range lines[r.start:r.end] {
			if fn := extractFuncName(line); fn != "" {
				priorFuncs = append(priorFuncs, fn)
			}
		}
	}

	return chunks
}

var funcNamePattern = regexp.MustCompile(`(?:func|function|def|void|int|String|public|private)\s+(\w+)\s*\(`)

// extractFuncName pulls a function name from a line, if present.
func extractFuncName(line string) string {
	m := funcNamePattern.FindStringSubmatch(line)
	if len(m) > 1 {
		// Skip common non-function keywords.
		switch m[1] {
		case "if", "for", "while", "switch", "class", "interface", "static":
			return ""
		}
		return m[1]
	}
	return ""
}
