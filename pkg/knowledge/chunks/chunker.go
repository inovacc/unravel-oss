/*
Copyright (c) 2026 Security Research

Package chunks implements semantic chunking for multi-language source code
and documentation. It identifies logical boundaries (Markdown headings,
JSON keys, code blocks) to break large files into searchable, high-precision
slices. Derived from context-mode patterns (D-40-SEMANTIC-CHUNKING).
*/
package chunks

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Chunk represents a semantic slice of a module.
type Chunk struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	HasCode bool   `json:"has_code"`
}

const maxChunkBytes = 4096

// Chunker provides strategies for different file types.
type Chunker struct{}

// New creates a new semantic chunker.
func New() *Chunker { return &Chunker{} }

// ChunkFile partitions a file body into semantic slices based on its extension.
func (c *Chunker) ChunkFile(path string, body []byte) []Chunk {
	ext := strings.ToLower(filepath.Ext(path))
	content := string(body)

	switch ext {
	case ".md", ".mdx":
		return c.chunkMarkdown(content)
	case ".json":
		return c.chunkJSON(content)
	default:
		// Fallback for code files and plain text
		return c.chunkGenericCode(content)
	}
}

// ─────────────────────────────────────────────────────────
// Markdown Chunker
// ─────────────────────────────────────────────────────────

var headingRe = regexp.MustCompile(`(?m)^(#{1,4})\s+(.+)$`)
var codeBlockRe = regexp.MustCompile("(?s)```.*?```")

func (c *Chunker) chunkMarkdown(text string) []Chunk {
	var chunks []Chunk
	lines := strings.Split(text, "\n")

	type heading struct {
		level int
		text  string
	}
	var stack []heading
	var currentLines []string
	var currentTitle string

	flush := func() {
		joined := strings.TrimSpace(strings.Join(currentLines, "\n"))
		if joined == "" {
			return
		}

		title := currentTitle
		if len(stack) > 0 {
			var titles []string
			for _, h := range stack {
				titles = append(titles, h.text)
			}
			title = strings.Join(titles, " > ")
		}

		if title == "" {
			title = "Intro"
		}

		hasCode := codeBlockRe.MatchString(joined)
		chunks = append(chunks, Chunk{Title: title, Content: joined, HasCode: hasCode})
		currentLines = nil
	}

	for _, line := range lines {
		if m := headingRe.FindStringSubmatch(line); m != nil {
			flush()
			level := len(m[1])
			text := strings.TrimSpace(m[2])

			// Pop deeper levels
			for len(stack) > 0 && stack[len(stack)-1].level >= level {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, heading{level: level, text: text})
			currentTitle = text
		}
		currentLines = append(currentLines, line)
	}

	flush()
	return chunks
}

// ─────────────────────────────────────────────────────────
// JSON Chunker
// ─────────────────────────────────────────────────────────

func (c *Chunker) chunkJSON(text string) []Chunk {
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return c.chunkGenericCode(text)
	}

	var chunks []Chunk
	c.walkJSON(parsed, nil, &chunks)
	return chunks
}

func (c *Chunker) walkJSON(v any, path []string, out *[]Chunk) {
	title := "(root)"
	if len(path) > 0 {
		title = strings.Join(path, " > ")
	}

	serialized, _ := json.MarshalIndent(v, "", "  ")

	// If small enough or primitive, emit.
	if len(serialized) <= maxChunkBytes {
		*out = append(*out, Chunk{Title: title, Content: string(serialized), HasCode: true})
		return
	}

	// If object, recurse
	if m, ok := v.(map[string]any); ok {
		for k, val := range m {
			c.walkJSON(val, append(path, k), out)
		}
		return
	}

	// If array, emit whole thing (batching would be Phase 2)
	*out = append(*out, Chunk{Title: title, Content: string(serialized), HasCode: true})
}

// ─────────────────────────────────────────────────────────
// Generic Code Chunker (Line-based)
// ─────────────────────────────────────────────────────────

func (c *Chunker) chunkGenericCode(text string) []Chunk {
	lines := strings.Split(text, "\n")
	if len(text) <= maxChunkBytes {
		return []Chunk{{Title: "Source", Content: text, HasCode: true}}
	}

	var chunks []Chunk
	linesPerChunk := 50
	overlap := 5

	for i := 0; i < len(lines); i += (linesPerChunk - overlap) {
		end := min(i+linesPerChunk, len(lines))

		slice := lines[i:end]
		content := strings.Join(slice, "\n")
		title := fmt.Sprintf("Lines %d-%d", i+1, end)

		chunks = append(chunks, Chunk{Title: title, Content: content, HasCode: true})

		if end == len(lines) {
			break
		}
	}

	return chunks
}
