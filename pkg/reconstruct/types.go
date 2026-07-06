// Package reconstruct provides AI-powered code reconstruction via MCP delegation.
package reconstruct

import "time"

// Language identifies the programming language of source code.
type Language string

const (
	LangJava       Language = "java"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangCSharp     Language = "csharp"
	LangGo         Language = "go"
	LangPython     Language = "python"
	LangUnknown    Language = "unknown"
)

// Options configures the reconstruction pipeline.
type Options struct {
	ChunkThreshold  int           // lines before chunking (default 500)
	OverlapLines    int           // overlap between chunks (default 25)
	Language        Language      // override auto-detection
	MCPMode         bool          // if true, return prompt instead of executing
	OutputDir       string        // teardown output directory
	PromptVersion   string        // for cache key
	TimeoutPerChunk time.Duration // default 2min
	NoCache         bool          // skip cache lookup/store
	IsRetry         bool          // true when applying a retry attempt
}

// Artifact represents a single source file entering the pipeline.
type Artifact struct {
	Path            string
	OriginalContent string
	CleanedContent  string
	Language        Language
	SourceTool      string // e.g. "jadx", "ilspycmd", "webpack"
}

// Chunk represents a portion of source code for chunked reconstruction.
type Chunk struct {
	Content   string
	StartLine int
	EndLine   int
	Context   string // summary header for cross-chunk context
	Index     int
	Total     int
}

// Provenance tracks how a reconstruction result was produced.
type Provenance struct {
	Source          string
	OriginalHash    string // SHA-256 of original content
	Confidence      float64
	Model           string
	PromptVersion   string
	ChunkBoundaries []int
	StageDurations  map[string]time.Duration
	Timestamp       time.Time
	Verified        bool
	VerifyFailures  []string
}

// Result holds the output of a reconstruction operation.
type Result struct {
	Prompt     string // MCP delegation prompt (stage 2)
	Content    string // reconstructed content (after apply)
	Provenance *Provenance
	Stage      string // "awaiting-mcp", "retry", "complete", "failed"
	Chunks     []Chunk
	Errors     []string
}
