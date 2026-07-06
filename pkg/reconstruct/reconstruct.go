package reconstruct

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/store"
)

// DefaultOptions returns Options with standard defaults.
func DefaultOptions() Options {
	return Options{
		ChunkThreshold:  500,
		OverlapLines:    25,
		PromptVersion:   "v1",
		TimeoutPerChunk: 2 * time.Minute,
	}
}

// Run executes stage 1 of the reconstruction pipeline: read file, detect
// language, perform structural cleanup, chunk content, and build prompt.
//
// If cache is available and opts.NoCache is false, it checks for a cached
// result first. On cache hit, returns the cached result immediately.
//
// With MCPMode=true, Run returns a Result with Stage="awaiting-mcp" and
// the generated prompt for MCP host delegation. The MCP host processes
// the prompt, then calls Apply() with the reconstructed output.
func Run(path string, opts Options) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reconstruct: read %s: %w", path, err)
	}
	content := string(data)

	// Detect language.
	lang := opts.Language
	if lang == "" || lang == LangUnknown {
		ext := filepath.Ext(path)
		lang = DetectLanguage(content, ext)
	}

	// Cache lookup (before any processing).
	if !opts.NoCache {
		cacheKey := CacheKey(content, opts.PromptVersion)
		s := store.New()
		cached, err := CacheLookup(s, cacheKey)
		if err != nil {
			slog.Warn("reconstruct: cache lookup failed", "error", err)
		}
		if cached != nil {
			cached.Stage = "complete"
			return cached, nil
		}
	}

	// Stage 1: deterministic structural cleanup.
	cleaned := StructuralCleanup(content, lang)

	// Chunk the cleaned content.
	chunks := ChunkContent(cleaned, lang, opts)

	// Build the MCP delegation prompt.
	artifact := Artifact{
		Path:            path,
		OriginalContent: content,
		CleanedContent:  cleaned,
		Language:        lang,
	}
	prompt := BuildPrompt(artifact, chunks, lang)

	result := &Result{
		Prompt: prompt,
		Chunks: chunks,
		Stage:  "awaiting-mcp",
	}

	return result, nil
}

// Apply takes the reconstructed content from the MCP host and finalizes it
// with verification, merger (for multi-chunk), provenance, and cache storage.
//
// Flow:
//  1. If multiple chunks, call Merge() first
//  2. Call Verify() on result
//  3. If !Passed and RetryRecommended (first attempt), return retry prompt
//  4. If Passed or second attempt, write provenance and output files
//  5. Store in cache (unless NoCache)
func Apply(original, reconstructed string, lang Language, opts Options) (*Result, error) {
	if reconstructed == "" {
		return &Result{
			Stage:  "failed",
			Errors: []string{"empty reconstructed content"},
		}, nil
	}

	// Verify the reconstruction against the original.
	vr := Verify(original, reconstructed, lang)

	// If verification failed and retry is recommended (first attempt), return retry prompt.
	if !vr.Passed && vr.RetryRecommended && !opts.IsRetry {
		retryPrompt := BuildRetryPrompt(original, reconstructed, vr.Failures)
		return &Result{
			Stage:  "retry",
			Prompt: retryPrompt,
			Errors: vr.Failures,
		}, nil
	}

	// Build provenance (verified or not).
	verified := vr.Passed
	var failures []string
	if !verified {
		failures = vr.Failures
	}
	prov := NewProvenance(original, reconstructed, verified, failures, opts)
	header := prov.Header(lang)

	finalContent := header + "\n" + reconstructed

	// Write output files if OutputDir is set.
	if opts.OutputDir != "" {
		if err := writeOutputFiles(opts.OutputDir, original, finalContent, lang); err != nil {
			slog.Warn("reconstruct: write output failed", "error", err)
		}
	}

	// Cache the result.
	if !opts.NoCache {
		result := &Result{
			Content:    finalContent,
			Provenance: prov,
			Stage:      "complete",
		}
		cacheKey := CacheKey(original, opts.PromptVersion)
		s := store.New()
		if err := CacheStore(s, cacheKey, result); err != nil {
			slog.Warn("reconstruct: cache store failed", "error", err)
		}
	}

	return &Result{
		Content:    finalContent,
		Provenance: prov,
		Stage:      "complete",
	}, nil
}

// ApplyChunked takes multiple reconstructed chunks, merges them, then runs
// Apply on the merged result.
func ApplyChunked(original string, chunks []Chunk, reconstructedChunks []string, lang Language, opts Options) (*Result, error) {
	merged, err := Merge(chunks, reconstructedChunks, lang)
	if err != nil {
		return &Result{
			Stage:  "failed",
			Errors: []string{fmt.Sprintf("merge failed: %v", err)},
		}, nil
	}
	return Apply(original, merged, lang, opts)
}

// writeOutputFiles writes original to decompiled/ and reconstructed to reconstructed/.
func writeOutputFiles(outputDir, original, reconstructed string, lang Language) error {
	ext := langExtension(lang)
	baseName := "source" + ext

	decompiledDir := filepath.Join(outputDir, "decompiled")
	reconstructedDir := filepath.Join(outputDir, "reconstructed")

	if err := os.MkdirAll(decompiledDir, 0o755); err != nil {
		return fmt.Errorf("create decompiled dir: %w", err)
	}
	if err := os.MkdirAll(reconstructedDir, 0o755); err != nil {
		return fmt.Errorf("create reconstructed dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(decompiledDir, baseName), []byte(original), 0o644); err != nil {
		return fmt.Errorf("write decompiled: %w", err)
	}
	if err := os.WriteFile(filepath.Join(reconstructedDir, baseName), []byte(reconstructed), 0o644); err != nil {
		return fmt.Errorf("write reconstructed: %w", err)
	}

	return nil
}

// langExtension returns the conventional file extension for a language.
func langExtension(lang Language) string {
	switch lang {
	case LangJava:
		return ".java"
	case LangJavaScript:
		return ".js"
	case LangTypeScript:
		return ".ts"
	case LangCSharp:
		return ".cs"
	case LangGo:
		return ".go"
	case LangPython:
		return ".py"
	default:
		return ".txt"
	}
}
