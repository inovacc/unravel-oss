package reconstruct

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/store"
)

func TestPipelineEndToEnd(t *testing.T) {
	// Run stage 1 on testdata Sample.java.
	opts := DefaultOptions()
	opts.MCPMode = true
	opts.NoCache = true

	result, err := Run("testdata/input/Sample.java", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Stage != "awaiting-mcp" {
		t.Fatalf("expected stage awaiting-mcp, got %s", result.Stage)
	}
	if result.Prompt == "" {
		t.Fatal("expected non-empty prompt")
	}
	if len(result.Chunks) == 0 {
		t.Fatal("expected at least 1 chunk")
	}

	// Read original for Apply.
	origData, err := os.ReadFile("testdata/input/Sample.java")
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	original := string(origData)

	// Simulate MCP host returning a well-formed reconstructed version.
	reconstructed := `package com.example.app;

import java.util.ArrayList;
import java.util.List;

/**
 * Manages a collection of string items with basic CRUD operations.
 */
public class DataManager {

    private List<String> items;

    /**
     * Creates a new DataManager with an empty item list.
     */
    public DataManager() {
        this.items = new ArrayList<>();
    }

    /**
     * Processes all items by printing each non-null item (trimmed).
     */
    public void processItems() {
        for (int i = 0; i < this.items.size(); i++) {
            String item = this.items.get(i);
            if (item == null) {
                continue;
            }
            System.out.println(item.trim());
        }
    }

    /**
     * Adds a non-null, non-empty item to the collection.
     */
    public void addItem(String item) {
        if (item != null && !item.isEmpty()) {
            this.items.add(item);
        }
    }

    /**
     * Returns the number of items in the collection.
     */
    public int getCount() {
        return this.items.size();
    }
}
`

	// Apply with output dir.
	outDir := t.TempDir()
	opts.OutputDir = outDir
	applyResult, err := Apply(original, reconstructed, LangJava, opts)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if applyResult.Stage != "complete" {
		t.Fatalf("expected stage complete, got %s (errors: %v)", applyResult.Stage, applyResult.Errors)
	}
	if applyResult.Provenance == nil {
		t.Fatal("expected provenance to be populated")
	}
	if applyResult.Content == "" {
		t.Fatal("expected non-empty content")
	}

	// Verify output files were written.
	decompiledPath := filepath.Join(outDir, "decompiled", "source.java")
	reconstructedPath := filepath.Join(outDir, "reconstructed", "source.java")

	if _, err := os.Stat(decompiledPath); err != nil {
		t.Fatalf("decompiled file not written: %v", err)
	}
	if _, err := os.Stat(reconstructedPath); err != nil {
		t.Fatalf("reconstructed file not written: %v", err)
	}
}

func TestPipelineCacheHit(t *testing.T) {
	opts := DefaultOptions()
	opts.MCPMode = true
	opts.NoCache = false // Enable cache

	// First run -- should be a cache miss (fresh).
	result1, err := Run("testdata/input/Sample.java", opts)
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	if result1.Stage != "awaiting-mcp" {
		t.Fatalf("expected awaiting-mcp on first run, got %s", result1.Stage)
	}

	// Store a result in cache for this input.
	origData, _ := os.ReadFile("testdata/input/Sample.java")
	cacheKey := CacheKey(string(origData), opts.PromptVersion)

	// Simulate Apply storing to cache by doing Apply with cache enabled.
	cachedResult := &Result{
		Content: "// cached content",
		Stage:   "complete",
		Provenance: &Provenance{
			Verified:      true,
			PromptVersion: opts.PromptVersion,
		},
	}

	// Store directly.
	storeInstance := newTestStore(t)
	if err := CacheStore(storeInstance, cacheKey, cachedResult); err != nil {
		t.Fatalf("CacheStore: %v", err)
	}

	// Second run -- should hit cache.
	// We need to check CacheLookup directly since Run creates its own store.
	lookup, err := CacheLookup(storeInstance, cacheKey)
	if err != nil {
		t.Fatalf("CacheLookup: %v", err)
	}
	if lookup == nil {
		t.Fatal("expected cache hit, got miss")
	}
	if lookup.Content != "// cached content" {
		t.Fatalf("expected cached content, got %q", lookup.Content)
	}
}

func TestPipelineVerificationRetry(t *testing.T) {
	origData, err := os.ReadFile("testdata/input/Sample.java")
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	original := string(origData)

	opts := DefaultOptions()
	opts.NoCache = true

	// First apply with badly reconstructed code (missing symbols).
	badReconstruction := `package com.example.app;

public class Foo {
    public void bar() {
        System.out.println("hello");
    }
}
`

	result, err := Apply(original, badReconstruction, LangJava, opts)
	if err != nil {
		t.Fatalf("Apply (bad): %v", err)
	}

	if result.Stage != "retry" {
		t.Fatalf("expected stage retry, got %s (errors: %v)", result.Stage, result.Errors)
	}
	if result.Prompt == "" {
		t.Fatal("expected retry prompt to be non-empty")
	}
	if !strings.Contains(result.Prompt, "Retry") {
		t.Fatal("expected retry prompt to contain 'Retry'")
	}

	// Second apply (retry) with proper reconstruction.
	goodReconstruction := `package com.example.app;

import java.util.ArrayList;
import java.util.List;

public class DataManager {

    private List<String> items;

    public DataManager() {
        this.items = new ArrayList<>();
    }

    public void processItems() {
        for (int i = 0; i < this.items.size(); i++) {
            String item = this.items.get(i);
            if (item == null) {
                continue;
            }
            System.out.println(item.trim());
        }
    }

    public void addItem(String item) {
        if (item != null && !item.isEmpty()) {
            this.items.add(item);
        }
    }

    public int getCount() {
        return this.items.size();
    }
}
`

	opts.IsRetry = true
	retryResult, err := Apply(original, goodReconstruction, LangJava, opts)
	if err != nil {
		t.Fatalf("Apply (retry): %v", err)
	}

	if retryResult.Stage != "complete" {
		t.Fatalf("expected stage complete after retry, got %s (errors: %v)", retryResult.Stage, retryResult.Errors)
	}
}

func TestBatchProcessing(t *testing.T) {
	opts := DefaultOptions()
	opts.MCPMode = true
	opts.NoCache = true

	var progressCalls []string
	progress := func(current, total int, path, status string) {
		progressCalls = append(progressCalls, path)
	}

	results, err := RunBatch("testdata/input", opts, progress)
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least 1 result from batch")
	}
	if len(progressCalls) == 0 {
		t.Fatal("expected progress callback to be called")
	}
	if len(progressCalls) != len(results) {
		t.Fatalf("progress calls (%d) != results (%d)", len(progressCalls), len(results))
	}

	// All should be awaiting-mcp (stage 1 only).
	for i, r := range results {
		if r.Stage != "awaiting-mcp" {
			t.Errorf("result %d: expected stage awaiting-mcp, got %s", i, r.Stage)
		}
	}
}

// newTestStore creates a store.Store using a temp directory for testing.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	os.Setenv("LOCALAPPDATA", dir)
	t.Cleanup(func() { os.Unsetenv("LOCALAPPDATA") })
	return store.New()
}
