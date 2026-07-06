package reconstruct

import (
	"strings"
	"testing"
)

func TestMergeSingleChunk(t *testing.T) {
	chunks := []Chunk{{Content: "original", Index: 0, Total: 1}}
	reconstructed := []string{"public class Foo {\n    void bar() {}\n}"}

	result, err := Merge(chunks, reconstructed, LangJava)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != reconstructed[0] {
		t.Errorf("single chunk should pass through unchanged.\ngot:  %q\nwant: %q", result, reconstructed[0])
	}
}

func TestMergeTwoChunksDeduplicatesImportsJava(t *testing.T) {
	chunks := []Chunk{
		{Content: "chunk1", Index: 0, Total: 2, StartLine: 1, EndLine: 10},
		{Content: "chunk2", Index: 1, Total: 2, StartLine: 11, EndLine: 20},
	}
	recon := []string{
		"import java.util.List;\nimport java.util.Map;\n\npublic class Foo {\n    void a() {}\n}",
		"import java.util.List;\nimport java.util.Set;\n\npublic class Bar {\n    void b() {}\n}",
	}

	result, err := Merge(chunks, recon, LangJava)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// java.util.List should appear exactly once
	count := strings.Count(result, "import java.util.List;")
	if count != 1 {
		t.Errorf("expected import java.util.List to appear once, got %d times", count)
	}

	// Both Map and Set should be present
	if !strings.Contains(result, "import java.util.Map;") {
		t.Error("missing import java.util.Map")
	}
	if !strings.Contains(result, "import java.util.Set;") {
		t.Error("missing import java.util.Set")
	}
}

func TestMergeTwoChunksDeduplicatesImportsJS(t *testing.T) {
	chunks := []Chunk{
		{Content: "chunk1", Index: 0, Total: 2},
		{Content: "chunk2", Index: 1, Total: 2},
	}
	recon := []string{
		"import React from 'react';\nimport { useState } from 'react';\n\nfunction App() { return null; }",
		"import React from 'react';\nimport { useEffect } from 'react';\n\nfunction Detail() { return null; }",
	}

	result, err := Merge(chunks, recon, LangJavaScript)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := strings.Count(result, "import React from 'react';")
	if count != 1 {
		t.Errorf("expected React import once, got %d", count)
	}
}

func TestMergeOverlapDeduplication(t *testing.T) {
	chunks := []Chunk{
		{Content: "chunk1", Index: 0, Total: 2, StartLine: 1, EndLine: 30},
		{Content: "chunk2", Index: 1, Total: 2, StartLine: 21, EndLine: 50},
	}

	// Last 5 lines of chunk 0 same as first 5 lines of chunk 1
	overlap := "    void shared1() {}\n    void shared2() {}\n    void shared3() {}\n    void shared4() {}\n    void shared5() {}"
	recon := []string{
		"public class Foo {\n    void unique1() {}\n" + overlap,
		overlap + "\n    void unique2() {}\n}",
	}

	result, err := Merge(chunks, recon, LangJava)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// shared functions should appear exactly once
	for i := 1; i <= 5; i++ {
		fname := "shared" + string(rune('0'+i))
		count := strings.Count(result, fname)
		if count != 1 {
			t.Errorf("expected %s to appear once, got %d", fname, count)
		}
	}

	// unique functions must be present
	if !strings.Contains(result, "unique1") {
		t.Error("missing unique1")
	}
	if !strings.Contains(result, "unique2") {
		t.Error("missing unique2")
	}
}

func TestMergePreservesFunctionOrder(t *testing.T) {
	chunks := []Chunk{
		{Content: "chunk1", Index: 0, Total: 2},
		{Content: "chunk2", Index: 1, Total: 2},
	}
	recon := []string{
		"void alpha() {}\nvoid beta() {}",
		"void gamma() {}\nvoid delta() {}",
	}

	result, err := Merge(chunks, recon, LangJava)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aIdx := strings.Index(result, "alpha")
	bIdx := strings.Index(result, "beta")
	gIdx := strings.Index(result, "gamma")
	dIdx := strings.Index(result, "delta")

	if aIdx >= bIdx || bIdx >= gIdx || gIdx >= dIdx {
		t.Errorf("function order not preserved: alpha=%d beta=%d gamma=%d delta=%d", aIdx, bIdx, gIdx, dIdx)
	}
}
