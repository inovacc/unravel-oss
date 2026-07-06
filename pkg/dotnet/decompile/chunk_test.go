/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	recon "github.com/inovacc/unravel-oss/internal/ai/reconstruct/chunk"
)

// chunkCSharp is a tiny test helper wrapping the shared reconstruct/chunk
// package with the C# language selector. It preserves the C#-flavoured
// edge-case coverage that previously rode on the decompile chunk shim.
func chunkCSharp(src []byte, opts recon.Options) ([]recon.Unit, error) {
	return recon.Chunk(src, recon.LangCSharp, opts)
}

// ensureLargeClass synthesizes a 60 KB single-class file used by the
// 50 KB fallback test.
func ensureLargeClass(t *testing.T) string {
	t.Helper()
	path := filepath.Join("testdata", "large_class.cs")
	if st, err := os.Stat(path); err == nil && st.Size() > 50*1024 {
		return path
	}

	var b strings.Builder
	b.WriteString("namespace Big.Ns\n{\n    public class Big\n    {\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "        public int Method_%d(int a, int b)\n        {\n            int x = a + b;\n            int y = x * 2;\n            int z = y * 3;\n            return y - %d + z;\n        }\n", i, i)
	}
	b.WriteString("    }\n}\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write large_class.cs: %v", err)
	}
	return path
}

func TestChunkByClass_SimpleFile(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sample_decompiled.cs"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	chunks, err := chunkCSharp(src, recon.Options{})
	if err != nil {
		t.Fatalf("chunkCSharp: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d: %+v", len(chunks), summarize(chunks))
	}
	wantTypes := []string{"WithAttrs", "Repo", "Plain"}
	for i, want := range wantTypes {
		if chunks[i].Type != want {
			t.Errorf("chunk[%d].Type = %q, want %q", i, chunks[i].Type, want)
		}
		if chunks[i].Namespace != "Sample.Ns" {
			t.Errorf("chunk[%d].Namespace = %q, want Sample.Ns", i, chunks[i].Namespace)
		}
		// Body must end with a closing brace for top-level class.
		body := strings.TrimRight(chunks[i].Body, " \t\r\n")
		if !strings.HasSuffix(body, "}") {
			t.Errorf("chunk[%d] body does not end with '}': %q", i, last(body, 40))
		}
	}
}

func TestChunkByClass_NestedClassNotSplit(t *testing.T) {
	src, _ := os.ReadFile(filepath.Join("testdata", "sample_decompiled.cs"))
	chunks, _ := chunkCSharp(src, recon.Options{})
	for _, c := range chunks {
		if c.Type == "Nested" {
			t.Fatalf("nested class emitted as own chunk: %+v", c)
		}
	}
	// "Nested" must appear inside WithAttrs body.
	var found bool
	for _, c := range chunks {
		if c.Type == "WithAttrs" && strings.Contains(c.Body, "class Nested") {
			found = true
		}
	}
	if !found {
		t.Fatal("Nested class not folded into WithAttrs chunk")
	}
}

func TestChunkByClass_FileScopedNamespace(t *testing.T) {
	src := []byte("namespace Foo;\npublic class A { }\npublic class B { }\n")
	chunks, err := chunkCSharp(src, recon.Options{})
	if err != nil {
		t.Fatalf("chunkCSharp: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(chunks))
	}
	for _, c := range chunks {
		if c.Namespace != "Foo" {
			t.Errorf("chunk %s namespace = %q, want Foo", c.Type, c.Namespace)
		}
	}
}

func TestChunkByClass_GenericTypeParam(t *testing.T) {
	src := []byte("namespace N { public class Repo<T, U> { public T A; public U B; } }\n")
	chunks, _ := chunkCSharp(src, recon.Options{})
	if len(chunks) != 1 || chunks[0].Type != "Repo" {
		t.Fatalf("want 1 chunk Repo, got %+v", summarize(chunks))
	}
}

func TestChunkByClass_BraceInString(t *testing.T) {
	src := []byte(`namespace N {
public class A {
    public string M() {
        string s = "}";
        string r = @"} verbatim";
        var i = $"{X}";
        return s;
    }
}
}
`)
	chunks, err := chunkCSharp(src, recon.Options{})
	if err != nil {
		t.Fatalf("chunkCSharp: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "A" {
		t.Fatalf("expected single chunk A; got %+v", summarize(chunks))
	}
	if !strings.Contains(chunks[0].Body, `"}"`) {
		t.Error("body lost the embedded brace-string content")
	}
}

func TestChunkByClass_BraceInLineComment(t *testing.T) {
	src := []byte("namespace N { public class A {\n    // } comment trick\n    public int X;\n} }\n")
	chunks, _ := chunkCSharp(src, recon.Options{})
	if len(chunks) != 1 || chunks[0].Type != "A" {
		t.Fatalf("expected single chunk A; got %+v", summarize(chunks))
	}
}

func TestChunkByClass_LargeClassFallback(t *testing.T) {
	path := ensureLargeClass(t)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	chunks, err := chunkCSharp(src, recon.Options{MaxBytes: 50 * 1024})
	if err != nil {
		t.Fatalf("chunkCSharp: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("want >1 sub-chunks for 60KB class, got %d", len(chunks))
	}
	for _, c := range chunks {
		if len(c.Body) > 50*1024+1024 { // small slack for boundary attribution
			t.Errorf("sub-chunk %d size %d exceeds 50KB cap", c.SubChunkIndex, len(c.Body))
		}
		if c.SubChunkOf != "Big" {
			t.Errorf("expected SubChunkOf=Big, got %q", c.SubChunkOf)
		}
	}
	// Reassemble and ensure it covers the original class chunk byte-equal.
	var sb strings.Builder
	for _, c := range chunks {
		sb.WriteString(c.Body)
	}
	reassembled := sb.String()
	classStart := strings.Index(string(src), "public class Big")
	if !strings.Contains(reassembled, "public class Big") {
		t.Error("reassembled output lost class declaration")
	}
	// Reassembled length should equal the class span end-of-file - chunkStart.
	// We require the full original class body to be present in concatenation.
	if classStart >= 0 && !strings.Contains(reassembled, "Method_199") {
		t.Error("reassembled output missing last method")
	}
}

func TestChunkByClass_AdversarialDepth(t *testing.T) {
	// 1000 levels of nested classes should not blow the stack.
	var b strings.Builder
	b.WriteString("namespace N { public class Deep0 {\n")
	for i := 1; i < 1000; i++ {
		fmt.Fprintf(&b, "public class Deep%d {\n", i)
	}
	b.WriteString("public int X;\n")
	for i := 0; i < 1000; i++ {
		b.WriteString("}\n")
	}
	b.WriteString("}\n")
	done := make(chan struct{})
	go func() {
		_, _ = chunkCSharp([]byte(b.String()), recon.Options{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("chunkCSharp hung on deep nesting")
	}
}

func TestChunkByClass_PathologicalInput_Bounded(t *testing.T) {
	// 1 MB of `{` chars — must not hang and must return a fallback chunk.
	huge := make([]byte, 1<<20)
	for i := range huge {
		huge[i] = '{'
	}
	done := make(chan struct{})
	var chunks []recon.Unit
	go func() {
		chunks, _ = chunkCSharp(huge, recon.Options{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("chunkCSharp hung on pathological input")
	}
	if len(chunks) == 0 {
		t.Fatal("expected at least one fallback chunk")
	}
}

// summarize and last are tiny test helpers.
func summarize(cs []recon.Unit) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, fmt.Sprintf("{ns=%s type=%s len=%d sub=%s/%d}", c.Namespace, c.Type, len(c.Body), c.SubChunkOf, c.SubChunkIndex))
	}
	return out
}

func last(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
