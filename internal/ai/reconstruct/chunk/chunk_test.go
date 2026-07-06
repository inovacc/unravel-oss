/*
Copyright (c) 2026 Security Research
*/
package chunk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChunk_LangCSharp_BackCompat(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sample_csharp.cs"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	chunks, err := Chunk(src, LangCSharp, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(chunks))
	}
	wantTypes := []string{"WithAttrs", "Repo", "Plain"}
	for i, want := range wantTypes {
		if chunks[i].Type != want {
			t.Errorf("chunk[%d].Type = %q, want %q", i, chunks[i].Type, want)
		}
		if chunks[i].Namespace != "Sample.Ns" {
			t.Errorf("chunk[%d].Namespace = %q, want Sample.Ns", i, chunks[i].Namespace)
		}
	}
	// Nested class folded into WithAttrs.
	for _, c := range chunks {
		if c.Type == "Nested" {
			t.Fatalf("nested class emitted as own chunk: %+v", c)
		}
	}
}

func TestChunk_LangJava_TopLevelClasses(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sample_java.java"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	chunks, err := Chunk(src, LangJava, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d: %v", len(chunks), summarize(chunks))
	}
	wantTypes := []string{"Alpha", "Repository", "Beta"}
	for i, want := range wantTypes {
		if chunks[i].Type != want {
			t.Errorf("chunk[%d].Type = %q, want %q", i, chunks[i].Type, want)
		}
		if chunks[i].Namespace != "com.example.app" {
			t.Errorf("chunk[%d].Namespace = %q, want com.example.app", i, chunks[i].Namespace)
		}
	}
	// Nested static class folded into Alpha.
	for _, c := range chunks {
		if c.Type == "Nested" {
			t.Fatalf("nested class emitted as own chunk: %+v", c)
		}
	}
	if !strings.Contains(chunks[0].Body, "class Nested") {
		t.Errorf("Nested not folded into Alpha body")
	}
}

func TestChunk_LangJava_PackageDecl(t *testing.T) {
	src := []byte("package com.foo;\nimport java.util.List;\npublic class A {}\n")
	chunks, err := Chunk(src, LangJava, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "A" {
		t.Fatalf("want 1 A chunk, got %v", summarize(chunks))
	}
	if chunks[0].Namespace != "com.foo" {
		t.Errorf("namespace = %q, want com.foo", chunks[0].Namespace)
	}
}

func TestChunk_LangJava_BraceInString(t *testing.T) {
	src := []byte(`package p;
public class A {
    public String m() {
        String s = "}";
        String t = "// not a comment";
        // real } comment
        /* } block */
        return s;
    }
}
`)
	chunks, err := Chunk(src, LangJava, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "A" {
		t.Fatalf("expected single chunk A; got %v", summarize(chunks))
	}
	if !strings.Contains(chunks[0].Body, `"}"`) {
		t.Error("body lost the embedded brace-string content")
	}
}

func TestChunk_LangJava_TextBlock(t *testing.T) {
	src := []byte("package p;\npublic class A {\n    public String m() {\n        String s = \"\"\"\n}\n\"\"\";\n        return s;\n    }\n}\n")
	chunks, err := Chunk(src, LangJava, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "A" {
		t.Fatalf("text block split incorrectly: %v", summarize(chunks))
	}
}

func TestChunk_LangJavaScript_TopLevelFns(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sample_javascript.js"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	chunks, err := Chunk(src, LangJavaScript, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d: %v", len(chunks), summarize(chunks))
	}
	wantTypes := []string{"foo", "bar", "Bar"}
	for i, want := range wantTypes {
		if chunks[i].Type != want {
			t.Errorf("chunk[%d].Type = %q, want %q", i, chunks[i].Type, want)
		}
	}
}

func TestChunk_LangJavaScript_TemplateLiteral(t *testing.T) {
	src := []byte("function f(x) {\n    const s = `}${x}`;\n    return s;\n}\n")
	chunks, err := Chunk(src, LangJavaScript, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "f" {
		t.Fatalf("template literal split fn wrongly: %v", summarize(chunks))
	}
}

func TestChunk_LangJavaScript_RegexLiteral(t *testing.T) {
	src := []byte("function g() {\n    const r = /\\}/g;\n    return r;\n}\n")
	chunks, err := Chunk(src, LangJavaScript, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "g" {
		t.Fatalf("regex literal split fn wrongly: %v", summarize(chunks))
	}
}

func TestChunk_LangJavaScript_RegexVsDivision(t *testing.T) {
	src := []byte("function h(a, b) {\n    const q = a / b;\n    return q;\n}\n")
	chunks, err := Chunk(src, LangJavaScript, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "h" {
		t.Fatalf("division mistaken for regex: %v", summarize(chunks))
	}
}

func TestChunk_LangJavaScript_LineComment_DoubleSlash(t *testing.T) {
	src := []byte("function k() {\n    // }\n    return 1;\n}\n")
	chunks, err := Chunk(src, LangJavaScript, Options{})
	if err != nil {
		t.Fatalf("Chunk: %v", err)
	}
	if len(chunks) != 1 || chunks[0].Type != "k" {
		t.Fatalf("line comment // split fn wrongly: %v", summarize(chunks))
	}
}

func TestChunk_LargeUnit_50kBFallback(t *testing.T) {
	cases := []struct {
		name string
		lang Lang
		src  []byte
	}{
		{"csharp", LangCSharp, synthLargeCSharp()},
		{"java", LangJava, synthLargeJava()},
		{"javascript", LangJavaScript, synthLargeJS()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chunks, err := Chunk(tc.src, tc.lang, Options{MaxBytes: 50 * 1024})
			if err != nil {
				t.Fatalf("Chunk: %v", err)
			}
			if len(chunks) < 2 {
				t.Fatalf("want >1 sub-chunks for 60KB unit, got %d", len(chunks))
			}
			var sb strings.Builder
			for _, c := range chunks {
				sb.WriteString(c.Body)
			}
			if !strings.Contains(sb.String(), "Method_499") && !strings.Contains(sb.String(), "method_499") {
				t.Errorf("reassembled output missing last method")
			}
		})
	}
}

func TestChunk_AdversarialDepth_Bounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("namespace N { public class Deep0 {\n")
	for i := 1; i < 1100; i++ {
		fmt.Fprintf(&b, "public class Deep%d {\n", i)
	}
	b.WriteString("public int X;\n")
	for range 1100 {
		b.WriteString("}\n")
	}
	b.WriteString("}\n")
	done := make(chan struct{})
	go func() {
		_, _ = Chunk([]byte(b.String()), LangCSharp, Options{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Chunk hung on deep nesting")
	}
}

func TestChunk_PathologicalInput_Bounded(t *testing.T) {
	huge := make([]byte, 1<<20)
	for i := range huge {
		huge[i] = '{'
	}
	done := make(chan struct{})
	var chunks []Unit
	go func() {
		chunks, _ = Chunk(huge, LangCSharp, Options{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Chunk hung on pathological input")
	}
	if len(chunks) == 0 {
		t.Fatal("expected at least one fallback chunk")
	}
}

func TestChunk_DefaultMaxBytes(t *testing.T) {
	if DefaultMaxBytes != 50*1024 {
		t.Fatalf("DefaultMaxBytes = %d, want %d", DefaultMaxBytes, 50*1024)
	}
}

func TestChunk_Languages_All(t *testing.T) {
	got := Languages()
	if len(got) != 3 {
		t.Fatalf("Languages() = %v, want 3", got)
	}
}

// synthLargeCSharp builds a >60KB single-class C# file.
func synthLargeCSharp() []byte {
	var b strings.Builder
	b.WriteString("namespace Big.Ns\n{\n    public class Big\n    {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "        public int Method_%d(int a, int b)\n        {\n            int x = a + b;\n            int y = x * 2;\n            int z = y * 3;\n            return y - %d + z;\n        }\n", i, i)
	}
	b.WriteString("    }\n}\n")
	return []byte(b.String())
}

func synthLargeJava() []byte {
	var b strings.Builder
	b.WriteString("package big.ns;\npublic class Big {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "    public int method_%d(int a, int b) {\n        int x = a + b;\n        int y = x * 2;\n        int z = y * 3;\n        return y - %d + z;\n    }\n", i, i)
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func synthLargeJS() []byte {
	var b strings.Builder
	b.WriteString("class Big {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "    method_%d(a, b) {\n        const x = a + b;\n        const y = x * 2;\n        const z = y * 3;\n        return y - %d + z;\n    }\n", i, i)
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

func summarize(cs []Unit) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, fmt.Sprintf("{ns=%s type=%s len=%d sub=%s/%d}", c.Namespace, c.Type, len(c.Body), c.SubChunkOf, c.SubChunkIndex))
	}
	return out
}
