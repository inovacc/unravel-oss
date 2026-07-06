package reconstruct

import (
	"os"
	"strings"
	"testing"
)

func TestChunkContentSingleChunk(t *testing.T) {
	content := "line1\nline2\nline3\n"
	opts := DefaultOptions()
	chunks := ChunkContent(content, LangJava, opts)

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].Index != 0 || chunks[0].Total != 1 {
		t.Errorf("expected Index=0 Total=1, got Index=%d Total=%d", chunks[0].Index, chunks[0].Total)
	}
}

func TestChunkContentMultiChunk(t *testing.T) {
	data, err := os.ReadFile("testdata/input/large_class.java")
	if err != nil {
		t.Fatalf("read large_class.java: %v", err)
	}
	content := string(data)
	lines := strings.Split(content, "\n")
	if len(lines) < 550 {
		t.Fatalf("large_class.java too small: %d lines", len(lines))
	}

	opts := DefaultOptions()
	chunks := ChunkContent(content, LangJava, opts)

	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks for %d-line file, got %d", len(lines), len(chunks))
	}

	// Verify sequential indices.
	for i, c := range chunks {
		if c.Index != i {
			t.Errorf("chunk %d: Index=%d", i, c.Index)
		}
		if c.Total != len(chunks) {
			t.Errorf("chunk %d: Total=%d, want %d", i, c.Total, len(chunks))
		}
	}
}

func TestChunkContentOverlapPresence(t *testing.T) {
	data, err := os.ReadFile("testdata/input/large_class.java")
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	opts := DefaultOptions()
	chunks := ChunkContent(string(data), LangJava, opts)

	if len(chunks) < 2 {
		t.Skip("not enough chunks to test overlap")
	}

	// Second chunk should start before the end of the first chunk (overlap).
	if chunks[1].StartLine >= chunks[0].EndLine {
		t.Errorf("expected overlap: chunk 1 starts at %d, chunk 0 ends at %d",
			chunks[1].StartLine, chunks[0].EndLine)
	}
}

func TestChunkContentContextHeader(t *testing.T) {
	data, err := os.ReadFile("testdata/input/large_class.java")
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	opts := DefaultOptions()
	chunks := ChunkContent(string(data), LangJava, opts)

	if len(chunks) < 2 {
		t.Skip("not enough chunks to test context")
	}

	// At least one non-first chunk should have a context header.
	hasContext := false
	for _, c := range chunks[1:] {
		if c.Context != "" {
			hasContext = true
			break
		}
	}
	if !hasContext {
		t.Error("expected at least one non-first chunk to have context header")
	}
}

func TestChunkContentBlankLineFallback(t *testing.T) {
	// Build a large file with no recognizable function boundaries but with blank lines.
	var b strings.Builder
	for i := range 600 {
		if i > 0 && i%50 == 0 {
			b.WriteString("\n") // blank line
		}
		b.WriteString("x = x + 1\n")
	}

	opts := DefaultOptions()
	chunks := ChunkContent(b.String(), LangUnknown, opts)

	if len(chunks) < 2 {
		t.Errorf("expected multiple chunks for 600-line file with unknown language, got %d", len(chunks))
	}
}
