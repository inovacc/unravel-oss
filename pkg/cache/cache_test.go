/* Copyright (c) 2026 Security Research */
package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		b    int64
		want string
	}{
		{name: "zero", b: 0, want: "0 B"},
		{name: "bytes", b: 500, want: "500 B"},
		{name: "kilobytes", b: 1024, want: "1.0 KB"},
		{name: "megabytes", b: 1024 * 1024, want: "1.0 MB"},
		{name: "gigabytes", b: 1024 * 1024 * 1024, want: "1.0 GB"},
		{name: "1023 bytes", b: 1023, want: "1023 B"},
		{name: "1.5 KB", b: 1536, want: "1.5 KB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatBytes(tt.b)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.b, got, tt.want)
			}
		})
	}
}

func TestFormatSummary(t *testing.T) {
	tests := []struct {
		name     string
		result   *ParseResult
		contains []string
	}{
		{
			name: "basic summary",
			result: &ParseResult{
				SourcePath:  "/tmp/cache",
				CacheFormat: "simple",
				ParsedAt:    "2026-01-01T00:00:00Z",
				Stats: CacheStats{
					TotalEntries:    10,
					ValidEntries:    8,
					ExtractedBodies: 5,
					TotalBodySize:   2048,
				},
				ByDomain: map[string]int{"example.com": 5},
				ByType:   map[string]int{},
			},
			contains: []string{
				"Chromium Cache Parse Summary",
				"/tmp/cache",
				"simple",
				"Total Entries: 10",
				"Valid Entries: 8",
				"Bodies Extracted: 5",
				"example.com: 5",
			},
		},
		{
			name: "empty result",
			result: &ParseResult{
				SourcePath:  "/empty",
				CacheFormat: "unknown",
				ParsedAt:    "2026-01-01T00:00:00Z",
				Stats:       CacheStats{},
				ByDomain:    map[string]int{},
				ByType:      map[string]int{},
			},
			contains: []string{
				"Total Entries: 0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatSummary(tt.result)
			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("FormatSummary() missing %q in output:\n%s", s, got)
				}
			}
		})
	}
}

func TestDetectFormat_NonexistentPath(t *testing.T) {
	got := DetectFormat("/tmp/nonexistent-cache-12345")
	if got != "unknown" {
		t.Errorf("expected 'unknown' for nonexistent path, got %q", got)
	}
}

func TestDetectFormat_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	got := DetectFormat(tmpDir)

	if got != "unknown" {
		t.Errorf("expected 'unknown' for empty dir, got %q", got)
	}
}

func TestDetectFormat_SimpleCache(t *testing.T) {
	tmpDir := t.TempDir()

	// Simple cache format is detected by the presence of files like "index-dir/the-real-index"
	indexDir := filepath.Join(tmpDir, "index-dir")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(indexDir, "the-real-index"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := DetectFormat(tmpDir)
	if got != "simple" {
		t.Errorf("expected 'simple' format, got %q", got)
	}
}

func TestParse_NonexistentPath(t *testing.T) {
	_, err := Parse("/tmp/nonexistent-cache-12345", "")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestParse_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.Stats.TotalEntries != 0 {
		t.Errorf("expected 0 entries for empty dir, got %d", result.Stats.TotalEntries)
	}
}

func TestFormatSummary_WithTypes(t *testing.T) {
	result := &ParseResult{
		SourcePath:  "/tmp/cache",
		CacheFormat: "simple",
		ParsedAt:    "2026-01-01",
		Stats: CacheStats{
			TotalEntries:    20,
			ValidEntries:    15,
			ExtractedBodies: 10,
			TotalBodySize:   1024 * 1024,
		},
		ByDomain: map[string]int{
			"cdn.example.com": 10,
			"api.example.com": 5,
		},
		ByType: map[string]int{
			"text/html":        8,
			"application/json": 7,
		},
	}

	got := FormatSummary(result)

	if !strings.Contains(got, "cdn.example.com") {
		t.Error("missing domain in summary")
	}

	if !strings.Contains(got, "Total Entries: 20") {
		t.Error("missing total entries in summary")
	}
}

func TestDetectFormat_BlockFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Block file cache is detected by "data_0", "data_1", "data_2", "data_3" files
	for _, name := range []string{"data_0", "data_1", "data_2", "data_3"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Also needs index file
	if err := os.WriteFile(filepath.Join(tmpDir, "index"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := DetectFormat(tmpDir)
	if got != "blockfile" {
		t.Errorf("expected 'blockfile' format, got %q", got)
	}
}

func TestParse_SimpleCache(t *testing.T) {
	tmpDir := t.TempDir()

	// Create simple cache structure
	indexDir := filepath.Join(tmpDir, "index-dir")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(indexDir, "the-real-index"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.CacheFormat != "simple" {
		t.Errorf("CacheFormat = %q, want 'simple'", result.CacheFormat)
	}
}

func TestFormatBytes_Zero(t *testing.T) {
	got := FormatBytes(0)
	if got != "0 B" {
		t.Errorf("FormatBytes(0) = %q, want %q", got, "0 B")
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "https with path", url: "https://api.example.com/path", want: "api.example.com"},
		{name: "http with port", url: "http://foo.bar:8080/x", want: "foo.bar"},
		{name: "not a url", url: "not-a-url", want: "not-a-url"},
		{name: "empty string", url: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.url)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsHexString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{name: "lowercase hex", s: "abcdef0123", want: true},
		{name: "uppercase hex", s: "ABCDEF", want: true},
		{name: "non-hex chars", s: "xyz", want: false},
		{name: "empty string", s: "", want: false},
		{name: "hex with special char", s: "abc123!", want: false},
		{name: "mixed case hex", s: "aAbB09", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHexString(tt.s)
			if got != tt.want {
				t.Errorf("isHexString(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsGzipped(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "gzip header", data: []byte{0x1f, 0x8b, 0x08}, want: true},
		{name: "not gzipped", data: []byte{0x00, 0x00}, want: false},
		{name: "nil data", data: nil, want: false},
		{name: "single byte", data: []byte{0x1f}, want: false},
		{name: "exact two byte match", data: []byte{0x1f, 0x8b}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGzipped(tt.data)
			if got != tt.want {
				t.Errorf("isGzipped(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestGetExtensionForContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{name: "html", contentType: "text/html", want: ".html"},
		{name: "json", contentType: "application/json", want: ".json"},
		{name: "png", contentType: "image/png", want: ".png"},
		{name: "unknown type", contentType: "unknown/type", want: ""},
		{name: "empty", contentType: "", want: ""},
		{name: "with whitespace", contentType: "  text/css  ", want: ".css"},
		{name: "uppercase", contentType: "TEXT/HTML", want: ".html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getExtensionForContentType(tt.contentType)
			if got != tt.want {
				t.Errorf("getExtensionForContentType(%q) = %q, want %q", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestDetectFileType(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "PNG", data: []byte("\x89PNG\r\n\x1a\n"), want: ".png"},
		{name: "JPEG", data: []byte("\xff\xd8\xff\xe0data"), want: ".jpg"},
		{name: "GIF", data: []byte("GIF89adata"), want: ".gif"},
		{name: "PDF", data: []byte("%PDF-1.4 data"), want: ".pdf"},
		{name: "HTML doctype", data: []byte("<!DOCTYPE html>"), want: ".html"},
		{name: "JSON object", data: []byte("{\"key\":\"value\"}"), want: ".json"},
		{name: "XML", data: []byte("<?xml version=\"1.0\"?>"), want: ".xml"},
		{name: "woff", data: []byte("wOFFdata"), want: ".woff"},
		{name: "woff2", data: []byte("wOF2data"), want: ".woff2"},
		{name: "short data", data: []byte{0x00, 0x01}, want: ".bin"},
		{name: "unknown binary", data: []byte{0x00, 0x01, 0x02, 0x03, 0x04}, want: ".bin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFileType(tt.data)
			if got != tt.want {
				t.Errorf("detectFileType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindBodyStart(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{name: "crlf separator", data: []byte("HTTP/1.1 200 OK\r\n\r\nbody"), want: 19},
		{name: "lf separator", data: []byte("HTTP/1.1 200 OK\n\nbody"), want: 17},
		{name: "no separator", data: []byte("no separator here"), want: -1},
		{name: "empty data", data: []byte{}, want: -1},
		{name: "crlf preferred over lf", data: []byte("header\r\n\r\nA\n\nB"), want: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findBodyStart(tt.data)
			if got != tt.want {
				t.Errorf("findBodyStart() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFormatSummary_EmptyDomains(t *testing.T) {
	result := &ParseResult{
		SourcePath:  "/cache",
		CacheFormat: "simple",
		ParsedAt:    "2026-01-01",
		Stats:       CacheStats{TotalEntries: 0},
		ByDomain:    map[string]int{},
		ByType:      map[string]int{},
	}

	got := FormatSummary(result)
	if !strings.Contains(got, "Total Entries: 0") {
		t.Error("expected Total Entries: 0 in output")
	}
}

// --- New synthetic data tests ---

func TestParseHTTPResponse(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		wantStatus  int
		wantCT      string
		wantCL      int64
		wantHeaders bool
	}{
		{
			name:        "200 OK with headers",
			data:        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\nbody",
			wantStatus:  200,
			wantCT:      "text/html",
			wantCL:      1234,
			wantHeaders: true,
		},
		{
			name:        "404 Not Found",
			data:        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{}",
			wantStatus:  404,
			wantCT:      "application/json",
			wantHeaders: true,
		},
		{
			name:        "no headers separator",
			data:        "HTTP/1.1 200 OK no double newline here",
			wantStatus:  0,
			wantHeaders: false,
		},
		{
			name:        "lf separator",
			data:        "HTTP/1.1 301 Moved\nLocation: /new\n\nbody",
			wantStatus:  301,
			wantHeaders: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &CacheEntry{}
			parseHTTPResponse([]byte(tt.data), entry)

			if entry.HTTPStatus != tt.wantStatus {
				t.Errorf("HTTPStatus = %d, want %d", entry.HTTPStatus, tt.wantStatus)
			}

			if tt.wantCT != "" && entry.ContentType != tt.wantCT {
				t.Errorf("ContentType = %q, want %q", entry.ContentType, tt.wantCT)
			}

			if tt.wantCL > 0 && entry.ContentLength != tt.wantCL {
				t.Errorf("ContentLength = %d, want %d", entry.ContentLength, tt.wantCL)
			}

			if tt.wantHeaders && entry.HTTPHeaders == nil {
				t.Error("expected HTTPHeaders to be populated")
			}
		})
	}
}

func TestDecompressGzip(t *testing.T) {
	// Create valid gzip data
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	_, _ = gzw.Write([]byte("hello compressed world"))
	_ = gzw.Close()

	got, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressGzip: %v", err)
	}

	if string(got) != "hello compressed world" {
		t.Errorf("decompressed = %q, want %q", got, "hello compressed world")
	}
}

func TestDecompressGzip_Truncated(t *testing.T) {
	// Truncated gzip data (just the magic bytes + incomplete header)
	truncated := []byte{0x1f, 0x8b, 0x08, 0x00}
	_, err := decompressGzip(truncated)
	if err == nil {
		t.Error("expected error for truncated gzip data")
	}
}

func TestDecompressGzip_Empty(t *testing.T) {
	_, err := decompressGzip([]byte{})
	if err == nil {
		t.Error("expected error for empty gzip data")
	}
}

func TestOrganizeResults(t *testing.T) {
	result := &ParseResult{
		Entries: []CacheEntry{
			{URL: "https://api.example.com/v1/data", ContentType: "application/json"},
			{URL: "https://api.example.com/v1/users", ContentType: "application/json"},
			{URL: "https://cdn.example.com/style.css", ContentType: "text/css"},
			{URL: "", ContentType: "text/html"}, // no URL entry
		},
		ByDomain: make(map[string]int),
		ByType:   make(map[string]int),
	}

	organizeResults(result)

	if result.ByDomain["api.example.com"] != 2 {
		t.Errorf("api.example.com count = %d, want 2", result.ByDomain["api.example.com"])
	}

	if result.ByDomain["cdn.example.com"] != 1 {
		t.Errorf("cdn.example.com count = %d, want 1", result.ByDomain["cdn.example.com"])
	}

	if result.ByType["application/json"] != 2 {
		t.Errorf("application/json count = %d, want 2", result.ByType["application/json"])
	}

	if result.ByType["text/css"] != 1 {
		t.Errorf("text/css count = %d, want 1", result.ByType["text/css"])
	}

	// Entry with no URL and ContentType should be counted as "unknown" in ByType
	// but not in ByDomain
	if result.ByType["text/html"] != 1 {
		t.Errorf("text/html count = %d, want 1", result.ByType["text/html"])
	}
}

func TestSaveBody(t *testing.T) {
	outDir := t.TempDir()
	bodiesDir := filepath.Join(outDir, "bodies")
	if err := os.MkdirAll(bodiesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	body := []byte("<html><body>Hello</body></html>")
	filename := saveBody(body, outDir, "https://example.com/page", "text/html")

	if filename == "" {
		t.Fatal("expected non-empty filename")
	}

	if !strings.HasSuffix(filename, ".html") {
		t.Errorf("filename %q should end with .html", filename)
	}

	// Verify file was written
	got, err := os.ReadFile(filepath.Join(bodiesDir, filename))
	if err != nil {
		t.Fatalf("read saved body: %v", err)
	}

	if string(got) != string(body) {
		t.Errorf("saved body = %q, want %q", got, body)
	}
}

func TestSaveBody_Empty(t *testing.T) {
	filename := saveBody([]byte{}, t.TempDir(), "https://example.com", "text/html")
	if filename != "" {
		t.Errorf("expected empty filename for empty body, got %q", filename)
	}
}

func TestSaveBody_NoURL(t *testing.T) {
	outDir := t.TempDir()
	bodiesDir := filepath.Join(outDir, "bodies")
	if err := os.MkdirAll(bodiesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	filename := saveBody([]byte("data"), outDir, "", "")
	if filename == "" {
		t.Fatal("expected non-empty filename even without URL")
	}
}

func TestParseSimpleCache_WithHTTPEntry(t *testing.T) {
	tmpDir := t.TempDir()

	// Create index-dir for detection
	indexDir := filepath.Join(tmpDir, "index-dir")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(indexDir, "the-real-index"), []byte("idx"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a hex-named cache file with HTTP response + body
	httpData := "https://example.com/api/data\x00" +
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"
	// Pad to >24 bytes (already is)
	if err := os.WriteFile(filepath.Join(tmpDir, "abcdef01"), []byte(httpData), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.CacheFormat != "simple" {
		t.Errorf("CacheFormat = %q, want 'simple'", result.CacheFormat)
	}

	if result.Stats.TotalEntries == 0 {
		t.Error("expected at least 1 total entry")
	}

	if result.Stats.ValidEntries == 0 {
		t.Error("expected at least 1 valid entry")
	}

	// Check that domain was organized
	if result.ByDomain["example.com"] == 0 {
		t.Error("expected example.com in ByDomain")
	}
}

func TestParseSimpleCache_TooSmall(t *testing.T) {
	tmpDir := t.TempDir()

	indexDir := filepath.Join(tmpDir, "index-dir")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(indexDir, "the-real-index"), []byte("idx"), 0o644); err != nil {
		t.Fatal(err)
	}

	// File <24 bytes should be skipped
	if err := os.WriteFile(filepath.Join(tmpDir, "aabbccdd"), []byte("tiny"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Entry counted in TotalEntries but not ValidEntries
	if result.Stats.ValidEntries != 0 {
		t.Errorf("expected 0 valid entries for tiny file, got %d", result.Stats.ValidEntries)
	}
}

func TestParseSimpleCache_GzipBody(t *testing.T) {
	tmpDir := t.TempDir()

	indexDir := filepath.Join(tmpDir, "index-dir")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(indexDir, "the-real-index"), []byte("idx"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create gzip body
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, _ = gzw.Write([]byte("<html>compressed page</html>"))
	_ = gzw.Close()

	// Build cache entry: URL + HTTP headers + gzip body
	var entry bytes.Buffer
	entry.WriteString("https://example.com/compressed\x00")
	entry.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n")
	entry.Write(gzBuf.Bytes())

	if err := os.WriteFile(filepath.Join(tmpDir, "aabbccee"), entry.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "output")
	result, err := Parse(tmpDir, outDir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.Stats.ValidEntries == 0 {
		t.Error("expected valid entries")
	}

	// Check that body was extracted
	if result.Stats.ExtractedBodies == 0 {
		t.Error("expected extracted bodies")
	}
}

func TestParseBlockFileCache_WithIndex(t *testing.T) {
	tmpDir := t.TempDir()

	// Create index file with valid magic
	indexData := make([]byte, 256)
	binary.LittleEndian.PutUint32(indexData[0:4], IndexMagic)
	binary.LittleEndian.PutUint32(indexData[4:8], 2) // version
	if err := os.WriteFile(filepath.Join(tmpDir, "index"), indexData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Create data_1 with HTTP response inside a block (>8192 header + block data)
	data1 := make([]byte, 8192+256*3) // header + 3 blocks of 256
	// Put HTTP data in block 1 (offset 8192+256)
	httpResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello from block")
	copy(data1[8192+256:], httpResp)
	// Put a URL in the surrounding area for extraction
	copy(data1[8192:], []byte("https://block.example.com/data "))
	if err := os.WriteFile(filepath.Join(tmpDir, "data_1"), data1, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.CacheFormat != "blockfile" {
		t.Errorf("CacheFormat = %q, want 'blockfile'", result.CacheFormat)
	}
}

func TestParseBlockFileCache_SeparateEntry(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a data_0 file so it detects as blockfile
	if err := os.WriteFile(filepath.Join(tmpDir, "data_0"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create an f_ entry file
	fData := []byte("https://fentry.example.com/page\x00HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>page</html>")
	if err := os.WriteFile(filepath.Join(tmpDir, "f_000001"), fData, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.Stats.ValidEntries == 0 {
		t.Error("expected valid entries from f_ file")
	}

	found := false
	for _, e := range result.Entries {
		if strings.Contains(e.URL, "fentry.example.com") {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected entry with fentry.example.com URL")
	}
}

func TestDetectFormat_BlockFileWithIndexMagic(t *testing.T) {
	tmpDir := t.TempDir()

	// Create index with valid magic
	indexData := make([]byte, 8)
	binary.LittleEndian.PutUint32(indexData[0:4], IndexMagic)

	if err := os.WriteFile(filepath.Join(tmpDir, "index"), indexData, 0o644); err != nil {
		t.Fatal(err)
	}

	got := DetectFormat(tmpDir)
	if got != "blockfile" {
		t.Errorf("expected 'blockfile' for index with magic, got %q", got)
	}
}

func TestParseGenericCache(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with HTTP content (not in simple or blockfile structure)
	data := []byte("https://generic.example.com/api\x00HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")
	if err := os.WriteFile(filepath.Join(tmpDir, "somefile"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, "")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Generic parser should find the HTTP content
	if result.Stats.ValidEntries == 0 {
		t.Error("expected generic parser to find valid entries")
	}
}

func TestParseSimpleCache_WithOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "output")

	indexDir := filepath.Join(tmpDir, "index-dir")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(indexDir, "the-real-index"), []byte("idx"), 0o644); err != nil {
		t.Fatal(err)
	}

	httpData := "https://example.com/page.html\x00HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello World</html>"
	if err := os.WriteFile(filepath.Join(tmpDir, "aabb0011"), []byte(httpData), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Parse(tmpDir, outDir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if result.Stats.ExtractedBodies == 0 {
		t.Error("expected bodies to be extracted with outputDir")
	}

	// Verify bodies directory was created
	if _, err := os.Stat(filepath.Join(outDir, "bodies")); err != nil {
		t.Errorf("bodies directory not created: %v", err)
	}
}
