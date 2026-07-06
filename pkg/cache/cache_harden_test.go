/*
Copyright (c) 2026 Security Research

Decompression-bomb hardening test (finding #21). decompressGzip processes
attacker-controlled cache bodies; a tiny gzip stream that expands to gigabytes
must be rejected rather than materialized into memory (OOM).
*/
package cache

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// TestDecompressGzip_BombBounded crafts a small gzip stream that decompresses to
// more than a (lowered-for-test) cap and asserts it is rejected, not slurped.
func TestDecompressGzip_BombBounded(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(make([]byte, 1<<20)); err != nil { // 1 MiB of zeros → tiny gzip
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	old := maxDecompressedCacheBody
	maxDecompressedCacheBody = 4096 // shrink the cap so the 1 MiB payload trips it
	defer func() { maxDecompressedCacheBody = old }()

	if _, err := decompressGzip(buf.Bytes()); !errors.Is(err, safeio.ErrLimitExceeded) {
		t.Fatalf("decompressGzip(bomb): got %v, want ErrLimitExceeded", err)
	}
}

// TestDecompressGzip_ValidPasses confirms a legitimate small body still decodes.
func TestDecompressGzip_ValidPasses(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	payload := []byte("hello world")
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	got, err := decompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("decompressGzip(valid): unexpected error %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decompressGzip(valid): got %q, want %q", got, payload)
	}
}
