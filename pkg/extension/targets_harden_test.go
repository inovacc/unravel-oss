/*
Copyright (c) 2026 Security Research
*/
package extension

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestReadCRXPayload_OffsetWrapRejected crafts a CRX2 whose pubLen+sigLen header
// sum wraps in uint32 (pubLen=0xFFFFFFF0, sigLen=0x20 -> 16+...=16). The old
// `int(offset) >= len(data)` check passed on the wrapped value and sliced from
// mid-header. The uint64 arithmetic must instead reject it with the clean
// "invalid CRX payload offset" error. Finding #25.
func TestReadCRXPayload_OffsetWrapRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))          // version 2
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0xFFFFFFF0)) // pubLen
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x20))       // sigLen
	// Trailing bytes (> 32) so a wrapped offset of 16/32 would otherwise slice.
	buf.Write(make([]byte, 64))

	path := filepath.Join(t.TempDir(), "wrap.crx")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readCRXPayload panicked on wrapping CRX header: %v", r)
		}
	}()

	if _, err := readCRXPayload(path); err == nil {
		t.Fatalf("expected error for wrapping CRX payload offset, got nil")
	}
}
