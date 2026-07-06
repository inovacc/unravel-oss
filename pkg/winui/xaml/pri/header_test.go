/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestPRIHeader_ValidMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf[:8], []byte("mrm_pri2"))
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	binary.LittleEndian.PutUint64(buf[12:20], uint64(HeaderSize))
	binary.LittleEndian.PutUint32(buf[20:24], HeaderSize)
	binary.LittleEndian.PutUint32(buf[24:28], 0)
	binary.LittleEndian.PutUint32(buf[28:32], HeaderSize)
	h, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Magic != "mrm_pri2" {
		t.Errorf("Magic = %q, want mrm_pri2", h.Magic)
	}
	if h.Version == 0 {
		t.Error("Version should be > 0")
	}
}

func TestPRIHeader_BadMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf[:8], []byte("xxxx_pri"))
	_, err := ParseHeader(buf)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
	if !strings.Contains(err.Error(), "magic mismatch") {
		t.Errorf("error = %q, want substring 'magic mismatch'", err)
	}
}

func TestPRIHeader_OversizedSize(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf[:8], []byte("mrm_pri2"))
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	// Total size declared > 64 MiB.
	binary.LittleEndian.PutUint64(buf[12:20], uint64(MaxFileSize)+1)
	_, err := ParseHeader(buf)
	if err == nil {
		t.Fatal("expected error for oversized declared size")
	}
	if !strings.Contains(err.Error(), "size exceeds limit") {
		t.Errorf("error = %q, want substring 'size exceeds limit'", err)
	}
}

func TestPRIHeader_Truncated(t *testing.T) {
	buf := make([]byte, 16) // < HeaderSize
	_, err := ParseHeader(buf)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}
