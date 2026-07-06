/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseHeader_ValidV21(t *testing.T) {
	b := newXBFBuilder()
	b.addType("Page")
	data := b.build()
	r := bytes.NewReader(data)
	h, err := ParseHeader(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Major != 2 || h.Minor != 1 {
		t.Fatalf("want 2.1 got %d.%d", h.Major, h.Minor)
	}
	if h.Magic != XBFMagic {
		t.Fatalf("magic mismatch: %v", h.Magic)
	}
	if h.TableTOC.Strings.Size == 0 {
		t.Fatalf("expected non-empty strings region")
	}
}

func TestParseHeader_BadMagic(t *testing.T) {
	data := make([]byte, HeaderSize)
	copy(data[0:4], []byte{'X', 'M', 'L', 0x00})
	r := bytes.NewReader(data)
	_, err := ParseHeader(r)
	if err == nil {
		t.Fatal("expected magic error")
	}
	if !strings.Contains(err.Error(), "magic mismatch") {
		t.Fatalf("expected magic mismatch error, got: %v", err)
	}
}

func TestParseHeader_TruncatedToc(t *testing.T) {
	// Build a valid header but with a region pointing past EOF.
	data := make([]byte, HeaderSize)
	copy(data[0:4], XBFMagic[:])
	binary.LittleEndian.PutUint16(data[4:6], 2)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	// First region: Offset=HeaderSize, Size=9999 (way past file).
	binary.LittleEndian.PutUint32(data[8:12], uint32(HeaderSize))
	binary.LittleEndian.PutUint32(data[12:16], 9999)
	r := bytes.NewReader(data)
	_, err := ParseHeader(r)
	if err == nil {
		t.Fatal("expected out-of-bounds error")
	}
	if !strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("expected out of bounds, got: %v", err)
	}
}

func TestParseHeader_OverflowOffset(t *testing.T) {
	data := make([]byte, HeaderSize)
	copy(data[0:4], XBFMagic[:])
	binary.LittleEndian.PutUint16(data[4:6], 2)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	// Overflow: 0xFFFFFFFE + 0x10 wraps in uint32.
	binary.LittleEndian.PutUint32(data[8:12], 0xFFFFFFFE)
	binary.LittleEndian.PutUint32(data[12:16], 0x10)
	r := bytes.NewReader(data)
	_, err := ParseHeader(r)
	if err == nil {
		t.Fatal("expected overflow error")
	}
	// Either "overflow" or "out of bounds" is acceptable — both indicate the
	// uint64 check caught it.
	if !strings.Contains(err.Error(), "overflow") && !strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("expected overflow detection, got: %v", err)
	}
}

func TestParseHeader_UnsupportedMajor(t *testing.T) {
	b := newXBFBuilder()
	b.major = 99
	b.addType("Page")
	data := b.build()
	r := bytes.NewReader(data)
	h, err := ParseHeader(r)
	if err != nil {
		t.Fatalf("unsupported major should still parse: %v", err)
	}
	if len(h.Warnings) == 0 {
		t.Fatal("expected warning on unsupported major version")
	}
}

func TestParseHeader_OversizedTableInToc(t *testing.T) {
	data := make([]byte, HeaderSize+128)
	copy(data[0:4], XBFMagic[:])
	binary.LittleEndian.PutUint16(data[4:6], 2)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	// Oversized region: 32 MiB > 16 MiB cap.
	binary.LittleEndian.PutUint32(data[8:12], uint32(HeaderSize))
	binary.LittleEndian.PutUint32(data[12:16], 32<<20)
	r := bytes.NewReader(data)
	_, err := ParseHeader(r)
	if err == nil {
		t.Fatal("expected size cap error")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected exceeds limit, got: %v", err)
	}
}

func TestHeader_MaxRegionEnd(t *testing.T) {
	b := newXBFBuilder()
	b.addType("Page")
	data := b.build()
	r := bytes.NewReader(data)
	h, err := ParseHeader(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if int(h.MaxRegionEnd()) <= HeaderSize {
		t.Fatalf("MaxRegionEnd should be past header, got %d", h.MaxRegionEnd())
	}
}
