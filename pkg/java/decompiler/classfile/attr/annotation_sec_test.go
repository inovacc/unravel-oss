package attr

import (
	"encoding/binary"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// buildLocalVarTargetBytes builds a raw byte stream for a localvar_target with the
// given tableLen, followed by tableLen*6 zero bytes (table entries).
func buildLocalVarTargetBytes(tableLen uint16) []byte {
	buf := make([]byte, 2+int(tableLen)*6)
	binary.BigEndian.PutUint16(buf[0:], tableLen)
	return buf
}

// TestLocalVarTarget_HugeTableLen verifies that tableLen > maxLocalVarTargetEntries
// is rejected before a large allocation occurs.
func TestLocalVarTarget_HugeTableLen(t *testing.T) {
	// tableLen = 65535 → 2 + 65535*6 = 393212 bytes per entry; nested annotations
	// can multiply this to ~25 GiB.
	const hugeLen = 65535
	buf := buildLocalVarTargetBytes(hugeLen)
	r := reader.NewReader(buf)
	_, err := readTargetInfo(r, 0x40)
	if err == nil {
		t.Fatal("expected error for huge localvar_target tableLen, got nil")
	}
}

// TestLocalVarTarget_SmallTableLen verifies a legitimate small table still parses.
func TestLocalVarTarget_SmallTableLen(t *testing.T) {
	const smallLen = 2
	buf := buildLocalVarTargetBytes(smallLen)
	r := reader.NewReader(buf)
	data, err := readTargetInfo(r, 0x40)
	if err != nil {
		t.Fatalf("unexpected error for small localvar_target: %v", err)
	}
	wantLen := 2 + int(smallLen)*6
	if len(data) != wantLen {
		t.Errorf("data length: got %d want %d", len(data), wantLen)
	}
}
