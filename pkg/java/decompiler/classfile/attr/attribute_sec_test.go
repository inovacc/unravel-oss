package attr

import (
	"encoding/binary"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// buildAttributeBytes builds a raw attribute stream: nameIdx(u2) + length(u4) + body.
// The constant pool must have a UTF-8 entry at nameIdx.
func buildAttributeBytes(nameIdx uint16, bodyLen uint32) []byte {
	buf := make([]byte, 6+int(bodyLen))
	binary.BigEndian.PutUint16(buf[0:], nameIdx)
	binary.BigEndian.PutUint32(buf[2:], bodyLen)
	return buf
}

// buildMinimalCP returns a Pool with one UTF-8 entry "UnknownAttr" at index 1.
func buildMinimalCP(t *testing.T) *constantpool.Pool {
	t.Helper()
	// constant_pool_count = 2 (one real entry at index 1)
	// entry: tag=1 (UTF8), length=11, data="UnknownAttr"
	s := "UnknownAttr"
	cpBuf := make([]byte, 1+2+len(s))
	cpBuf[0] = 1 // TagUTF8
	binary.BigEndian.PutUint16(cpBuf[1:], uint16(len(s)))
	copy(cpBuf[3:], s)

	r := reader.NewReader(cpBuf)
	cp, err := constantpool.Read(r, 2) // count=2 → 1 real entry
	if err != nil {
		t.Fatalf("build minimal CP: %v", err)
	}
	return cp
}

// TestReadAttributes_HugeLength verifies that an attribute with length > 64 MiB
// is rejected before attempting a 4 GiB allocation via r.Slice.
func TestReadAttributes_HugeLength(t *testing.T) {
	cp := buildMinimalCP(t)

	// Attribute: nameIdx=1 ("UnknownAttr"), length=0xFFFFFFFF
	const hugeLen = 0xFFFFFFFF
	buf := buildAttributeBytes(1, hugeLen)
	r := reader.NewReader(buf)

	_, err := ReadAttributes(r, cp, 1)
	if err == nil {
		t.Fatal("expected error for attribute length=0xFFFFFFFF, got nil")
	}
}

// TestReadAttributes_SmallLength verifies a normal-sized unknown attribute is stored as Raw.
func TestReadAttributes_SmallLength(t *testing.T) {
	cp := buildMinimalCP(t)

	body := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := buildAttributeBytes(1, uint32(len(body)))
	buf = append(buf[:6], body...)
	r := reader.NewReader(buf)

	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Get("UnknownAttr") == nil {
		t.Error("expected UnknownAttr in attribute map")
	}
}
