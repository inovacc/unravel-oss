/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"errors"
	"testing"
)

func TestParse_RejectsPtrIndirection(t *testing.T) {
	ptrTables := []byte{0x03, 0x05, 0x07, 0x12, 0x13}
	for _, id := range ptrTables {
		b := newMeta()
		b.heapSizes = 0
		b.setRows(0x00, 1, make([]byte, b.moduleRowWidth())) // a valid Module row
		// Present a *Ptr table with one 2-byte index row.
		b.setRows(id, 1, []byte{0x01, 0x00})
		_, _, err := Parse(b.build())
		if !errors.Is(err, ErrIndirectionTablesUnsupported) {
			t.Errorf("table %#x: err = %v, want ErrIndirectionTablesUnsupported", id, err)
		}
	}
}

func TestParse_NoIndirection_OK(t *testing.T) {
	b := newMeta()
	b.heapSizes = 0
	b.setRows(0x00, 1, make([]byte, b.moduleRowWidth()))
	if _, _, err := Parse(b.build()); err != nil {
		t.Fatalf("Parse without *Ptr should succeed: %v", err)
	}
}
