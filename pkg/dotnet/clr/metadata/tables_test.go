/*
Copyright (c) 2026 Security Research
*/
package metadata

import "testing"

func TestParse_TildeHeader(t *testing.T) {
	b := newMeta()
	b.heapSizes = heapSizeStrings
	b.setRows(0x00, 1, make([]byte, 12)) // Module row (12 bytes: 4-byte #Strings idx); decode lands M0-5
	// TypeDef rows are now schema-sized (M0-5): 18 bytes/row with the wide
	// #Strings index — Flags(4)+Name(4)+Namespace(4)+Extends(2)+Fields(2)+Methods(2).
	b.setRows(0x02, 3, make([]byte, 3*18))
	b.sorted = 1 << 0x0B // Constant table sorted

	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := tabs.RowCount(0x02); got != 3 {
		t.Errorf("RowCount(TypeDef) = %d, want 3", got)
	}
	if got := tabs.RowCount(0x01); got != 0 {
		t.Errorf("RowCount(TypeRef) = %d, want 0", got)
	}
	if !tabs.heapSizes2byte(0x02) { // GUID index narrow (bit not set)
		t.Errorf("GUID index should be 2 bytes when heap bit unset")
	}
}
