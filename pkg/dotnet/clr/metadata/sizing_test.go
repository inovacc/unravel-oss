/*
Copyright (c) 2026 Security Research
*/
package metadata

import "testing"

func TestIndexWidths(t *testing.T) {
	tabs := &Tables{}
	tabs.rowCount[0x06] = 5       // MethodDef: small
	tabs.rowCount[0x02] = 1 << 17 // TypeDef: large -> 4-byte simple index
	tabs.heapSizes = heapSizeBlob // blob index 4 bytes; string/guid 2 bytes

	if w := tabs.stringIdxWidth(); w != 2 {
		t.Errorf("stringIdxWidth = %d, want 2", w)
	}
	if w := tabs.blobIdxWidth(); w != 4 {
		t.Errorf("blobIdxWidth = %d, want 4", w)
	}
	if w := tabs.simpleIdxWidth(0x06); w != 2 {
		t.Errorf("simpleIdxWidth(MethodDef small) = %d, want 2", w)
	}
	if w := tabs.simpleIdxWidth(0x02); w != 4 {
		t.Errorf("simpleIdxWidth(TypeDef large) = %d, want 4", w)
	}
}

// moduleRefW is the computed ModuleRef row width: a single #Strings index.
// With heapSizes == 0 the #Strings index is 2 bytes, so the fixture supplies
// the right number of bytes; the implementation must agree.
const moduleRefW = 2

func TestRowWindow_Slicing(t *testing.T) {
	// Two tables: Module(0x00) with 1 row of 10 bytes, ModuleRef(0x1A) with 2
	// rows. Width is exercised end-to-end through Parse.
	b := newMeta()
	b.heapSizes = 0                                // all heap indexes 2 bytes
	b.setRows(0x00, 1, make([]byte, 10))           // Module row width = 10 here
	b.setRows(0x1A, 2, make([]byte, 2*moduleRefW)) // ModuleRef rows
	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := len(tabs.rowData[0x1A]); got != 2*int(tabs.rowWidth[0x1A]) {
		t.Errorf("ModuleRef window = %d bytes, want %d", got, 2*int(tabs.rowWidth[0x1A]))
	}
}
