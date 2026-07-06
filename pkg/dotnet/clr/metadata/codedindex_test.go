/*
Copyright (c) 2026 Security Research
*/
package metadata

import "testing"

func TestCodedIndex_TagBits(t *testing.T) {
	// Golden: tagBits = ceil(log2(len(tables))) for each coded-index kind.
	want := map[codedKind]struct {
		bits   int
		tables int
	}{
		ciTypeDefOrRef:    {2, 3},
		ciResolutionScope: {2, 4},
		ciMemberRefParent: {3, 5},
		ciHasConstant:     {2, 3},
		ciCustomAttrType:  {3, 5}, // 5 slots (2 reserved), 3 bits
		ciHasCustomAttr:   {5, 22},
	}
	for k, w := range want {
		sc := codedSchemas[k]
		if len(sc.tables) != w.tables {
			t.Errorf("%v: %d tables, want %d", k, len(sc.tables), w.tables)
		}
		if sc.tagBits != w.bits {
			t.Errorf("%v: %d tag bits, want %d", k, sc.tagBits, w.bits)
		}
	}
	// Guard: every kind's tagBits matches ceil(log2(len(tables))).
	for k, sc := range codedSchemas {
		if got := roundUpBits(len(sc.tables)); got != sc.tagBits {
			t.Errorf("%v: tagBits %d, want roundUpBits(%d)=%d", k, sc.tagBits, len(sc.tables), got)
		}
	}
}

func TestCodedIndexWidth(t *testing.T) {
	tabs := &Tables{}
	// HasConstant tags Field/Param/Property; 2 tag bits => threshold 2^14.
	tabs.rowCount[0x04] = 100 // Field small
	if w := tabs.codedIdxWidth(ciHasConstant); w != 2 {
		t.Errorf("codedIdxWidth(HasConstant small) = %d, want 2", w)
	}
	tabs.rowCount[0x04] = 1 << 15 // Field exceeds 2^14 => 4 bytes
	if w := tabs.codedIdxWidth(ciHasConstant); w != 4 {
		t.Errorf("codedIdxWidth(HasConstant large) = %d, want 4", w)
	}
}
