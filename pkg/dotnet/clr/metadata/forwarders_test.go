/*
Copyright (c) 2026 Security Research
*/
package metadata

import "testing"

func TestForwarders_Recorded(t *testing.T) {
	b := newMeta()
	b.heapSizes = 0
	fn := uint16(b.intern("LinkedIn.Core.dll"))
	b.emitFile(0, fn, 0) // Flags, Name, HashValue(blob)
	tn := uint16(b.intern("Widget"))
	ns := uint16(b.intern("LinkedIn.UI"))
	// ExportedType: Flags, TypeDefId, TypeName(str), TypeNamespace(str), Implementation(coded ->File rid1)
	b.emitExportedType(0, 0, tn, ns, implementationFile(1))

	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	files := tabs.Files()
	if len(files) != 1 || files[0].Name != "LinkedIn.Core.dll" {
		t.Fatalf("Files() = %+v", files)
	}
	ets := tabs.ExportedTypes()
	if len(ets) != 1 || ets[0].Name != "Widget" || ets[0].Namespace != "LinkedIn.UI" {
		t.Fatalf("ExportedTypes() = %+v", ets)
	}
	if ets[0].Implementation.TableID() != 0x26 || ets[0].Implementation.RowID() != 1 {
		t.Errorf("Implementation token = %#x", uint32(ets[0].Implementation))
	}
}
