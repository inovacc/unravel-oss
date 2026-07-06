/*
Copyright (c) 2026 Security Research
*/
package metadata

import "testing"

func TestTypes_OwnerRanges(t *testing.T) {
	b := newMeta()
	b.heapSizes = 0
	nsOff := uint16(b.intern("LinkedIn"))
	// Two fields, three methods, split across two TypeDefs.
	f0 := uint16(b.intern("a"))
	f1 := uint16(b.intern("b"))
	b.emitField(0x0001, f0, 0)
	b.emitField(0x0001, f1, 0)
	m0 := uint16(b.intern("M0"))
	m1 := uint16(b.intern("M1"))
	m2 := uint16(b.intern("M2"))
	b.emitMethodDef(0x2000, 0, 0, m0, 0, 0)
	b.emitMethodDef(0x2010, 0, 0, m1, 0, 0)
	b.emitMethodDef(0x2020, 0, 0, m2, 0, 0)
	// Type A owns fields [1,2) and methods [1,3); Type B owns [2,3) and [3,4).
	tA := uint16(b.intern("TypeA"))
	tB := uint16(b.intern("TypeB"))
	b.emitTypeDef(0, nsOff, tA, 0, 1, 1) // fieldStart=1, methodStart=1
	b.emitTypeDef(0, nsOff, tB, 0, 2, 3) // fieldStart=2, methodStart=3

	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	types := tabs.Types()
	if len(types) != 2 {
		t.Fatalf("Types() = %d, want 2", len(types))
	}
	if got := len(types[0].Fields); got != 1 || types[0].Fields[0].Name != "a" {
		t.Errorf("TypeA fields = %d (%v)", got, types[0].Fields)
	}
	if got := len(types[0].Methods); got != 2 || types[0].Methods[1].Name != "M1" {
		t.Errorf("TypeA methods = %d", got)
	}
	if got := len(types[1].Methods); got != 1 || types[1].Methods[0].Name != "M2" {
		t.Errorf("TypeB methods = %d", got)
	}
	if types[0].Token.TableID() != 0x02 || types[0].Token.RowID() != 1 {
		t.Errorf("TypeA token = %#x", uint32(types[0].Token))
	}
}

func TestPInvokes(t *testing.T) {
	b := newMeta()
	b.heapSizes = 0
	mr := uint16(b.intern("M0"))
	b.emitMethodDef(0, 0, 0x2000, mr, 0, 0) // a method to forward (flags has PInvokeImpl)
	dll := uint16(b.intern("kernel32.dll"))
	b.emitModuleRef(dll)
	ep := uint16(b.intern("CreateFileW"))
	// ImplMap: Flags, MemberForwarded(coded ->MethodDef rid1), ImportName, ImportScope(ModuleRef rid1)
	b.emitImplMap(0x0100, memberForwardedMethod(1), ep, 1)

	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pis := tabs.PInvokes()
	if len(pis) != 1 || pis[0].ImportName != "CreateFileW" || pis[0].ImportScope != "kernel32.dll" {
		t.Fatalf("PInvokes() = %+v", pis)
	}
	if pis[0].MemberForwarded.TableID() != 0x06 || pis[0].MemberForwarded.RowID() != 1 {
		t.Errorf("MemberForwarded token = %#x", uint32(pis[0].MemberForwarded))
	}
}
