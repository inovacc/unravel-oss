/*
Copyright (c) 2026 Security Research
*/
package metadata

import "testing"

func TestDecode_AssemblyAndRefs(t *testing.T) {
	b := newMeta()
	b.heapSizes = 0 // 2-byte heap indexes throughout
	// Assembly(0x20): HashAlgId(4) Maj/Min/Build/Rev(2*4) Flags(4) PublicKey(blob) Name(str) Culture(str)
	asmName := uint16(b.intern("LinkedIn"))
	pk := uint16(b.addBlob([]byte{0xAB, 0xCD}))
	b.emitAssembly(0x8004, [4]uint16{3, 0, 43, 0}, 0, pk, asmName, 0)
	// AssemblyRef(0x23): Maj/Min/Build/Rev(2*4) Flags(4) PublicKeyOrToken(blob) Name(str) Culture(str) HashValue(blob)
	refName := uint16(b.intern("System.Runtime"))
	b.emitAssemblyRef([4]uint16{8, 0, 0, 0}, 0, 0, refName, 0, 0)

	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	asm, ok := tabs.Assembly()
	if !ok || asm.Name != "LinkedIn" || asm.Version != [4]uint16{3, 0, 43, 0} {
		t.Fatalf("Assembly() = %+v ok=%v", asm, ok)
	}
	if len(asm.PublicKey) != 2 || asm.PublicKey[0] != 0xAB {
		t.Errorf("PublicKey = %v", asm.PublicKey)
	}
	refs := tabs.AssemblyRefs()
	if len(refs) != 1 || refs[0].Name != "System.Runtime" || refs[0].Version[0] != 8 {
		t.Fatalf("AssemblyRefs() = %+v", refs)
	}
}
