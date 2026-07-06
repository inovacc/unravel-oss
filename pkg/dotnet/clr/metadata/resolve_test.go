/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

func TestResolveNames(t *testing.T) {
	b := newMeta()
	b.heapSizes = 0
	// MethodDef rid1 "Compute" with a sig blob.
	mName := uint16(b.intern("Compute"))
	mSig := uint16(b.addBlob([]byte{0x20, 0x01, 0x08})) // arbitrary method sig bytes
	b.emitMethodDef(0, 0, 0, mName, mSig, 0)
	// Field rid1 "counter".
	fName := uint16(b.intern("counter"))
	fSig := uint16(b.addBlob([]byte{0x06, 0x08}))
	b.emitField(0, fName, fSig)
	// TypeDef rid1 "Engine" / TypeRef rid1 "Console".
	nsOff := uint16(b.intern("LinkedIn"))
	tdName := uint16(b.intern("Engine"))
	b.emitTypeDef(0, nsOff, tdName, 0, 1, 1)
	trName := uint16(b.intern("Console"))
	trNs := uint16(b.intern("System"))
	b.emitTypeRef(0, trNs, trName) // ResolutionScope, Namespace, Name
	// MemberRef rid1 "WriteLine" (parent TypeRef rid1), sig blob.
	mrName := uint16(b.intern("WriteLine"))
	mrSig := uint16(b.addBlob([]byte{0x00, 0x01, 0x01}))
	b.emitMemberRef(memberRefParentTypeRef(1), mrName, mrSig)

	tabs, _, err := Parse(b.build())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if name, sig, ok := tabs.MethodName(clrtok.Token(uint32(clrtok.TblMethodDef)<<24 | 1)); !ok || name != "Compute" || len(sig) != 3 {
		t.Errorf("MethodName(MethodDef rid1) = %q, sig=%v, ok=%v", name, sig, ok)
	}
	if name, _, ok := tabs.MethodName(clrtok.Token(uint32(clrtok.TblMemberRef)<<24 | 1)); !ok || name != "WriteLine" {
		t.Errorf("MethodName(MemberRef rid1) = %q, ok=%v", name, ok)
	}
	if name, _, ok := tabs.FieldName(clrtok.Token(uint32(clrtok.TblField)<<24 | 1)); !ok || name != "counter" {
		t.Errorf("FieldName(Field rid1) = %q, ok=%v", name, ok)
	}
	if name, ok := tabs.TypeName(clrtok.Token(uint32(clrtok.TblTypeDef)<<24 | 1)); !ok || name != "LinkedIn.Engine" {
		t.Errorf("TypeName(TypeDef rid1) = %q, ok=%v", name, ok)
	}
	if name, ok := tabs.TypeName(clrtok.Token(uint32(clrtok.TblTypeRef)<<24 | 1)); !ok || name != "System.Console" {
		t.Errorf("TypeName(TypeRef rid1) = %q, ok=%v", name, ok)
	}
	// Out-of-range RID and wrong-table token both report not-ok.
	if _, _, ok := tabs.MethodName(clrtok.Token(uint32(clrtok.TblMethodDef)<<24 | 999)); ok {
		t.Errorf("MethodName(out-of-range) should be ok=false")
	}
	if _, ok := tabs.TypeName(clrtok.Token(uint32(clrtok.TblField)<<24 | 1)); ok {
		t.Errorf("TypeName(wrong table) should be ok=false")
	}
}
