/*
Copyright (c) 2026 Security Research
*/
package metadata

import "math/bits"

type codedKind int

const (
	ciTypeDefOrRef codedKind = iota
	ciHasConstant
	ciHasCustomAttr
	ciHasFieldMarshal
	ciHasDeclSecurity
	ciMemberRefParent
	ciHasSemantics
	ciMethodDefOrRef
	ciMemberForwarded
	ciImplementation
	ciCustomAttrType
	ciResolutionScope
	ciTypeOrMethodDef
)

const reservedTag = 0xFF

type codedSchema struct {
	tagBits int
	tables  []byte // tag value -> table id (reservedTag for unused slots)
}

// codedSchemas is the ECMA-335 II.24.2.6 coded-index encoding. tagBits =
// ceil(log2(len(tables))).
var codedSchemas = map[codedKind]codedSchema{
	ciTypeDefOrRef:    {2, []byte{0x02, 0x01, 0x1B}},                                                                                                                   // TypeDef,TypeRef,TypeSpec
	ciHasConstant:     {2, []byte{0x04, 0x08, 0x17}},                                                                                                                   // Field,Param,Property
	ciHasCustomAttr:   {5, []byte{0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2B, 0x2C}}, // 22 tables
	ciHasFieldMarshal: {1, []byte{0x04, 0x08}},                                                                                                                         // Field,Param
	ciHasDeclSecurity: {2, []byte{0x02, 0x06, 0x20}},                                                                                                                   // TypeDef,MethodDef,Assembly
	ciMemberRefParent: {3, []byte{0x02, 0x01, 0x1A, 0x06, 0x1B}},                                                                                                       // TypeDef,TypeRef,ModuleRef,MethodDef,TypeSpec
	ciHasSemantics:    {1, []byte{0x14, 0x17}},                                                                                                                         // Event,Property
	ciMethodDefOrRef:  {1, []byte{0x06, 0x0A}},                                                                                                                         // MethodDef,MemberRef
	ciMemberForwarded: {1, []byte{0x04, 0x06}},                                                                                                                         // Field,MethodDef
	ciImplementation:  {2, []byte{0x26, 0x23, 0x27}},                                                                                                                   // File,AssemblyRef,ExportedType
	ciCustomAttrType:  {3, []byte{reservedTag, reservedTag, 0x06, 0x0A, reservedTag}},                                                                                  // _,_,MethodDef,MemberRef,_
	ciResolutionScope: {2, []byte{0x00, 0x1A, 0x23, 0x01}},                                                                                                             // Module,ModuleRef,AssemblyRef,TypeRef
	ciTypeOrMethodDef: {1, []byte{0x02, 0x06}},                                                                                                                         // TypeDef,MethodDef
}

// codedIdxWidth returns the byte width of a coded index of kind k: 4 bytes iff
// the largest tagged table exceeds 2^(16-tagBits) rows (II.24.2.6).
func (t *Tables) codedIdxWidth(k codedKind) int {
	sc := codedSchemas[k]
	threshold := uint32(1) << uint(16-sc.tagBits)
	for _, id := range sc.tables {
		if id == reservedTag {
			continue
		}
		if t.rowCount[id] >= threshold {
			return 4
		}
	}
	return 2
}

// decodeCoded splits a raw coded-index value into (tableID, rowID). rowID is
// 1-based; a 0 rowID means a null reference (tableID is then meaningless).
func decodeCoded(k codedKind, raw uint32) (tableID byte, rowID uint32) {
	sc := codedSchemas[k]
	mask := uint32(1)<<uint(sc.tagBits) - 1
	tag := raw & mask
	rowID = raw >> uint(sc.tagBits)
	if int(tag) >= len(sc.tables) {
		return reservedTag, rowID
	}
	return sc.tables[tag], rowID
}

// roundUpBits is a helper used by the golden test to validate tagBits.
func roundUpBits(n int) int {
	if n <= 1 {
		return 0
	}
	return bits.Len(uint(n - 1))
}
