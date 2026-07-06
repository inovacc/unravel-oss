/*
Copyright (c) 2026 Security Research
*/
package metadata

import "encoding/binary"

// metaBuilder hand-rolls an ECMA-335 metadata region (BSJB root + streams),
// mirroring the repo's decompile.synthPE byte-level fixture pattern. It is
// intentionally minimal: only the fields M0-B parses are populated.
type metaBuilder struct {
	strings   []byte            // #Strings heap (starts with a 0 byte)
	stringOff map[string]uint32 // name -> offset into #Strings
	us        []byte            // #US heap (starts with a 0 byte)
	blob      []byte            // #Blob heap (starts with a 0 byte)
	guid      []byte            // #GUID heap (16-byte records, 1-based)

	heapSizes byte            // HeapSizes bitvector
	rows      map[byte]uint32 // table id -> row count
	rowData   map[byte][]byte // table id -> concatenated raw row bytes
	sorted    uint64          // Sorted mask
}

func newMeta() *metaBuilder {
	b := &metaBuilder{
		strings:   []byte{0},
		stringOff: map[string]uint32{"": 0},
		us:        []byte{0},
		blob:      []byte{0},
		rows:      map[byte]uint32{},
		rowData:   map[byte][]byte{},
	}
	return b
}

// intern adds s to #Strings (deduped) and returns its offset.
func (b *metaBuilder) intern(s string) uint32 {
	if off, ok := b.stringOff[s]; ok {
		return off
	}
	off := uint32(len(b.strings))
	b.strings = append(b.strings, []byte(s)...)
	b.strings = append(b.strings, 0)
	b.stringOff[s] = off
	return off
}

// addGUID appends a 16-byte GUID and returns its 1-based index.
func (b *metaBuilder) addGUID(g [16]byte) uint32 {
	b.guid = append(b.guid, g[:]...)
	return uint32(len(b.guid) / 16)
}

// setRows records a row count + raw row bytes for table id.
func (b *metaBuilder) setRows(id byte, count uint32, data []byte) {
	b.rows[id] = count
	b.rowData[id] = data
}

// moduleRowWidth returns the Module (0x00) row width for heapSizes=0:
// uint16(2) + #Strings(2) + 3×#GUID(2) = 10 bytes, matching what sizeTables
// expects for the setRows byte count.
func (b *metaBuilder) moduleRowWidth() int {
	return 2 + 2 + 3*2
}

// addBlob appends a length-prefixed blob to #Blob and returns its offset.
func (b *metaBuilder) addBlob(data []byte) uint32 {
	off := uint32(len(b.blob))
	b.blob = append(b.blob, byte(len(data))) // 1-byte compressed length (fixtures stay < 0x80)
	b.blob = append(b.blob, data...)
	return off
}

// idx2 emits a 2-byte little-endian heap/index value. The fixtures pin
// heapSizes=0, so every heap index is 2 bytes wide.
func idx2(v uint16) []byte {
	return []byte{byte(v), byte(v >> 8)}
}

// u16 emits a 2-byte little-endian column value.
func u16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }

// u32 emits a 4-byte little-endian column value.
func u32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// emitAssembly appends one Assembly row (table 0x20, II.22.2):
// HashAlgId(u32) Maj/Min/Build/Rev(4*u16) Flags(u32) PublicKey(blob) Name(str) Culture(str).
func (b *metaBuilder) emitAssembly(hashAlgID uint32, ver [4]uint16, flags uint32, pk, name, culture uint16) {
	row := []byte{}
	row = append(row, u32(hashAlgID)...)
	for _, v := range ver {
		row = append(row, u16(v)...)
	}
	row = append(row, u32(flags)...)
	row = append(row, idx2(pk)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(culture)...)
	b.rows[0x20]++
	b.rowData[0x20] = append(b.rowData[0x20], row...)
}

// emitAssemblyRef appends one AssemblyRef row (table 0x23, II.22.5):
// Maj/Min/Build/Rev(4*u16) Flags(u32) PublicKeyOrToken(blob) Name(str) Culture(str) HashValue(blob).
func (b *metaBuilder) emitAssemblyRef(ver [4]uint16, flags uint32, pkOrTok, name, culture, hashValue uint16) {
	row := []byte{}
	for _, v := range ver {
		row = append(row, u16(v)...)
	}
	row = append(row, u32(flags)...)
	row = append(row, idx2(pkOrTok)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(culture)...)
	row = append(row, idx2(hashValue)...)
	b.rows[0x23]++
	b.rowData[0x23] = append(b.rowData[0x23], row...)
}

// emitField appends one Field row (table 0x04, II.22.15):
// Flags(u16) Name(str) Sig(blob).
func (b *metaBuilder) emitField(flags, name, sig uint16) {
	row := []byte{}
	row = append(row, u16(flags)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(sig)...)
	b.rows[0x04]++
	b.rowData[0x04] = append(b.rowData[0x04], row...)
}

// emitMethodDef appends one MethodDef row (table 0x06, II.22.26):
// RVA(u32) ImplFlags(u16) Flags(u16) Name(str) Sig(blob) ParamList(simple 0x08).
func (b *metaBuilder) emitMethodDef(rva uint32, implFlags, flags, name, sig, paramList uint16) {
	row := []byte{}
	row = append(row, u32(rva)...)
	row = append(row, u16(implFlags)...)
	row = append(row, u16(flags)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(sig)...)
	row = append(row, idx2(paramList)...)
	b.rows[0x06]++
	b.rowData[0x06] = append(b.rowData[0x06], row...)
}

// emitTypeDef appends one TypeDef row (table 0x02, II.22.37). Note the schema
// column order is Name before Namespace; callers pass (flags, namespace, name,
// extends, fieldStart, methodStart) for readability.
// Flags(u32) Name(str) Namespace(str) Extends(coded TypeDefOrRef)
// FieldList(simple 0x04) MethodList(simple 0x06).
func (b *metaBuilder) emitTypeDef(flags uint32, namespace, name, extends, fieldStart, methodStart uint16) {
	row := []byte{}
	row = append(row, u32(flags)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(namespace)...)
	row = append(row, idx2(extends)...)
	row = append(row, idx2(fieldStart)...)
	row = append(row, idx2(methodStart)...)
	b.rows[0x02]++
	b.rowData[0x02] = append(b.rowData[0x02], row...)
}

// emitTypeRef appends one TypeRef row (table 0x01, II.22.38). The schema column
// order is ResolutionScope(coded) Name(str) Namespace(str); callers pass
// (resolutionScope, namespace, name) for readability.
func (b *metaBuilder) emitTypeRef(resolutionScope, namespace, name uint16) {
	row := []byte{}
	row = append(row, idx2(resolutionScope)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(namespace)...)
	b.rows[0x01]++
	b.rowData[0x01] = append(b.rowData[0x01], row...)
}

// emitMemberRef appends one MemberRef row (table 0x0A, II.22.25):
// Class(coded MemberRefParent) Name(str) Signature(blob).
func (b *metaBuilder) emitMemberRef(parent, name, sig uint16) {
	row := []byte{}
	row = append(row, idx2(parent)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(sig)...)
	b.rows[0x0A]++
	b.rowData[0x0A] = append(b.rowData[0x0A], row...)
}

// memberRefParentTypeRef encodes a MemberRefParent coded index for a TypeRef row
// (tag 1, since the schema order is {TypeDef, TypeRef, ModuleRef, MethodDef,
// TypeSpec}): rid<<3 | 1 (3 tag bits).
func memberRefParentTypeRef(rid uint16) uint16 { return rid<<3 | 1 }

// emitModuleRef appends one ModuleRef row (table 0x1A, II.22.31): Name(str).
func (b *metaBuilder) emitModuleRef(name uint16) {
	b.rows[0x1A]++
	b.rowData[0x1A] = append(b.rowData[0x1A], idx2(name)...)
}

// emitImplMap appends one ImplMap row (table 0x1C, II.22.22):
// MappingFlags(u16) MemberForwarded(coded) ImportName(str) ImportScope(simple 0x1A).
func (b *metaBuilder) emitImplMap(flags, memberForwarded, importName, importScope uint16) {
	row := []byte{}
	row = append(row, u16(flags)...)
	row = append(row, idx2(memberForwarded)...)
	row = append(row, idx2(importName)...)
	row = append(row, idx2(importScope)...)
	b.rows[0x1C]++
	b.rowData[0x1C] = append(b.rowData[0x1C], row...)
}

// memberForwardedMethod encodes a MemberForwarded coded index for a MethodDef
// row (tag 1, since the schema order is {Field, MethodDef}): rid<<1 | 1.
func memberForwardedMethod(rid uint16) uint16 { return rid<<1 | 1 }

// emitFile appends one File row (table 0x26, II.22.19):
// Flags(u32) Name(str) HashValue(blob).
func (b *metaBuilder) emitFile(flags uint32, name, hashValue uint16) {
	row := []byte{}
	row = append(row, u32(flags)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(hashValue)...)
	b.rows[0x26]++
	b.rowData[0x26] = append(b.rowData[0x26], row...)
}

// emitExportedType appends one ExportedType row (table 0x27, II.22.14):
// Flags(u32) TypeDefId(u32) TypeName(str) TypeNamespace(str) Implementation(coded).
func (b *metaBuilder) emitExportedType(flags, typeDefID uint32, name, namespace, impl uint16) {
	row := []byte{}
	row = append(row, u32(flags)...)
	row = append(row, u32(typeDefID)...)
	row = append(row, idx2(name)...)
	row = append(row, idx2(namespace)...)
	row = append(row, idx2(impl)...)
	b.rows[0x27]++
	b.rowData[0x27] = append(b.rowData[0x27], row...)
}

// implementationFile encodes an Implementation coded index for a File row
// (schema order {File, AssemblyRef, ExportedType} → File tag = 0): rid<<2 | 0
// (2 tag bits).
func implementationFile(rid uint16) uint16 { return rid<<2 | 0 }

func align4(n int) int { return (n + 3) &^ 3 }

// build serializes the full metadata region: BSJB root, stream headers, then
// the #~ , #Strings, #US, #Blob, #GUID stream bodies in that order.
func (b *metaBuilder) build() []byte {
	tilde := b.buildTilde()

	type stream struct {
		name string
		data []byte
	}
	streams := []stream{{"#~", tilde}}
	if len(b.strings) > 1 || len(b.stringOff) > 1 {
		streams = append(streams, stream{"#Strings", b.strings})
	}
	if len(b.us) > 1 {
		streams = append(streams, stream{"#US", b.us})
	}
	if len(b.blob) > 1 {
		streams = append(streams, stream{"#Blob", b.blob})
	}
	if len(b.guid) > 0 {
		streams = append(streams, stream{"#GUID", b.guid})
	}

	const version = "v4.0.30319\x00\x00" // 12 bytes, multiple of 4
	// Root fixed prefix: sig(4)+major(2)+minor(2)+reserved(4)+verlen(4)+ver+flags(2)+nstreams(2).
	headerLen := 16 + len(version) + 4
	for _, s := range streams {
		nm := s.name + "\x00"
		headerLen += 8 + align4(len(nm)) // offset(4)+size(4)+padded name
	}

	out := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(out[0:], bsjbSignature)
	binary.LittleEndian.PutUint16(out[4:], 1) // MajorVersion
	binary.LittleEndian.PutUint16(out[6:], 1) // MinorVersion
	binary.LittleEndian.PutUint32(out[8:], 0) // Reserved
	binary.LittleEndian.PutUint32(out[12:], uint32(len(version)))
	copy(out[16:], version)
	p := 16 + len(version)
	binary.LittleEndian.PutUint16(out[p:], 0) // Flags
	binary.LittleEndian.PutUint16(out[p+2:], uint16(len(streams)))
	p += 4

	// Stream bodies are appended after the header; record offsets as we go.
	bodies := []byte{}
	for _, s := range streams {
		off := uint32(headerLen + len(bodies))
		binary.LittleEndian.PutUint32(out[p:], off)
		binary.LittleEndian.PutUint32(out[p+4:], uint32(len(s.data)))
		nm := s.name + "\x00"
		copy(out[p+8:], nm)
		p += 8 + align4(len(nm))
		bodies = append(bodies, s.data...)
	}
	return append(out, bodies...)
}

// buildTilde serializes the #~ stream: header + Rows[] + (later) row data.
func (b *metaBuilder) buildTilde() []byte {
	var valid uint64
	for id := byte(0); id <= maxTableID; id++ {
		if b.rows[id] > 0 || b.rowData[id] != nil {
			valid |= 1 << id
		}
	}
	out := make([]byte, 24)
	// Reserved(4)=0, Major(1)=2, Minor(1)=0, HeapSizes(1), Reserved(1)=1, Valid(8), Sorted(8).
	out[4] = 2
	out[6] = b.heapSizes
	out[7] = 1
	binary.LittleEndian.PutUint64(out[8:], valid)
	binary.LittleEndian.PutUint64(out[16:], b.sorted)
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			var n [4]byte
			binary.LittleEndian.PutUint32(n[:], b.rows[id])
			out = append(out, n[:]...)
		}
	}
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, b.rowData[id]...)
		}
	}
	return out
}
