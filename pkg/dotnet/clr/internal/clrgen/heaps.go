/*
Copyright (c) 2026 Security Research
*/
package clrgen

import (
	"bytes"
	"encoding/binary"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

// heapBuilder accumulates one metadata heap and hands back byte offsets.
type heapBuilder struct {
	buf bytes.Buffer
	// off memoizes string -> heap offset so identical strings intern once.
	off map[string]uint32
}

func newStringsHeap() *heapBuilder {
	h := &heapBuilder{off: map[string]uint32{}}
	h.buf.WriteByte(0) // #Strings index 0 == empty string (ECMA-335 II.24.2.3)
	h.off[""] = 0
	return h
}

// addString appends a null-terminated UTF-8 string, returns its heap offset.
// Identical strings are interned so they share one offset.
func (h *heapBuilder) addString(s string) uint32 {
	if o, ok := h.off[s]; ok {
		return o
	}
	off := uint32(h.buf.Len())
	h.buf.WriteString(s)
	h.buf.WriteByte(0)
	h.off[s] = off
	return off
}

// userStrings builds a #US heap. II.24.2.4: 7-bit compressed length prefix over
// (2*chars + 1), UTF-16LE bytes, then one trailing flag byte (0).
func buildUS(strs []string) []byte {
	var b bytes.Buffer
	b.WriteByte(0) // #US index 0 == empty (single null)
	for _, s := range strs {
		u := utf16le(s)
		writeCompressedUint(&b, uint32(len(u)+1)) // +1 for trailing flag
		b.Write(u)
		b.WriteByte(0) // trailing "contains non-ASCII?" flag
	}
	return b.Bytes()
}

func utf16le(s string) []byte {
	r := []rune(s)
	out := make([]byte, 0, len(r)*2)
	for _, c := range r {
		out = append(out, byte(c), byte(c>>8)) // BMP only — fixtures stay BMP
	}
	return out
}

// writeCompressedUint emits an ECMA-335 II.23.2 compressed unsigned integer.
func writeCompressedUint(b *bytes.Buffer, v uint32) {
	switch {
	case v < 0x80:
		b.WriteByte(byte(v))
	case v < 0x4000:
		b.WriteByte(byte(v>>8) | 0x80)
		b.WriteByte(byte(v))
	default:
		b.WriteByte(byte(v>>24) | 0xC0)
		b.WriteByte(byte(v >> 16))
		b.WriteByte(byte(v >> 8))
		b.WriteByte(byte(v))
	}
}

// buildBlob builds a #Blob heap; entry 0 is a single 0x00 (empty blob).
func buildBlob(blobs [][]byte) ([]byte, []uint32) {
	var b bytes.Buffer
	b.WriteByte(0)
	offs := make([]uint32, len(blobs))
	for i, bl := range blobs {
		offs[i] = uint32(b.Len())
		writeCompressedUint(&b, uint32(len(bl)))
		b.Write(bl)
	}
	return b.Bytes(), offs
}

// metaVersion is the length-prefixed, 4-byte-aligned version string in the BSJB
// root (II.24.2.1). "v4.0.30319" is 10 bytes; with a NUL terminator that is 11,
// rounded up to 12 (a multiple of 4).
const metaVersion = "v4.0.30319"

// align4 rounds n up to the next multiple of 4.
func align4(n uint32) uint32 { return (n + 3) &^ 3 }

// writeStreamHeader writes one BSJB stream header (II.24.2.2): Offset (u32, from
// the start of the metadata root), Size (u32), then the NUL-terminated, 4-byte-
// aligned stream name.
func writeStreamHeader(w *bytes.Buffer, off, size uint32, name string) {
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:], off)
	binary.LittleEndian.PutUint32(hdr[4:], size)
	w.Write(hdr[:])
	w.WriteString(name)
	w.WriteByte(0)
	for n := uint32(len(name)) + 1; n%4 != 0; n++ {
		w.WriteByte(0)
	}
}

// buildMetadata assembles the BSJB root + stream headers + #~ + heaps. The byte
// layout mirrors M0-A's metaRegion fixture exactly so the reader and emitter stay
// byte-aligned. The #~ table rows are produced by tableLayout (T-G02); this method
// owns the root, the version string, the stream directory, and heap concatenation.
func (b *Builder) buildMetadata() []byte {
	// Build the five stream bodies first so we can compute their offsets.
	tablesStream := b.tableLayout() // #~ rows, via clrtok-built tokens (T-G02)
	strings, us, blob, guid := b.buildHeaps()

	const streamCount = 5
	// Root prefix: signature(4) + major(2) + minor(2) + reserved(4)
	//   + verLen(4) + version(align4) + flags(2) + streamCount(2).
	verBuf := make([]byte, align4(uint32(len(metaVersion))+1))
	copy(verBuf, metaVersion) // remaining bytes stay zero (NUL pad)

	var root bytes.Buffer
	var sig [4]byte
	binary.LittleEndian.PutUint32(sig[:], 0x424A5342) // "BSJB"
	root.Write(sig[:])
	var word [4]byte
	binary.LittleEndian.PutUint16(word[0:], 1) // MajorVersion
	binary.LittleEndian.PutUint16(word[2:], 1) // MinorVersion
	root.Write(word[:])
	binary.LittleEndian.PutUint32(word[:], 0) // Reserved
	root.Write(word[:])
	binary.LittleEndian.PutUint32(word[:], uint32(len(verBuf))) // version length
	root.Write(word[:])
	root.Write(verBuf)
	binary.LittleEndian.PutUint16(word[0:], 0)           // Flags
	binary.LittleEndian.PutUint16(word[2:], streamCount) // number of streams
	root.Write(word[:])

	// Compute the body region start: root prefix + 5 stream headers.
	hdrLen := func(name string) uint32 { return 8 + align4(uint32(len(name))+1) }
	bodyStart := uint32(root.Len()) +
		hdrLen("#~") + hdrLen("#Strings") + hdrLen("#US") + hdrLen("#Blob") + hdrLen("#GUID")

	tOff := bodyStart
	sOff := tOff + align4(uint32(len(tablesStream)))
	uOff := sOff + align4(uint32(len(strings)))
	blOff := uOff + align4(uint32(len(us)))
	gOff := blOff + align4(uint32(len(blob)))

	writeStreamHeader(&root, tOff, uint32(len(tablesStream)), "#~")
	writeStreamHeader(&root, sOff, uint32(len(strings)), "#Strings")
	writeStreamHeader(&root, uOff, uint32(len(us)), "#US")
	writeStreamHeader(&root, blOff, uint32(len(blob)), "#Blob")
	writeStreamHeader(&root, gOff, uint32(len(guid)), "#GUID")

	writeAligned := func(body []byte) {
		root.Write(body)
		for root.Len()%4 != 0 { // pad each stream body to a 4-byte boundary
			root.WriteByte(0)
		}
	}
	writeAligned(tablesStream)
	writeAligned(strings)
	writeAligned(us)
	writeAligned(blob)
	writeAligned(guid)

	return root.Bytes()
}

// buildHeaps materializes the #Strings, #US, #Blob and #GUID heap bodies from the
// builder's accumulated intent. The #Strings heap interns every name referenced by
// the emitted tables; the #US heap holds the user strings; the #Blob heap holds the
// method/field/local signatures; the #GUID heap holds the single module MVID.
//
// This method is the heap-owning half of the M0-A metaRegion fixture seam. It is a
// dependency of buildMetadata (T-G01) and is expanded with full per-table signature
// blobs by the table-layout work (T-G02). The string-offset and blob-offset maps it
// computes are consumed by tableLayout so the two stay byte-aligned.
func (b *Builder) buildHeaps() (strings, us, blob, guid []byte) {
	h := b.stringsHeap()
	us = buildUS(b.userStrings)
	bl, _ := buildBlob(b.blobs())
	// #GUID: one 16-byte module version id (all-zero is a valid placeholder MVID).
	guid = make([]byte, 16)
	return h.buf.Bytes(), us, bl, guid
}

// stringsHeap interns, in a deterministic order, every #Strings name the emitted
// tables reference: the assembly name, each AssemblyRef name, every TypeDef
// namespace+name and its methods, and each P/Invoke entry/module pair.
func (b *Builder) stringsHeap() *heapBuilder {
	h := newStringsHeap()
	h.addString(b.asmName)
	for _, r := range b.refs {
		h.addString(r.name)
	}
	for _, t := range b.types {
		h.addString(t.ns)
		h.addString(t.name)
		for _, m := range t.methods {
			h.addString(m.name)
		}
	}
	for _, p := range b.pinvokes {
		h.addString(p.entry)
		h.addString(p.module)
	}
	return h
}

// blobs returns the signature blobs referenced by the emitted tables. The Tier-1
// fixtures use canonical minimal signatures: a static parameterless void method
// (II.23.2.1: HASTHIS=0, ParamCount=0, RetType=void). T-G02 widens this to per-method
// real signatures; here every MethodDef shares the one canonical blob.
func (b *Builder) blobs() [][]byte {
	var out [][]byte
	// void Method(): CallingConvention(DEFAULT=0x00), ParamCount(0x00), RetType(VOID=0x01).
	voidSig := []byte{0x00, 0x00, 0x01}
	for _, t := range b.types {
		for range t.methods {
			out = append(out, voidSig)
		}
	}
	return out
}

// tableLayout emits the #~ tables stream (II.24.2.6): a 24-byte header (Reserved,
// MajorVersion, MinorVersion, HeapSizes=0, Reserved, Valid bitvector, Sorted
// bitvector), the per-present-table row counts, then the row data in ascending
// TableID order. HeapSizes=0 means every #Strings/#GUID/#Blob index is 2 bytes.
//
// Tokens and table ids come from clrtok (clrtok.Token + the Tbl* consts) so the
// emitter never imports package clr. This is the T-G01-minimal row writer; the
// byte-golden table fidelity (every column, coded-index width) is locked by T-G02.
func (b *Builder) tableLayout() []byte {
	tl := newTableLayout()

	h := b.stringsHeap() // recompute offsets (deterministic, same order)
	_, blobOffs := buildBlob(b.blobs())

	// Module (Tbl 0x00): Generation(u16) Name(str) Mvid(guid#1) EncId/EncBaseId(guid#0).
	tl.row(clrtok.TblModule, concat(
		u16b(0), strIdx(h, b.asmName), guidIdx(1), guidIdx(0), guidIdx(0))...)

	// TypeRef (Tbl 0x01): ResolutionScope(coded) Name(str) Namespace(str). One per
	// AssemblyRef as a coarse system-type placeholder.
	for i := range b.refs {
		// ResolutionScope tag 2 (AssemblyRef), 2 tag bits: rid<<2 | 2.
		scope := uint16(i+1)<<2 | 2
		tl.row(clrtok.TblTypeRef, concat(u16b(scope), strIdx(h, "Object"), strIdx(h, "System"))...)
	}

	// TypeDef (Tbl 0x02): Flags(u32) Name(str) Namespace(str) Extends(coded)
	// FieldList(field idx) MethodList(method idx).
	methodIdx := uint16(1)
	for _, t := range b.types {
		tl.row(clrtok.TblTypeDef, concat(
			u32b(0),
			strIdx(h, t.name), strIdx(h, t.ns),
			u16b(0),         // Extends (nil coded index)
			u16b(1),         // FieldList -> first field
			u16b(methodIdx), // MethodList -> first owned method
		)...)
		methodIdx += uint16(len(t.methods))
	}

	// MethodDef (Tbl 0x06): RVA(u32) ImplFlags(u16) Flags(u16) Name(str)
	// Signature(blob) ParamList(param idx).
	sigN := 0
	for _, t := range b.types {
		for _, m := range t.methods {
			var sig uint16
			if sigN < len(blobOffs) {
				sig = uint16(blobOffs[sigN])
			}
			sigN++
			tl.row(clrtok.TblMethodDef, concat(
				u32b(m.rva),
				u16b(0),      // ImplFlags (managed IL)
				u16b(0x0016), // Flags: Public|Static
				strIdx(h, m.name),
				u16b(sig),
				u16b(1), // ParamList
			)...)
		}
	}

	// MethodPtr (Tbl 0x05): emitted only under WithPtrIndirection to prove the
	// reader rejects *Ptr indirection (spec §3 Must-fix #3).
	b.emitPtrIndirection(tl)

	// ModuleRef (Tbl 0x1A) + ImplMap (Tbl 0x1C): native P/Invoke forwards. Each
	// P/Invoke forwards the first emitted MethodDef (rid 1) for a deterministic
	// layout. Rows are sorted into ascending TableID order by tableLayoutBuilder.
	b.emitPInvokeTables(tl, h, 1)

	// Assembly (Tbl 0x20): HashAlgId(u32) Ver(4*u16) Flags(u32) PublicKey(blob)
	// Name(str) Culture(str).
	asmRow := u32b(0)
	for _, v := range b.asmVer {
		asmRow = append(asmRow, u16b(v)...)
	}
	asmRow = append(asmRow, u32b(0)...)              // Flags
	asmRow = append(asmRow, u16b(0)...)              // PublicKey blob
	asmRow = append(asmRow, strIdx(h, b.asmName)...) // Name
	asmRow = append(asmRow, u16b(0)...)              // Culture
	tl.row(0x20, asmRow...)

	// AssemblyRef (Tbl 0x23): Ver(4*u16) Flags(u32) PublicKeyOrToken(blob)
	// Name(str) Culture(str) HashValue(blob).
	for _, r := range b.refs {
		row := []byte{}
		for _, v := range r.ver {
			row = append(row, u16b(v)...)
		}
		row = append(row, u32b(0)...)           // Flags
		row = append(row, u16b(0)...)           // PublicKeyOrToken blob
		row = append(row, strIdx(h, r.name)...) // Name
		row = append(row, u16b(0)...)           // Culture
		row = append(row, u16b(0)...)           // HashValue blob
		tl.row(0x23, row...)
	}

	return tl.bytes()
}

// tableLayoutBuilder accumulates per-table row counts and row bytes, then renders
// the #~ stream header + counts + row data.
type tableLayoutBuilder struct {
	counts map[byte]uint32
	data   map[byte][]byte
}

// maxTableID bounds the Valid/row iteration to the largest table id clrgen emits.
const maxTableID = 0x2C

func newTableLayout() *tableLayoutBuilder {
	return &tableLayoutBuilder{counts: map[byte]uint32{}, data: map[byte][]byte{}}
}

func (t *tableLayoutBuilder) row(id byte, b ...byte) {
	t.counts[id]++
	t.data[id] = append(t.data[id], b...)
}

func (t *tableLayoutBuilder) bytes() []byte {
	var valid uint64
	for id := byte(0); id <= maxTableID; id++ {
		if t.counts[id] > 0 {
			valid |= 1 << id
		}
	}
	out := make([]byte, 24)
	out[4] = 2 // MajorVersion
	out[5] = 0 // MinorVersion
	out[6] = 0 // HeapSizes = 0 (all 2-byte indexes)
	out[7] = 1 // Reserved (always 1)
	binary.LittleEndian.PutUint64(out[8:], valid)
	binary.LittleEndian.PutUint64(out[16:], 0) // Sorted bitvector
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, u32b(t.counts[id])...)
		}
	}
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, t.data[id]...)
		}
	}
	return out
}

// --- small little-endian byte helpers (II.24.2.1) ---

func u16b(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func u32b(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }

// strIdx returns the 2-byte #Strings index for s (HeapSizes=0 => 2-byte indexes).
func strIdx(h *heapBuilder, s string) []byte { return u16b(uint16(h.addString(s))) }

// guidIdx returns the 2-byte #GUID index (1-based; 0 == none).
func guidIdx(n uint16) []byte { return u16b(n) }

// concat flattens variadic byte slices into one.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
