/*
Copyright (c) 2026 Security Research
*/
package clrgen

import "encoding/binary"

// EH fixture constants asserted by edge_eh_test.go.
const (
	EHMethodRVA           uint32 = 0x2070
	EHClauseCount                = 2
	EHSecondHandlerOffset uint32 = 0x000C
)

// WithEHMethod adds a type with one fat-header method carrying two chained fat
// EH sections (II.25.4.5). The first section sets the "more sections" bit.
func (b *Builder) WithEHMethod() *Builder {
	b.ehMethod = true
	b.types = append(b.types, typeSpec{
		ns: "Edge", name: "Handler",
		methods: []methodSpec{{name: "Guarded", rva: EHMethodRVA}},
	})
	return b
}

// MultiSectionEH is the canonical multi-section-EH edge fixture.
func MultiSectionEH() []byte {
	return New().WithAssembly("EHAsm", [4]uint16{1, 0, 0, 0}).WithEHMethod().Emit()
}

// Fat-method-header / EH-section layout constants (ECMA-335 II.25.4.3-5).
const (
	ehFatFlagsFat       = 0x03 // CorILMethod_FatFormat
	ehFatFlagsMoreSects = 0x08 // CorILMethod_MoreSects
	ehFatHdrDwords      = 3    // fat header is 3 dwords (12 bytes)

	ehSectKindEHTable   = 0x01 // CorILMethod_Sect_EHTable
	ehSectKindFatFormat = 0x40 // CorILMethod_Sect_FatFormat
	ehSectKindMoreSects = 0x80 // CorILMethod_Sect_MoreSects

	ehFatClauseSize = 24 // a fat EH clause is 24 bytes
	ehFatSectHdr    = 4  // fat section header is 4 bytes (kind + 24-bit DataSize)
)

// ehMethodBytes emits a fat-header method body followed by two chained fat EH
// sections. The first section sets the "more sections" bit so the reader loops
// into the second; each fat section header carries its DataSize as a 24-bit
// field (4 + 24*clauseCount). The two sections hold one clause each, so the
// decoded body has EHClauseCount clauses total and clause[1] (in the second,
// chained section) has HandlerOffset == EHSecondHandlerOffset.
func ehMethodBytes() []byte {
	// Fat header: 2-byte Flags|Size word, MaxStack u16, CodeSize u32, LocalVarSigTok u32.
	flags := uint16(ehFatFlagsFat | ehFatFlagsMoreSects)
	flagsAndSize := flags | (uint16(ehFatHdrDwords) << 12)

	// A tiny, 4-aligned IL body: nop nop nop ret.
	code := []byte{0x00, 0x00, 0x00, 0x2A}

	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint16(hdr[0:], flagsAndSize)
	binary.LittleEndian.PutUint16(hdr[2:], 8)                 // MaxStack
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(code))) // CodeSize
	binary.LittleEndian.PutUint32(hdr[8:], 0)                 // LocalVarSigTok (none)

	// One fat clause = 24 bytes; one clause per section.
	sectDataSize := ehFatSectHdr + ehFatClauseSize // 28

	// Section 1: EHTable | FatFormat | MoreSects, one clause.
	sect1 := make([]byte, sectDataSize)
	sect1[0] = byte(ehSectKindEHTable | ehSectKindFatFormat | ehSectKindMoreSects)
	put24(sect1[1:], uint32(sectDataSize))
	writeFatClause(sect1[ehFatSectHdr:], 0x0000) // clause[0].HandlerOffset

	// Section 2 (chained): EHTable | FatFormat, one clause, HandlerOffset asserted.
	sect2 := make([]byte, sectDataSize)
	sect2[0] = byte(ehSectKindEHTable | ehSectKindFatFormat)
	put24(sect2[1:], uint32(sectDataSize))
	writeFatClause(sect2[ehFatSectHdr:], EHSecondHandlerOffset) // clause[1].HandlerOffset

	out := make([]byte, 0, len(hdr)+len(code)+len(sect1)+len(sect2))
	out = append(out, hdr...)
	out = append(out, code...)
	// EH sections start 4-aligned past the code; 12+4 == 16 is already aligned.
	out = append(out, sect1...)
	out = append(out, sect2...)
	return out
}

// put24 writes v as a little-endian 24-bit value into dst[0:3].
func put24(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
}

// writeFatClause writes a 24-byte fat EH clause (Flags, TryOffset, TryLength,
// HandlerOffset, HandlerLength, ClassToken) into dst with the given handler
// offset; the other fields are left as benign zero/small values.
func writeFatClause(dst []byte, handlerOffset uint32) {
	binary.LittleEndian.PutUint32(dst[0:], 0)              // Flags: typed catch
	binary.LittleEndian.PutUint32(dst[4:], 0x0000)         // TryOffset
	binary.LittleEndian.PutUint32(dst[8:], 0x0004)         // TryLength
	binary.LittleEndian.PutUint32(dst[12:], handlerOffset) // HandlerOffset
	binary.LittleEndian.PutUint32(dst[16:], 0x0004)        // HandlerLength
	binary.LittleEndian.PutUint32(dst[20:], 0)             // ClassToken
}
