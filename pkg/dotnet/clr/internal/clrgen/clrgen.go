/*
Copyright (c) 2026 Security Research
*/
// Package clrgen emits minimal, spec-valid managed PE images from hand-rolled
// little-endian bytes — no .NET SDK required. It is the Tier-1 fixture source
// of truth for the pure-Go CLR reader (ECMA-335 II.24, II.25). All multi-byte
// values are little-endian (II.24.2.1).
package clrgen

import "encoding/binary"

// SectionRVA is the virtual address of the single .text section that holds the
// COR20 header and the whole metadata region. file-offset(SectionRVA) == SectionRaw.
const (
	SectionRVA  uint32 = 0x2000
	SectionRaw  uint32 = 0x400
	cor20Off    uint32 = 0         // COR20 header at start of section
	cor20Size   uint32 = 72        // II.25.3.3
	metaRootOff uint32 = cor20Size // metadata BSJB root follows the COR20 header
)

// methodSpec is a planned MethodDef row.
type methodSpec struct {
	name string
	rva  uint32
}

// typeSpec is a planned TypeDef row with its owned methods.
type typeSpec struct {
	ns      string
	name    string
	methods []methodSpec
}

type pinvokeSpec struct {
	entry  string // ImplMap.ImportName
	module string // ModuleRef native dll
}

type asmRefSpec struct {
	name string
	ver  [4]uint16
}

// Builder accumulates the assembly's intended contents.
type Builder struct {
	asmName     string
	asmVer      [4]uint16
	refs        []asmRefSpec
	types       []typeSpec
	userStrings []string
	pinvokes    []pinvokeSpec
	// edge knobs (set by T-G02..05 helpers)
	emitPtrTables bool
	nativeBodyRVA uint32
	ehMethod      bool
}

// Method is a convenience constructor for a planned method.
func Method(name string, rva uint32) methodSpec { return methodSpec{name: name, rva: rva} }

// New returns an empty Builder.
func New() *Builder { return &Builder{} }

func (b *Builder) WithAssembly(name string, ver [4]uint16) *Builder {
	b.asmName, b.asmVer = name, ver
	return b
}

func (b *Builder) WithAssemblyRef(name string, ver [4]uint16) *Builder {
	b.refs = append(b.refs, asmRefSpec{name: name, ver: ver})
	return b
}

func (b *Builder) WithType(ns, name string, methods ...methodSpec) *Builder {
	b.types = append(b.types, typeSpec{ns: ns, name: name, methods: methods})
	return b
}

func (b *Builder) WithUserString(s string) *Builder {
	b.userStrings = append(b.userStrings, s)
	return b
}

func (b *Builder) WithPInvoke(entry, module string) *Builder {
	b.pinvokes = append(b.pinvokes, pinvokeSpec{entry: entry, module: module})
	return b
}

// Emit lays out the full PE image and returns it.
func (b *Builder) Emit() []byte {
	meta := b.buildMetadata()

	// Section raw data = COR20 header + metadata region.
	sectionLen := cor20Size + uint32(len(meta))

	// Native-method edge fixture: place four garbage bytes (0xCC, not a valid
	// tiny/fat IL header) at the section offset for nativeBodyRVA. The reader's
	// ImplFlags gate must report IsNative without ever reading these.
	var nativeOff uint32
	if b.nativeBodyRVA != 0 {
		nativeOff = b.nativeBodyRVA - SectionRVA
		if end := nativeOff + 4; end > sectionLen {
			sectionLen = end
		}
	}

	// EH edge fixture: a fat-header method with two chained fat EH sections lives
	// at EHMethodRVA inside the section. Reserve room for its full body.
	var ehOff uint32
	var ehBody []byte
	if b.ehMethod {
		ehBody = ehMethodBytes()
		ehOff = EHMethodRVA - SectionRVA
		if end := ehOff + uint32(len(ehBody)); end > sectionLen {
			sectionLen = end
		}
	}

	sectionData := make([]byte, sectionLen)
	b.writeCOR20(sectionData[cor20Off:], uint32(len(meta)))
	copy(sectionData[metaRootOff:], meta)
	if b.nativeBodyRVA != 0 {
		copy(sectionData[nativeOff:], []byte{0xCC, 0xCC, 0xCC, 0xCC})
	}
	if b.ehMethod {
		copy(sectionData[ehOff:], ehBody)
	}

	return b.wrapPE(sectionData)
}

// writeCOR20 writes the IMAGE_COR20_HEADER (II.25.3.3) into dst. MetaData.RVA
// points just past this header inside the same section.
func (b *Builder) writeCOR20(dst []byte, metaLen uint32) {
	binary.LittleEndian.PutUint32(dst[0:], cor20Size)            // Cb
	binary.LittleEndian.PutUint16(dst[4:], 2)                    // MajorRuntimeVersion
	binary.LittleEndian.PutUint16(dst[6:], 5)                    // MinorRuntimeVersion
	binary.LittleEndian.PutUint32(dst[8:], SectionRVA+cor20Size) // MetaData.RVA
	binary.LittleEndian.PutUint32(dst[12:], metaLen)             // MetaData.Size
	binary.LittleEndian.PutUint32(dst[16:], 0x00000001)          // Flags = ILONLY
	// remaining DataDir fields (EntryPointToken, Resources, ...) left zero.
}

// wrapPE wraps section raw data into a PE32+ image with DataDirectory[14] set.
// Layout mirrors decompile.synthPE but adds a real, slurpable section payload.
func (b *Builder) wrapPE(sectionData []byte) []byte {
	const (
		ntOff       = 0x80
		optHdrSize  = 240
		sectHdrOff  = ntOff + 24 + optHdrSize
		headersSize = 0x400 // SectionRaw
	)
	total := headersSize + len(sectionData)
	// round up to 0x200 so SizeOfRawData is satisfiable
	if pad := total % 0x200; pad != 0 {
		total += 0x200 - pad
	}
	buf := make([]byte, total)

	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], ntOff)
	copy(buf[ntOff:], []byte{'P', 'E', 0, 0})

	fh := buf[ntOff+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664) // AMD64
	binary.LittleEndian.PutUint16(fh[2:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(fh[16:], optHdrSize)
	binary.LittleEndian.PutUint16(fh[18:], 0x2022) // DLL | EXECUTABLE | LARGE_ADDRESS_AWARE

	oh := buf[ntOff+24:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b) // PE32+
	binary.LittleEndian.PutUint32(oh[108:], 16)  // NumberOfRvaAndSizes
	dd := oh[112:]
	binary.LittleEndian.PutUint32(dd[14*8:], SectionRVA)  // COM Descriptor RVA
	binary.LittleEndian.PutUint32(dd[14*8+4:], cor20Size) // COM Descriptor Size

	sh := buf[sectHdrOff:]
	copy(sh[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sh[8:], uint32(len(sectionData)))     // VirtualSize
	binary.LittleEndian.PutUint32(sh[12:], SectionRVA)                  // VirtualAddress
	binary.LittleEndian.PutUint32(sh[16:], uint32(len(buf))-SectionRaw) // SizeOfRawData
	binary.LittleEndian.PutUint32(sh[20:], SectionRaw)                  // PointerToRawData
	binary.LittleEndian.PutUint32(sh[36:], 0x60000020)

	copy(buf[SectionRaw:], sectionData)
	return buf
}
