/*
Copyright (c) 2026 Security Research
*/
package clr

import (
	"encoding/binary"
	"testing"
)

// clrgen is a minimal, self-contained metadata + managed-PE emitter used by the
// M1 module-assembly tests. It mirrors the byte-rolling fixture style of
// image_test.go's synthManagedPE and metadata's metaBuilder, but lives in
// package clr so the ExtractModules consumer can be exercised end to end. It is
// a soft local stand-in for the Testing-group T-G01 clrgen emitter; if that
// lands, collapse these two into one shared emitter.

const clrgenMaxTableID = 0x2C

type clrgenMeta struct {
	strings   []byte
	stringOff map[string]uint32
	us        []byte
	blob      []byte

	rows    map[byte]uint32
	rowData map[byte][]byte
}

func newClrgenMeta() *clrgenMeta {
	return &clrgenMeta{
		strings:   []byte{0},
		stringOff: map[string]uint32{"": 0},
		us:        []byte{0},
		blob:      []byte{0},
		rows:      map[byte]uint32{},
		rowData:   map[byte][]byte{},
	}
}

func (b *clrgenMeta) intern(s string) uint16 {
	if off, ok := b.stringOff[s]; ok {
		return uint16(off)
	}
	off := uint32(len(b.strings))
	b.strings = append(b.strings, []byte(s)...)
	b.strings = append(b.strings, 0)
	b.stringOff[s] = off
	return uint16(off)
}

// addUserString appends a #US literal (UTF-16LE body + trailing flag byte,
// 1-byte compressed length prefix) and returns its heap offset.
func (b *clrgenMeta) addUserString(s string) uint16 {
	off := uint16(len(b.us))
	body := make([]byte, 0, len(s)*2+1)
	for _, r := range s {
		var u [2]byte
		binary.LittleEndian.PutUint16(u[:], uint16(r))
		body = append(body, u[:]...)
	}
	body = append(body, 0) // trailing flag byte
	b.us = append(b.us, byte(len(body)))
	b.us = append(b.us, body...)
	return off
}

// addBlob appends a length-prefixed blob (< 0x80 bytes) and returns its offset.
func (b *clrgenMeta) addBlob(data []byte) uint16 {
	off := uint16(len(b.blob))
	b.blob = append(b.blob, byte(len(data)))
	b.blob = append(b.blob, data...)
	return off
}

func clrgenU16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func clrgenU32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func (b *clrgenMeta) appendRow(id byte, row []byte) {
	b.rows[id]++
	b.rowData[id] = append(b.rowData[id], row...)
}

// emitAssembly: HashAlgId(u32) Ver(4*u16) Flags(u32) PublicKey(blob) Name(str) Culture(str).
func (b *clrgenMeta) emitAssembly(name, culture uint16) {
	row := clrgenU32(0)
	for i := 0; i < 4; i++ {
		row = append(row, clrgenU16(0)...)
	}
	row = append(row, clrgenU32(0)...) // Flags
	row = append(row, clrgenU16(0)...) // PublicKey blob idx
	row = append(row, clrgenU16(name)...)
	row = append(row, clrgenU16(culture)...)
	b.appendRow(0x20, row)
}

// emitAssemblyRef: Ver(4*u16) Flags(u32) PublicKeyOrToken(blob) Name(str) Culture(str) HashValue(blob).
func (b *clrgenMeta) emitAssemblyRef(name uint16) {
	row := []byte{}
	for i := 0; i < 4; i++ {
		row = append(row, clrgenU16(0)...)
	}
	row = append(row, clrgenU32(0)...) // Flags
	row = append(row, clrgenU16(0)...) // PublicKeyOrToken blob idx
	row = append(row, clrgenU16(name)...)
	row = append(row, clrgenU16(0)...) // Culture
	row = append(row, clrgenU16(0)...) // HashValue blob idx
	b.appendRow(0x23, row)
}

// emitTypeRef: ResolutionScope(coded) Name(str) Namespace(str).
func (b *clrgenMeta) emitTypeRef(resolutionScope, name, namespace uint16) {
	row := clrgenU16(resolutionScope)
	row = append(row, clrgenU16(name)...)
	row = append(row, clrgenU16(namespace)...)
	b.appendRow(0x01, row)
}

// emitMemberRef: Class(coded MemberRefParent) Name(str) Signature(blob).
func (b *clrgenMeta) emitMemberRef(class, name, sig uint16) {
	row := clrgenU16(class)
	row = append(row, clrgenU16(name)...)
	row = append(row, clrgenU16(sig)...)
	b.appendRow(0x0A, row)
}

// emitTypeDef: Flags(u32) Name(str) Namespace(str) Extends(coded) FieldList(0x04) MethodList(0x06).
func (b *clrgenMeta) emitTypeDef(name, namespace, extends, fieldStart, methodStart uint16) {
	row := clrgenU32(0)
	row = append(row, clrgenU16(name)...)
	row = append(row, clrgenU16(namespace)...)
	row = append(row, clrgenU16(extends)...)
	row = append(row, clrgenU16(fieldStart)...)
	row = append(row, clrgenU16(methodStart)...)
	b.appendRow(0x02, row)
}

// emitMethodDef: RVA(u32) ImplFlags(u16) Flags(u16) Name(str) Sig(blob) ParamList(0x08).
func (b *clrgenMeta) emitMethodDef(rva uint32, name, sig, paramList uint16) {
	row := clrgenU32(rva)
	row = append(row, clrgenU16(0)...) // ImplFlags = 0 (managed IL)
	row = append(row, clrgenU16(0)...) // Flags
	row = append(row, clrgenU16(name)...)
	row = append(row, clrgenU16(sig)...)
	row = append(row, clrgenU16(paramList)...)
	b.appendRow(0x06, row)
}

// memberRefParentTypeRef: MemberRefParent coded index for a TypeRef (tag 1).
func memberRefParentTypeRef(rid uint16) uint16 { return rid<<3 | 1 }

func clrgenAlign4(n int) int { return (n + 3) &^ 3 }

const clrgenBSJB = 0x424A5342

func (b *clrgenMeta) build() []byte {
	tilde := b.buildTilde()

	type stream struct {
		name string
		data []byte
	}
	streams := []stream{{"#~", tilde}}
	streams = append(streams, stream{"#Strings", b.strings})
	streams = append(streams, stream{"#US", b.us})
	streams = append(streams, stream{"#Blob", b.blob})

	const version = "v4.0.30319\x00\x00" // 12 bytes, multiple of 4
	headerLen := 16 + len(version) + 4
	for _, s := range streams {
		nm := s.name + "\x00"
		headerLen += 8 + clrgenAlign4(len(nm))
	}

	out := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(out[0:], clrgenBSJB)
	binary.LittleEndian.PutUint16(out[4:], 1)
	binary.LittleEndian.PutUint16(out[6:], 1)
	binary.LittleEndian.PutUint32(out[8:], 0)
	binary.LittleEndian.PutUint32(out[12:], uint32(len(version)))
	copy(out[16:], version)
	p := 16 + len(version)
	binary.LittleEndian.PutUint16(out[p:], 0)
	binary.LittleEndian.PutUint16(out[p+2:], uint16(len(streams)))
	p += 4

	bodies := []byte{}
	for _, s := range streams {
		off := uint32(headerLen + len(bodies))
		binary.LittleEndian.PutUint32(out[p:], off)
		binary.LittleEndian.PutUint32(out[p+4:], uint32(len(s.data)))
		nm := s.name + "\x00"
		copy(out[p+8:], nm)
		p += 8 + clrgenAlign4(len(nm))
		bodies = append(bodies, s.data...)
	}
	return append(out, bodies...)
}

func (b *clrgenMeta) buildTilde() []byte {
	var valid uint64
	for id := byte(0); id <= clrgenMaxTableID; id++ {
		if b.rows[id] > 0 {
			valid |= 1 << id
		}
	}
	out := make([]byte, 24)
	out[4] = 2 // Major
	out[6] = 0 // HeapSizes = all 2-byte
	out[7] = 1
	binary.LittleEndian.PutUint64(out[8:], valid)
	binary.LittleEndian.PutUint64(out[16:], 0)
	for id := byte(0); id <= clrgenMaxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, clrgenU32(b.rows[id])...)
		}
	}
	for id := byte(0); id <= clrgenMaxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, b.rowData[id]...)
		}
	}
	return out
}

// clrgenGreeterImage builds a one-type managed PE: Demo.Greeter::Hello() whose
// body is `ldstr "hi"; call [System.Console]System.Console::WriteLine(string); ret`.
func clrgenGreeterImage(t *testing.T) *Image {
	t.Helper()

	const (
		ntHeaderOffset = 0x80
		secVA          = 0x2000
		secRaw         = 0x400
		cor20Size      = 72
		bodyOff        = cor20Size // method body sits right after the COR20 header
	)

	m := newClrgenMeta()

	// Heaps / references.
	usHi := m.addUserString("hi")
	writeLineSig := m.addBlob([]byte{0x00, 0x01, 0x01, 0x0e}) // void WriteLine(string)
	helloSig := m.addBlob([]byte{0x00, 0x00, 0x01})           // void Hello()

	// Assembly identity + one AssemblyRef (mscorlib-ish).
	m.emitAssembly(m.intern("Greeter"), 0)
	corlibName := m.intern("System.Console")
	m.emitAssemblyRef(corlibName)

	// TypeRef System.Console in AssemblyRef #1.
	// ResolutionScope coded index: schema {Module, ModuleRef, AssemblyRef,
	// TypeRef}; AssemblyRef tag = 2, 2 tag bits => rid<<2 | 2.
	consoleNS := m.intern("System")
	consoleName := m.intern("Console")
	m.emitTypeRef(uint16(1)<<2|2, consoleName, consoleNS)

	// MemberRef WriteLine on TypeRef #1.
	m.emitMemberRef(memberRefParentTypeRef(1), m.intern("WriteLine"), writeLineSig)

	// TypeDef Demo.Greeter with one method Hello at index 1.
	greeterName := m.intern("Greeter")
	greeterNS := m.intern("Demo")
	m.emitMethodDef(secVA+bodyOff, m.intern("Hello"), helloSig, 1)
	m.emitTypeDef(greeterName, greeterNS, 0, 1, 1)

	meta := m.build()

	// Method body: tiny header + IL.
	usTok := uint32(0x70)<<24 | uint32(usHi) // #US token
	memberRefTok := uint32(0x0A)<<24 | 1     // MemberRef rid 1
	il := []byte{0x72}                       // ldstr
	il = append(il, clrgenU32(usTok)...)
	il = append(il, 0x28) // call
	il = append(il, clrgenU32(memberRefTok)...)
	il = append(il, 0x2a) // ret
	tinyHdr := byte(len(il)<<2) | 0x02

	body := append([]byte{tinyHdr}, il...)

	// Section raw layout: [COR20][body][pad to 4][metadata].
	metaStart := clrgenAlign4(bodyOff + len(body))
	rawLen := metaStart + len(meta) + 16
	metaRVA := uint32(secVA + metaStart)

	buf := make([]byte, secRaw+clrgenRoundUp(rawLen, 0x200))

	// DOS header.
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], ntHeaderOffset)
	copy(buf[ntHeaderOffset:], []byte{'P', 'E', 0, 0})

	// IMAGE_FILE_HEADER.
	fh := buf[ntHeaderOffset+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664)
	binary.LittleEndian.PutUint16(fh[2:], 1)
	binary.LittleEndian.PutUint16(fh[16:], 240)
	binary.LittleEndian.PutUint16(fh[18:], 0x2022)

	// IMAGE_OPTIONAL_HEADER64.
	oh := buf[ntHeaderOffset+24:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b)
	binary.LittleEndian.PutUint32(oh[108:], 16)
	dd := oh[112:]
	binary.LittleEndian.PutUint32(dd[14*8:], secVA)
	binary.LittleEndian.PutUint32(dd[14*8+4:], cor20Size)

	// Section header.
	sh := buf[ntHeaderOffset+24+240:]
	copy(sh[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sh[8:], uint32(rawLen))
	binary.LittleEndian.PutUint32(sh[12:], secVA)
	binary.LittleEndian.PutUint32(sh[16:], uint32(clrgenRoundUp(rawLen, 0x200)))
	binary.LittleEndian.PutUint32(sh[20:], secRaw)
	binary.LittleEndian.PutUint32(sh[36:], 0x60000020)

	// COR20 header at section start.
	c := buf[secRaw:]
	binary.LittleEndian.PutUint32(c[0:], cor20Size)
	binary.LittleEndian.PutUint16(c[4:], 2)
	binary.LittleEndian.PutUint16(c[6:], 5)
	binary.LittleEndian.PutUint32(c[8:], metaRVA)
	binary.LittleEndian.PutUint32(c[12:], uint32(len(meta)))
	binary.LittleEndian.PutUint32(c[16:], 1) // ILONLY

	// Method body + metadata.
	copy(buf[secRaw+bodyOff:], body)
	copy(buf[secRaw+metaStart:], meta)

	img, err := OpenReaderAt(bytesReaderAt(buf), int64(len(buf)))
	if err != nil {
		t.Fatalf("OpenReaderAt synth greeter: %v", err)
	}
	return img
}

func clrgenRoundUp(n, a int) int { return (n + a - 1) / a * a }
