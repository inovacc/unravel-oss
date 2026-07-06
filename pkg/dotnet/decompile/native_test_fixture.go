/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// synthManagedAssembly writes a minimal-but-valid managed PE to path: one type
// Demo.Greeter with a single method Hello() whose body is
// `ldstr "hi"; call [System.Console]System.Console::WriteLine(string); ret`.
//
// It is a file-emitting twin of the clr package's clrgenGreeterImage test
// fixture (group T-G01): the byte layout is identical, but bytes are written to
// disk so the native engine's clr.Open(path) -> clr.ExtractModules path can be
// exercised end to end. When the shared Testing-group clrgen emitter lands,
// collapse this wrapper onto it.
func synthManagedAssembly(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, buildGreeterPE(), 0o644); err != nil {
		t.Fatalf("write managed assembly %s: %v", path, err)
	}
	// Drop a sibling *.deps.json referencing this assembly by its base name so
	// the FullApp walk (which requires a deps.json) discovers it. Harmless for
	// the ModeSingle path, which targets the file directly via WalkSingle.
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	depsJSON := fmt.Sprintf(
		`{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"libraries":{"%s/1.0.0":{"type":"project"}},"targets":{}}`,
		base,
	)
	depsPath := filepath.Join(filepath.Dir(path), "App.deps.json")
	if err := os.WriteFile(depsPath, []byte(depsJSON), 0o644); err != nil {
		t.Fatalf("write deps.json %s: %v", depsPath, err)
	}
}

// --- minimal metadata + managed-PE byte emitter (mirrors clr.clrgen) ---

type synthMeta struct {
	strings   []byte
	stringOff map[string]uint32
	us        []byte
	blob      []byte

	rows    map[byte]uint32
	rowData map[byte][]byte
}

func newSynthMeta() *synthMeta {
	return &synthMeta{
		strings:   []byte{0},
		stringOff: map[string]uint32{"": 0},
		us:        []byte{0},
		blob:      []byte{0},
		rows:      map[byte]uint32{},
		rowData:   map[byte][]byte{},
	}
}

func (b *synthMeta) intern(s string) uint16 {
	if off, ok := b.stringOff[s]; ok {
		return uint16(off)
	}
	off := uint32(len(b.strings))
	b.strings = append(b.strings, []byte(s)...)
	b.strings = append(b.strings, 0)
	b.stringOff[s] = off
	return uint16(off)
}

func (b *synthMeta) addUserString(s string) uint16 {
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

func (b *synthMeta) addBlob(data []byte) uint16 {
	off := uint16(len(b.blob))
	b.blob = append(b.blob, byte(len(data)))
	b.blob = append(b.blob, data...)
	return off
}

func synthU16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func synthU32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func (b *synthMeta) appendRow(id byte, row []byte) {
	b.rows[id]++
	b.rowData[id] = append(b.rowData[id], row...)
}

func (b *synthMeta) emitAssembly(name, culture uint16) {
	row := synthU32(0)
	for i := 0; i < 4; i++ {
		row = append(row, synthU16(0)...)
	}
	row = append(row, synthU32(0)...) // Flags
	row = append(row, synthU16(0)...) // PublicKey blob idx
	row = append(row, synthU16(name)...)
	row = append(row, synthU16(culture)...)
	b.appendRow(0x20, row)
}

func (b *synthMeta) emitAssemblyRef(name uint16) {
	row := []byte{}
	for i := 0; i < 4; i++ {
		row = append(row, synthU16(0)...)
	}
	row = append(row, synthU32(0)...) // Flags
	row = append(row, synthU16(0)...) // PublicKeyOrToken blob idx
	row = append(row, synthU16(name)...)
	row = append(row, synthU16(0)...) // Culture
	row = append(row, synthU16(0)...) // HashValue blob idx
	b.appendRow(0x23, row)
}

func (b *synthMeta) emitTypeRef(resolutionScope, name, namespace uint16) {
	row := synthU16(resolutionScope)
	row = append(row, synthU16(name)...)
	row = append(row, synthU16(namespace)...)
	b.appendRow(0x01, row)
}

func (b *synthMeta) emitMemberRef(class, name, sig uint16) {
	row := synthU16(class)
	row = append(row, synthU16(name)...)
	row = append(row, synthU16(sig)...)
	b.appendRow(0x0A, row)
}

func (b *synthMeta) emitTypeDef(name, namespace, extends, fieldStart, methodStart uint16) {
	row := synthU32(0)
	row = append(row, synthU16(name)...)
	row = append(row, synthU16(namespace)...)
	row = append(row, synthU16(extends)...)
	row = append(row, synthU16(fieldStart)...)
	row = append(row, synthU16(methodStart)...)
	b.appendRow(0x02, row)
}

func (b *synthMeta) emitMethodDef(rva uint32, name, sig, paramList uint16) {
	row := synthU32(rva)
	row = append(row, synthU16(0)...) // ImplFlags = 0 (managed IL)
	row = append(row, synthU16(0)...) // Flags
	row = append(row, synthU16(name)...)
	row = append(row, synthU16(sig)...)
	row = append(row, synthU16(paramList)...)
	b.appendRow(0x06, row)
}

func synthMemberRefParentTypeRef(rid uint16) uint16 { return rid<<3 | 1 }

func synthAlign4(n int) int { return (n + 3) &^ 3 }

const synthBSJB = 0x424A5342

func (b *synthMeta) build() []byte {
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
		headerLen += 8 + synthAlign4(len(nm))
	}

	out := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(out[0:], synthBSJB)
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
		p += 8 + synthAlign4(len(nm))
		bodies = append(bodies, s.data...)
	}
	return append(out, bodies...)
}

func (b *synthMeta) buildTilde() []byte {
	const maxTableID = 0x2C
	var valid uint64
	for id := byte(0); id <= maxTableID; id++ {
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
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, synthU32(b.rows[id])...)
		}
	}
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, b.rowData[id]...)
		}
	}
	return out
}

func synthRoundUp(n, a int) int { return (n + a - 1) / a * a }

// buildGreeterPE returns the raw bytes of a one-type managed PE.
func buildGreeterPE() []byte {
	const (
		ntHeaderOffset = 0x80
		secVA          = 0x2000
		secRaw         = 0x400
		cor20Size      = 72
		bodyOff        = cor20Size // method body sits right after the COR20 header
	)

	m := newSynthMeta()

	usHi := m.addUserString("hi")
	writeLineSig := m.addBlob([]byte{0x00, 0x01, 0x01, 0x0e}) // void WriteLine(string)
	helloSig := m.addBlob([]byte{0x00, 0x00, 0x01})           // void Hello()

	m.emitAssembly(m.intern("Greeter"), 0)
	corlibName := m.intern("System.Console")
	m.emitAssemblyRef(corlibName)

	consoleNS := m.intern("System")
	consoleName := m.intern("Console")
	m.emitTypeRef(uint16(1)<<2|2, consoleName, consoleNS)

	m.emitMemberRef(synthMemberRefParentTypeRef(1), m.intern("WriteLine"), writeLineSig)

	greeterName := m.intern("Greeter")
	greeterNS := m.intern("Demo")
	m.emitMethodDef(secVA+bodyOff, m.intern("Hello"), helloSig, 1)
	m.emitTypeDef(greeterName, greeterNS, 0, 1, 1)

	meta := m.build()

	usTok := uint32(0x70)<<24 | uint32(usHi) // #US token
	memberRefTok := uint32(0x0A)<<24 | 1     // MemberRef rid 1
	il := []byte{0x72}                       // ldstr
	il = append(il, synthU32(usTok)...)
	il = append(il, 0x28) // call
	il = append(il, synthU32(memberRefTok)...)
	il = append(il, 0x2a) // ret
	tinyHdr := byte(len(il)<<2) | 0x02

	body := append([]byte{tinyHdr}, il...)

	metaStart := synthAlign4(bodyOff + len(body))
	rawLen := metaStart + len(meta) + 16
	metaRVA := uint32(secVA + metaStart)

	buf := make([]byte, secRaw+synthRoundUp(rawLen, 0x200))

	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], ntHeaderOffset)
	copy(buf[ntHeaderOffset:], []byte{'P', 'E', 0, 0})

	fh := buf[ntHeaderOffset+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664)
	binary.LittleEndian.PutUint16(fh[2:], 1)
	binary.LittleEndian.PutUint16(fh[16:], 240)
	binary.LittleEndian.PutUint16(fh[18:], 0x2022)

	oh := buf[ntHeaderOffset+24:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b)
	binary.LittleEndian.PutUint32(oh[108:], 16)
	dd := oh[112:]
	binary.LittleEndian.PutUint32(dd[14*8:], secVA)
	binary.LittleEndian.PutUint32(dd[14*8+4:], cor20Size)

	sh := buf[ntHeaderOffset+24+240:]
	copy(sh[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sh[8:], uint32(rawLen))
	binary.LittleEndian.PutUint32(sh[12:], secVA)
	binary.LittleEndian.PutUint32(sh[16:], uint32(synthRoundUp(rawLen, 0x200)))
	binary.LittleEndian.PutUint32(sh[20:], secRaw)
	binary.LittleEndian.PutUint32(sh[36:], 0x60000020)

	c := buf[secRaw:]
	binary.LittleEndian.PutUint32(c[0:], cor20Size)
	binary.LittleEndian.PutUint16(c[4:], 2)
	binary.LittleEndian.PutUint16(c[6:], 5)
	binary.LittleEndian.PutUint32(c[8:], metaRVA)
	binary.LittleEndian.PutUint32(c[12:], uint32(len(meta)))
	binary.LittleEndian.PutUint32(c[16:], 1) // ILONLY

	copy(buf[secRaw+bodyOff:], body)
	copy(buf[secRaw+metaStart:], meta)

	return buf
}
