/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestDotNetInfo_FromM0 exercises the pure-Go M0 identity+deps reader (INT-8):
// it synthesises a minimal managed PE on disk and asserts dotnetInfo extracts
// the assembly identity plus at least one AssemblyRef edge with no external
// tool and no DB.
func TestDotNetInfo_FromM0(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "Sample.dll")
	synthManagedAssemblyForTools(t, asm) // identity "Sample" v0.0.0.0, 1 AssemblyRef

	out, err := dotnetInfo(context.Background(), DotNetInfoInput{Path: asm})
	if err != nil {
		t.Fatalf("dotnetInfo: %v", err)
	}
	if out.AssemblyName == "" {
		t.Fatalf("AssemblyName empty: %+v", out)
	}
	if len(out.AssemblyRefs) == 0 {
		t.Fatalf("expected >=1 AssemblyRef, got 0")
	}
}

// --- self-contained synth managed-PE emitter (test-only) -------------------
//
// synthManagedAssemblyForTools writes a one-type managed PE to path whose
// Assembly identity is "Sample" with one AssemblyRef ("System.Console"). It is
// a soft local stand-in mirroring pkg/dotnet/clr/clrgen_test.go's emitter,
// duplicated here because that emitter is package-private to clr. If the
// Testing-group clrgen emitter is exported, collapse this into it.

func synthManagedAssemblyForTools(t *testing.T, path string) {
	t.Helper()

	const (
		ntHeaderOffset = 0x80
		secVA          = 0x2000
		secRaw         = 0x400
		cor20Size      = 72
	)

	m := newToolsMeta()

	// Assembly identity + one AssemblyRef.
	m.emitAssembly(m.intern("Sample"))
	m.emitAssemblyRef(m.intern("System.Console"))

	meta := m.build()

	// Metadata sits right after the COR20 header so it does not clobber it
	// (section raw layout: [COR20][pad to 4][metadata]).
	metaStart := toolsAlign4(cor20Size)
	rawLen := metaStart + len(meta) + 16
	metaRVA := uint32(secVA + metaStart)

	buf := make([]byte, secRaw+toolsRoundUp(rawLen, 0x200))

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
	binary.LittleEndian.PutUint32(sh[16:], uint32(toolsRoundUp(rawLen, 0x200)))
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

	copy(buf[secRaw+metaStart:], meta)

	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write synth assembly: %v", err)
	}
}

type toolsMeta struct {
	strings   []byte
	stringOff map[string]uint32
	us        []byte
	blob      []byte
	rows      map[byte]uint32
	rowData   map[byte][]byte
}

func newToolsMeta() *toolsMeta {
	return &toolsMeta{
		strings:   []byte{0},
		stringOff: map[string]uint32{"": 0},
		us:        []byte{0},
		blob:      []byte{0},
		rows:      map[byte]uint32{},
		rowData:   map[byte][]byte{},
	}
}

func (b *toolsMeta) intern(s string) uint16 {
	if off, ok := b.stringOff[s]; ok {
		return uint16(off)
	}
	off := uint32(len(b.strings))
	b.strings = append(b.strings, []byte(s)...)
	b.strings = append(b.strings, 0)
	b.stringOff[s] = off
	return uint16(off)
}

func toolsU16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func toolsU32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func (b *toolsMeta) appendRow(id byte, row []byte) {
	b.rows[id]++
	b.rowData[id] = append(b.rowData[id], row...)
}

// emitAssembly: HashAlgId(u32) Ver(4*u16) Flags(u32) PublicKey(blob) Name(str) Culture(str).
func (b *toolsMeta) emitAssembly(name uint16) {
	row := toolsU32(0)
	for i := 0; i < 4; i++ {
		row = append(row, toolsU16(0)...)
	}
	row = append(row, toolsU32(0)...) // Flags
	row = append(row, toolsU16(0)...) // PublicKey blob idx
	row = append(row, toolsU16(name)...)
	row = append(row, toolsU16(0)...) // Culture
	b.appendRow(0x20, row)
}

// emitAssemblyRef: Ver(4*u16) Flags(u32) PublicKeyOrToken(blob) Name(str) Culture(str) HashValue(blob).
func (b *toolsMeta) emitAssemblyRef(name uint16) {
	row := []byte{}
	for i := 0; i < 4; i++ {
		row = append(row, toolsU16(0)...)
	}
	row = append(row, toolsU32(0)...) // Flags
	row = append(row, toolsU16(0)...) // PublicKeyOrToken blob idx
	row = append(row, toolsU16(name)...)
	row = append(row, toolsU16(0)...) // Culture
	row = append(row, toolsU16(0)...) // HashValue blob idx
	b.appendRow(0x23, row)
}

func toolsAlign4(n int) int { return (n + 3) &^ 3 }

const toolsBSJB = 0x424A5342

func (b *toolsMeta) build() []byte {
	tilde := b.buildTilde()

	type stream struct {
		name string
		data []byte
	}
	streams := []stream{
		{"#~", tilde},
		{"#Strings", b.strings},
		{"#US", b.us},
		{"#Blob", b.blob},
	}

	const version = "v4.0.30319\x00\x00" // 12 bytes, multiple of 4
	headerLen := 16 + len(version) + 4
	for _, s := range streams {
		nm := s.name + "\x00"
		headerLen += 8 + toolsAlign4(len(nm))
	}

	out := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(out[0:], toolsBSJB)
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
		p += 8 + toolsAlign4(len(nm))
		bodies = append(bodies, s.data...)
	}
	return append(out, bodies...)
}

func (b *toolsMeta) buildTilde() []byte {
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
			out = append(out, toolsU32(b.rows[id])...)
		}
	}
	for id := byte(0); id <= maxTableID; id++ {
		if valid&(1<<id) != 0 {
			out = append(out, b.rowData[id]...)
		}
	}
	return out
}

func toolsRoundUp(n, a int) int { return (n + a - 1) / a * a }
