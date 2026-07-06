/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

// synthManyTypeAssembly writes a metadata-only managed PE to path containing n
// empty TypeDefs (no methods, no fields). It exists to exercise INT-4's
// MaxSingleBufferModules cap: clr.ExtractModules emits one module per TypeDef,
// so an n-type assembly yields n modules without needing IL bodies.
func synthManyTypeAssembly(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.WriteFile(path, buildManyTypePE(n), 0o644); err != nil {
		t.Fatalf("write many-type assembly %s: %v", path, err)
	}
}

// emitEmptyTypeDef appends a TypeDef with no fields and no methods. fieldStart
// and methodStart both point at rid 1 of their (empty) child tables, so the
// owner-range walk yields an empty span for every row.
func (b *synthMeta) emitEmptyTypeDef(name, namespace uint16) {
	b.emitTypeDef(name, namespace, 0, 1, 1)
}

// buildManyTypePE returns a metadata-only managed PE with n empty TypeDefs.
func buildManyTypePE(n int) []byte {
	const (
		ntHeaderOffset = 0x80
		secVA          = 0x2000
		secRaw         = 0x400
		cor20Size      = 72
	)

	m := newSynthMeta()
	m.emitAssembly(m.intern("ManyTypes"), 0)

	for i := 0; i < n; i++ {
		name := m.intern(fmt.Sprintf("T%d", i))
		ns := m.intern("Gen")
		m.emitEmptyTypeDef(name, ns)
	}

	meta := m.build()

	// No method bodies, but the COR20 header occupies the section start, so the
	// metadata must sit after it (4-byte aligned).
	metaStart := synthAlign4(cor20Size)
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

	copy(buf[secRaw+metaStart:], meta)

	return buf
}
