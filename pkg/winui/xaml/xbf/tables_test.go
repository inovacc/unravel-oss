/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseTables_StringTable(t *testing.T) {
	b := newXBFBuilder()
	b.addString("Page")
	b.addString("Button")
	b.addString("x:Key")
	data := b.build()
	r := bytes.NewReader(data)
	h, err := ParseHeader(r)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	tables, err := ParseTables(r, h)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	want := []string{"Page", "Button", "x:Key"}
	if len(tables.Strings) != len(want) {
		t.Fatalf("len strings: got %d want %d (%v)", len(tables.Strings), len(want), tables.Strings)
	}
	for i, w := range want {
		if tables.Strings[i] != w {
			t.Errorf("strings[%d]: got %q want %q", i, tables.Strings[i], w)
		}
	}
}

func TestParseTables_StringTableTruncated(t *testing.T) {
	// Build a region with count=5 but only 2 bytes of payload.
	region := make([]byte, 2+2)
	binary.LittleEndian.PutUint16(region[0:2], 5) // count
	binary.LittleEndian.PutUint16(region[2:4], 4) // first entry says 4 chars but no body

	hdr := make([]byte, HeaderSize)
	copy(hdr[0:4], XBFMagic[:])
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 1)
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(HeaderSize))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(region)))

	full := append(hdr, region...)
	r := bytes.NewReader(full)
	h, err := ParseHeader(r)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	_, err = ParseTables(r, h)
	if err == nil {
		t.Fatal("expected truncation error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncated error, got: %v", err)
	}
}

func TestParseTables_OversizedTable(t *testing.T) {
	// We can't easily construct a 16 MiB+ blob in test; instead force the
	// readRegion-level cap via direct call.
	hdr := &Header{}
	hdr.TableTOC.Strings = Region{Offset: 64, Size: 32 << 20}
	// Build a fake reader large enough to satisfy seeks.
	fake := make([]byte, 64+128)
	copy(fake[0:4], XBFMagic[:])
	binary.LittleEndian.PutUint16(fake[4:6], 2)
	binary.LittleEndian.PutUint16(fake[6:8], 1)
	r := bytes.NewReader(fake)
	_, err := ParseTables(r, hdr)
	if err == nil {
		t.Fatal("expected size cap error")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected exceeds limit, got: %v", err)
	}
}

func TestParseTables_AllSeven(t *testing.T) {
	b := newXBFBuilder()
	pageNameIdx := b.addString("Page")
	b.addString("Microsoft.UI.Xaml")
	asmIdx := uint16(len(b.assemblies))
	b.assemblies = append(b.assemblies, AssemblyRef{NameIdx: pageNameIdx})
	tnsIdx := uint16(len(b.typeNS))
	b.typeNS = append(b.typeNS, TypeNamespaceRef{AssemblyIdx: asmIdx, NameIdx: pageNameIdx})
	b.types = append(b.types, TypeRef{NamespaceIdx: tnsIdx, NameIdx: pageNameIdx})
	b.properties = append(b.properties, PropertyRef{TypeIdx: 0, NameIdx: pageNameIdx})
	b.xmlNS = append(b.xmlNS, XmlNamespaceRef{NameIdx: pageNameIdx})
	b.events = append(b.events, EventRef{TypeIdx: 0, NameIdx: pageNameIdx})

	data := b.build()
	r := bytes.NewReader(data)
	h, err := ParseHeader(r)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	tables, err := ParseTables(r, h)
	if err != nil {
		t.Fatalf("tables: %v", err)
	}
	if len(tables.Strings) == 0 {
		t.Error("strings empty")
	}
	if len(tables.Assemblies) == 0 {
		t.Error("assemblies empty")
	}
	if len(tables.TypeNamespaces) == 0 {
		t.Error("type-namespaces empty")
	}
	if len(tables.Types) == 0 {
		t.Error("types empty")
	}
	if len(tables.Properties) == 0 {
		t.Error("properties empty")
	}
	if len(tables.XmlNamespaces) == 0 {
		t.Error("xml-namespaces empty")
	}
	if len(tables.Events) == 0 {
		t.Error("events empty")
	}
}

func TestTables_StringOOB(t *testing.T) {
	tables := &Tables{Strings: []string{"a", "b"}}
	got := tables.String(999)
	if !strings.Contains(got, "string-oob:999") {
		t.Fatalf("expected oob placeholder, got %q", got)
	}
}
