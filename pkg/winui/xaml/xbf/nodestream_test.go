/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"bytes"
	"strings"
	"testing"
)

func decodeStream(t *testing.T, b *xbfBuilder) (*NodeTree, *Tables) {
	t.Helper()
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
	streamStart := h.MaxRegionEnd()
	if _, err := r.Seek(int64(streamStart), 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	tree, err := DecodeNodeStream(r, tables)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return tree, tables
}

func TestDecodeNodeStream_StartEnd(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	b.startObject(pageIdx)
	b.endObject()
	b.endOfStream()

	tree, _ := decodeStream(t, b)
	if tree.Root == nil {
		t.Fatal("nil root")
	}
	if tree.Root.Op != OpStartObject {
		t.Fatalf("got op 0x%02X want StartObject", byte(tree.Root.Op))
	}
	if tree.Root.Name != "Page" {
		t.Fatalf("got name %q want Page", tree.Root.Name)
	}
}

func TestDecodeNodeStream_NestedObject(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	gridIdx := b.addType("Grid")
	b.startObject(pageIdx)
	b.startObject(gridIdx)
	b.endObject()
	b.endObject()
	b.endOfStream()

	tree, _ := decodeStream(t, b)
	if tree.Root == nil || len(tree.Root.Children) != 1 {
		t.Fatalf("want 1 child got %v", tree.Root)
	}
	if tree.Root.Children[0].Name != "Grid" {
		t.Fatalf("want Grid got %q", tree.Root.Children[0].Name)
	}
	if tree.Stats.DepthMax < 2 {
		t.Fatalf("depth max %d < 2", tree.Stats.DepthMax)
	}
}

func TestDecodeNodeStream_PropertySetValue(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	xClassIdx := b.addProperty("x:Class")
	valIdx := b.addString("App.MainPage")

	b.startObject(pageIdx)
	b.startProperty(xClassIdx)
	b.setValue(valIdx)
	b.endProperty()
	b.endObject()
	b.endOfStream()

	tree, _ := decodeStream(t, b)
	if tree.Root == nil {
		t.Fatal("nil root")
	}
	if len(tree.Root.Properties) != 1 {
		t.Fatalf("want 1 property got %d", len(tree.Root.Properties))
	}
	p := tree.Root.Properties[0]
	if p.Name != "x:Class" {
		t.Fatalf("want x:Class got %q", p.Name)
	}
	if p.Value != "App.MainPage" {
		t.Fatalf("want App.MainPage got %q", p.Value)
	}
}

func TestDecodeNodeStream_UnknownOpcode(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	b.startObject(pageIdx)
	b.emit(0xFE) // unknown opcode
	b.endObject()
	b.endOfStream()

	tree, _ := decodeStream(t, b)
	if tree.Stats.UnknownNodes < 1 {
		t.Fatalf("expected >=1 unknown node, got %d", tree.Stats.UnknownNodes)
	}
	if len(tree.UnknownOpcodes) == 0 || tree.UnknownOpcodes[0] != 0xFE {
		t.Fatalf("expected UnknownOpcodes[0]=0xFE got %v", tree.UnknownOpcodes)
	}
	// Unknown should attach to current parent.
	found := false
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		if n.Unknown && n.UnknownByte == 0xFE {
			found = true
		}
		for _, c := range n.Children {
			walk(c)
		}
		for _, p := range n.Properties {
			walk(p)
		}
	}
	walk(tree.Root)
	if !found {
		t.Fatal("did not find unknown node in tree")
	}
}

func TestDecodeNodeStream_DepthBomb(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	for range 100 {
		b.startObject(pageIdx)
	}
	// Don't bother to close — decoder must unwind on its own.
	b.endOfStream()

	// We must not panic, must not hang. decodeStream calls DecodeNodeStream
	// which returns once max-depth tripped.
	tree, _ := decodeStream(t, b)
	hasWarn := false
	for _, w := range tree.Warnings() {
		if strings.Contains(w, "max recursion depth") || strings.Contains(w, "max depth exceeded") {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Fatalf("expected max-depth warning; got %v", tree.Warnings())
	}
	if tree.Stats.DepthMax > MaxDepth+1 {
		t.Fatalf("depth max %d > cap %d (+1 tolerance)", tree.Stats.DepthMax, MaxDepth)
	}
}

func TestDecodeNodeStream_StringTableOOB(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	xClassIdx := b.addProperty("x:Class")

	b.startObject(pageIdx)
	b.startProperty(xClassIdx)
	// Reference string idx 999, well beyond the 2-string table.
	b.setValue(999)
	b.endProperty()
	b.endObject()
	b.endOfStream()

	tree, _ := decodeStream(t, b)
	hasWarn := false
	for _, w := range tree.Warnings() {
		if strings.Contains(w, "out of range") {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Fatalf("expected oob warning; got %v", tree.Warnings())
	}
	// Value should be a placeholder.
	if !strings.Contains(tree.Root.Properties[0].Value, "string-oob") {
		t.Fatalf("expected oob placeholder in value, got %q", tree.Root.Properties[0].Value)
	}
}
