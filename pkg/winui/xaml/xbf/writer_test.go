/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"strings"
	"testing"
)

func TestRenderXAML_Indentation(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	gridIdx := b.addType("Grid")
	btnIdx := b.addType("Button")
	b.startObject(pageIdx)
	b.startObject(gridIdx)
	b.startObject(btnIdx)
	b.endObject()
	b.endObject()
	b.endObject()
	b.endOfStream()
	tree, _ := decodeStream(t, b)
	out := RenderXAML(tree, nil)
	// Depth 1 for Grid (2 spaces), depth 2 for Button (4 spaces).
	if !strings.Contains(out, "\n  <Grid") {
		t.Errorf("expected 2-space indent for Grid in:\n%s", out)
	}
	if !strings.Contains(out, "\n    <Button") {
		t.Errorf("expected 4-space indent for Button in:\n%s", out)
	}
}

func TestRenderXAML_AttributeOrder(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	a := b.addProperty("Aaa")
	bb := b.addProperty("Bbb")
	cc := b.addProperty("Ccc")
	v1 := b.addString("1")
	v2 := b.addString("2")
	v3 := b.addString("3")
	b.startObject(pageIdx)
	b.startProperty(a)
	b.setValue(v1)
	b.endProperty()
	b.startProperty(bb)
	b.setValue(v2)
	b.endProperty()
	b.startProperty(cc)
	b.setValue(v3)
	b.endProperty()
	b.endObject()
	b.endOfStream()
	tree, _ := decodeStream(t, b)
	out := RenderXAML(tree, nil)
	iA := strings.Index(out, `Aaa="1"`)
	iB := strings.Index(out, `Bbb="2"`)
	iC := strings.Index(out, `Ccc="3"`)
	if iA < 0 || iB < 0 || iC < 0 {
		t.Fatalf("missing attrs in %q", out)
	}
	if !(iA < iB && iB < iC) {
		t.Errorf("expected document order Aaa<Bbb<Ccc, got %d %d %d in %q", iA, iB, iC, out)
	}
}

func TestRenderXAML_NamespacePropagation(t *testing.T) {
	b := newXBFBuilder()
	emptyIdx := b.addString("")
	uri := b.addString("http://example.com/a")
	prefix := b.addString("foo")
	uri2 := b.addString("http://example.com/b")
	pageIdx := b.addType("Page")

	b.addNamespace(emptyIdx, uri)
	b.addNamespace(prefix, uri2)
	b.startObject(pageIdx)
	b.endObject()
	b.endOfStream()
	tree, _ := decodeStream(t, b)
	out := RenderXAML(tree, nil)
	if !strings.Contains(out, `xmlns="http://example.com/a"`) {
		t.Errorf("missing default namespace in:\n%s", out)
	}
	if !strings.Contains(out, `xmlns:foo="http://example.com/b"`) {
		t.Errorf("missing prefixed namespace in:\n%s", out)
	}
}

func TestRenderXAML_UnknownPlaceholderFormat(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	b.startObject(pageIdx)
	b.emit(0xFE)
	b.endObject()
	b.endOfStream()
	tree, _ := decodeStream(t, b)
	out := RenderXAML(tree, nil)
	if !strings.Contains(out, "<!-- xbf:opcode 0xFE unknown -->") {
		t.Errorf("missing canonical placeholder in:\n%s", out)
	}
}

func TestRenderXAML_NilSafe(t *testing.T) {
	if got := RenderXAML(nil, nil); got != "" {
		t.Errorf("nil tree should render empty, got %q", got)
	}
	if got := RenderXAML(&NodeTree{}, nil); got != "" {
		t.Errorf("empty tree should render empty, got %q", got)
	}
}

func TestRenderXAML_XMLEscape(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	prop := b.addProperty("Title")
	val := b.addString(`Hello & <world>`)
	b.startObject(pageIdx)
	b.startProperty(prop)
	b.setValue(val)
	b.endProperty()
	b.endObject()
	b.endOfStream()
	tree, _ := decodeStream(t, b)
	out := RenderXAML(tree, nil)
	if strings.Contains(out, "<world>") {
		t.Errorf("expected escaped <world>; got: %s", out)
	}
	if !strings.Contains(out, "&amp;") {
		t.Errorf("expected escaped &amp;; got: %s", out)
	}
}
