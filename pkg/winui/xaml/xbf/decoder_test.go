/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const syntheticMinimalPath = "testdata/synthetic_minimal.xbf"

// TestMain regenerates the synthetic_minimal.xbf fixture before any test
// runs. The fixture is otherwise checked in; this keeps it deterministic.
func TestMain(m *testing.M) {
	if err := regenerateSyntheticMinimal(syntheticMinimalPath); err != nil {
		// Don't fail TestMain — let individual tests fail with proper context.
		_, _ = os.Stderr.WriteString("warning: regen synthetic_minimal.xbf: " + err.Error() + "\n")
	}
	os.Exit(m.Run())
}

// regenerateSyntheticMinimal writes a hand-built valid XBF v2.1 file
// representing:
//
//	<Page xmlns="...presentation" xmlns:x="...xaml" x:Class="App.MainPage">
//	  <Grid>
//	    <Button Content="Click Me"/>
//	  </Grid>
//	</Page>
func regenerateSyntheticMinimal(path string) error {
	b := newXBFBuilder()

	// Strings — pre-seed so namespace declarations can reference them.
	emptyIdx := b.addString("")
	uriDefault := b.addString("http://schemas.microsoft.com/winfx/2006/xaml/presentation")
	prefixX := b.addString("x")
	uriX := b.addString("http://schemas.microsoft.com/winfx/2006/xaml")
	mainPage := b.addString("App.MainPage")
	clickMe := b.addString("Click Me")
	_ = mainPage
	_ = clickMe

	// Types.
	pageIdx := b.addType("Page")
	gridIdx := b.addType("Grid")
	buttonIdx := b.addType("Button")

	// Properties.
	xClassIdx := b.addProperty("x:Class")
	contentIdx := b.addProperty("Content")

	// Stream:
	//   AddNamespace("", uriDefault)
	//   AddNamespace("x", uriX)
	//   StartObject Page
	//     StartProperty x:Class
	//       SetValue mainPage
	//     EndProperty
	//     StartObject Grid
	//       StartObject Button
	//         StartProperty Content
	//           SetValue clickMe
	//         EndProperty
	//       EndObject
	//     EndObject
	//   EndObject
	//   EndOfStream
	b.addNamespace(emptyIdx, uriDefault)
	b.addNamespace(prefixX, uriX)
	b.startObject(pageIdx)
	b.startProperty(xClassIdx)
	b.setValue(mainPage)
	b.endProperty()
	b.startObject(gridIdx)
	b.startObject(buttonIdx)
	b.startProperty(contentIdx)
	b.setValue(clickMe)
	b.endProperty()
	b.endObject()
	b.endObject()
	b.endObject()
	b.endOfStream()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b.build(), 0o644) //nolint:gosec
}

func TestRegenerateSyntheticMinimal(t *testing.T) {
	if err := regenerateSyntheticMinimal(syntheticMinimalPath); err != nil {
		t.Fatalf("regen: %v", err)
	}
	if _, err := os.Stat(syntheticMinimalPath); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
}

func TestDecodeXBF_SyntheticMinimal(t *testing.T) {
	d, err := DecodeXBF(syntheticMinimalPath)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	must := []string{
		"<Page",
		`xmlns="`,
		`x:Class="App.MainPage"`,
		"<Grid",
		"<Button",
		"</Page>",
	}
	for _, s := range must {
		if !strings.Contains(d.Recovered, s) {
			t.Errorf("Recovered missing %q\n--- recovered:\n%s", s, d.Recovered)
		}
	}
	// Whitespace-tolerant compare against golden.
	wantBytes, err := os.ReadFile("testdata/synthetic_minimal.xaml")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if normalize(string(wantBytes)) != normalize(d.Recovered) {
		t.Errorf("golden mismatch\nwant:\n%s\ngot:\n%s", string(wantBytes), d.Recovered)
	}
	if d.Version != "2.1" {
		t.Errorf("want version 2.1 got %q", d.Version)
	}
}

func TestDecodeXBF_TruncatedFile(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "trunc.xbf")
	if err := os.WriteFile(p, []byte{'X', 'B', 'F', 0x00, 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := DecodeXBF(p)
	if err == nil {
		t.Fatal("expected truncation error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncated, got %v", err)
	}
}

func TestDecodeXBF_BadMagic(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "bad.xbf")
	data := make([]byte, HeaderSize)
	copy(data[0:4], []byte{'X', 'M', 'L', 0})
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := DecodeXBF(p)
	if err == nil {
		t.Fatal("expected magic error")
	}
}

func TestDecodeXBF_NonexistentPath(t *testing.T) {
	_, err := DecodeXBF("/no/such/path/in/repo.xbf.synthetic")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Logf("err: %v (acceptable so long as err != nil)", err)
	}
}

func TestDecodeXBF_PathTraversal(t *testing.T) {
	_, err := DecodeXBF("../etc/passwd")
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func TestDecodeXBFBytes_PartialUnknown(t *testing.T) {
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	b.startObject(pageIdx)
	b.emit(0xFE) // unknown
	b.endObject()
	b.endOfStream()
	d, err := DecodeXBFBytes(b.build())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(d.Recovered, "<Page") {
		t.Errorf("missing <Page in %s", d.Recovered)
	}
	if !strings.Contains(d.Recovered, "<!-- xbf:opcode 0xFE unknown -->") {
		t.Errorf("missing placeholder in %s", d.Recovered)
	}
	if len(d.UnknownOpcodes) == 0 || d.UnknownOpcodes[0] != 0xFE {
		t.Errorf("UnknownOpcodes: %v", d.UnknownOpcodes)
	}
}

func TestDecodeXBF_Performance(t *testing.T) {
	// Build a synthetic XBF with many start/end pairs to approach 100 KiB.
	b := newXBFBuilder()
	pageIdx := b.addType("Page")
	// Each start+end+set pair is 6 bytes; we want ~100 KiB so ~16k pairs.
	b.startObject(pageIdx)
	for range 8000 {
		b.startObject(pageIdx)
		b.endObject()
	}
	b.endObject()
	b.endOfStream()
	data := b.build()
	if len(data) < 30_000 {
		t.Logf("warning: fixture size %d below 30 KiB; performance test less meaningful", len(data))
	}
	start := time.Now()
	_, err := DecodeXBFBytes(data)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("decode took %v; budget 1s", elapsed)
	}
}

func TestDecodeXBFBytes_OversizedRejected(t *testing.T) {
	data := make([]byte, MaxFileSize+1)
	_, err := DecodeXBFBytes(data)
	if err == nil {
		t.Fatal("expected size cap rejection")
	}
}

func TestDecodeXBFBytes_PanicSafety(t *testing.T) {
	// Random garbage that will exercise the bounds-check paths; must not panic.
	junk := []byte{'X', 'B', 'F', 0x00, 2, 0, 1, 0}
	junk = append(junk, make([]byte, HeaderSize-len(junk))...)
	_, err := DecodeXBFBytes(junk)
	// Either err or success; we only assert no panic — recover() catches it.
	_ = err
}

func TestToXAMLEntry(t *testing.T) {
	d := &DecodedXAML{
		Version:        "2.1",
		Recovered:      "<Page/>\n",
		SourceBytes:    128,
		UnknownOpcodes: []byte{0xFE},
	}
	e := ToXAMLEntry(d, "src/Page.xbf")
	if e.Kind != "xbf" {
		t.Errorf("kind: %s", e.Kind)
	}
	if e.Path != "src/Page.xbf" {
		t.Errorf("path: %s", e.Path)
	}
	if e.Recovered != d.Recovered {
		t.Errorf("recovered mismatch")
	}
	if e.SourceBytes != 128 {
		t.Errorf("sourcebytes: %d", e.SourceBytes)
	}
	found := false
	for _, er := range e.Errors {
		if strings.Contains(er, "unknown opcodes") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unknown opcodes error: %v", e.Errors)
	}
}

// normalize collapses whitespace runs so golden compare is layout-tolerant.
func normalize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, "\n")
}
