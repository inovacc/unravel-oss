/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"encoding/binary"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var regenPRI = flag.Bool("pri.regen", false, "regenerate testdata/synthetic.pri")

const syntheticPath = "testdata/synthetic.pri"

// buildSyntheticPRI builds the canonical synthetic PRI fixture in-memory.
// Layout documented in testdata/.README.
func buildSyntheticPRI() []byte {
	hsch := encodeStringPool([]string{"AppName", "AppDescription", "AppPublisher"})
	hsdt := encodeStringPool([]string{"Hello", "World", "Pri"})

	const tocCount = 2
	tocEnd := uint32(HeaderSize) + tocCount*sectionTOCEntrySize
	offHsch := tocEnd
	offHsdt := offHsch + uint32(len(hsch))
	totalLen := offHsdt + uint32(len(hsdt))

	buf := make([]byte, totalLen)
	copy(buf[:8], []byte("mrm_pri2"))
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	binary.LittleEndian.PutUint64(buf[12:20], uint64(totalLen))
	binary.LittleEndian.PutUint32(buf[20:24], HeaderSize)
	binary.LittleEndian.PutUint32(buf[24:28], tocCount)
	binary.LittleEndian.PutUint32(buf[28:32], tocEnd)

	copy(buf[HeaderSize:], makeTOCEntry("[mrm_hsch]", offHsch, uint32(len(hsch))))
	copy(buf[HeaderSize+sectionTOCEntrySize:], makeTOCEntry("[mrm_hsdt]", offHsdt, uint32(len(hsdt))))
	copy(buf[offHsch:], hsch)
	copy(buf[offHsdt:], hsdt)
	return buf
}

func TestMain(m *testing.M) {
	flag.Parse()
	// Ensure the synthetic fixture is materialised before any test runs.
	if err := ensureSyntheticFixture(); err != nil {
		// Tests will fail anyway; we don't os.Exit here to allow Go's
		// own test reporter to surface the failure.
		_ = err
	}
	os.Exit(m.Run())
}

func ensureSyntheticFixture() error {
	if _, err := os.Stat(syntheticPath); err == nil && !*regenPRI {
		return nil
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		return err
	}
	return os.WriteFile(syntheticPath, buildSyntheticPRI(), 0o600)
}

func TestPRIParse_SyntheticFixture(t *testing.T) {
	abs, err := filepath.Abs(syntheticPath)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse(abs)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Magic != "mrm_pri2" {
		t.Errorf("Magic = %q, want mrm_pri2", res.Magic)
	}
	if len(res.Resources) < 1 {
		t.Fatalf("expected >=1 resource, got %d", len(res.Resources))
	}
	gotName, gotValue := false, false
	for _, r := range res.Resources {
		if r.Name != "" {
			gotName = true
		}
		if r.Value != "" {
			gotValue = true
		}
	}
	if !gotName {
		t.Error("no resource has a non-empty Name")
	}
	if !gotValue {
		t.Error("no resource has a non-empty Value")
	}
}

func TestPRIParse_TruncatedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tiny.pri")
	if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Parse(p)
	if err == nil {
		t.Fatal("expected error for truncated file")
	}
}

func TestPRIParse_PathTraversal(t *testing.T) {
	_, err := Parse("../etc/passwd")
	if err == nil {
		t.Fatal("expected error for traversal path")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error = %q, want substring 'rejected'", err)
	}
}

func TestPRIParseBytes_Oversized(t *testing.T) {
	// A buffer larger than the cap should fail before any decode work.
	data := make([]byte, MaxFileSize+1)
	_, err := ParseBytes(data)
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestPRIParseBytes_BadMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf[:8], []byte("xxxx_pri"))
	_, err := ParseBytes(buf)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestRegenerateSyntheticPRI(t *testing.T) {
	if !*regenPRI {
		t.Skip("re-run with -pri.regen to regenerate fixture")
	}
	if err := os.WriteFile(syntheticPath, buildSyntheticPRI(), 0o600); err != nil {
		t.Fatal(err)
	}
}
