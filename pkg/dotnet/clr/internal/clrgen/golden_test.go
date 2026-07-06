/*
Copyright (c) 2026 Security Research
*/
package clrgen_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/internal/clrgen"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata"
)

var update = flag.Bool("update", false, "rewrite golden digests")

func TestMain(m *testing.M) {
	flag.Parse()
	if *update {
		sum := sha256.Sum256(clrgen.Canonical())
		_ = os.WriteFile("testdata/canonical.sha256", []byte(hex.EncodeToString(sum[:])), 0o644)
	}
	os.Exit(m.Run())
}

func TestCanonical_ByteStable(t *testing.T) {
	b := clrgen.Canonical()
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])

	want, err := os.ReadFile("testdata/canonical.sha256")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if g := string(bytes.TrimSpace(want)); g != got {
		t.Fatalf("Canonical() digest = %s, want %s (run go test -run TestCanonical -update)", got, g)
	}
}

func TestCanonical_ParsesThroughFrozenAPI(t *testing.T) {
	img, err := clr.OpenReaderAt(bytes.NewReader(clrgen.Canonical()), int64(len(clrgen.Canonical())))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tbls, heaps, err := metadata.Parse(img.Metadata())
	if err != nil {
		t.Fatalf("metadata.Parse: %v", err)
	}

	asm, ok := tbls.Assembly()
	if !ok || asm.Name != "CanonAsm" {
		t.Fatalf("Assembly() = %+v, ok=%v; want name CanonAsm", asm, ok)
	}
	if refs := tbls.AssemblyRefs(); len(refs) != 1 || refs[0].Name != "System.Runtime" {
		t.Fatalf("AssemblyRefs() = %+v; want [System.Runtime]", refs)
	}
	types := tbls.Types()
	if len(types) != 1 || types[0].Name != "Widget" || types[0].Namespace != "Canon.Core" {
		t.Fatalf("Types() = %+v; want Canon.Core.Widget", types)
	}
	if len(types[0].Methods) != 2 {
		t.Fatalf("method count = %d, want 2", len(types[0].Methods))
	}
	if us := tbls.UserStrings(); len(us) != 1 || us[0] != "canon literal" {
		t.Fatalf("UserStrings() = %v; want [canon literal]", us)
	}
	pinv := tbls.PInvokes()
	if len(pinv) != 1 || pinv[0].ImportName != "Beep" || pinv[0].ImportScope != "kernel32.dll" {
		t.Fatalf("PInvokes() = %+v; want Beep@kernel32.dll", pinv)
	}
	_ = heaps
}
