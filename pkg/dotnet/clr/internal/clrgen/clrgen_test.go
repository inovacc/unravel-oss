/*
Copyright (c) 2026 Security Research
*/
package clrgen_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/internal/clrgen"
)

func TestEmit_OpensAsManagedImage(t *testing.T) {
	b := clrgen.New().
		WithAssembly("HelloAsm", [4]uint16{1, 2, 3, 4}).
		WithAssemblyRef("System.Runtime", [4]uint16{8, 0, 0, 0}).
		WithType("Hello.World", "Greeter",
			clrgen.Method("SayHi", 0x2050),
			clrgen.Method("SayBye", 0x2060)).
		WithUserString("hello from clrgen").
		WithPInvoke("MessageBoxW", "user32.dll").
		Emit()

	if len(b) < 0x400 {
		t.Fatalf("emitted image too small: %d bytes", len(b))
	}

	img, err := clr.Open(writeTemp(t, b))
	if err != nil {
		t.Fatalf("clr.Open on emitted image: %v", err)
	}

	meta := img.Metadata()
	if got := binary.LittleEndian.Uint32(meta[:4]); got != 0x424A5342 { // "BSJB"
		t.Fatalf("metadata sig = %#x, want BSJB", got)
	}

	// RVAToOffset must round-trip the COR20 RVA we placed.
	if _, ok := img.RVAToOffset(clrgen.SectionRVA); !ok {
		t.Fatalf("RVAToOffset(%#x) not mapped", clrgen.SectionRVA)
	}

	// OpenReaderAt parity with Open.
	if _, err := clr.OpenReaderAt(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatalf("OpenReaderAt: %v", err)
	}
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	p := t.TempDir() + "/clrgen.dll"
	if err := writeFile(p, b); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func writeFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}
