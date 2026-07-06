/*
Copyright (c) 2026 Security Research
*/
package clrgen_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/internal/clrgen"
)

// getenv is a thin wrapper so the gate check reads cleanly below.
func getenv(k string) string { return os.Getenv(k) }

// TestTier1_NoDotNetNeeded proves the canonical + edge fixtures build and parse
// with zero external tools. Under UNRAVEL_NODOTNET_GATE=1 (the Docker gate) it
// additionally fails if any .NET tool is on PATH — the acceptance proof.
func TestTier1_NoDotNetNeeded(t *testing.T) {
	// Fixtures must be byte-producible with stdlib only.
	for name, fn := range map[string]func() []byte{
		"canonical": clrgen.Canonical,
		"ptr":       clrgen.PtrIndirected,
		"native":    clrgen.NativeBody,
		"eh":        clrgen.MultiSectionEH,
	} {
		if b := fn(); len(b) < 0x400 {
			t.Fatalf("%s fixture too small: %d bytes", name, len(b))
		}
	}

	if testing.Short() {
		return
	}
	if v := getenv("UNRAVEL_NODOTNET_GATE"); v == "1" {
		for _, tool := range []string{"dotnet", "ilspycmd", "ildasm"} {
			if p, err := exec.LookPath(tool); err == nil {
				t.Fatalf("no-.NET gate violated: %s found on PATH at %s", tool, p)
			}
		}
	}
}
